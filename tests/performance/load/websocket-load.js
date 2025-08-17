/**
 * WebSocket Load Testing - Phase 2 Week 4
 * Dedicated WebSocket performance and concurrency testing
 */

import ws from 'k6/ws';
import { check, sleep } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

// Custom metrics for WebSocket testing
const wsConnectionTime = new Trend('ws_connection_time');
const wsMessageLatency = new Trend('ws_message_latency');
const wsActiveConnections = new Trend('ws_active_connections');
const wsConnectionErrors = new Rate('ws_connection_errors');
const wsMessageErrors = new Rate('ws_message_errors');
const wsReconnections = new Rate('ws_reconnections');
const wsMessagesSent = new Counter('ws_messages_sent');
const wsMessagesReceived = new Counter('ws_messages_received');

export const options = {
  stages: [
    { duration: '2m', target: 50 },   // Ramp up to 50 WebSocket connections
    { duration: '5m', target: 50 },   // Stay at 50 connections
    { duration: '2m', target: 100 },  // Ramp up to 100 connections
    { duration: '5m', target: 100 },  // Stay at 100 connections
    { duration: '2m', target: 200 },  // Stress test with 200 connections
    { duration: '3m', target: 200 },  // Hold stress level
    { duration: '2m', target: 0 }     // Ramp down
  ],
  thresholds: {
    ws_connection_time: ['avg<1000', 'p(95)<2000'],
    ws_message_latency: ['avg<100', 'p(95)<200'],
    ws_connection_errors: ['rate<0.05'],
    ws_message_errors: ['rate<0.01'],
    ws_reconnections: ['rate<0.1']
  }
};

export default function () {
  const wsUrl = `ws://${__ENV.WS_HOST || 'localhost:5000'}/ws`;
  const connectionStart = Date.now();
  
  const response = ws.connect(wsUrl, {
    headers: {
      'Authorization': `Bearer ${generateMockToken()}`,
      'Origin': 'http://localhost:3000'
    }
  }, function (socket) {
    // Record connection time
    const connectionEnd = Date.now();
    wsConnectionTime.add(connectionEnd - connectionStart);
    
    let activeConnections = 1;
    wsActiveConnections.add(activeConnections);
    
    // Connection established successfully
    check(null, {
      'WebSocket connection established': () => socket.readyState === ws.READY_STATE_OPEN
    });

    // Test real-time room operations
    performRoomOperations(socket);
    
    // Test real-time card operations
    performCardOperations(socket);
    
    // Test user presence updates
    performPresenceUpdates(socket);
    
    // Test high-frequency messaging
    performHighFrequencyMessaging(socket);
    
    // Handle connection errors and reconnection
    socket.on('error', function (e) {
      console.error('WebSocket error:', e);
      wsConnectionErrors.add(1);
      
      // Attempt reconnection
      setTimeout(() => {
        wsReconnections.add(1);
      }, 1000);
    });
    
    socket.on('close', function (code) {
      activeConnections--;
      wsActiveConnections.add(activeConnections);
      console.log(`WebSocket closed with code: ${code}`);
    });
    
    // Keep connection alive for testing duration
    sleep(Math.random() * 30 + 10); // 10-40 seconds
    
    socket.close();
  });

  check(response, {
    'WebSocket connection attempt succeeded': (r) => r && r.status === 101
  }) || wsConnectionErrors.add(1);
}

function performRoomOperations(socket) {
  const operations = [
    {
      type: 'JOIN_ROOM',
      payload: { roomId: `room-${Math.floor(Math.random() * 10)}` }
    },
    {
      type: 'LEAVE_ROOM', 
      payload: { roomId: `room-${Math.floor(Math.random() * 10)}` }
    },
    {
      type: 'GET_ROOM_STATE',
      payload: { roomId: `room-${Math.floor(Math.random() * 10)}` }
    }
  ];

  operations.forEach((operation, index) => {
    setTimeout(() => {
      const messageStart = Date.now();
      
      socket.send(JSON.stringify(operation));
      wsMessagesSent.add(1);
      
      // Set up response handler
      const responseHandler = (message) => {
        try {
          const data = JSON.parse(message);
          if (data.type === `${operation.type}_RESPONSE`) {
            const messageEnd = Date.now();
            wsMessageLatency.add(messageEnd - messageStart);
            wsMessagesReceived.add(1);
            
            socket.removeEventListener('message', responseHandler);
          }
        } catch (e) {
          wsMessageErrors.add(1);
        }
      };
      
      socket.addEventListener('message', responseHandler);
      
      // Timeout handler
      setTimeout(() => {
        socket.removeEventListener('message', responseHandler);
        wsMessageErrors.add(1);
      }, 5000);
      
    }, index * 500); // Stagger operations
  });
}

function performCardOperations(socket) {
  const cardOperations = [
    {
      type: 'MOVE_CARD',
      payload: {
        cardId: `card-${Math.floor(Math.random() * 100)}`,
        fromPosition: { x: 100, y: 100 },
        toPosition: { x: 200, y: 200 },
        roomId: `room-${Math.floor(Math.random() * 10)}`
      }
    },
    {
      type: 'FLIP_CARD',
      payload: {
        cardId: `card-${Math.floor(Math.random() * 100)}`,
        roomId: `room-${Math.floor(Math.random() * 10)}`
      }
    },
    {
      type: 'ROTATE_CARD',
      payload: {
        cardId: `card-${Math.floor(Math.random() * 100)}`,
        rotation: Math.floor(Math.random() * 360),
        roomId: `room-${Math.floor(Math.random() * 10)}`
      }
    }
  ];

  cardOperations.forEach((operation, index) => {
    setTimeout(() => {
      const messageStart = Date.now();
      
      socket.send(JSON.stringify(operation));
      wsMessagesSent.add(1);
      
      // Monitor for real-time updates to other clients
      const updateHandler = (message) => {
        try {
          const data = JSON.parse(message);
          if (data.type === 'CARD_UPDATE') {
            const messageEnd = Date.now();
            wsMessageLatency.add(messageEnd - messageStart);
            wsMessagesReceived.add(1);
            
            // Verify update contains expected data
            check(data, {
              'Card update has valid structure': (d) => d.payload && d.payload.cardId,
              'Card update has position data': (d) => d.payload.position !== undefined
            });
            
            socket.removeEventListener('message', updateHandler);
          }
        } catch (e) {
          wsMessageErrors.add(1);
        }
      };
      
      socket.addEventListener('message', updateHandler);
      
      // Cleanup timeout
      setTimeout(() => {
        socket.removeEventListener('message', updateHandler);
      }, 3000);
      
    }, index * 300); // Faster card operations
  });
}

function performPresenceUpdates(socket) {
  const presenceEvents = [
    {
      type: 'USER_CURSOR_UPDATE',
      payload: {
        x: Math.floor(Math.random() * 1920),
        y: Math.floor(Math.random() * 1080),
        roomId: `room-${Math.floor(Math.random() * 10)}`
      }
    },
    {
      type: 'USER_SELECTION',
      payload: {
        selectedCards: [`card-${Math.floor(Math.random() * 100)}`],
        roomId: `room-${Math.floor(Math.random() * 10)}`
      }
    },
    {
      type: 'USER_TYPING',
      payload: {
        isTyping: Math.random() > 0.5,
        roomId: `room-${Math.floor(Math.random() * 10)}`
      }
    }
  ];

  // Send presence updates at high frequency
  let presenceInterval = setInterval(() => {
    const event = presenceEvents[Math.floor(Math.random() * presenceEvents.length)];
    
    socket.send(JSON.stringify(event));
    wsMessagesSent.add(1);
  }, 500); // Every 500ms

  // Stop after 10 seconds
  setTimeout(() => {
    clearInterval(presenceInterval);
  }, 10000);
}

function performHighFrequencyMessaging(socket) {
  // Simulate collaborative editing with high-frequency updates
  const updateTypes = ['cursor', 'selection', 'scroll', 'zoom'];
  let messageCount = 0;
  const maxMessages = 50;
  
  const highFreqInterval = setInterval(() => {
    if (messageCount >= maxMessages) {
      clearInterval(highFreqInterval);
      return;
    }
    
    const updateType = updateTypes[Math.floor(Math.random() * updateTypes.length)];
    const messageStart = Date.now();
    
    const message = {
      type: 'REAL_TIME_UPDATE',
      payload: {
        updateType: updateType,
        data: generateUpdateData(updateType),
        timestamp: Date.now(),
        userId: `user-${Math.floor(Math.random() * 100)}`,
        roomId: `room-${Math.floor(Math.random() * 10)}`
      }
    };
    
    socket.send(JSON.stringify(message));
    wsMessagesSent.add(1);
    messageCount++;
    
    // Measure round-trip time for echo responses
    const echoHandler = (response) => {
      try {
        const data = JSON.parse(response);
        if (data.type === 'REAL_TIME_UPDATE_ACK' && data.timestamp === message.payload.timestamp) {
          const messageEnd = Date.now();
          wsMessageLatency.add(messageEnd - messageStart);
          wsMessagesReceived.add(1);
          
          socket.removeEventListener('message', echoHandler);
        }
      } catch (e) {
        wsMessageErrors.add(1);
      }
    };
    
    socket.addEventListener('message', echoHandler);
    
    // Cleanup
    setTimeout(() => {
      socket.removeEventListener('message', echoHandler);
    }, 1000);
    
  }, 100); // Very high frequency - every 100ms
}

function generateUpdateData(updateType) {
  switch (updateType) {
    case 'cursor':
      return {
        x: Math.floor(Math.random() * 1920),
        y: Math.floor(Math.random() * 1080)
      };
    case 'selection':
      return {
        selectedItems: Array.from({ length: Math.floor(Math.random() * 5) + 1 }, 
          () => `item-${Math.floor(Math.random() * 100)}`)
      };
    case 'scroll':
      return {
        scrollX: Math.floor(Math.random() * 2000),
        scrollY: Math.floor(Math.random() * 2000)
      };
    case 'zoom':
      return {
        zoomLevel: Math.random() * 2 + 0.5, // 0.5x to 2.5x zoom
        centerX: Math.floor(Math.random() * 1920),
        centerY: Math.floor(Math.random() * 1080)
      };
    default:
      return {};
  }
}

function generateMockToken() {
  const tokens = [
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkxIiwibmFtZSI6IkphbmUgU21pdGgiLCJpYXQiOjE1MTYyMzkwMjJ9.abc123',
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkyIiwibmFtZSI6IkJvYiBKb2huc29uIiwiaWF0IjoxNTE2MjM5MDIyfQ.def456'
  ];
  
  return tokens[Math.floor(Math.random() * tokens.length)];
}

// Handle test summary and results
export function handleSummary(data) {
  return {
    'websocket-load-summary.json': JSON.stringify({
      timestamp: new Date().toISOString(),
      metrics: {
        ws_connection_time: data.metrics.ws_connection_time,
        ws_message_latency: data.metrics.ws_message_latency,
        ws_active_connections: data.metrics.ws_active_connections,
        ws_connection_errors: data.metrics.ws_connection_errors,
        ws_message_errors: data.metrics.ws_message_errors,
        ws_reconnections: data.metrics.ws_reconnections,
        ws_messages_sent: data.metrics.ws_messages_sent,
        ws_messages_received: data.metrics.ws_messages_received
      },
      thresholds: data.root_group.checks,
      summary: {
        totalConnections: data.metrics.ws_active_connections?.values?.max || 0,
        avgConnectionTime: data.metrics.ws_connection_time?.values?.avg || 0,
        avgMessageLatency: data.metrics.ws_message_latency?.values?.avg || 0,
        connectionErrorRate: data.metrics.ws_connection_errors?.values?.rate || 0,
        messageErrorRate: data.metrics.ws_message_errors?.values?.rate || 0,
        totalMessagesSent: data.metrics.ws_messages_sent?.values?.count || 0,
        totalMessagesReceived: data.metrics.ws_messages_received?.values?.count || 0
      }
    }, null, 2)
  };
}


