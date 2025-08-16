// Performance and Load Testing with k6
import { check } from 'k6';
import { WebSocket } from 'k6/ws';
import http from 'k6/http';

// Test configuration for different load scenarios
export let options = {
  stages: [
    // Ramp up to 50 users over 30 seconds
    { duration: '30s', target: 50 },
    // Stay at 50 users for 1 minute
    { duration: '1m', target: 50 },
    // Ramp up to 100 users over 30 seconds
    { duration: '30s', target: 100 },
    // Stay at 100 users for 2 minutes
    { duration: '2m', target: 100 },
    // Ramp down to 0 users over 30 seconds
    { duration: '30s', target: 0 }
  ],
  thresholds: {
    // HTTP request duration should be < 100ms for 95% of requests
    http_req_duration: ['p(95)<100'],
    // WebSocket connection time should be < 1000ms
    ws_connecting: ['avg<1000'],
    // WebSocket session duration should be acceptable
    ws_session_duration: ['avg<60000'],
    // Message receive rate should be > 0
    ws_msgs_received: ['count>0'],
    // Error rate should be < 1%
    http_req_failed: ['rate<0.01']
  }
};

const BASE_URL = __ENV.BASE_URL || 'http://localhost:5000';
const WS_URL = __ENV.WS_URL || 'ws://localhost:5000/ws';

// Mock authentication token for load testing
function getAuthToken() {
  return `load-test-token-${Math.random().toString(36).substring(7)}`;
}

// API Load Testing
export function apiLoadTest() {
  const authToken = getAuthToken();
  const headers = {
    'Authorization': `Bearer ${authToken}`,
    'Content-Type': 'application/json'
  };

  // Test room creation
  const roomData = {
    name: `Load Test Room ${Math.random().toString(36).substring(7)}`,
    description: 'Room created during load testing',
    maxPlayers: 6,
    isPublic: false
  };

  const createRoomResponse = http.post(
    `${BASE_URL}/api/rooms`,
    JSON.stringify(roomData),
    { headers }
  );

  check(createRoomResponse, {
    'room creation status is 201': (r) => r.status === 201,
    'room creation response time < 200ms': (r) => r.timings.duration < 200,
    'room creation has valid response': (r) => {
      const body = JSON.parse(r.body);
      return body.data && body.data.name === roomData.name;
    }
  });

  if (createRoomResponse.status === 201) {
    const roomId = JSON.parse(createRoomResponse.body).data.id;

    // Test room retrieval
    const getRoomResponse = http.get(
      `${BASE_URL}/api/rooms/${roomId}`,
      { headers }
    );

    check(getRoomResponse, {
      'room retrieval status is 200': (r) => r.status === 200,
      'room retrieval response time < 100ms': (r) => r.timings.duration < 100
    });

    // Test asset upload simulation
    const assetData = {
      name: 'Load Test Asset',
      type: 'card',
      category: 'test-assets'
    };

    const uploadAssetResponse = http.post(
      `${BASE_URL}/api/rooms/${roomId}/assets`,
      JSON.stringify(assetData),
      { headers }
    );

    check(uploadAssetResponse, {
      'asset upload status is 201': (r) => r.status === 201,
      'asset upload response time < 500ms': (r) => r.timings.duration < 500
    });

    // Test room assets retrieval
    const getAssetsResponse = http.get(
      `${BASE_URL}/api/rooms/${roomId}/assets`,
      { headers }
    );

    check(getAssetsResponse, {
      'assets retrieval status is 200': (r) => r.status === 200,
      'assets retrieval response time < 150ms': (r) => r.timings.duration < 150
    });
  }
}

// WebSocket Load Testing
export function websocketLoadTest() {
  const authToken = getAuthToken();
  
  const wsResponse = WebSocket.connect(WS_URL, {}, function(socket) {
    socket.on('open', () => {
      console.log(`WebSocket connection established for user ${__VU}`);
      
      // Authenticate
      socket.send(JSON.stringify({
        type: 'auth:authenticate',
        data: { token: authToken },
        timestamp: new Date().toISOString(),
        correlationId: `load-test-${__VU}-${Date.now()}`
      }));

      // Join a test room
      socket.send(JSON.stringify({
        type: 'room:join',
        data: { roomId: 'load-test-room' },
        timestamp: new Date().toISOString(),
        correlationId: `load-test-join-${__VU}-${Date.now()}`
      }));

      // Simulate periodic game activity
      let messageCount = 0;
      const activityInterval = setInterval(() => {
        if (messageCount >= 10) {
          clearInterval(activityInterval);
          socket.close();
          return;
        }

        // Simulate asset movement
        socket.send(JSON.stringify({
          type: 'asset:moved',
          data: {
            assetId: `test-asset-${__VU}`,
            position: {
              x: Math.random() * 800,
              y: Math.random() * 600
            },
            playerId: `load-test-user-${__VU}`
          },
          timestamp: new Date().toISOString(),
          correlationId: `load-test-move-${__VU}-${messageCount}-${Date.now()}`
        }));

        messageCount++;
      }, 2000); // Send movement every 2 seconds
    });

    socket.on('message', (data) => {
      try {
        const message = JSON.parse(data);
        check(message, {
          'WebSocket message has valid structure': (msg) => {
            return msg.type && msg.data && msg.timestamp;
          },
          'WebSocket message type is recognized': (msg) => {
            const validTypes = [
              'auth:success', 'auth:failed',
              'room:joined', 'room:left', 'room:state_updated',
              'asset:moved', 'asset:flipped',
              'dice:rolled', 'chat:message'
            ];
            return validTypes.includes(msg.type);
          }
        });
      } catch (error) {
        console.error('Invalid WebSocket message format:', data);
      }
    });

    socket.on('error', (error) => {
      console.error(`WebSocket error for user ${__VU}:`, error);
    });

    socket.on('close', () => {
      console.log(`WebSocket connection closed for user ${__VU}`);
    });

    // Keep connection alive for test duration
    socket.setTimeout(() => {
      socket.close();
    }, 30000); // Close after 30 seconds
  });

  check(wsResponse, {
    'WebSocket connection established': (r) => r && r.status === 101
  });
}

// Mixed Load Test (API + WebSocket)
export default function() {
  // Randomly choose between API and WebSocket testing
  const testType = Math.random();
  
  if (testType < 0.6) {
    // 60% API testing
    apiLoadTest();
  } else {
    // 40% WebSocket testing
    websocketLoadTest();
  }
  
  // Add think time between requests
  sleep(Math.random() * 3 + 1); // 1-4 seconds
}

// Stress Testing Scenario
export function stressTest() {
  const options = {
    stages: [
      { duration: '2m', target: 200 }, // Ramp up to 200 users
      { duration: '5m', target: 500 }, // Ramp up to 500 users
      { duration: '2m', target: 500 }, // Stay at 500 users
      { duration: '2m', target: 1000 }, // Ramp up to 1000 users
      { duration: '5m', target: 1000 }, // Stay at 1000 users
      { duration: '2m', target: 0 } // Ramp down
    ],
    thresholds: {
      http_req_duration: ['p(95)<500'], // Relaxed threshold for stress test
      http_req_failed: ['rate<0.05'], // Allow 5% error rate under stress
      ws_connecting: ['avg<2000'] // Relaxed WebSocket connection time
    }
  };

  // Similar test logic but with higher concurrency
  apiLoadTest();
}

// Database Load Testing
export function databaseLoadTest() {
  const authToken = getAuthToken();
  const headers = {
    'Authorization': `Bearer ${authToken}`,
    'Content-Type': 'application/json'
  };

  // Test database-intensive operations
  const queries = [
    // Room queries
    { method: 'GET', url: '/api/rooms?page=1&limit=50' },
    { method: 'GET', url: '/api/rooms/search?q=test' },
    
    // Asset queries
    { method: 'GET', url: '/api/assets?type=card&category=playing-cards' },
    { method: 'GET', url: '/api/systems?category=card-game' },
    
    // User queries
    { method: 'GET', url: '/api/auth/user' },
    { method: 'GET', url: '/api/users/profile' }
  ];

  queries.forEach(query => {
    const response = http.get(`${BASE_URL}${query.url}`, { headers });
    
    check(response, {
      [`${query.url} status is 200`]: (r) => r.status === 200,
      [`${query.url} response time < 300ms`]: (r) => r.timings.duration < 300,
      [`${query.url} has valid JSON`]: (r) => {
        try {
          JSON.parse(r.body);
          return true;
        } catch {
          return false;
        }
      }
    });
  });
}

// Memory and Resource Testing
export function resourceTest() {
  // Test large payload handling
  const largeRoomData = {
    name: 'Large Room Test',
    description: 'A'.repeat(10000), // 10KB description
    settings: {
      largeConfig: 'B'.repeat(50000) // 50KB config
    }
  };

  const response = http.post(
    `${BASE_URL}/api/rooms`,
    JSON.stringify(largeRoomData),
    {
      headers: {
        'Authorization': `Bearer ${getAuthToken()}`,
        'Content-Type': 'application/json'
      }
    }
  );

  check(response, {
    'large payload handled correctly': (r) => r.status < 400,
    'large payload response time acceptable': (r) => r.timings.duration < 2000
  });
}

// Export different test scenarios
export { stressTest, databaseLoadTest, resourceTest };
