/**
 * Basic Load Testing - Phase 2 Week 4
 * Tests basic application load handling with realistic user scenarios
 */

import http from 'k6/http';
import ws from 'k6/ws';
import { check, sleep } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';

// Custom metrics
export const errorRate = new Rate('errors');
export const responseTime = new Trend('response_time');
export const requestsPerSecond = new Rate('requests_per_second');
export const wsConnectionTime = new Trend('ws_connection_time');
export const wsMessagesSent = new Counter('ws_messages_sent');
export const wsMessagesReceived = new Counter('ws_messages_received');

// Test configuration
export const options = {
  stages: [
    { duration: '2m', target: 20 },   // Ramp up to 20 users
    { duration: '5m', target: 20 },   // Stay at 20 users
    { duration: '2m', target: 50 },   // Ramp up to 50 users
    { duration: '5m', target: 50 },   // Stay at 50 users
    { duration: '2m', target: 100 },  // Ramp up to 100 users
    { duration: '5m', target: 100 },  // Stay at 100 users
    { duration: '5m', target: 0 },    // Ramp down to 0 users
  ],
  thresholds: {
    http_req_duration: ['p(95)<500'], // 95% of requests must complete below 500ms
    http_req_failed: ['rate<0.05'],   // Error rate must be below 5%
    ws_connecting: ['p(95)<1000'],    // WebSocket connections under 1s
    ws_session_duration: ['avg<30000'], // Average session duration under 30s
  },
};

const BASE_URL = __ENV.BASE_URL || 'http://localhost:5000';
const WS_URL = __ENV.WS_URL || 'ws://localhost:5000';

// Test data
const testUsers = [
  { email: 'loadtest1@example.com', name: 'Load Test User 1' },
  { email: 'loadtest2@example.com', name: 'Load Test User 2' },
  { email: 'loadtest3@example.com', name: 'Load Test User 3' },
  { email: 'loadtest4@example.com', name: 'Load Test User 4' },
  { email: 'loadtest5@example.com', name: 'Load Test User 5' },
];

export function setup() {
  // Setup test data
  console.log('Setting up load test environment...');
  
  // Create test rooms
  const testRooms = [];
  for (let i = 1; i <= 10; i++) {
    const response = http.post(`${BASE_URL}/api/rooms`, JSON.stringify({
      name: `Load Test Room ${i}`,
      description: `Room for load testing - ${i}`,
      gameSystemId: 'default'
    }), {
      headers: { 'Content-Type': 'application/json' }
    });
    
    if (response.status === 201) {
      testRooms.push(JSON.parse(response.body).data);
    }
  }
  
  return { testRooms };
}

export default function(data) {
  const testRoom = data.testRooms[Math.floor(Math.random() * data.testRooms.length)];
  const testUser = testUsers[Math.floor(Math.random() * testUsers.length)];
  
  // Scenario 1: User authentication and room access
  group('Authentication and Room Access', () => {
    const authResponse = http.post(`${BASE_URL}/api/auth/mock-login`, JSON.stringify({
      email: testUser.email,
      name: testUser.name
    }), {
      headers: { 'Content-Type': 'application/json' }
    });
    
    check(authResponse, {
      'auth status is 200': (r) => r.status === 200,
      'auth response time < 200ms': (r) => r.timings.duration < 200,
    });
    
    errorRate.add(authResponse.status !== 200);
    responseTime.add(authResponse.timings.duration);
    requestsPerSecond.add(1);
    
    if (authResponse.status === 200) {
      const authData = JSON.parse(authResponse.body);
      const token = authData.token;
      
      // Get room details
      const roomResponse = http.get(`${BASE_URL}/api/rooms/${testRoom.id}`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      
      check(roomResponse, {
        'room status is 200': (r) => r.status === 200,
        'room response time < 150ms': (r) => r.timings.duration < 150,
      });
      
      errorRate.add(roomResponse.status !== 200);
      responseTime.add(roomResponse.timings.duration);
      requestsPerSecond.add(1);
    }
  });
  
  // Scenario 2: Asset operations
  group('Asset Operations', () => {
    // Simulate asset upload
    const assetData = {
      name: `LoadTest-Asset-${Math.random().toString(36).substr(2, 9)}.png`,
      type: 'image/png',
      size: Math.floor(Math.random() * 1000000) + 100000, // 100KB - 1MB
    };
    
    const uploadResponse = http.post(`${BASE_URL}/api/rooms/${testRoom.id}/assets`, JSON.stringify(assetData), {
      headers: { 'Content-Type': 'application/json' }
    });
    
    check(uploadResponse, {
      'upload status is 201': (r) => r.status === 201,
      'upload response time < 1000ms': (r) => r.timings.duration < 1000,
    });
    
    errorRate.add(uploadResponse.status !== 201);
    responseTime.add(uploadResponse.timings.duration);
    
    // Get assets list
    const assetsResponse = http.get(`${BASE_URL}/api/rooms/${testRoom.id}/assets`);
    
    check(assetsResponse, {
      'assets list status is 200': (r) => r.status === 200,
      'assets list response time < 100ms': (r) => r.timings.duration < 100,
    });
    
    errorRate.add(assetsResponse.status !== 200);
    responseTime.add(assetsResponse.timings.duration);
  });
  
  // Scenario 3: WebSocket connection and real-time interaction
  group('WebSocket Real-time Interaction', () => {
    const wsStart = Date.now();
    
    const wsResponse = ws.connect(`${WS_URL}/ws`, {}, function(socket) {
      const connectionTime = Date.now() - wsStart;
      wsConnectionTime.add(connectionTime);
      
      socket.on('open', () => {
        console.log('WebSocket connected');
        
        // Authenticate via WebSocket
        socket.send(JSON.stringify({
          type: 'auth:authenticate',
          data: { 
            email: testUser.email,
            name: testUser.name 
          }
        }));
        wsMessagesSent.add(1);
        
        // Join room
        socket.send(JSON.stringify({
          type: 'room:join',
          data: { roomId: testRoom.id }
        }));
        wsMessagesSent.add(1);
        
        // Simulate game activity
        const activities = [
          { type: 'asset:moved', data: { assetId: 'test-asset', position: { x: Math.random() * 800, y: Math.random() * 600 } } },
          { type: 'chat:message', data: { message: `Load test message ${Math.random()}` } },
          { type: 'dice:roll', data: { sides: 20, count: 1 } },
          { type: 'card:draw', data: { deckId: 'main-deck', count: 1 } }
        ];
        
        // Send random activities
        const activityInterval = setInterval(() => {
          const activity = activities[Math.floor(Math.random() * activities.length)];
          socket.send(JSON.stringify(activity));
          wsMessagesSent.add(1);
        }, 2000 + Math.random() * 3000); // Every 2-5 seconds
        
        // Clean up after 10-20 seconds
        setTimeout(() => {
          clearInterval(activityInterval);
          socket.close();
        }, 10000 + Math.random() * 10000);
      });
      
      socket.on('message', (data) => {
        wsMessagesReceived.add(1);
        const message = JSON.parse(data);
        
        check(message, {
          'WebSocket message has type': (msg) => msg.type !== undefined,
          'WebSocket message has data': (msg) => msg.data !== undefined,
        });
      });
      
      socket.on('close', () => {
        console.log('WebSocket disconnected');
      });
      
      socket.on('error', (e) => {
        console.log('WebSocket error:', e);
        errorRate.add(1);
      });
    });
    
    check(wsResponse, {
      'WebSocket connection successful': (r) => r && r.status === 101,
    });
  });
  
  // Random sleep between 1-5 seconds to simulate user think time
  sleep(1 + Math.random() * 4);
}

export function teardown(data) {
  console.log('Cleaning up load test environment...');
  
  // Clean up test rooms
  data.testRooms.forEach(room => {
    http.del(`${BASE_URL}/api/rooms/${room.id}`);
  });
}
