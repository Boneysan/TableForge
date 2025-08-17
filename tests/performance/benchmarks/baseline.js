// tests/performance/benchmarks/baseline.js
import http from 'k6/http';
import ws from 'k6/ws';
import { check, sleep } from 'k6';

export let options = {
  stages: [
    { duration: '1m', target: 10 },  // Baseline with 10 users
    { duration: '3m', target: 10 },  // Maintain baseline
    { duration: '1m', target: 0 }    // Ramp down
  ],
  thresholds: {
    http_req_duration: ['p(95)<100', 'avg<50'],
    http_req_failed: ['rate<0.01'],
    ws_connecting: ['avg<500'],
    ws_session_duration: ['avg<30000']
  }
};

export default function() {
  const baseUrl = 'http://localhost:5000';
  
  // Baseline API performance measurements
  const endpoints = [
    '/api/health',
    '/api/rooms',
    '/api/systems',
    '/api/auth/user'
  ];
  
  endpoints.forEach(endpoint => {
    const response = http.get(`${baseUrl}${endpoint}`, {
      headers: { 'Authorization': 'Bearer benchmark-token' }
    });
    
    check(response, {
      [`${endpoint} baseline status`]: (r) => r.status === 200,
      [`${endpoint} baseline latency`]: (r) => r.timings.duration < 100
    });
  });
  
  // Baseline WebSocket performance
  const wsResponse = ws.connect(`ws://localhost:5000/ws`, {}, function(socket) {
    socket.on('open', () => {
      socket.send(JSON.stringify({
        type: 'auth:authenticate',
        data: { token: 'benchmark-token' }
      }));
      
      // Single asset movement for baseline
      socket.send(JSON.stringify({
        type: 'asset:moved',
        data: { assetId: 'benchmark-asset', position: { x: 100, y: 100 } }
      }));
      
      setTimeout(() => socket.close(), 5000);
    });
    
    socket.on('message', (data) => {
      check(data, {
        'baseline WebSocket response': (msg) => msg.length > 0
      });
    });
  });
  
  check(wsResponse, {
    'baseline WebSocket connection': (r) => r && r.status === 101
  });
  
  sleep(1);
}
