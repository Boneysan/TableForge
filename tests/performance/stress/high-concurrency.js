// tests/performance/stress/high-concurrency.js
import ws from 'k6/ws';
import http from 'k6/http';
import { check, sleep } from 'k6';

export let options = {
  stages: [
    { duration: '2m', target: 200 },   // Ramp up to 200 users
    { duration: '5m', target: 500 },   // Ramp up to 500 users  
    { duration: '2m', target: 500 },   // Stay at 500 users
    { duration: '2m', target: 1000 },  // Ramp up to 1000 users
    { duration: '5m', target: 1000 },  // Stay at 1000 users
    { duration: '2m', target: 0 }      // Ramp down
  ],
  thresholds: {
    http_req_duration: ['p(95)<500'],   // 95% of requests under 500ms
    http_req_failed: ['rate<0.05'],     // Less than 5% error rate
    ws_connecting: ['avg<2000'],        // WebSocket connection under 2s
    ws_session_duration: ['avg<120000'] // Session duration under 2 minutes
  }
};

export default function() {
  const baseUrl = 'http://localhost:5000';
  const wsUrl = 'ws://localhost:5000/ws';
  
  // 70% HTTP API testing, 30% WebSocket testing
  if (Math.random() < 0.7) {
    // HTTP API stress testing
    const response = http.get(`${baseUrl}/api/rooms`, {
      headers: { 'Authorization': 'Bearer stress-test-token' }
    });
    
    check(response, {
      'API available under stress': (r) => r.status === 200,
      'API response time acceptable': (r) => r.timings.duration < 1000
    });
    
  } else {
    // WebSocket stress testing
    const wsResponse = ws.connect(wsUrl, {}, function(socket) {
      socket.on('open', () => {
        // Rapid authentication and room joining
        socket.send(JSON.stringify({
          type: 'auth:authenticate', 
          data: { token: 'stress-test-token' }
        }));
        
        socket.send(JSON.stringify({
          type: 'room:join',
          data: { roomId: `stress-room-${__VU % 10}` } // Distribute across 10 rooms
        }));
        
        // High-frequency asset movements
        let moveCount = 0;
        const rapidMovement = setInterval(() => {
          if (moveCount >= 20) {
            clearInterval(rapidMovement);
            socket.close();
            return;
          }
          
          socket.send(JSON.stringify({
            type: 'asset:moved',
            data: {
              assetId: `stress-asset-${__VU}`,
              position: { x: Math.random() * 1000, y: Math.random() * 1000 }
            }
          }));
          moveCount++;
        }, 100); // Move every 100ms
      });
      
      socket.on('message', (data) => {
        check(data, {
          'WebSocket responsive under stress': (msg) => msg.length > 0
        });
      });
    });
    
    check(wsResponse, {
      'WebSocket connects under stress': (r) => r && r.status === 101
    });
  }
  
  // Brief pause between actions
  sleep(Math.random() * 0.5);
}
