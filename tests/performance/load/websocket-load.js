// tests/performance/load/websocket-load.js
import ws from 'k6/ws';
import { check } from 'k6';

export let options = {
  stages: [
    { duration: '30s', target: 50 },
    { duration: '1m', target: 100 },
    { duration: '30s', target: 0 }
  ],
  thresholds: {
    ws_connecting: ['avg<1000'],
    ws_msgs_received: ['count>0'],
    ws_session_duration: ['avg<60000']
  }
};

export default function() {
  const url = 'ws://localhost:5000/ws';
  
  const response = ws.connect(url, {}, function(socket) {
    socket.on('open', () => {
      console.log('Connected');
      
      // Authenticate
      socket.send(JSON.stringify({
        type: 'auth:authenticate',
        data: { token: 'test-token' }
      }));

      // Join room
      socket.send(JSON.stringify({
        type: 'room:join',
        data: { roomId: 'load-test-room' }
      }));

      // Simulate game activity
      setInterval(() => {
        socket.send(JSON.stringify({
          type: 'asset:moved',
          data: {
            assetId: 'test-asset',
            position: {
              x: Math.random() * 800,
              y: Math.random() * 600
            }
          }
        }));
      }, 2000);
    });

    socket.on('message', (data) => {
      check(data, {
        'message received': (msg) => msg.length > 0
      });
    });

    socket.on('close', () => console.log('Disconnected'));
  });

  check(response, {
    'status is 101': (r) => r && r.status === 101
  });
}


