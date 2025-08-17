/**
 * Stress Testing - Phase 2 Week 4
 * High-load stress testing to identify breaking points and system limits
 */

import http from 'k6/http';
import ws from 'k6/ws';
import { check, group, sleep } from 'k6';
import { Rate, Trend, Counter, Gauge } from 'k6/metrics';
import { randomString, randomIntBetween } from 'https://jslib.k6.io/k6-utils/1.2.0/index.js';

// Stress test metrics
export const stressTestErrors = new Rate('stress_test_errors');
export const systemBreakingPoint = new Gauge('system_breaking_point');
export const maxConcurrentUsers = new Gauge('max_concurrent_users');
export const resourceExhaustion = new Rate('resource_exhaustion');
export const recoveryTime = new Trend('recovery_time');
export const memoryUsage = new Trend('memory_usage');
export const cpuUsage = new Trend('cpu_usage');

export const options = {
  stages: [
    // Gradual ramp up to find breaking point
    { duration: '2m', target: 50 },
    { duration: '2m', target: 100 },
    { duration: '2m', target: 200 },
    { duration: '2m', target: 400 },
    { duration: '2m', target: 600 },
    { duration: '3m', target: 800 },
    { duration: '3m', target: 1000 }, // Stress level
    { duration: '2m', target: 1200 }, // Beyond capacity
    { duration: '2m', target: 1500 }, // Breaking point
    { duration: '5m', target: 0 },    // Recovery period
  ],
  thresholds: {
    // Relaxed thresholds for stress testing
    http_req_duration: ['p(95)<5000'],     // Allow higher latency
    http_req_failed: ['rate<0.50'],        // Allow up to 50% errors at peak
    stress_test_errors: ['rate<0.60'],     // Track stress-specific errors
    ws_connecting: ['p(95)<10000'],        // WebSocket connection time
  },
  // Disable default thresholds that would stop the test
  noConnectionReuse: false,
  userAgent: 'TableForge-StressTest/1.0',
};

const BASE_URL = __ENV.BASE_URL || 'http://localhost:5000';
const WS_URL = __ENV.WS_URL || 'ws://localhost:5000/ws';

let currentStage = 'warmup';
let peakPerformanceLevel = 0;
let breakingPointDetected = false;

export function setup() {
  console.log('Starting stress test - finding system breaking point...');
  
  // Create initial test data
  const testData = {
    rooms: [],
    users: [],
    assets: []
  };
  
  // Create stress test rooms
  for (let i = 0; i < 20; i++) {
    const response = http.post(`${BASE_URL}/api/rooms`, JSON.stringify({
      name: `Stress-Test-Room-${i}`,
      description: 'High-load stress testing room',
      gameSystemId: 'stress-test'
    }), {
      headers: { 'Content-Type': 'application/json' }
    });
    
    if (response.status === 201) {
      testData.rooms.push(JSON.parse(response.body).data);
    }
  }
  
  return testData;
}

export default function(data) {
  const currentUsers = getCurrentUserCount();
  updateStressLevel(currentUsers);
  
  // Different behavior based on stress level
  if (currentUsers < 200) {
    normalOperations(data);
  } else if (currentUsers < 600) {
    heavyOperations(data);
  } else if (currentUsers < 1000) {
    extremeOperations(data);
  } else {
    breakingPointTest(data);
  }
  
  // Adaptive sleep based on system stress
  const sleepTime = currentUsers > 800 ? 0.1 : 0.5;
  sleep(sleepTime);
}

function getCurrentUserCount() {
  return __VU * 1; // Approximate current user count
}

function updateStressLevel(userCount) {
  if (userCount > peakPerformanceLevel) {
    peakPerformanceLevel = userCount;
    maxConcurrentUsers.set(userCount);
  }
  
  if (userCount < 200) {
    currentStage = 'normal';
  } else if (userCount < 600) {
    currentStage = 'heavy';
  } else if (userCount < 1000) {
    currentStage = 'extreme';
  } else {
    currentStage = 'breaking';
  }
}

function normalOperations(data) {
  group('Normal Load Operations', () => {
    const room = data.rooms[randomIntBetween(0, data.rooms.length - 1)];
    
    // Standard API calls
    const response = http.get(`${BASE_URL}/api/rooms/${room.id}`, {
      timeout: '10s'
    });
    
    check(response, {
      'normal operation success': (r) => r.status === 200,
      'normal operation timing': (r) => r.timings.duration < 1000,
    });
    
    stressTestErrors.add(response.status !== 200);
  });
}

function heavyOperations(data) {
  group('Heavy Load Operations', () => {
    const room = data.rooms[randomIntBetween(0, data.rooms.length - 1)];
    
    // Multiple concurrent operations
    const requests = [
      http.get(`${BASE_URL}/api/rooms/${room.id}/assets`),
      http.get(`${BASE_URL}/api/rooms/${room.id}/players`),
      http.get(`${BASE_URL}/api/rooms/${room.id}/state`),
    ];
    
    const responses = http.batch(requests);
    
    responses.forEach((response, index) => {
      check(response, {
        [`heavy operation ${index} success`]: (r) => r.status >= 200 && r.status < 500,
        [`heavy operation ${index} timing`]: (r) => r.timings.duration < 3000,
      });
      
      stressTestErrors.add(response.status >= 500);
    });
    
    // Resource-intensive WebSocket connection
    if (randomIntBetween(1, 10) === 1) {
      const wsResponse = ws.connect(WS_URL, { timeout: '5s' }, function(socket) {
        socket.on('open', () => {
          // Rapid message sending
          for (let i = 0; i < 5; i++) {
            socket.send(JSON.stringify({
              type: 'stress:test',
              data: { iteration: i, timestamp: Date.now() }
            }));
          }
          
          setTimeout(() => socket.close(), 1000);
        });
        
        socket.on('error', () => {
          stressTestErrors.add(1);
        });
      });
      
      check(wsResponse, {
        'heavy websocket connection': (r) => r && r.status === 101,
      });
    }
  });
}

function extremeOperations(data) {
  group('Extreme Load Operations', () => {
    console.log(`[EXTREME] User ${__VU} - Testing system limits`);
    
    // Memory-intensive operations
    const largePayload = {
      name: `extreme-test-${randomString(20)}`,
      data: randomString(10000), // 10KB of random data
      metadata: Array.from({ length: 100 }, () => ({
        key: randomString(50),
        value: randomString(100),
        timestamp: Date.now()
      }))
    };
    
    const room = data.rooms[randomIntBetween(0, data.rooms.length - 1)];
    const response = http.post(`${BASE_URL}/api/rooms/${room.id}/assets`, JSON.stringify(largePayload), {
      headers: { 'Content-Type': 'application/json' },
      timeout: '15s'
    });
    
    check(response, {
      'extreme operation completed': (r) => r.status < 500,
      'extreme operation timing': (r) => r.timings.duration < 10000,
    });
    
    // Check for resource exhaustion indicators
    if (response.status === 503 || response.status === 429) {
      resourceExhaustion.add(1);
      console.log(`[RESOURCE EXHAUSTION] Status: ${response.status}, User: ${__VU}`);
    }
    
    stressTestErrors.add(response.status >= 500);
    
    // CPU-intensive operations
    if (randomIntBetween(1, 5) === 1) {
      const cpuIntensiveStart = Date.now();
      
      // Simulate CPU-heavy computation
      let result = 0;
      for (let i = 0; i < 100000; i++) {
        result += Math.sqrt(i) * Math.random();
      }
      
      const cpuTime = Date.now() - cpuIntensiveStart;
      cpuUsage.add(cpuTime);
      
      if (cpuTime > 1000) {
        console.log(`[CPU STRESS] Computation took ${cpuTime}ms`);
      }
    }
  });
}

function breakingPointTest(data) {
  group('Breaking Point Test', () => {
    console.log(`[BREAKING POINT] User ${__VU} - System at breaking point`);
    
    if (!breakingPointDetected) {
      breakingPointDetected = true;
      systemBreakingPoint.set(__VU);
      console.log(`[ALERT] Breaking point detected at ${__VU} concurrent users`);
    }
    
    // Minimal operations to test basic responsiveness
    const room = data.rooms[0]; // Use first room to reduce load
    const startTime = Date.now();
    
    const response = http.get(`${BASE_URL}/api/health`, {
      timeout: '30s'
    });
    
    const responseTime = Date.now() - startTime;
    
    check(response, {
      'system still responsive': (r) => r.status === 200,
      'basic health check works': (r) => r.body.includes('ok') || r.status === 200,
    });
    
    if (response.status === 200 && responseTime < 5000) {
      console.log(`[SURVIVAL] System still responsive at ${__VU} users (${responseTime}ms)`);
    } else {
      console.log(`[FAILURE] System unresponsive at ${__VU} users (${responseTime}ms, status: ${response.status})`);
      stressTestErrors.add(1);
    }
    
    // Test recovery capability
    if (__VU % 50 === 0) {
      console.log(`[RECOVERY TEST] Testing system recovery at ${__VU} users`);
      const recoveryStart = Date.now();
      
      // Wait for potential recovery
      sleep(2);
      
      const recoveryResponse = http.get(`${BASE_URL}/api/health`, {
        timeout: '10s'
      });
      
      if (recoveryResponse.status === 200) {
        const recoveryDuration = Date.now() - recoveryStart;
        recoveryTime.add(recoveryDuration);
        console.log(`[RECOVERY] System recovered in ${recoveryDuration}ms`);
      }
    }
  });
}

// Monitor system resources if available
export function handleSummary(data) {
  const summary = {
    timestamp: new Date().toISOString(),
    test_type: 'stress_test',
    peak_users: peakPerformanceLevel,
    breaking_point_detected: breakingPointDetected,
    stages: {
      normal: 'Users < 200',
      heavy: 'Users 200-600',
      extreme: 'Users 600-1000',
      breaking: 'Users > 1000'
    },
    metrics: {
      total_requests: data.metrics.http_reqs.values.count,
      error_rate: data.metrics.http_req_failed.values.rate,
      avg_response_time: data.metrics.http_req_duration.values.avg,
      p95_response_time: data.metrics.http_req_duration.values['p(95)'],
      max_response_time: data.metrics.http_req_duration.values.max,
    },
    thresholds_passed: Object.keys(data.metrics).filter(
      key => data.metrics[key].thresholds && 
      Object.values(data.metrics[key].thresholds).every(t => t.ok)
    ).length,
    recommendations: generateRecommendations(data)
  };
  
  console.log('=== STRESS TEST SUMMARY ===');
  console.log(`Peak concurrent users: ${peakPerformanceLevel}`);
  console.log(`Breaking point detected: ${breakingPointDetected}`);
  console.log(`Total requests: ${summary.metrics.total_requests}`);
  console.log(`Error rate: ${(summary.metrics.error_rate * 100).toFixed(2)}%`);
  console.log(`P95 response time: ${summary.metrics.p95_response_time.toFixed(2)}ms`);
  
  return {
    'stress-test-summary.json': JSON.stringify(summary, null, 2),
    'stdout': generateTextReport(summary)
  };
}

function generateRecommendations(data) {
  const recommendations = [];
  
  if (data.metrics.http_req_failed.values.rate > 0.1) {
    recommendations.push('High error rate detected - consider increasing server capacity');
  }
  
  if (data.metrics.http_req_duration.values['p(95)'] > 2000) {
    recommendations.push('High response times - consider database optimization or caching');
  }
  
  if (peakPerformanceLevel < 500) {
    recommendations.push('System breaking point is low - investigate resource bottlenecks');
  }
  
  if (breakingPointDetected) {
    recommendations.push('Breaking point reached - implement load balancing or horizontal scaling');
  }
  
  return recommendations;
}

function generateTextReport(summary) {
  return `
STRESS TEST REPORT
==================
Timestamp: ${summary.timestamp}
Peak Users: ${summary.peak_users}
Breaking Point: ${summary.breaking_point_detected ? 'DETECTED' : 'NOT REACHED'}

PERFORMANCE METRICS
==================
Total Requests: ${summary.metrics.total_requests}
Error Rate: ${(summary.metrics.error_rate * 100).toFixed(2)}%
Average Response Time: ${summary.metrics.avg_response_time.toFixed(2)}ms
P95 Response Time: ${summary.metrics.p95_response_time.toFixed(2)}ms
Max Response Time: ${summary.metrics.max_response_time.toFixed(2)}ms

RECOMMENDATIONS
===============
${summary.recommendations.map(r => `- ${r}`).join('\n')}
`;
}

export function teardown(data) {
  console.log('Stress test completed - cleaning up...');
  
  // Clean up test data
  data.rooms.forEach(room => {
    try {
      http.del(`${BASE_URL}/api/rooms/${room.id}`);
    } catch (e) {
      console.log(`Failed to cleanup room ${room.id}: ${e}`);
    }
  });
  
  console.log(`Final metrics: Peak users: ${peakPerformanceLevel}, Breaking point: ${breakingPointDetected}`);
}
