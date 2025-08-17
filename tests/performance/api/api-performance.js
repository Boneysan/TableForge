/**
 * API Performance Benchmarks - Phase 2 Week 4
 * Comprehensive API endpoint performance testing with detailed metrics
 */

import http from 'k6/http';
import { check, group, sleep } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';
import { randomString, randomIntBetween } from 'https://jslib.k6.io/k6-utils/1.2.0/index.js';

// Custom metrics for API performance
export const apiResponseTime = new Trend('api_response_time');
export const apiThroughput = new Rate('api_throughput');
export const apiErrorRate = new Rate('api_error_rate');
export const authLatency = new Trend('auth_latency');
export const roomOperationsLatency = new Trend('room_operations_latency');
export const assetOperationsLatency = new Trend('asset_operations_latency');
export const databaseQueryTime = new Trend('database_query_time');
export const cacheHitRate = new Rate('cache_hit_rate');

export const options = {
  stages: [
    { duration: '1m', target: 10 },   // Warm up
    { duration: '2m', target: 25 },   // Light load
    { duration: '3m', target: 50 },   // Medium load
    { duration: '3m', target: 100 },  // High load
    { duration: '2m', target: 150 },  // Peak load
    { duration: '2m', target: 0 },    // Cool down
  ],
  thresholds: {
    // API response time thresholds
    api_response_time: ['p(95)<500', 'p(99)<1000'],
    http_req_duration: ['p(95)<500'],
    
    // Error rate thresholds
    api_error_rate: ['rate<0.05'],
    http_req_failed: ['rate<0.05'],
    
    // Throughput thresholds
    http_reqs: ['rate>50'],
    
    // Specific operation thresholds
    auth_latency: ['p(95)<200'],
    room_operations_latency: ['p(95)<300'],
    asset_operations_latency: ['p(95)<1000'],
  },
};

const BASE_URL = __ENV.BASE_URL || 'http://localhost:5000';
const API_TOKEN = __ENV.API_TOKEN || 'test-token';

// Test data generators
function generateUser() {
  return {
    email: `perf-test-${randomString(8)}@example.com`,
    name: `Performance Test User ${randomString(6)}`,
    displayName: `PerfUser${randomString(4)}`
  };
}

function generateRoom() {
  return {
    name: `Performance Test Room ${randomString(8)}`,
    description: `Auto-generated room for performance testing - ${Date.now()}`,
    gameSystemId: 'default',
    isPrivate: Math.random() > 0.7,
    maxPlayers: randomIntBetween(2, 8)
  };
}

function generateAsset() {
  const types = ['card', 'token', 'board', 'dice'];
  return {
    name: `perf-asset-${randomString(10)}.png`,
    type: 'image/png',
    category: types[randomIntBetween(0, types.length - 1)],
    size: randomIntBetween(10000, 1000000), // 10KB to 1MB
    metadata: {
      width: randomIntBetween(100, 2000),
      height: randomIntBetween(100, 2000),
      tags: [`tag${randomIntBetween(1, 10)}`, `category${randomIntBetween(1, 5)}`]
    }
  };
}

export function setup() {
  console.log('Setting up API performance test environment...');
  
  // Create baseline test data
  const testRooms = [];
  const testUsers = [];
  
  // Create test users
  for (let i = 0; i < 5; i++) {
    const userData = generateUser();
    const response = http.post(`${BASE_URL}/api/auth/create-test-user`, JSON.stringify(userData), {
      headers: { 'Content-Type': 'application/json' }
    });
    
    if (response.status === 201) {
      testUsers.push(JSON.parse(response.body).data);
    }
  }
  
  // Create test rooms
  for (let i = 0; i < 10; i++) {
    const roomData = generateRoom();
    const response = http.post(`${BASE_URL}/api/rooms`, JSON.stringify(roomData), {
      headers: { 
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${API_TOKEN}`
      }
    });
    
    if (response.status === 201) {
      testRooms.push(JSON.parse(response.body).data);
    }
  }
  
  return { testRooms, testUsers };
}

export default function(data) {
  const testRoom = data.testRooms[randomIntBetween(0, data.testRooms.length - 1)];
  const testUser = data.testUsers[randomIntBetween(0, data.testUsers.length - 1)];
  
  // Test scenario selection (weighted)
  const scenario = Math.random();
  
  if (scenario < 0.3) {
    authenticationBenchmark();
  } else if (scenario < 0.6) {
    roomOperationsBenchmark(testRoom);
  } else if (scenario < 0.85) {
    assetOperationsBenchmark(testRoom);
  } else {
    mixedWorkloadBenchmark(testRoom, testUser);
  }
  
  sleep(0.1 + Math.random() * 0.5); // 100-600ms think time
}

function authenticationBenchmark() {
  group('Authentication Performance', () => {
    const userData = generateUser();
    
    // Register new user
    const registerStart = Date.now();
    const registerResponse = http.post(`${BASE_URL}/api/auth/register`, JSON.stringify(userData), {
      headers: { 'Content-Type': 'application/json' }
    });
    const registerTime = Date.now() - registerStart;
    
    check(registerResponse, {
      'register status is 201': (r) => r.status === 201,
      'register response has token': (r) => JSON.parse(r.body).token !== undefined,
    });
    
    authLatency.add(registerTime);
    apiResponseTime.add(registerTime);
    apiThroughput.add(1);
    apiErrorRate.add(registerResponse.status !== 201);
    
    if (registerResponse.status === 201) {
      const { token } = JSON.parse(registerResponse.body);
      
      // Validate token
      const validateStart = Date.now();
      const validateResponse = http.get(`${BASE_URL}/api/auth/validate`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const validateTime = Date.now() - validateStart;
      
      check(validateResponse, {
        'validate status is 200': (r) => r.status === 200,
        'validate response has user data': (r) => JSON.parse(r.body).user !== undefined,
      });
      
      authLatency.add(validateTime);
      apiResponseTime.add(validateTime);
      apiThroughput.add(1);
      apiErrorRate.add(validateResponse.status !== 200);
      
      // Refresh token
      const refreshStart = Date.now();
      const refreshResponse = http.post(`${BASE_URL}/api/auth/refresh`, {}, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const refreshTime = Date.now() - refreshStart;
      
      check(refreshResponse, {
        'refresh status is 200': (r) => r.status === 200,
        'refresh response has new token': (r) => JSON.parse(r.body).token !== undefined,
      });
      
      authLatency.add(refreshTime);
      apiResponseTime.add(refreshTime);
      apiThroughput.add(1);
      apiErrorRate.add(refreshResponse.status !== 200);
    }
  });
}

function roomOperationsBenchmark(testRoom) {
  group('Room Operations Performance', () => {
    // Get room details
    const getStart = Date.now();
    const getResponse = http.get(`${BASE_URL}/api/rooms/${testRoom.id}`, {
      headers: { 'Authorization': `Bearer ${API_TOKEN}` }
    });
    const getTime = Date.now() - getStart;
    
    check(getResponse, {
      'get room status is 200': (r) => r.status === 200,
      'get room has correct data': (r) => JSON.parse(r.body).data.id === testRoom.id,
    });
    
    roomOperationsLatency.add(getTime);
    apiResponseTime.add(getTime);
    apiThroughput.add(1);
    apiErrorRate.add(getResponse.status !== 200);
    
    // Update room
    const updateData = {
      description: `Updated at ${Date.now()}`,
      maxPlayers: randomIntBetween(2, 12)
    };
    
    const updateStart = Date.now();
    const updateResponse = http.patch(`${BASE_URL}/api/rooms/${testRoom.id}`, JSON.stringify(updateData), {
      headers: { 
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${API_TOKEN}`
      }
    });
    const updateTime = Date.now() - updateStart;
    
    check(updateResponse, {
      'update room status is 200': (r) => r.status === 200,
      'update room reflects changes': (r) => JSON.parse(r.body).data.maxPlayers === updateData.maxPlayers,
    });
    
    roomOperationsLatency.add(updateTime);
    apiResponseTime.add(updateTime);
    apiThroughput.add(1);
    apiErrorRate.add(updateResponse.status !== 200);
    
    // Get room players
    const playersStart = Date.now();
    const playersResponse = http.get(`${BASE_URL}/api/rooms/${testRoom.id}/players`, {
      headers: { 'Authorization': `Bearer ${API_TOKEN}` }
    });
    const playersTime = Date.now() - playersStart;
    
    check(playersResponse, {
      'get players status is 200': (r) => r.status === 200,
      'get players returns array': (r) => Array.isArray(JSON.parse(r.body).data),
    });
    
    roomOperationsLatency.add(playersTime);
    apiResponseTime.add(playersTime);
    apiThroughput.add(1);
    apiErrorRate.add(playersResponse.status !== 200);
    
    // Check cache performance
    const cacheStart = Date.now();
    const cacheResponse = http.get(`${BASE_URL}/api/rooms/${testRoom.id}`, {
      headers: { 
        'Authorization': `Bearer ${API_TOKEN}`,
        'Cache-Control': 'max-age=60'
      }
    });
    const cacheTime = Date.now() - cacheStart;
    
    // Assume cache hit if response is very fast
    const isCacheHit = cacheTime < 50;
    cacheHitRate.add(isCacheHit ? 1 : 0);
    
    if (isCacheHit) {
      console.log(`Cache hit for room ${testRoom.id} (${cacheTime}ms)`);
    }
  });
}

function assetOperationsBenchmark(testRoom) {
  group('Asset Operations Performance', () => {
    const assetData = generateAsset();
    
    // Upload asset
    const uploadStart = Date.now();
    const uploadResponse = http.post(`${BASE_URL}/api/rooms/${testRoom.id}/assets`, JSON.stringify(assetData), {
      headers: { 
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${API_TOKEN}`
      }
    });
    const uploadTime = Date.now() - uploadStart;
    
    check(uploadResponse, {
      'upload asset status is 201': (r) => r.status === 201,
      'upload asset returns asset data': (r) => JSON.parse(r.body).data.name === assetData.name,
    });
    
    assetOperationsLatency.add(uploadTime);
    apiResponseTime.add(uploadTime);
    apiThroughput.add(1);
    apiErrorRate.add(uploadResponse.status !== 201);
    
    if (uploadResponse.status === 201) {
      const uploadedAsset = JSON.parse(uploadResponse.body).data;
      
      // Get asset details
      const getAssetStart = Date.now();
      const getAssetResponse = http.get(`${BASE_URL}/api/rooms/${testRoom.id}/assets/${uploadedAsset.id}`, {
        headers: { 'Authorization': `Bearer ${API_TOKEN}` }
      });
      const getAssetTime = Date.now() - getAssetStart;
      
      check(getAssetResponse, {
        'get asset status is 200': (r) => r.status === 200,
        'get asset has correct data': (r) => JSON.parse(r.body).data.id === uploadedAsset.id,
      });
      
      assetOperationsLatency.add(getAssetTime);
      apiResponseTime.add(getAssetTime);
      apiThroughput.add(1);
      apiErrorRate.add(getAssetResponse.status !== 200);
      
      // Update asset metadata
      const updateAssetData = {
        metadata: {
          ...assetData.metadata,
          updated: Date.now(),
          performanceTest: true
        }
      };
      
      const updateAssetStart = Date.now();
      const updateAssetResponse = http.patch(`${BASE_URL}/api/rooms/${testRoom.id}/assets/${uploadedAsset.id}`, 
        JSON.stringify(updateAssetData), {
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${API_TOKEN}`
        }
      });
      const updateAssetTime = Date.now() - updateAssetStart;
      
      check(updateAssetResponse, {
        'update asset status is 200': (r) => r.status === 200,
        'update asset reflects changes': (r) => JSON.parse(r.body).data.metadata.performanceTest === true,
      });
      
      assetOperationsLatency.add(updateAssetTime);
      apiResponseTime.add(updateAssetTime);
      apiThroughput.add(1);
      apiErrorRate.add(updateAssetResponse.status !== 200);
    }
    
    // List assets with pagination
    const listStart = Date.now();
    const listResponse = http.get(`${BASE_URL}/api/rooms/${testRoom.id}/assets?page=1&limit=20&sort=created_at`, {
      headers: { 'Authorization': `Bearer ${API_TOKEN}` }
    });
    const listTime = Date.now() - listStart;
    
    check(listResponse, {
      'list assets status is 200': (r) => r.status === 200,
      'list assets has pagination': (r) => JSON.parse(r.body).pagination !== undefined,
    });
    
    assetOperationsLatency.add(listTime);
    apiResponseTime.add(listTime);
    apiThroughput.add(1);
    apiErrorRate.add(listResponse.status !== 200);
  });
}

function mixedWorkloadBenchmark(testRoom, testUser) {
  group('Mixed Workload Performance', () => {
    // Simulate realistic user session with multiple operations
    const operations = [
      () => {
        const response = http.get(`${BASE_URL}/api/rooms/${testRoom.id}/state`, {
          headers: { 'Authorization': `Bearer ${API_TOKEN}` }
        });
        return { response, operation: 'get_state' };
      },
      () => {
        const response = http.post(`${BASE_URL}/api/rooms/${testRoom.id}/join`, {}, {
          headers: { 'Authorization': `Bearer ${API_TOKEN}` }
        });
        return { response, operation: 'join_room' };
      },
      () => {
        const response = http.get(`${BASE_URL}/api/rooms/${testRoom.id}/assets?limit=10`, {
          headers: { 'Authorization': `Bearer ${API_TOKEN}` }
        });
        return { response, operation: 'list_assets' };
      },
      () => {
        const response = http.get(`${BASE_URL}/api/rooms/${testRoom.id}/chat?limit=20`, {
          headers: { 'Authorization': `Bearer ${API_TOKEN}` }
        });
        return { response, operation: 'get_chat' };
      }
    ];
    
    // Execute 3-5 random operations
    const operationCount = randomIntBetween(3, 5);
    for (let i = 0; i < operationCount; i++) {
      const operation = operations[randomIntBetween(0, operations.length - 1)];
      const start = Date.now();
      const result = operation();
      const duration = Date.now() - start;
      
      check(result.response, {
        [`${result.operation} status is ok`]: (r) => r.status >= 200 && r.status < 400,
      });
      
      apiResponseTime.add(duration);
      apiThroughput.add(1);
      apiErrorRate.add(result.response.status >= 400);
      
      // Small delay between operations
      sleep(0.05 + Math.random() * 0.1);
    }
  });
}

export function teardown(data) {
  console.log('Cleaning up API performance test environment...');
  
  // Clean up test rooms
  data.testRooms.forEach(room => {
    http.del(`${BASE_URL}/api/rooms/${room.id}`, {
      headers: { 'Authorization': `Bearer ${API_TOKEN}` }
    });
  });
  
  // Clean up test users
  data.testUsers.forEach(user => {
    http.del(`${BASE_URL}/api/users/${user.id}`, {
      headers: { 'Authorization': `Bearer ${API_TOKEN}` }
    });
  });
  
  console.log('API performance test completed');
}
