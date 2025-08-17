// tests/performance/api/endpoints.test.ts
import autocannon from 'autocannon';
import { test } from 'vitest';

test('API Performance Benchmarks', async () => {
  const baseUrl = 'http://localhost:5000';
  
  // Test room creation endpoint
  const roomCreationResult = await autocannon({
    url: `${baseUrl}/api/rooms`,
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer test-token'
    },
    body: JSON.stringify({
      name: 'Performance Test Room'
    }),
    duration: 30,
    connections: 10
  });

  console.log('Room Creation Performance:', roomCreationResult);
  
  // Assertions
  expect(roomCreationResult.latency.average).toBeLessThan(100);
  expect(roomCreationResult.requests.average).toBeGreaterThan(50);

  // Test asset retrieval endpoint
  const assetRetrievalResult = await autocannon({
    url: `${baseUrl}/api/rooms/test-room/assets`,
    method: 'GET',
    headers: {
      'Authorization': 'Bearer test-token'
    },
    duration: 30,
    connections: 20
  });

  console.log('Asset Retrieval Performance:', assetRetrievalResult);
  
  expect(assetRetrievalResult.latency.average).toBeLessThan(50);
  expect(assetRetrievalResult.requests.average).toBeGreaterThan(100);
});
