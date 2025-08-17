// tests/performance/api/additional-endpoints.test.ts
import autocannon from 'autocannon';
import { test, describe, expect } from 'vitest';

describe('Extended API Performance Tests', () => {
  const baseUrl = 'http://localhost:5000';
  
  test('Authentication endpoint performance', async () => {
    const authResult = await autocannon({
      url: `${baseUrl}/api/auth/login`,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        email: 'test@example.com',
        password: 'test-password'
      }),
      duration: 20,
      connections: 15
    });

    console.log('Authentication Performance:', authResult);
    
    expect(authResult.latency.average).toBeLessThan(150);
    expect(authResult.requests.average).toBeGreaterThan(30);
  });

  test('Game systems endpoint performance', async () => {
    const systemsResult = await autocannon({
      url: `${baseUrl}/api/systems`,
      method: 'GET',
      headers: {
        'Authorization': 'Bearer test-token'
      },
      duration: 25,
      connections: 25
    });

    console.log('Game Systems Performance:', systemsResult);
    
    expect(systemsResult.latency.average).toBeLessThan(75);
    expect(systemsResult.requests.average).toBeGreaterThan(80);
  });

  test('User profile endpoint performance', async () => {
    const profileResult = await autocannon({
      url: `${baseUrl}/api/users/profile`,
      method: 'GET',
      headers: {
        'Authorization': 'Bearer test-token'
      },
      duration: 15,
      connections: 12
    });

    console.log('User Profile Performance:', profileResult);
    
    expect(profileResult.latency.average).toBeLessThan(60);
    expect(profileResult.requests.average).toBeGreaterThan(120);
  });

  test('Asset upload endpoint performance', async () => {
    const uploadResult = await autocannon({
      url: `${baseUrl}/api/rooms/test-room/assets`,
      method: 'POST',
      headers: {
        'Authorization': 'Bearer test-token',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        name: 'Test Asset',
        type: 'card',
        data: 'base64-encoded-image-data'
      }),
      duration: 20,
      connections: 8
    });

    console.log('Asset Upload Performance:', uploadResult);
    
    expect(uploadResult.latency.average).toBeLessThan(500);
    expect(uploadResult.requests.average).toBeGreaterThan(15);
  });
});
