# WebSocket Scaling System Configuration Guide

This guide covers the complete setup and configuration of the TableForge WebSocket horizontal scaling system using Redis Pub/Sub.

## Table of Contents

1. [System Overview](#system-overview)
2. [Prerequisites](#prerequisites)
3. [Installation & Setup](#installation--setup)
4. [Configuration](#configuration)
5. [Deployment Strategies](#deployment-strategies)
6. [Monitoring & Observability](#monitoring--observability)
7. [Troubleshooting](#troubleshooting)
8. [Performance Tuning](#performance-tuning)
9. [Security Considerations](#security-considerations)
10. [Best Practices](#best-practices)

## System Overview

The TableForge WebSocket scaling system provides horizontal scaling capabilities for WebSocket connections across multiple server instances using Redis Pub/Sub messaging. This enables:

- **Load Distribution**: Connections spread across multiple server instances
- **Cross-Instance Communication**: Messages routed between users on different instances
- **Room Management**: Game rooms coordinated across the entire cluster
- **High Availability**: Automatic failover and recovery mechanisms
- **Scalability**: Dynamic scaling based on load requirements

### Architecture Components

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Instance 1    │    │   Instance 2    │    │   Instance N    │
│                 │    │                 │    │                 │
│ ┌─────────────┐ │    │ ┌─────────────┐ │    │ ┌─────────────┐ │
│ │ WebSocket   │ │    │ │ WebSocket   │ │    │ │ WebSocket   │ │
│ │ Manager     │ │    │ │ Manager     │ │    │ │ Manager     │ │
│ └─────────────┘ │    │ └─────────────┘ │    │ └─────────────┘ │
│        │        │    │        │        │    │        │        │
│ ┌─────────────┐ │    │ ┌─────────────┐ │    │ ┌─────────────┐ │
│ │ Scaling     │ │    │ │ Scaling     │ │    │ │ Scaling     │ │
│ │ Manager     │ │    │ │ Manager     │ │    │ │ Manager     │ │
│ └─────────────┘ │    │ └─────────────┘ │    │ └─────────────┘ │
└─────────┬───────┘    └─────────┬───────┘    └─────────┬───────┘
          │                      │                      │
          └──────────────────────┼──────────────────────┘
                                 │
                    ┌─────────────────────┐
                    │    Redis Cluster    │
                    │                     │
                    │ ┌─────────────────┐ │
                    │ │   Pub/Sub       │ │
                    │ │   Messaging     │ │
                    │ └─────────────────┘ │
                    │ ┌─────────────────┐ │
                    │ │   Instance      │ │
                    │ │   Registry      │ │
                    │ └─────────────────┘ │
                    └─────────────────────┘
```

## Prerequisites

### System Requirements

- **Node.js**: Version 18.0 or higher
- **Redis**: Version 6.0 or higher (Redis Cluster recommended for production)
- **Memory**: Minimum 512MB per instance (2GB+ recommended for production)
- **Network**: Low-latency network connection between instances and Redis

### Dependencies

```json
{
  "dependencies": {
    "ws": "^8.14.2",
    "redis": "^4.6.0",
    "uuid": "^9.0.1"
  },
  "devDependencies": {
    "@types/ws": "^8.5.8",
    "@types/uuid": "^9.0.6"
  }
}
```

## Installation & Setup

### 1. Install Dependencies

```bash
npm install ws redis uuid
npm install --save-dev @types/ws @types/uuid
```

### 2. Redis Setup

#### Single Redis Instance (Development)

```bash
# Install Redis
sudo apt-get install redis-server  # Ubuntu/Debian
brew install redis                  # macOS

# Start Redis
redis-server

# Test connection
redis-cli ping
```

#### Redis Cluster (Production)

```bash
# Create Redis cluster configuration
# See redis-cluster-setup.conf for detailed configuration
redis-cli --cluster create \
  127.0.0.1:7000 127.0.0.1:7001 127.0.0.1:7002 \
  127.0.0.1:7003 127.0.0.1:7004 127.0.0.1:7005 \
  --cluster-replicas 1
```

### 3. Environment Configuration

Create a `.env` file:

```env
# Redis Configuration
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=your_redis_password
REDIS_DB=0
REDIS_PUBSUB_DB=1

# WebSocket Configuration
WS_PORT=3001
WS_HOST=0.0.0.0
WS_MAX_CONNECTIONS=1000

# Scaling Configuration
INSTANCE_ID=instance-1
HEARTBEAT_INTERVAL=30000
CLEANUP_INTERVAL=60000
INACTIVE_THRESHOLD=120000

# Auth Configuration (if using authentication)
JWT_SECRET=your_jwt_secret
AUTH_REQUIRED=true

# Logging
LOG_LEVEL=info
LOG_FORMAT=json
```

## Configuration

### Basic Configuration

```typescript
// server/config/websocket-scaling.ts
export const scalingConfig = {
  redis: {
    host: process.env.REDIS_HOST || 'localhost',
    port: parseInt(process.env.REDIS_PORT || '6379'),
    password: process.env.REDIS_PASSWORD,
    db: parseInt(process.env.REDIS_DB || '0'),
    pubSubDb: parseInt(process.env.REDIS_PUBSUB_DB || '1'),
    retryDelayOnFailover: 100,
    maxRetriesPerRequest: 3,
    lazyConnect: true
  },
  websocket: {
    port: parseInt(process.env.WS_PORT || '3001'),
    host: process.env.WS_HOST || '0.0.0.0',
    maxConnections: parseInt(process.env.WS_MAX_CONNECTIONS || '1000'),
    pingInterval: 30000,
    pongTimeout: 5000
  },
  scaling: {
    instanceId: process.env.INSTANCE_ID || `instance-${Date.now()}`,
    heartbeatInterval: parseInt(process.env.HEARTBEAT_INTERVAL || '30000'),
    cleanupInterval: parseInt(process.env.CLEANUP_INTERVAL || '60000'),
    inactiveThreshold: parseInt(process.env.INACTIVE_THRESHOLD || '120000'),
    messageQueueSize: 1000,
    retryAttempts: 3,
    retryDelay: 1000
  },
  auth: {
    required: process.env.AUTH_REQUIRED === 'true',
    jwtSecret: process.env.JWT_SECRET || 'your-secret-key',
    tokenExpiry: '24h'
  }
};
```

### Advanced Configuration

```typescript
// server/config/websocket-scaling-advanced.ts
export const advancedScalingConfig = {
  // Load balancing
  loadBalancing: {
    strategy: 'round-robin', // 'round-robin' | 'least-connections' | 'weighted'
    maxConnectionsPerInstance: 2000,
    connectionThreshold: 0.8, // Trigger scaling at 80% capacity
    scaleUpCooldown: 300000, // 5 minutes
    scaleDownCooldown: 600000 // 10 minutes
  },
  
  // Performance optimization
  performance: {
    enableCompression: true,
    compressionThreshold: 1024, // Compress messages > 1KB
    batchMessageDelay: 10, // Batch messages for 10ms
    maxBatchSize: 100,
    enableMessageQueuing: true,
    queueFlushInterval: 100
  },
  
  // Monitoring and metrics
  monitoring: {
    enableMetrics: true,
    metricsInterval: 60000, // 1 minute
    healthCheckInterval: 30000, // 30 seconds
    enableDetailedLogging: false,
    logLevel: 'info'
  },
  
  // Security
  security: {
    enableRateLimiting: true,
    maxMessagesPerSecond: 100,
    maxMessagesPerMinute: 1000,
    enableConnectionLimiting: true,
    maxConnectionsPerIP: 10,
    enableDDoSProtection: true
  },
  
  // Clustering
  clustering: {
    enableAutoDiscovery: true,
    discoveryInterval: 60000,
    enableFailover: true,
    failoverTimeout: 30000,
    enableLoadRebalancing: true,
    rebalanceThreshold: 0.3 // Rebalance if instance load differs by 30%
  }
};
```

## Deployment Strategies

### 1. Single Instance (Development)

```typescript
// server/deploy/single-instance.ts
import { setupScalableWebSockets } from '../websocket/scaling/scaling-examples';

async function deploySingleInstance() {
  const wsManager = await setupScalableWebSockets(3001);
  
  console.log('Single instance WebSocket server deployed on port 3001');
  
  // Health monitoring
  setInterval(async () => {
    const health = await wsManager.healthCheck();
    console.log('Health:', health.status);
  }, 30000);
}

deploySingleInstance().catch(console.error);
```

### 2. Multi-Instance (Production)

```typescript
// server/deploy/multi-instance.ts
import { ProductionScalingHelpers } from '../websocket/scaling/scaling-examples';

async function deployMultiInstance() {
  // Deploy 3 instances
  const instances = await ProductionScalingHelpers.deployMultipleInstances(3);
  
  // Setup health monitoring for each instance
  const monitors = instances.map(instance => 
    ProductionScalingHelpers.setupHealthMonitoring(instance)
  );
  
  // Graceful shutdown handler
  process.on('SIGTERM', async () => {
    console.log('Shutting down instances...');
    
    // Clear monitors
    monitors.forEach(monitor => clearInterval(monitor));
    
    // Shutdown instances
    await ProductionScalingHelpers.gracefulShutdown(instances);
    
    process.exit(0);
  });
  
  console.log(`Deployed ${instances.length} WebSocket instances`);
}

deployMultiInstance().catch(console.error);
```

### 3. Docker Deployment

```dockerfile
# Dockerfile
FROM node:18-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy source code
COPY . .

# Build TypeScript
RUN npm run build

# Expose WebSocket port
EXPOSE 3001

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:3001/health || exit 1

# Start the application
CMD ["npm", "start"]
```

```yaml
# docker-compose.yml
version: '3.8'

services:
  redis:
    image: redis:7-alpine
    command: redis-server --appendonly yes
    volumes:
      - redis_data:/data
    ports:
      - "6379:6379"
    networks:
      - tableforge_network

  websocket-1:
    build: .
    environment:
      - INSTANCE_ID=ws-instance-1
      - WS_PORT=3001
      - REDIS_HOST=redis
    ports:
      - "3001:3001"
    depends_on:
      - redis
    networks:
      - tableforge_network

  websocket-2:
    build: .
    environment:
      - INSTANCE_ID=ws-instance-2
      - WS_PORT=3002
      - REDIS_HOST=redis
    ports:
      - "3002:3002"
    depends_on:
      - redis
    networks:
      - tableforge_network

  websocket-3:
    build: .
    environment:
      - INSTANCE_ID=ws-instance-3
      - WS_PORT=3003
      - REDIS_HOST=redis
    ports:
      - "3003:3003"
    depends_on:
      - redis
    networks:
      - tableforge_network

  nginx:
    image: nginx:alpine
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
    ports:
      - "80:80"
    depends_on:
      - websocket-1
      - websocket-2
      - websocket-3
    networks:
      - tableforge_network

volumes:
  redis_data:

networks:
  tableforge_network:
    driver: bridge
```

### 4. Kubernetes Deployment

```yaml
# k8s/websocket-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: tableforge-websocket
  labels:
    app: tableforge-websocket
spec:
  replicas: 3
  selector:
    matchLabels:
      app: tableforge-websocket
  template:
    metadata:
      labels:
        app: tableforge-websocket
    spec:
      containers:
      - name: websocket
        image: tableforge/websocket:latest
        ports:
        - containerPort: 3001
        env:
        - name: INSTANCE_ID
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
        - name: REDIS_HOST
          value: "redis-service"
        - name: WS_PORT
          value: "3001"
        resources:
          requests:
            memory: "256Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 3001
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 3001
          initialDelaySeconds: 5
          periodSeconds: 5

---
apiVersion: v1
kind: Service
metadata:
  name: tableforge-websocket-service
spec:
  selector:
    app: tableforge-websocket
  ports:
  - protocol: TCP
    port: 3001
    targetPort: 3001
  type: LoadBalancer

---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: tableforge-websocket-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: tableforge-websocket
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
```

## Monitoring & Observability

### 1. Health Check Endpoints

```typescript
// server/monitoring/health-endpoints.ts
import { Request, Response } from 'express';
import { ScalableWebSocketManager } from '../websocket/scaling/websocket-manager';

export class HealthEndpoints {
  constructor(private wsManager: ScalableWebSocketManager) {}

  async healthCheck(req: Request, res: Response) {
    try {
      const health = await this.wsManager.healthCheck();
      res.status(health.status === 'healthy' ? 200 : 503).json(health);
    } catch (error) {
      res.status(500).json({
        status: 'error',
        error: error instanceof Error ? error.message : String(error)
      });
    }
  }

  async metrics(req: Request, res: Response) {
    try {
      const stats = await this.wsManager.getInstanceStats();
      res.json(stats);
    } catch (error) {
      res.status(500).json({
        error: error instanceof Error ? error.message : String(error)
      });
    }
  }

  async roomDistribution(req: Request, res: Response) {
    try {
      const distribution = await this.wsManager.getRoomDistribution();
      res.json(distribution);
    } catch (error) {
      res.status(500).json({
        error: error instanceof Error ? error.message : String(error)
      });
    }
  }
}
```

### 2. Prometheus Metrics

```typescript
// server/monitoring/prometheus-metrics.ts
import promClient from 'prom-client';

// Create metrics
const websocketConnections = new promClient.Gauge({
  name: 'tableforge_websocket_connections_total',
  help: 'Total number of WebSocket connections',
  labelNames: ['instance_id']
});

const websocketRooms = new promClient.Gauge({
  name: 'tableforge_websocket_rooms_total',
  help: 'Total number of WebSocket rooms',
  labelNames: ['instance_id']
});

const messagesSent = new promClient.Counter({
  name: 'tableforge_websocket_messages_sent_total',
  help: 'Total number of messages sent',
  labelNames: ['instance_id', 'message_type']
});

const messagesReceived = new promClient.Counter({
  name: 'tableforge_websocket_messages_received_total',
  help: 'Total number of messages received',
  labelNames: ['instance_id', 'message_type']
});

export class PrometheusMetrics {
  constructor(private instanceId: string) {
    // Initialize default metrics
    promClient.collectDefaultMetrics({
      labels: { instance_id: this.instanceId }
    });
  }

  updateConnections(count: number): void {
    websocketConnections.set({ instance_id: this.instanceId }, count);
  }

  updateRooms(count: number): void {
    websocketRooms.set({ instance_id: this.instanceId }, count);
  }

  incrementMessagesSent(messageType: string): void {
    messagesSent.inc({ instance_id: this.instanceId, message_type: messageType });
  }

  incrementMessagesReceived(messageType: string): void {
    messagesReceived.inc({ instance_id: this.instanceId, message_type: messageType });
  }

  getMetrics(): string {
    return promClient.register.metrics();
  }
}
```

### 3. Grafana Dashboard Configuration

```json
{
  "dashboard": {
    "title": "TableForge WebSocket Scaling",
    "panels": [
      {
        "title": "WebSocket Connections",
        "type": "graph",
        "targets": [
          {
            "expr": "sum(tableforge_websocket_connections_total) by (instance_id)",
            "legendFormat": "{{instance_id}}"
          }
        ]
      },
      {
        "title": "Message Throughput",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(tableforge_websocket_messages_sent_total[5m])",
            "legendFormat": "Messages Sent/sec"
          },
          {
            "expr": "rate(tableforge_websocket_messages_received_total[5m])",
            "legendFormat": "Messages Received/sec"
          }
        ]
      },
      {
        "title": "Instance Health",
        "type": "table",
        "targets": [
          {
            "expr": "tableforge_websocket_connections_total",
            "format": "table"
          }
        ]
      }
    ]
  }
}
```

## Troubleshooting

### Common Issues

#### 1. Redis Connection Issues

**Problem**: Instances cannot connect to Redis
```
Error: Redis connection failed: ECONNREFUSED
```

**Solution**:
```bash
# Check Redis status
redis-cli ping

# Check Redis configuration
redis-cli CONFIG GET "*"

# Verify network connectivity
telnet redis-host 6379
```

#### 2. Message Delivery Failures

**Problem**: Messages not reaching all instances
```
Warning: Message delivery failed to instance-2
```

**Solution**:
```typescript
// Enable message debugging
process.env.LOG_LEVEL = 'debug';

// Check instance heartbeats
const distribution = await wsManager.getRoomDistribution();
console.log('Instance heartbeats:', distribution);

// Verify Redis pub/sub
redis-cli PUBSUB CHANNELS "*tableforge*"
```

#### 3. Memory Leaks

**Problem**: Increasing memory usage over time
```
Warning: Memory usage exceeding threshold: 512MB
```

**Solution**:
```typescript
// Enable memory monitoring
setInterval(async () => {
  const stats = await wsManager.getInstanceStats();
  if (stats.memory.used > 512 * 1024 * 1024) {
    console.warn('Memory threshold exceeded:', stats.memory);
    // Implement cleanup logic
  }
}, 60000);
```

### Debug Mode

Enable debug logging:
```bash
export DEBUG=tableforge:websocket:*
export LOG_LEVEL=debug
```

## Performance Tuning

### 1. Redis Optimization

```conf
# redis.conf optimizations
maxmemory 2gb
maxmemory-policy allkeys-lru
save 900 1
save 300 10
save 60 10000

# Pub/Sub optimizations
client-output-buffer-limit pubsub 32mb 8mb 60
```

### 2. WebSocket Optimization

```typescript
// WebSocket performance settings
const wsConfig = {
  perMessageDeflate: {
    zlibDeflateOptions: {
      threshold: 1024,
      concurrencyLimit: 10,
      chunkSize: 1024
    }
  },
  maxPayload: 100 * 1024, // 100KB max message size
  skipUTF8Validation: false // Keep validation for security
};
```

### 3. Load Balancer Configuration

```nginx
# nginx.conf for WebSocket load balancing
upstream websocket_backend {
    ip_hash; # Sticky sessions for WebSocket
    server 127.0.0.1:3001;
    server 127.0.0.1:3002;
    server 127.0.0.1:3003;
}

server {
    listen 80;
    
    location /ws {
        proxy_pass http://websocket_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 86400;
    }
}
```

## Security Considerations

### 1. Authentication & Authorization

```typescript
// Implement JWT-based authentication
export class WebSocketAuth {
  static async authenticateConnection(token: string): Promise<User | null> {
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET!) as any;
      return await getUserById(decoded.userId);
    } catch {
      return null;
    }
  }

  static async authorizeRoomAccess(userId: string, roomId: string): Promise<boolean> {
    // Implement room access control logic
    return await checkRoomPermissions(userId, roomId);
  }
}
```

### 2. Rate Limiting

```typescript
// Implement rate limiting per connection
export class RateLimiter {
  private limits = new Map<string, { count: number; resetTime: number }>();

  checkLimit(connectionId: string, maxRequests: number = 100, windowMs: number = 60000): boolean {
    const now = Date.now();
    const limit = this.limits.get(connectionId);

    if (!limit || now > limit.resetTime) {
      this.limits.set(connectionId, { count: 1, resetTime: now + windowMs });
      return true;
    }

    if (limit.count >= maxRequests) {
      return false;
    }

    limit.count++;
    return true;
  }
}
```

### 3. Input Validation

```typescript
// Validate all incoming messages
export class MessageValidator {
  static validateMessage(message: any): boolean {
    if (!message || typeof message !== 'object') return false;
    if (!message.type || typeof message.type !== 'string') return false;
    if (message.type.length > 50) return false;
    
    // Validate payload size
    const messageSize = JSON.stringify(message).length;
    if (messageSize > 100 * 1024) return false; // 100KB limit
    
    return true;
  }
}
```

## Best Practices

### 1. Connection Management

- Implement proper connection cleanup on disconnect
- Use heartbeat/ping-pong to detect dead connections
- Limit concurrent connections per client
- Implement graceful degradation under high load

### 2. Message Design

- Keep messages small and focused
- Use compression for large payloads
- Implement message queuing for offline users
- Use message acknowledgments for critical messages

### 3. Error Handling

- Implement comprehensive error logging
- Use circuit breakers for external dependencies
- Implement retry logic with exponential backoff
- Provide meaningful error messages to clients

### 4. Monitoring

- Monitor key metrics: connections, messages, memory, CPU
- Set up alerts for critical thresholds
- Log important events and errors
- Implement distributed tracing for debugging

### 5. Deployment

- Use blue-green deployments for zero downtime
- Implement health checks and readiness probes
- Use horizontal pod autoscaling in Kubernetes
- Implement proper resource limits and requests

---

This configuration guide provides a comprehensive overview of setting up, configuring, and operating the TableForge WebSocket scaling system. For additional support, refer to the API documentation and example implementations.
