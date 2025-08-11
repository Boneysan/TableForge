# Observability Infrastructure

## Overview

Vorpal Board includes comprehensive observability infrastructure with metrics collection, distributed tracing, and health monitoring. This enables production-ready monitoring, debugging, and performance optimization.

## Architecture

### Components

1. **OpenTelemetry SDK** - Distributed tracing and instrumentation
2. **Prometheus Metrics** - Metrics collection and exposure
3. **OTLP Exporter** - Trace export to observability backends
4. **Structured Logging** - Correlation with traces and metrics

### Telemetry

- **Service**: `vorpal-board`
- **Version**: `1.0.0`
- **Trace Endpoint**: `OTLP_ENDPOINT` environment variable
- **Authentication**: `OTLP_AUTH_TOKEN` environment variable

## Metrics

### Core Metrics

#### Room Management
- `vorpal_active_rooms_total` - Number of currently active game rooms
- `vorpal_rooms_created_total` - Total number of rooms created
- `vorpal_rooms_deleted_total` - Total number of rooms deleted

#### WebSocket Connections
- `vorpal_websocket_connections_active` - Number of active WebSocket connections
- `vorpal_websocket_connects_total` - Total WebSocket connections established
- `vorpal_websocket_disconnects_total` - Total WebSocket disconnections
- `vorpal_websocket_messages_total` - Total WebSocket messages sent/received

#### Game Moves
- `vorpal_card_moves_total` - Total number of card moves performed
- `vorpal_moves_per_minute` - Number of moves per minute (real-time)
- `vorpal_deck_operations_total` - Total deck operations (shuffle, deal, etc.)

#### Asset Management
- `vorpal_asset_uploads_total` - Total number of assets uploaded
- `vorpal_asset_upload_size_bytes` - Distribution of asset upload sizes
- `vorpal_asset_upload_duration_seconds` - Duration of asset uploads

#### Authentication
- `vorpal_authentication_attempts_total` - Total authentication attempts
- `vorpal_active_users_total` - Number of currently active users

#### Performance
- `vorpal_http_request_duration_seconds` - HTTP request duration
- `vorpal_database_query_duration_seconds` - Database query duration
- `vorpal_database_connections_active` - Active database connections

#### Errors
- `vorpal_errors_total` - Total errors by type and severity
- `vorpal_uncaught_exceptions_total` - Total uncaught exceptions

#### System Resources
- `vorpal_memory_usage_bytes` - Memory usage by type
- `vorpal_cpu_usage_percent` - CPU usage percentage

### Metrics Labels

All metrics include contextual labels for filtering and aggregation:

- **Rooms**: `room_id`, `status`, `created_by_type`
- **Users**: `auth_provider`, `auth_status`
- **Moves**: `move_type`, `source_type`, `target_type`
- **Assets**: `asset_type`, `upload_status`
- **HTTP**: `method`, `route`, `status_code`
- **Database**: `operation`, `table`
- **Errors**: `error_type`, `severity`, `component`

## Tracing

### End-to-End Deck Move Tracing

Complete tracing coverage for card/deck move operations:

1. **WebSocket Message Receipt**
   - Span: `websocket.card_move_received`
   - Attributes: Connection ID, room ID, user ID, move type

2. **Move Validation**
   - Span: `deck.move.validation`
   - Attributes: Move ID, validation rules, source/target validation

3. **Concurrency Control**
   - Span: `deck.move.concurrency_check`
   - Attributes: Version conflicts, lock acquisition, conflict resolution

4. **Database Operations**
   - Span: `db.update.card_pile`
   - Attributes: Table name, operation type, affected rows

5. **State Synchronization**
   - Span: `deck.move.broadcast`
   - Attributes: Connected clients, message size, broadcast success

6. **Result Response**
   - Span: `websocket.card_move_result`
   - Attributes: Success status, error details, client response time

### Custom Trace Attributes

#### Deck Move Operations
- `deck.move.type` - Type of move (card_to_pile, shuffle, etc.)
- `deck.move.source.type` - Source type (deck, pile, hand, board)
- `deck.move.target.type` - Target type (deck, pile, hand, board)
- `deck.move.card.count` - Number of cards being moved
- `deck.move.id` - Unique move identifier
- `deck.move.client.id` - Client connection identifier

#### WebSocket Operations
- `websocket.event.type` - Type of WebSocket event
- `websocket.connection.id` - Connection identifier
- `websocket.message.id` - Message identifier
- `room.id` - Room identifier
- `player.id` - Player identifier

#### Performance Timing
- `performance.operation` - Operation being timed
- `performance.duration_ms` - Operation duration in milliseconds
- `performance.start_time` - Operation start timestamp
- `performance.end_time` - Operation end timestamp

## Endpoints

### Metrics Endpoint
```
GET /api/observability/metrics
```
Prometheus-compatible metrics endpoint for scraping.

### Health Check
```
GET /api/observability/health/metrics
```
Health status of metrics collection system.

### Trace Context
```
GET /api/observability/trace/current
```
Current active trace context information.

### Observability Status
```
GET /api/observability/status
```
Overall observability system status including metrics, tracing, and logging.

### Manual Collection
```
POST /api/observability/collect
```
Manually trigger metrics collection (for debugging).

### Specific Metrics
```
GET /api/observability/metrics/:metricName
```
Retrieve specific metric values and metadata.

## Environment Configuration

### Required Variables

```bash
# OpenTelemetry Configuration
OTLP_ENDPOINT=http://localhost:4318/v1/traces
OTLP_AUTH_TOKEN=your-auth-token

# Logging Configuration
LOG_LEVEL=info

# Tracing Configuration (optional)
TRACE_ROOM_IDS=room1,room2  # Always sample these rooms
```

### Optional Variables

```bash
# Disable filesystem instrumentation for performance
OTEL_NODE_DISABLED_INSTRUMENTATIONS=fs

# Custom service configuration
OTEL_SERVICE_NAME=vorpal-board
OTEL_SERVICE_VERSION=1.0.0
```

## Usage Examples

### Metrics Collection

```typescript
import { recordCardMove, recordDeckOperation } from '@server/observability/metrics';

// Record a card move
recordCardMove('card_to_pile', 'deck', 'hand', roomId);

// Record a deck operation
recordDeckOperation('shuffle', 'standard_deck', roomId);
```

### Distributed Tracing

```typescript
import { traceDeckMoveOperation } from '@server/observability/telemetry';

// Trace a complete deck move operation
await traceDeckMoveOperation(
  'process_move',
  {
    roomId,
    playerId,
    moveType: 'card_to_pile',
    sourceType: 'deck',
    targetType: 'hand',
    cardCount: 5,
    moveId,
    clientId,
  },
  async (span) => {
    // Your move processing logic here
    // All operations within this function will be traced
    span.addEvent('move_validated');
    // ... process move ...
    span.addEvent('move_completed');
  }
);
```

### Custom Events

```typescript
import { recordCustomEvent, recordError } from '@server/observability/telemetry';

// Record a custom event in the current trace
recordCustomEvent('card.shuffled', {
  deck_type: 'standard',
  card_count: 52,
});

// Record an error with context
recordError(new Error('Deck not found'), {
  operation: 'shuffle_deck',
  deck_id: deckId,
});
```

## Monitoring Setup

### Prometheus Configuration

```yaml
scrape_configs:
  - job_name: 'vorpal-board'
    static_configs:
      - targets: ['localhost:3000']
    metrics_path: '/api/observability/metrics'
    scrape_interval: 15s
```

### Grafana Dashboards

Key visualizations to monitor:

1. **Room Activity**
   - Active rooms gauge
   - Room creation/deletion rates
   - Average session duration

2. **User Engagement**
   - Active connections
   - Authentication success rates
   - Moves per minute

3. **Performance**
   - HTTP request latency percentiles
   - Database query performance
   - WebSocket message throughput

4. **System Health**
   - Memory usage trends
   - Error rates by component
   - Uncaught exception alerts

### Alerting Rules

```yaml
groups:
  - name: vorpal-board
    rules:
      - alert: HighErrorRate
        expr: rate(vorpal_errors_total[5m]) > 0.1
        for: 1m
        labels:
          severity: warning
        annotations:
          summary: High error rate detected
          
      - alert: DatabaseConnectionsHigh
        expr: vorpal_database_connections_active > 50
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: Database connection pool near limit
```

## Troubleshooting

### Common Issues

1. **Missing Traces**
   - Check `OTLP_ENDPOINT` configuration
   - Verify network connectivity to trace backend
   - Ensure `OTLP_AUTH_TOKEN` is valid

2. **High Memory Usage**
   - Adjust trace sampling rates
   - Disable unused instrumentations
   - Monitor span creation rates

3. **Performance Impact**
   - Use sampling for high-volume operations
   - Disable filesystem instrumentation
   - Consider async trace export

### Debug Commands

```bash
# Check metrics endpoint
curl http://localhost:3000/api/observability/metrics

# Verify health status
curl http://localhost:3000/api/observability/status

# Get current trace context
curl http://localhost:3000/api/observability/trace/current
```

## Performance Considerations

### Trace Sampling

- 10% sampling for regular operations
- 100% sampling for errors and critical operations
- Room-specific sampling for debugging
- Configurable via environment variables

### Metrics Collection

- 30-second intervals for resource metrics
- Real-time for move counters
- Efficient move tracking with sliding windows
- Automatic cleanup of stale connections

### Memory Management

- Automatic span lifecycle management
- Bounded trace context storage
- Periodic metrics registry cleanup
- Connection pool monitoring