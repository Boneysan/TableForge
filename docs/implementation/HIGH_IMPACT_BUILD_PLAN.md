# High-Impact Build Plan for TableForge VTT (Replit-Optimized)

*A comprehensive roadmap for production-ready virtual tabletop implementation tailored for Replit infrastructure*

## 🔧 Replit Infrastructure Considerations

**Replit Strengths:**
- Node.js 20 + TypeScript native support
- Built-in PostgreSQL database
- Autoscale deployment for horizontal scaling
- WebSocket support with proper port handling
- Integrated secrets management

**Replit Limitations & External Services:**
- Memory: ~4GB limit (upgrade for more)
- Storage: Use external services (GCS, S3)
- Advanced monitoring: External APM required
- Redis: Use Redis Cloud or Upstash
- Multi-region: Single-region deployment

## 🚨 High-Impact Risks & Fixes

### 1) WebSocket Auth & Multiserver Scale (Replit-Adapted)

**Why:** Real-time VTTs hinge on correct room scoping, auth, and broadcast fan-out.

**What to do:**

- **JWT Authentication**: Use JWT or short-lived access tokens during the WS handshake; re-verify on reconnect; enforce room-scoped ACLs server-side.

- **Replit Autoscale**: Leverage Replit's Autoscale deployment for horizontal scaling instead of manual sticky sessions or custom load balancers.

- **External Redis**: Use Redis Cloud or Upstash for pub/sub and session storage (Replit doesn't include Redis).
  ```bash
  # Add to Replit Secrets:
  REDIS_URL=redis://your-redis-cloud-url
  ```

- **Rate Limiting**: Implement rate limits (messages/sec per client) using in-memory store + Redis backend for distributed rate limiting.

- **Authoritative State**: Introduce server-side authoritative state for sensitive moves (e.g., hidden hands, shuffles) and idempotent operations (server assigns move IDs to prevent duplicates).

### 2) Asset Pipeline & Storage Safety (External Services)

**Why:** GCS buckets + user uploads are a common attack surface and cost hotspot.

**What to do:**

- **External Storage**: Use Google Cloud Storage, AWS S3, or Cloudflare R2 via API (Replit doesn't provide large storage).
  ```bash
  # Add to Replit Secrets:
  GCS_BUCKET_NAME=your-bucket
  GCS_PROJECT_ID=your-project
  GCS_CREDENTIALS=your-service-account-json
  ```

- **Signed URLs**: Switch to signed URLs (time-bound) for downloads and direct-to-cloud uploads (client gets a single-use upload URL). Validate Content-Type, max size, and file signatures server-side before issuing URLs.

- **Media Optimization**: Generate thumbnails/server-side derivatives (webp, capped dimensions) to cut bandwidth. Use Replit's compute for image processing.

- **Quotas & Lifecycle**: Enforce per-room/per-user quotas, lifecycle rules (auto-expire temp assets), and virus scanning via external service (ClamAV API or SaaS).

### 3) Data Model Constraints & Integrity (Replit PostgreSQL)

**Why:** Board state drifts and race conditions are the silent killers of VTTs.

**What to do:**

- **Database Constraints**: Use Replit's built-in PostgreSQL or external Neon/Supabase. Add NOT NULL, CHECK, UNIQUE constraints; ON DELETE rules that match gameplay semantics; partial indexes for hot queries.
  ```bash
  # Recommended external PostgreSQL for production:
  DATABASE_URL=postgresql://your-neon-db-url
  # Or use Replit's built-in PostgreSQL for development
  ```

- **Event Sourcing**: For turn/room events, persist append-only event logs (immutable) + projected state tables for fast reads; this helps debugging desyncs.

- **Concurrency Control**: Use advisory locks (pg_advisory_xact_lock) or optimistic concurrency (row version) for atomic shuffles/deals.

### 4) Server Performance Guardrails (Replit Limits)

**Why:** Real-time + assets can melt a single box quickly, especially with Replit's resource constraints.

**What to do:**

- **Backpressure**: Add p-limit style backpressure on expensive endpoints; queue/merge bursty operations (e.g., batch position updates at 30–60 Hz).

- **External Caching**: Cache room snapshots in Redis Cloud/Upstash; invalidate on writes; support delta updates to clients.
  ```typescript
  // Use external Redis for caching in Replit
  const redis = new Redis(process.env.REDIS_URL);
  ```

- **Memory Management**: Monitor Replit's ~4GB memory limit; implement garbage collection hints and connection pooling.

- **Observability**: Expose /metrics (Prometheus), count WS connections/room, broadcast size, cache hit rate, query p95/p99. Use Replit's built-in monitoring + external APM (DataDog, New Relic).

### 5) Security Posture

**Why:** You'll host user-generated content and private game rooms.

**What to do:**

- **Headers & CSP**: Enforce CSP (default-src 'self'; images media from bucket domains; block inline scripts), Helmet headers, SameSite=strict cookies for sessions.

- **Input Validation**: Input validation with Zod on every API/WS message; reject unknown keys; cap array lengths and string sizes.

- **Audit Logging**: Audit logs: who did what in which room (minimal PII), rotated and redactable.

- **Secrets Management**: Secrets: prefer workload identity/OIDC on cloud; avoid long-lived JSON creds in .env.

- **RBAC**: Admin/GM/Player RBAC: centralize in middleware; add unit tests for permission matrices.

### 6) Testing Depth & Determinism

**Why:** A VTT has lots of UI + WS edge cases.

**What to do:**

- **Property-Based Testing**: Property-based tests for deck operations (shuffle/deal/merge) ensuring invariants (no duplicates, all cards accounted).

- **Load Testing**: Soak tests for 20–100 clients joining/leaving/broadcasting; assert no memory leaks and steady p95 latency.

- **Flake Control**: E2E flake control: freeze time (fake timers), seed RNG for deterministic shuffles in tests, mock storage.

- **Contract Testing**: Contract tests between shared/ schemas and server routes to guarantee API stability.

### 7) Frontend Performance & UX Resilience

**Why:** Tables with thousands of tokens/annotations can jank.

**What to do:**

- **Virtualization**: Window/virtualize heavy lists and canvas layers; consolidate state updates with requestAnimationFrame.

- **Caching Strategy**: Use React Query cache TTLs per resource (rooms short, systems long).

- **Offline Resilience**: Offline-tolerant command queue (optimistic UI) with server reconciliation and "last writer wins" or vector clocks for drawing/annotations.

### 8) Observability You Can Act On (Hybrid Approach)

**Why:** You can't fix what you can't see, but Replit has monitoring limitations.

**What to do:**

- **Basic Metrics**: Use Replit's built-in monitoring + custom Prometheus endpoint for development.
  ```typescript
  // /metrics endpoint for Replit monitoring
  app.get('/metrics', (req, res) => {
    // Basic metrics compatible with Replit
  });
  ```

- **External APM**: For production, use DataDog, New Relic, or Sentry for advanced tracing and alerting.
  ```bash
  # Add to Replit Secrets:
  DATADOG_API_KEY=your-datadog-key
  NEW_RELIC_LICENSE_KEY=your-newrelic-key
  ```

- **Structured Logging**: Structured logs (pino) with request/room IDs; sample chatty logs. Use LogTail or similar for log aggregation.

- **Alerting**: Alert on: WS error rate, broadcast lag, memory usage (Replit limits), Redis evictions, 429/5xx spikes.

### 9) Deployment Hardening (Replit-Native)

**Why:** Local dev is fine; prod needs guardrails, and Replit has specific deployment patterns.

**What to do:**

- **Replit Configuration**: Optimize `.replit` file for production deployment.
  ```toml
  # .replit optimized for TableForge
  modules = ["nodejs-20", "web", "postgresql-16"]
  run = "npm run dev"
  
  [deployment]
  deploymentTarget = "autoscale"  # Handles horizontal scaling
  build = ["npm", "run", "build"]
  run = ["npm", "run", "start"]
  
  [env]
  NODE_ENV = "production"
  PORT = "5000"
  MEMORY_LIMIT = "4096"  # Max for Replit Core
  ```

- **Health Checks**: Implement robust health checks for Replit's autoscaler.
  ```typescript
  // Health check endpoint for Replit
  app.get('/health', async (req, res) => {
    // Check DB, Redis, and memory usage
  });
  ```

- **Resource Monitoring**: Monitor Replit's memory/CPU limits; implement graceful degradation when approaching limits.

- **Secrets Management**: Use Replit Secrets for all sensitive configuration instead of .env files.

### 10) Product Fit for VTTs

**Why:** Polishing the "table feel" matters.

**What to do:**

- **Authoritative Randomness**: Authoritative shuffles with server-seeded randomness; client can request seed for reproducible replays.

- **History & Undo**: Replay/undo: bounded event history with checkpoint snapshots.

- **System Evolution**: Template versioning for systems; migration helpers when schemas change.

- **Accessibility**: Accessibility: keyboard shortcuts for core actions; focus management with Radix + ARIA.

---

## 🔧 Replit-Specific Improvements

- **External Service Integration**: Set up Redis Cloud, external PostgreSQL (Neon/Supabase), and cloud storage APIs.
- **Memory Optimization**: Implement memory monitoring and garbage collection strategies for Replit's 4GB limit.
- **Auto-scaling Configuration**: Configure Replit's autoscale deployment with proper health checks.
- **Performance Monitoring**: Use Replit's built-in monitoring + external APM for comprehensive observability.
- **Development Workflow**: Optimize Replit workspace for collaborative development with proper secrets management.

---

## ⚡ Quick Wins You Can Ship This Week (Replit-Ready)

### Security & Validation (100% Replit Compatible)
- Add Helmet+CSP, max body size limits, and Zod validation on all API and WS payloads.
- Configure Replit Secrets for JWT and session management.

### External Services Setup
- Set up Redis Cloud/Upstash for caching and pub/sub.
- Configure external storage (GCS/S3) with signed URLs and validation.

### Replit Optimization
- Configure `.replit` file for autoscale deployment.
- Implement health checks and memory monitoring.

### Testing (Native Replit Support)
- Write property-based tests for card/deck invariants using Vitest.
- Set up load testing with k6 (works in Replit terminal).

### Infrastructure
- Configure external PostgreSQL (Neon recommended for Replit).
- Set up basic Prometheus metrics endpoint.

---

## 🎯 Replit-Optimized Implementation Priority Matrix

### Phase 1 (This Week) - Replit Foundation
1. ✅ **WebSocket Tests Fixed** - Basic connection tests working
2. 🔄 **Security Headers** - Helmet + CSP implementation (100% Replit compatible)
3. 🔄 **Input Validation** - Zod validation on all endpoints (Native npm package)
4. 🔄 **External Services Setup** - Redis Cloud + PostgreSQL (Neon) configuration
5. 🔄 **Replit Configuration** - Optimize `.replit` for autoscale deployment

### Phase 2 (Next 2 Weeks) - External Service Integration
1. **Asset Security** - Cloud storage (GCS/S3) with signed URLs
2. **Database Optimization** - External PostgreSQL with proper constraints and indexes
3. **Caching Layer** - Redis Cloud integration for sessions and pub/sub
4. **Rate Limiting** - Distributed rate limiting with Redis backend
5. **Memory Monitoring** - Replit resource limit monitoring and alerts

### Phase 3 (Month 1) - Production Readiness on Replit
1. **Event Sourcing** - Implement append-only event logs with external PostgreSQL
2. **Load Testing** - Multi-client stress tests (k6 compatible with Replit)
3. **External Monitoring** - DataDog/New Relic integration for advanced observability
4. **Auto-scaling** - Replit autoscale configuration with health checks

### Phase 4 (Month 2+) - Advanced Features & Optimization
1. **Frontend Performance** - Virtualization and optimization (React compatible)
2. **Advanced Features** - Replay, undo, templates (server-side logic)
3. **Accessibility** - Full a11y compliance (client-side focus)
4. **Performance Tuning** - Memory optimization for Replit's 4GB limit

---

## 📋 Replit-Specific Configuration Checklist

### ✅ Replit Secrets Setup
```bash
# Database
DATABASE_URL=postgresql://neon-db-url
DIRECT_URL=postgresql://neon-direct-url

# Redis
REDIS_URL=redis://redis-cloud-url

# Authentication
JWT_SECRET=your-jwt-secret
SESSION_SECRET=your-session-secret

# External Storage
GCS_BUCKET_NAME=your-bucket
GCS_PROJECT_ID=your-project
GCS_CREDENTIALS=service-account-json

# Monitoring
DATADOG_API_KEY=your-datadog-key
SENTRY_DSN=your-sentry-dsn

# Production Settings
NODE_ENV=production
PORT=5000
MEMORY_LIMIT=4096
```

### ✅ .replit Configuration
```toml
modules = ["nodejs-20", "web", "postgresql-16"]
run = "npm run dev"
hidden = [".config", ".git", "node_modules", "dist"]

[deployment]
deploymentTarget = "autoscale"
build = ["npm", "run", "build"]
run = ["npm", "run", "start"]

[env]
NODE_ENV = "production"
PORT = "5000"
```

### ✅ External Service Recommendations
- **Database**: Neon (Postgres) - Best Replit integration
- **Redis**: Redis Cloud - Reliable and scalable
- **Storage**: Google Cloud Storage - Good API integration
- **Monitoring**: DataDog - Comprehensive APM for Replit
- **Logging**: LogTail - Simple log aggregation service

---

*Last updated: August 17, 2025*
*Status: Comprehensive build plan optimized for Replit infrastructure*
*Replit Compatibility: 95% - External services required for Redis, storage, and advanced monitoring*
