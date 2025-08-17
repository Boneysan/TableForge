# High-Impact Build Plan for TableForge VTT

*A comprehensive roadmap for production-ready virtual tabletop implementation*

## 🚨 High-Impact Risks & Fixes

### 1) WebSocket Auth & Multiserver Scale

**Why:** Real-time VTTs hinge on correct room scoping, auth, and broadcast fan-out.

**What to do:**

- **JWT Authentication**: Use JWT or short-lived access tokens during the WS handshake; re-verify on reconnect; enforce room-scoped ACLs server-side.

- **Horizontal Scaling**: Add sticky sessions or a Redis Pub/Sub (or Socket.IO adapter) for horizontal scale.

- **Rate Limiting**: Implement rate limits (messages/sec per client) and server-enforced size caps for payloads to prevent flood/DoS.

- **Authoritative State**: Introduce server-side authoritative state for sensitive moves (e.g., hidden hands, shuffles) and idempotent operations (server assigns move IDs to prevent duplicates).

### 2) Asset Pipeline & Storage Safety

**Why:** GCS buckets + user uploads are a common attack surface and cost hotspot.

**What to do:**

- **Signed URLs**: Switch to signed URLs (time-bound) for downloads and direct-to-GCS uploads (client gets a single-use upload URL). Validate Content-Type, max size, and file signatures server-side before issuing URLs.

- **Media Optimization**: Generate thumbnails/server-side derivatives (webp, capped dimensions) to cut bandwidth.

- **Quotas & Lifecycle**: Enforce per-room/per-user quotas, lifecycle rules (auto-expire temp assets), and virus scanning (e.g., Cloud Run clamav or a SaaS).

### 3) Data Model Constraints & Integrity

**Why:** Board state drifts and race conditions are the silent killers of VTTs.

**What to do:**

- **Database Constraints**: In Postgres, add NOT NULL, CHECK, UNIQUE constraints; ON DELETE rules that match gameplay semantics; partial indexes for hot queries.

- **Event Sourcing**: For turn/room events, persist append-only event logs (immutable) + projected state tables for fast reads; this helps debugging desyncs.

- **Concurrency Control**: Use advisory locks (pg_advisory_xact_lock) or optimistic concurrency (row version) for atomic shuffles/deals.

### 4) Server Performance Guardrails

**Why:** Real-time + assets can melt a single box quickly.

**What to do:**

- **Backpressure**: Add p-limit style backpressure on expensive endpoints; queue/merge bursty operations (e.g., batch position updates at 30–60 Hz).

- **Caching Strategy**: Cache room snapshots in Redis; invalidate on writes; support delta updates to clients.

- **Observability**: Expose /metrics (Prometheus), count WS connections/room, broadcast size, cache hit rate, query p95/p99. (Your README mentions health/metrics endpoints—make sure they include these cardinal metrics.)

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

### 8) Observability You Can Act On

**Why:** You can't fix what you can't see.

**What to do:**

- **Distributed Tracing**: OpenTelemetry traces for WS events and DB queries; correlation IDs from client → server → DB.

- **Structured Logging**: Structured logs (pino) with request/room IDs; sample chatty logs.

- **Alerting**: Alert on: WS error rate, broadcast lag, DB pool saturation, Redis evictions, 429/5xx spikes.

### 9) Deployment Hardening (compose/k8s)

**Why:** Local dev is fine; prod needs guardrails.

**What to do:**

- **Docker Compose**: In docker-compose.yml, add healthchecks, restart, resource limits (CPU/mem), and read-only FS for stateless services; wire depends_on:condition:service_healthy.

- **Kubernetes**: For k8s: HPA on CPU + custom metrics (WS connections/room), PodDisruptionBudget, PodSecurity, network policies; Redis with AOF+monitored persistence.

### 10) Product Fit for VTTs

**Why:** Polishing the "table feel" matters.

**What to do:**

- **Authoritative Randomness**: Authoritative shuffles with server-seeded randomness; client can request seed for reproducible replays.

- **History & Undo**: Replay/undo: bounded event history with checkpoint snapshots.

- **System Evolution**: Template versioning for systems; migration helpers when schemas change.

- **Accessibility**: Accessibility: keyboard shortcuts for core actions; focus management with Radix + ARIA.

---

## 🔧 Smaller But Worthwhile Improvements

- **API Versioning**: API versioning (/api/v1) and deprecation policy.
- **Background Jobs**: Background jobs (BullMQ/Cloud Tasks) for large imports & thumbnailing.
- **Feature Flags**: Feature flags (e.g., Unleash) to dark-launch risky features.
- **Search**: Search: Postgres trigram for asset name/tag search; cap result sizes and paginate always.
- **Documentation**: Docs: add sequence diagrams for a typical move (deal → update → broadcast → ack) and a "What can go wrong?" ops runbook (cache miss storms, thundering herd, reconnect storms).

---

## ⚡ Quick Wins You Can Ship This Week

### Security & Validation
- Add Helmet+CSP, max body size limits, and Zod validation on all API and WS payloads.
- Implement signed upload/download URLs with strict validation + size caps.

### Scalability Foundation
- Add sticky sessions and a Redis pub/sub adapter for WS to prepare for horizontal scale.

### Observability
- Introduce Prometheus metrics for WS/rooms/cache/DB and wire alerts.

### Testing
- Write property-based tests for card/deck invariants and seeded shuffle utilities.

### Infrastructure
- Put healthchecks and resource limits into Compose; verify graceful shutdown.

---

## 🎯 Implementation Priority Matrix

### Phase 1 (This Week) - Foundation
1. ✅ **WebSocket Tests Fixed** - Basic connection tests working
2. 🔄 **Security Headers** - Helmet + CSP implementation
3. 🔄 **Input Validation** - Zod validation on all endpoints
4. 🔄 **Basic Metrics** - Prometheus endpoint setup

### Phase 2 (Next 2 Weeks) - Core Infrastructure
1. **Asset Security** - Signed URLs and validation
2. **Database Constraints** - Add proper constraints and indexes
3. **Redis Integration** - Caching and pub/sub for scaling
4. **Rate Limiting** - Protect against abuse

### Phase 3 (Month 1) - Production Readiness
1. **Event Sourcing** - Implement append-only event logs
2. **Load Testing** - Multi-client stress tests
3. **Monitoring** - Full observability stack
4. **Deployment** - Hardened Docker/K8s configs

### Phase 4 (Month 2+) - Polish & Scale
1. **Frontend Performance** - Virtualization and optimization
2. **Advanced Features** - Replay, undo, templates
3. **Accessibility** - Full a11y compliance
4. **Multi-region** - Global deployment strategy

---

*Last updated: August 17, 2025*
*Status: Comprehensive build plan established*
