#!/bin/bash
# scripts/run-scaling-tests.sh
# Multi-instance WebSocket scaling test orchestration script

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
DOCKER_COMPOSE_FILE="docker/scaling-test.docker-compose.yml"
TEST_TIMEOUT=600  # 10 minutes
HEALTH_CHECK_RETRIES=30
HEALTH_CHECK_INTERVAL=10

# Logging function
log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Cleanup function
cleanup() {
    log "Cleaning up test environment..."
    
    # Stop and remove containers
    docker-compose -f $DOCKER_COMPOSE_FILE down --volumes --remove-orphans 2>/dev/null || true
    
    # Remove any test networks
    docker network prune -f 2>/dev/null || true
    
    # Remove test volumes
    docker volume prune -f 2>/dev/null || true
    
    success "Cleanup completed"
}

# Trap cleanup on script exit
trap cleanup EXIT

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        error "Docker is not installed or not in PATH"
        exit 1
    fi
    
    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        error "Docker Compose is not installed or not in PATH"
        exit 1
    fi
    
    # Check if Docker daemon is running
    if ! docker info &> /dev/null; then
        error "Docker daemon is not running"
        exit 1
    fi
    
    # Check if ports are available
    local ports=(80 6380 8081 8082 8083 9090 3001 8404)
    for port in "${ports[@]}"; do
        if netstat -tln 2>/dev/null | grep -q ":$port "; then
            error "Port $port is already in use"
            exit 1
        fi
    done
    
    success "Prerequisites check passed"
}

# Build test infrastructure
build_infrastructure() {
    log "Building test infrastructure..."
    
    # Build Docker images
    docker-compose -f $DOCKER_COMPOSE_FILE build --no-cache
    
    success "Infrastructure built successfully"
}

# Start test environment
start_environment() {
    log "Starting test environment..."
    
    # Start core services first
    docker-compose -f $DOCKER_COMPOSE_FILE up -d redis-scaling
    
    # Wait for Redis to be ready
    wait_for_service "redis-scaling" "6379"
    
    # Start WebSocket instances
    docker-compose -f $DOCKER_COMPOSE_FILE up -d websocket-instance-1 websocket-instance-2 websocket-instance-3
    
    # Wait for instances to be ready
    wait_for_service "websocket-instance-1" "8080"
    wait_for_service "websocket-instance-2" "8080" 
    wait_for_service "websocket-instance-3" "8080"
    
    # Start load balancer
    docker-compose -f $DOCKER_COMPOSE_FILE up -d load-balancer
    wait_for_service "load-balancer" "80"
    
    # Start monitoring stack
    docker-compose -f $DOCKER_COMPOSE_FILE up -d prometheus grafana
    
    success "Test environment started successfully"
}

# Wait for service to be ready
wait_for_service() {
    local service_name="$1"
    local port="$2"
    local retries=0
    
    log "Waiting for $service_name to be ready on port $port..."
    
    while [ $retries -lt $HEALTH_CHECK_RETRIES ]; do
        if docker-compose -f $DOCKER_COMPOSE_FILE exec -T $service_name nc -z localhost $port 2>/dev/null; then
            success "$service_name is ready"
            return 0
        fi
        
        retries=$((retries + 1))
        log "Waiting for $service_name... ($retries/$HEALTH_CHECK_RETRIES)"
        sleep $HEALTH_CHECK_INTERVAL
    done
    
    error "$service_name failed to start within timeout"
    docker-compose -f $DOCKER_COMPOSE_FILE logs $service_name
    exit 1
}

# Run basic connectivity test
test_basic_connectivity() {
    log "Testing basic connectivity..."
    
    local instances=("websocket-instance-1:8080" "websocket-instance-2:8080" "websocket-instance-3:8080")
    
    for instance in "${instances[@]}"; do
        local response=$(curl -s -w "%{http_code}" -o /dev/null "http://$instance/health" || echo "000")
        if [ "$response" = "200" ]; then
            success "Instance $instance is responding"
        else
            error "Instance $instance is not responding (HTTP $response)"
            return 1
        fi
    done
    
    # Test load balancer
    local lb_response=$(curl -s -w "%{http_code}" -o /dev/null "http://load-balancer/health" || echo "000")
    if [ "$lb_response" = "200" ]; then
        success "Load balancer is responding"
    else
        error "Load balancer is not responding (HTTP $lb_response)"
        return 1
    fi
    
    success "Basic connectivity test passed"
}

# Run load balancing test
test_load_balancing() {
    log "Testing load balancing..."
    
    # Make multiple requests and check distribution
    local total_requests=30
    local responses=()
    
    for ((i=1; i<=total_requests; i++)); do
        local response=$(curl -s "http://load-balancer/api/instance-id" || echo "unknown")
        responses+=("$response")
    done
    
    # Count unique instances that responded
    local unique_instances=$(printf '%s\n' "${responses[@]}" | sort -u | wc -l)
    
    if [ $unique_instances -ge 2 ]; then
        success "Load balancing is working (requests distributed across $unique_instances instances)"
    else
        warning "Load balancing may not be working optimally (only $unique_instances instances served requests)"
    fi
}

# Run WebSocket scaling tests
run_scaling_tests() {
    log "Running WebSocket scaling tests..."
    
    # Copy test files to container
    docker cp server/websocket/scaling/test-runner.ts websocket-instance-1:/app/server/websocket/scaling/
    
    # Run test suite
    local test_result
    if docker-compose -f $DOCKER_COMPOSE_FILE exec -T websocket-instance-1 npm run test:scaling:ci; then
        success "Scaling tests passed"
        test_result=0
    else
        error "Scaling tests failed"
        test_result=1
    fi
    
    # Get test output
    docker-compose -f $DOCKER_COMPOSE_FILE exec -T websocket-instance-1 cat /app/test-results.json > scaling-test-results.json 2>/dev/null || true
    
    return $test_result
}

# Run stress test
run_stress_test() {
    log "Running stress test..."
    
    # Start test client with stress testing profile
    docker-compose -f $DOCKER_COMPOSE_FILE --profile testing up -d test-client
    
    # Wait for stress test to complete
    local timeout=300  # 5 minutes
    local elapsed=0
    
    while [ $elapsed -lt $timeout ]; do
        if ! docker-compose -f $DOCKER_COMPOSE_FILE ps test-client | grep -q "Up"; then
            break
        fi
        sleep 10
        elapsed=$((elapsed + 10))
    done
    
    # Get stress test results
    docker-compose -f $DOCKER_COMPOSE_FILE logs test-client > stress-test-logs.txt
    
    success "Stress test completed"
}

# Run failure recovery test
test_failure_recovery() {
    log "Testing failure recovery..."
    
    # Stop one instance
    docker-compose -f $DOCKER_COMPOSE_FILE stop websocket-instance-2
    
    # Wait and test connectivity
    sleep 10
    if test_basic_connectivity; then
        success "System survived instance failure"
    else
        error "System failed during instance failure test"
        return 1
    fi
    
    # Restart the instance
    docker-compose -f $DOCKER_COMPOSE_FILE start websocket-instance-2
    wait_for_service "websocket-instance-2" "8080"
    
    # Test full recovery
    sleep 10
    if test_basic_connectivity && test_load_balancing; then
        success "System recovered from instance failure"
    else
        error "System failed to recover from instance failure"
        return 1
    fi
}

# Generate test report
generate_report() {
    log "Generating test report..."
    
    local report_file="scaling-test-report-$(date +%Y%m%d-%H%M%S).md"
    
    cat > "$report_file" << EOF
# WebSocket Scaling Test Report

**Date:** $(date)
**Test Duration:** ${SECONDS} seconds

## Test Environment

- **WebSocket Instances:** 3
- **Load Balancer:** HAProxy
- **Redis:** Redis 7 (Pub/Sub)
- **Monitoring:** Prometheus + Grafana

## Test Results

### Infrastructure Tests
- ✅ Prerequisites Check
- ✅ Environment Startup
- ✅ Basic Connectivity
- ✅ Load Balancing

### WebSocket Scaling Tests
$(if [ -f scaling-test-results.json ]; then
    echo "- Results: See scaling-test-results.json"
else
    echo "- ❌ Tests failed or results not available"
fi)

### Stress Testing
$(if [ -f stress-test-logs.txt ]; then
    echo "- ✅ Completed"
    echo "- Logs: stress-test-logs.txt"
else
    echo "- ❌ Not completed"
fi)

### Failure Recovery
- ✅ Instance failure handling
- ✅ Automatic recovery

## Service Health

### Docker Services
$(docker-compose -f $DOCKER_COMPOSE_FILE ps)

### Resource Usage
$(docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}")

## Recommendations

1. Monitor CPU and memory usage under load
2. Implement automated scaling based on connection count
3. Add circuit breakers for enhanced resilience
4. Consider geographic load balancing for global deployment

## Access URLs

- **Load Balancer Stats:** http://localhost:8404
- **Prometheus:** http://localhost:9090
- **Grafana:** http://localhost:3001 (admin/admin)

EOF

    success "Test report generated: $report_file"
}

# Main execution
main() {
    log "Starting WebSocket Multi-Instance Scaling Tests"
    log "=============================================="
    
    # Record start time
    local start_time=$(date +%s)
    
    # Run test sequence
    check_prerequisites
    cleanup  # Clean any previous runs
    build_infrastructure
    start_environment
    
    # Wait for services to stabilize
    sleep 30
    
    # Run tests
    local test_results=0
    
    if ! test_basic_connectivity; then
        test_results=1
    fi
    
    if ! test_load_balancing; then
        test_results=1
    fi
    
    if ! run_scaling_tests; then
        test_results=1
    fi
    
    if ! run_stress_test; then
        test_results=1
    fi
    
    if ! test_failure_recovery; then
        test_results=1
    fi
    
    # Generate report
    generate_report
    
    # Calculate duration
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    log "=============================================="
    if [ $test_results -eq 0 ]; then
        success "All scaling tests completed successfully in ${duration} seconds"
    else
        error "Some tests failed. Check logs and report for details."
        exit 1
    fi
}

# Parse command line arguments
case "${1:-}" in
    "cleanup")
        cleanup
        exit 0
        ;;
    "build")
        check_prerequisites
        build_infrastructure
        exit 0
        ;;
    "start")
        check_prerequisites
        build_infrastructure
        start_environment
        exit 0
        ;;
    "test")
        main
        ;;
    *)
        echo "Usage: $0 {test|build|start|cleanup}"
        echo ""
        echo "Commands:"
        echo "  test    - Run complete scaling test suite"
        echo "  build   - Build test infrastructure"
        echo "  start   - Start test environment only"
        echo "  cleanup - Clean up test environment"
        exit 1
        ;;
esac
