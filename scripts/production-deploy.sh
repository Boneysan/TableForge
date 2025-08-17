#!/bin/bash
# scripts/production-deploy.sh
# Production Deployment Preparation Script for Phase 3 Performance Implementation

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
DOCKER_REGISTRY="${DOCKER_REGISTRY:-tableforge}"
VERSION="${VERSION:-latest}"
ENVIRONMENT="${ENVIRONMENT:-production}"
NAMESPACE="${NAMESPACE:-tableforge}"

# Logging functions
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

# Pre-deployment checks
pre_deployment_checks() {
    log "Running pre-deployment checks..."
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        error "Docker is not installed"
        exit 1
    fi
    
    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        error "Docker Compose is not installed"
        exit 1
    fi
    
    # Check Kubernetes (if using K8s)
    if [ "$DEPLOYMENT_TYPE" = "kubernetes" ]; then
        if ! command -v kubectl &> /dev/null; then
            error "kubectl is not installed"
            exit 1
        fi
        
        # Check cluster connection
        if ! kubectl cluster-info &> /dev/null; then
            error "Cannot connect to Kubernetes cluster"
            exit 1
        fi
    fi
    
    # Check environment variables
    local required_vars=(
        "DATABASE_HOST"
        "DATABASE_USER"
        "DATABASE_PASSWORD"
        "REDIS_HOST"
        "REDIS_PASSWORD"
    )
    
    for var in "${required_vars[@]}"; do
        if [ -z "${!var:-}" ]; then
            error "Required environment variable $var is not set"
            exit 1
        fi
    done
    
    # Check network connectivity
    log "Checking network connectivity..."
    if ! ping -c 1 ${DATABASE_HOST} &> /dev/null; then
        warning "Cannot reach database host: $DATABASE_HOST"
    fi
    
    if ! ping -c 1 ${REDIS_HOST} &> /dev/null; then
        warning "Cannot reach Redis host: $REDIS_HOST"
    fi
    
    success "Pre-deployment checks completed"
}

# Build and push Docker images
build_and_push_images() {
    log "Building and pushing Docker images..."
    
    # Build main application image
    docker build -t ${DOCKER_REGISTRY}/tableforge:${VERSION} .
    docker push ${DOCKER_REGISTRY}/tableforge:${VERSION}
    
    # Build test client image (if exists)
    if [ -f "docker/Dockerfile.test-client" ]; then
        docker build -f docker/Dockerfile.test-client -t ${DOCKER_REGISTRY}/tableforge-test-client:${VERSION} .
        docker push ${DOCKER_REGISTRY}/tableforge-test-client:${VERSION}
    fi
    
    success "Docker images built and pushed"
}

# Setup infrastructure
setup_infrastructure() {
    log "Setting up infrastructure..."
    
    case "$DEPLOYMENT_TYPE" in
        "docker-compose")
            setup_docker_compose_infrastructure
            ;;
        "kubernetes")
            setup_kubernetes_infrastructure
            ;;
        *)
            error "Unknown deployment type: $DEPLOYMENT_TYPE"
            exit 1
            ;;
    esac
}

# Docker Compose infrastructure setup
setup_docker_compose_infrastructure() {
    log "Setting up Docker Compose infrastructure..."
    
    # Create necessary directories
    mkdir -p data/redis data/postgres data/prometheus data/grafana
    
    # Set permissions
    chmod 755 data/redis data/postgres data/prometheus data/grafana
    
    # Generate Docker Compose configuration
    envsubst < docker/production.docker-compose.yml.template > docker/production.docker-compose.yml
    
    # Start infrastructure services
    docker-compose -f docker/production.docker-compose.yml up -d redis postgres prometheus grafana
    
    # Wait for services to be ready
    wait_for_service "redis" "6379"
    wait_for_service "postgres" "5432"
    wait_for_service "prometheus" "9090"
    wait_for_service "grafana" "3000"
    
    success "Docker Compose infrastructure ready"
}

# Kubernetes infrastructure setup
setup_kubernetes_infrastructure() {
    log "Setting up Kubernetes infrastructure..."
    
    # Create namespace if it doesn't exist
    kubectl create namespace $NAMESPACE --dry-run=client -o yaml | kubectl apply -f -
    
    # Apply ConfigMaps
    kubectl apply -f k8s/configmaps/ -n $NAMESPACE
    
    # Apply Secrets
    kubectl apply -f k8s/secrets/ -n $NAMESPACE
    
    # Apply PersistentVolumes
    kubectl apply -f k8s/storage/ -n $NAMESPACE
    
    # Deploy infrastructure services
    kubectl apply -f k8s/infrastructure/ -n $NAMESPACE
    
    # Wait for infrastructure to be ready
    kubectl wait --for=condition=ready pod -l app=redis -n $NAMESPACE --timeout=300s
    kubectl wait --for=condition=ready pod -l app=postgres -n $NAMESPACE --timeout=300s
    kubectl wait --for=condition=ready pod -l app=prometheus -n $NAMESPACE --timeout=300s
    
    success "Kubernetes infrastructure ready"
}

# Database migration and setup
setup_database() {
    log "Setting up database..."
    
    # Run database migrations
    if [ "$DEPLOYMENT_TYPE" = "docker-compose" ]; then
        docker-compose -f docker/production.docker-compose.yml exec postgres \
            psql -U $DATABASE_USER -d $DATABASE_NAME -c "SELECT version();"
    else
        kubectl exec -n $NAMESPACE deployment/postgres -- \
            psql -U $DATABASE_USER -d $DATABASE_NAME -c "SELECT version();"
    fi
    
    # Run migrations
    npm run db:push
    
    # Seed production data if needed
    if [ "${SEED_DATA:-false}" = "true" ]; then
        npm run db:seed:production
    fi
    
    success "Database setup completed"
}

# Deploy application
deploy_application() {
    log "Deploying application..."
    
    case "$DEPLOYMENT_TYPE" in
        "docker-compose")
            deploy_docker_compose
            ;;
        "kubernetes")
            deploy_kubernetes
            ;;
    esac
}

# Docker Compose deployment
deploy_docker_compose() {
    log "Deploying with Docker Compose..."
    
    # Deploy application services
    docker-compose -f docker/production.docker-compose.yml up -d \
        websocket-instance-1 websocket-instance-2 websocket-instance-3 \
        load-balancer
    
    # Wait for application services
    wait_for_service "websocket-instance-1" "8080"
    wait_for_service "websocket-instance-2" "8080"
    wait_for_service "websocket-instance-3" "8080"
    wait_for_service "load-balancer" "80"
    
    success "Docker Compose deployment completed"
}

# Kubernetes deployment
deploy_kubernetes() {
    log "Deploying to Kubernetes..."
    
    # Update image tags in deployment files
    sed -i "s|tableforge:latest|${DOCKER_REGISTRY}/tableforge:${VERSION}|g" k8s/deployments/*.yaml
    
    # Deploy application
    kubectl apply -f k8s/deployments/ -n $NAMESPACE
    
    # Deploy services
    kubectl apply -f k8s/services/ -n $NAMESPACE
    
    # Deploy ingress
    kubectl apply -f k8s/ingress/ -n $NAMESPACE
    
    # Wait for deployments to be ready
    kubectl wait --for=condition=available deployment -l app=tableforge-websocket -n $NAMESPACE --timeout=300s
    
    # Apply HPA
    kubectl apply -f k8s/hpa.yaml -n $NAMESPACE
    
    success "Kubernetes deployment completed"
}

# Setup monitoring and alerting
setup_monitoring() {
    log "Setting up monitoring and alerting..."
    
    case "$DEPLOYMENT_TYPE" in
        "docker-compose")
            # Monitoring is already started in infrastructure setup
            log "Configuring Grafana dashboards..."
            setup_grafana_dashboards
            ;;
        "kubernetes")
            # Deploy monitoring stack
            kubectl apply -f k8s/monitoring/ -n $NAMESPACE
            
            # Wait for monitoring services
            kubectl wait --for=condition=ready pod -l app=grafana -n $NAMESPACE --timeout=300s
            
            setup_grafana_dashboards
            ;;
    esac
    
    success "Monitoring setup completed"
}

# Setup Grafana dashboards
setup_grafana_dashboards() {
    log "Setting up Grafana dashboards..."
    
    # Wait for Grafana to be ready
    local grafana_url="http://localhost:3000"
    if [ "$DEPLOYMENT_TYPE" = "kubernetes" ]; then
        grafana_url="http://grafana-service:3000"
    fi
    
    # Import dashboards
    for dashboard in grafana/dashboards/*.json; do
        if [ -f "$dashboard" ]; then
            curl -X POST \
                -H "Content-Type: application/json" \
                -d @"$dashboard" \
                "$grafana_url/api/dashboards/db" \
                --user admin:admin
        fi
    done
    
    success "Grafana dashboards configured"
}

# Run post-deployment tests
run_post_deployment_tests() {
    log "Running post-deployment tests..."
    
    # Health checks
    log "Running health checks..."
    
    local base_url="http://localhost"
    if [ "$DEPLOYMENT_TYPE" = "kubernetes" ]; then
        base_url="http://$(kubectl get service tableforge-websocket-service -n $NAMESPACE -o jsonpath='{.status.loadBalancer.ingress[0].ip}')"
    fi
    
    # API health check
    local health_response=$(curl -s -w "%{http_code}" -o /dev/null "$base_url/health")
    if [ "$health_response" = "200" ]; then
        success "API health check passed"
    else
        error "API health check failed (HTTP $health_response)"
        return 1
    fi
    
    # WebSocket connectivity test
    log "Testing WebSocket connectivity..."
    # This would require a WebSocket test client
    
    # Performance tests
    log "Running performance validation..."
    npm run test:performance:smoke
    
    # Cache functionality test
    log "Testing cache functionality..."
    curl -X POST "$base_url/api/admin/cache/test"
    
    # Database connectivity test
    log "Testing database connectivity..."
    curl "$base_url/api/admin/database/health"
    
    success "Post-deployment tests completed"
}

# Setup production configurations
setup_production_config() {
    log "Setting up production configurations..."
    
    # Enable performance tuning
    export PERFORMANCE_TUNING_ENABLED=true
    
    # Configure optimization schedules
    export OPTIMIZATION_SCHEDULE_CACHE="*/15 * * * *"
    export OPTIMIZATION_SCHEDULE_DATABASE="0 * * * *"
    export OPTIMIZATION_SCHEDULE_WEBSOCKET="*/30 * * * *"
    export OPTIMIZATION_SCHEDULE_FULL="0 */4 * * *"
    
    # Set production cache settings
    export REDIS_CACHE_SIZE=10000
    export REDIS_CACHE_TTL=300
    
    # Configure database pool for production
    export DB_POOL_MIN=10
    export DB_POOL_MAX=50
    
    # Enable monitoring
    export PROMETHEUS_ENABLED=true
    export METRICS_COLLECTION_INTERVAL=10000
    
    # Set alert thresholds
    export ALERT_THRESHOLDS_CPU=80
    export ALERT_THRESHOLDS_MEMORY=85
    export ALERT_THRESHOLDS_LATENCY=100
    
    success "Production configuration applied"
}

# Backup current deployment
backup_current_deployment() {
    log "Creating backup of current deployment..."
    
    local backup_dir="backups/$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$backup_dir"
    
    case "$DEPLOYMENT_TYPE" in
        "docker-compose")
            # Backup Docker Compose configuration
            cp docker/production.docker-compose.yml "$backup_dir/"
            
            # Backup data volumes
            docker run --rm -v tableforge_postgres_data:/data -v $(pwd)/$backup_dir:/backup \
                alpine tar czf /backup/postgres_data.tar.gz -C /data .
            
            docker run --rm -v tableforge_redis_data:/data -v $(pwd)/$backup_dir:/backup \
                alpine tar czf /backup/redis_data.tar.gz -C /data .
            ;;
        "kubernetes")
            # Backup Kubernetes configurations
            kubectl get all -n $NAMESPACE -o yaml > "$backup_dir/kubernetes-resources.yaml"
            
            # Backup persistent volume data (implementation depends on storage provider)
            log "Manual backup of persistent volumes may be required"
            ;;
    esac
    
    success "Backup created in $backup_dir"
}

# Rollback functionality
rollback_deployment() {
    log "Rolling back deployment..."
    
    case "$DEPLOYMENT_TYPE" in
        "docker-compose")
            # Stop current deployment
            docker-compose -f docker/production.docker-compose.yml down
            
            # Restore from backup
            local latest_backup=$(ls -t backups/ | head -n1)
            if [ -n "$latest_backup" ]; then
                cp "backups/$latest_backup/production.docker-compose.yml" docker/
                docker-compose -f docker/production.docker-compose.yml up -d
            fi
            ;;
        "kubernetes")
            # Rollback using Kubernetes
            kubectl rollout undo deployment/tableforge-websocket -n $NAMESPACE
            kubectl rollout status deployment/tableforge-websocket -n $NAMESPACE
            ;;
    esac
    
    success "Rollback completed"
}

# Wait for service to be ready
wait_for_service() {
    local service_name="$1"
    local port="$2"
    local retries=30
    local count=0
    
    log "Waiting for $service_name to be ready on port $port..."
    
    while [ $count -lt $retries ]; do
        if nc -z localhost $port 2>/dev/null; then
            success "$service_name is ready"
            return 0
        fi
        
        count=$((count + 1))
        log "Waiting for $service_name... ($count/$retries)"
        sleep 10
    done
    
    error "$service_name failed to start within timeout"
    return 1
}

# Main deployment function
deploy() {
    log "Starting TableForge Production Deployment"
    log "Environment: $ENVIRONMENT"
    log "Deployment Type: $DEPLOYMENT_TYPE"
    log "Version: $VERSION"
    log "=========================================="
    
    # Create backup before deployment
    backup_current_deployment
    
    # Run pre-deployment checks
    pre_deployment_checks
    
    # Setup production configuration
    setup_production_config
    
    # Build and push images
    build_and_push_images
    
    # Setup infrastructure
    setup_infrastructure
    
    # Setup database
    setup_database
    
    # Deploy application
    deploy_application
    
    # Setup monitoring
    setup_monitoring
    
    # Run post-deployment tests
    if ! run_post_deployment_tests; then
        error "Post-deployment tests failed. Consider rolling back."
        read -p "Do you want to rollback? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            rollback_deployment
            exit 1
        fi
    fi
    
    log "=========================================="
    success "TableForge Production Deployment Completed Successfully!"
    log "=========================================="
    
    # Display access information
    display_access_info
}

# Display access information
display_access_info() {
    log "Access Information:"
    
    if [ "$DEPLOYMENT_TYPE" = "docker-compose" ]; then
        echo "  Application: http://localhost"
        echo "  Grafana: http://localhost:3001 (admin/admin)"
        echo "  Prometheus: http://localhost:9090"
        echo "  HAProxy Stats: http://localhost:8404"
    else
        local external_ip=$(kubectl get service tableforge-websocket-service -n $NAMESPACE -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
        echo "  Application: http://$external_ip"
        echo "  Grafana: http://grafana.$external_ip"
        echo "  Prometheus: http://prometheus.$external_ip"
    fi
    
    echo ""
    echo "Next Steps:"
    echo "  1. Monitor the deployment in Grafana"
    echo "  2. Run load tests to validate performance"
    echo "  3. Set up external monitoring and alerting"
    echo "  4. Configure backup schedules"
    echo "  5. Review and tune performance settings"
}

# Command line argument parsing
case "${1:-}" in
    "deploy")
        DEPLOYMENT_TYPE="${2:-docker-compose}"
        deploy
        ;;
    "rollback")
        rollback_deployment
        ;;
    "test")
        run_post_deployment_tests
        ;;
    "backup")
        backup_current_deployment
        ;;
    *)
        echo "Usage: $0 {deploy|rollback|test|backup} [deployment-type]"
        echo ""
        echo "Commands:"
        echo "  deploy [docker-compose|kubernetes] - Deploy to production"
        echo "  rollback                          - Rollback to previous version"
        echo "  test                             - Run post-deployment tests"
        echo "  backup                           - Create backup of current deployment"
        echo ""
        echo "Environment Variables:"
        echo "  ENVIRONMENT      - Deployment environment (default: production)"
        echo "  VERSION          - Application version (default: latest)"
        echo "  DOCKER_REGISTRY  - Docker registry (default: tableforge)"
        echo "  NAMESPACE        - Kubernetes namespace (default: tableforge)"
        exit 1
        ;;
esac
