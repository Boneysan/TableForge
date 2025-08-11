#!/bin/bash

# Vorpal Board Development Setup Script
# This script sets up the complete development environment

set -e  # Exit on any error

echo "🎲 Vorpal Board Development Setup"
echo "=================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if we're in the right directory
if [ ! -f "package.json" ]; then
    print_error "package.json not found. Please run this script from the project root directory."
    exit 1
fi

# Check Node.js version
print_status "Checking Node.js version..."
if ! command -v node &> /dev/null; then
    print_error "Node.js is not installed. Please install Node.js 18+ first."
    exit 1
fi

NODE_VERSION=$(node --version | cut -c2-)
REQUIRED_VERSION="18.0.0"

# Simple version comparison (works for major versions)
NODE_MAJOR=$(echo $NODE_VERSION | cut -d. -f1)
if [ "$NODE_MAJOR" -lt 18 ]; then
    print_error "Node.js version $NODE_VERSION found. Required: 18+. Please upgrade Node.js."
    exit 1
fi

print_success "Node.js version $NODE_VERSION is compatible"

# Check if npm is available
print_status "Checking npm..."
if ! command -v npm &> /dev/null; then
    print_error "npm is not installed. Please install npm first."
    exit 1
fi

print_success "npm is available"

# Install dependencies
print_status "Installing dependencies..."
if ! npm install; then
    print_error "Failed to install dependencies"
    exit 1
fi

print_success "Dependencies installed successfully"

# Check for required environment files
print_status "Checking environment configuration..."

if [ ! -f ".env" ]; then
    if [ -f ".env.example" ]; then
        print_warning ".env file not found. Creating from .env.example..."
        cp .env.example .env
        print_status "Please edit .env file with your configuration"
    else
        print_warning "No .env file found. You may need to create one for database and Firebase configuration."
    fi
else
    print_success ".env file exists"
fi

# Database setup check
print_status "Checking database configuration..."

if [ -z "${DATABASE_URL:-}" ]; then
    if grep -q "DATABASE_URL" .env 2>/dev/null; then
        print_success "DATABASE_URL found in .env file"
    else
        print_warning "DATABASE_URL not configured. Database operations may fail."
        echo "Please set DATABASE_URL in your .env file or environment variables."
    fi
else
    print_success "DATABASE_URL is configured"
fi

# Firebase configuration check
print_status "Checking Firebase configuration..."

FIREBASE_VARS=("VITE_FIREBASE_API_KEY" "VITE_FIREBASE_PROJECT_ID" "VITE_FIREBASE_APP_ID")
MISSING_FIREBASE=()

for var in "${FIREBASE_VARS[@]}"; do
    if [ -z "${!var:-}" ] && ! grep -q "^$var=" .env 2>/dev/null; then
        MISSING_FIREBASE+=("$var")
    fi
done

if [ ${#MISSING_FIREBASE[@]} -eq 0 ]; then
    print_success "Firebase configuration appears complete"
else
    print_warning "Missing Firebase configuration variables:"
    for var in "${MISSING_FIREBASE[@]}"; do
        echo "  - $var"
    done
    echo "Please configure Firebase variables in your .env file."
fi

# Run database migrations if available
print_status "Setting up database..."

if npm run --silent db:push > /dev/null 2>&1; then
    print_success "Database schema updated successfully"
elif command -v npx &> /dev/null && npx drizzle-kit --version > /dev/null 2>&1; then
    print_status "Running database migrations..."
    if npx drizzle-kit push:pg; then
        print_success "Database migrations completed"
    else
        print_warning "Database migrations failed. Check your DATABASE_URL configuration."
    fi
else
    print_warning "Could not run database setup. Please ensure DATABASE_URL is configured."
fi

# Build TypeScript if needed
print_status "Checking TypeScript build..."

if npm run build > /dev/null 2>&1; then
    print_success "TypeScript build successful"
else
    print_warning "TypeScript build failed. You may have type errors to fix."
fi

# Create necessary directories
print_status "Creating necessary directories..."

DIRS=("logs" "uploads" "temp" "backups")
for dir in "${DIRS[@]}"; do
    if [ ! -d "$dir" ]; then
        mkdir -p "$dir"
        print_status "Created directory: $dir"
    fi
done

# Setup git hooks if husky is available
if [ -f ".husky/pre-commit" ]; then
    print_status "Git hooks are already configured"
elif command -v npx &> /dev/null && npm list husky > /dev/null 2>&1; then
    print_status "Setting up git hooks..."
    npx husky install > /dev/null 2>&1 || print_warning "Could not setup husky git hooks"
fi

# Health check
print_status "Running health checks..."

# Check if server starts without errors
print_status "Testing server startup..."
if timeout 10s npm run build > /dev/null 2>&1; then
    print_success "Server build check passed"
else
    print_warning "Server build check failed or timed out"
fi

echo ""
print_success "Development setup complete!"
echo ""
echo "🚀 Next Steps:"
echo "=============="
echo ""
echo "1. Configure your environment variables in .env file:"
echo "   - DATABASE_URL (PostgreSQL connection string)"
echo "   - Firebase configuration variables"
echo "   - Object storage credentials (if using file uploads)"
echo ""
echo "2. Start development services (optional):"
echo "   docker-compose up -d    # PostgreSQL + MinIO + Adminer"
echo ""
echo "3. Seed demo data:"
echo "   npx tsx scripts/seed.ts # Creates demo game systems and data"
echo ""
echo "4. Start the development server:"
echo "   npm run dev"
echo ""
echo "5. Visit the application:"
echo "   - Web app: http://localhost:5000"
echo "   - API docs: http://localhost:5000/docs"
echo "   - Health check: http://localhost:5000/api/observability/status"
echo ""
echo "6. Optional local services (via Docker):"
echo "   - PostgreSQL: localhost:5432 (postgres/postgres)"
echo "   - MinIO S3: localhost:9000 (minioadmin/minioadmin123)"
echo "   - MinIO Console: http://localhost:9001"
echo "   - Database UI: http://localhost:8080"
echo ""

# Provide additional guidance based on environment
if [ -n "${REPL_ID:-}" ]; then
    echo "📝 Replit Environment Detected:"
    echo "   - Your app will be available at: https://$REPL_ID.replit.dev"
    echo "   - Database should be automatically configured"
    echo "   - Use Replit's secret management for sensitive variables"
    echo ""
fi

echo "📚 Documentation:"
echo "   - README.md - General information and setup"
echo "   - OBSERVABILITY.md - Monitoring and metrics guide"
echo "   - IMPLEMENTATION_SUMMARY.md - Technical details"
echo "   - API docs at /docs once server is running"
echo ""

echo "❓ Need help?"
echo "   - Check the logs for any error messages"
echo "   - Ensure all environment variables are configured"
echo "   - Visit /docs for API documentation"
echo "   - Check /api/observability/status for system health"
echo ""

print_success "Happy coding! 🎉"