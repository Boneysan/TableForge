#!/bin/bash

# Vorpal Board Demo Data Seeder
# Creates comprehensive demo data for instant smoke-testing

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${PURPLE}$1${NC}"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

main() {
    print_header "🎲 Vorpal Board Demo Data Seeder"
    print_header "═══════════════════════════════════════════════════════════════"
    echo ""

    # Check if database URL is available
    if [ -z "$DATABASE_URL" ]; then
        print_error "DATABASE_URL environment variable is not set"
        print_info "Please ensure your .env file is configured with a valid database connection"
        exit 1
    fi

    # Check if tsx is available (for TypeScript execution)
    if ! command -v npx &> /dev/null; then
        print_error "npx is not available. Please ensure Node.js and npm are installed."
        exit 1
    fi

    print_info "Database URL is configured"
    print_info "Preparing to create comprehensive demo data..."
    echo ""

    # Run the TypeScript seeding script
    print_info "Executing seed script..."
    echo ""
    
    if npx tsx scripts/seed.ts; then
        echo ""
        print_success "Demo data created successfully!"
        
        # Summary of what was created
        print_header "📊 Demo Environment Ready!"
        print_header "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo -e "${CYAN}🎮 Game Systems:${NC} D&D 5e + Poker"
        echo -e "${CYAN}👥 Users:${NC} 1 Game Master + 3 Players"
        echo -e "${CYAN}🏠 Active Rooms:${NC} 3 (Tavern Brawl, Dragon Lair, Poker Night)"
        echo -e "${CYAN}🎨 Assets:${NC} Tokens, Maps, Cards, Chips"
        echo -e "${CYAN}🃏 Card Decks:${NC} Spell Cards + Poker Deck"
        echo -e "${CYAN}🗺️  Board Setup:${NC} Pre-positioned tokens"
        echo -e "${CYAN}💬 Chat History:${NC} Sample conversations"
        print_header "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""

        print_header "🚀 Quick Test Instructions:"
        echo -e "${GREEN}1.${NC} Start server: ${BLUE}npm run dev${NC}"
        echo -e "${GREEN}2.${NC} Open: ${BLUE}http://localhost:5000${NC}"
        echo -e "${GREEN}3.${NC} Browse public rooms"
        echo -e "${GREEN}4.${NC} Join 'The Tavern Brawl' for D&D testing"
        echo -e "${GREEN}5.${NC} Test token movement, chat, dice rolling"
        echo -e "${GREEN}6.${NC} Try 'Dragon's Lair' for boss battle mechanics"
        echo ""

        print_header "📧 Demo Accounts:"
        echo -e "${CYAN}Game Master:${NC} demo-gm@vorpalboard.local"
        echo -e "${CYAN}Players:${NC}"
        echo -e "  • demo-alice@vorpalboard.local (Alice Adventurer)"
        echo -e "  • demo-bob@vorpalboard.local (Bob Warrior)"
        echo -e "  • demo-carol@vorpalboard.local (Carol Mage)"
        echo ""

        print_header "🎯 Testing Scenarios:"
        echo -e "${GREEN}🐉 The Tavern Brawl${NC} - Basic combat and character interactions"
        echo -e "${GREEN}🔥 Dragon's Lair${NC} - Epic boss battle with special abilities" 
        echo -e "${GREEN}🃏 Poker Night${NC} - Card game mechanics and player interactions"
        echo ""

        print_success "Demo environment is ready for comprehensive testing!"
        
    else
        echo ""
        print_error "Failed to create demo data"
        print_info "Check the error messages above for details"
        print_info "Common issues:"
        echo "  • Database connection problems"
        echo "  • Missing environment variables"
        echo "  • Database schema not up to date (run 'npm run db:push')"
        exit 1
    fi
}

# Show help if requested
if [[ "$1" == "--help" || "$1" == "-h" ]]; then
    echo "Vorpal Board Demo Data Seeder"
    echo ""
    echo "Usage: $0"
    echo ""
    echo "This script creates comprehensive demo data for testing:"
    echo "  • Demo users (GM and players)"
    echo "  • Game systems (D&D 5e and Poker)"
    echo "  • Game assets (tokens, maps, cards)"
    echo "  • Active rooms with pre-positioned pieces"
    echo "  • Sample chat conversations"
    echo ""
    echo "Requirements:"
    echo "  • DATABASE_URL environment variable"
    echo "  • Node.js and npm installed"
    echo "  • Database schema up to date"
    echo ""
    echo "Environment:"
    echo "  DATABASE_URL - PostgreSQL connection string"
    echo ""
    echo "Example:"
    echo "  export DATABASE_URL='postgresql://user:pass@localhost/db'"
    echo "  $0"
    echo ""
    exit 0
fi

# Run main function
main "$@"