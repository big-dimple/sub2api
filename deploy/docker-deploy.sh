#!/bin/bash
# =============================================================================
# Sub2API Docker Deployment Preparation Script
# =============================================================================
# This script prepares deployment files for Sub2API:
#   - Downloads docker-compose.local.yml and .env.example
#   - Downloads upgrade_main.sh for future upgrades
#   - Generates secure secrets (JWT_SECRET, TOTP_ENCRYPTION_KEY, POSTGRES_PASSWORD)
#   - Creates necessary data directories
#
# After running this script, you can start services with:
#   docker-compose up -d
# =============================================================================

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# GitHub raw content base URL
GITHUB_RAW_URL="https://raw.githubusercontent.com/big-dimple/sub2api/main/deploy"

# Print colored message
print_info() {
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

# Generate random secret
generate_secret() {
    openssl rand -hex 32
}

generate_admin_password() {
    openssl rand -base64 24 | tr -d '/+=' | cut -c1-20
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

init_directory_permissions() {
    chmod 775 data postgres_data redis_data 2>/dev/null || true

    if [ "$(id -u)" -eq 0 ]; then
        # sub2api app runs as 1000:1000
        chown -R 1000:1000 data || true
        # postgres:18-alpine default uid/gid
        chown -R 70:70 postgres_data || true
        # redis:8-alpine commonly runs as uid 999
        chown -R 999:1000 redis_data || true
        print_success "Initialized data directory ownership for container users"
    else
        print_warning "Running as non-root; skipped chown. If startup fails, fix directory ownership manually."
    fi
}

run_self_check_snapshot() {
    print_info "Running post-script self-check snapshot..."

    if ! command_exists docker; then
        print_warning "docker command not found; skipping self-check."
        return 0
    fi

    if docker compose -f docker-compose.local.yml ps >/tmp/sub2api-compose-ps.log 2>&1; then
        cat /tmp/sub2api-compose-ps.log
    else
        print_warning "docker compose ps failed (containers may not be started yet)."
        cat /tmp/sub2api-compose-ps.log || true
    fi

    if docker compose -f docker-compose.local.yml logs --tail=120 sub2api >/tmp/sub2api-compose-logs.log 2>&1; then
        cat /tmp/sub2api-compose-logs.log
    else
        print_warning "docker compose logs failed (sub2api may not be running yet)."
        cat /tmp/sub2api-compose-logs.log || true
    fi

    if grep -Eqi "permission denied|/app/data.*(read-only|not writable)|open /app/data/config\\.yaml" /tmp/sub2api-compose-logs.log 2>/dev/null; then
        print_warning "Detected possible data directory permission issue. Ensure data is writable by uid=1000."
    fi
    if grep -Eqi "curl: not found|wget: not found|healthcheck.*not found" /tmp/sub2api-compose-logs.log 2>/dev/null; then
        print_warning "Detected possible healthcheck command mismatch. Check image and compose healthcheck command consistency."
    fi

    rm -f /tmp/sub2api-compose-ps.log /tmp/sub2api-compose-logs.log
}

# Main installation function
main() {
    echo ""
    echo "=========================================="
    echo "  Sub2API Deployment Preparation"
    echo "=========================================="
    echo ""

    # Check if openssl is available
    if ! command_exists openssl; then
        print_error "openssl is not installed. Please install openssl first."
        exit 1
    fi

    # Check if deployment already exists
    if [ -f "docker-compose.yml" ] && [ -f ".env" ]; then
        print_warning "Deployment files already exist in current directory."
        read -p "Overwrite existing files? (y/N): " -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_info "Cancelled."
            exit 0
        fi
    fi

    # Download docker-compose.local.yml and save as docker-compose.yml
    print_info "Downloading docker-compose.yml..."
    if command_exists curl; then
        curl -sSL "${GITHUB_RAW_URL}/docker-compose.local.yml" -o docker-compose.yml
    elif command_exists wget; then
        wget -q "${GITHUB_RAW_URL}/docker-compose.local.yml" -O docker-compose.yml
    else
        print_error "Neither curl nor wget is installed. Please install one of them."
        exit 1
    fi
    print_success "Downloaded docker-compose.yml"

    # Download .env.example
    print_info "Downloading .env.example..."
    if command_exists curl; then
        curl -sSL "${GITHUB_RAW_URL}/.env.example" -o .env.example
    else
        wget -q "${GITHUB_RAW_URL}/.env.example" -O .env.example
    fi
    print_success "Downloaded .env.example"

    # Download upgrade_main.sh
    print_info "Downloading upgrade_main.sh..."
    if command_exists curl; then
        curl -sSL "${GITHUB_RAW_URL}/upgrade_main.sh" -o upgrade_main.sh
    else
        wget -q "${GITHUB_RAW_URL}/upgrade_main.sh" -O upgrade_main.sh
    fi
    chmod +x upgrade_main.sh
    print_success "Downloaded upgrade_main.sh"

    # Generate .env file with auto-generated secrets
    print_info "Generating secure secrets..."
    echo ""

    # Generate secrets
    JWT_SECRET=$(generate_secret)
    TOTP_ENCRYPTION_KEY=$(generate_secret)
    POSTGRES_PASSWORD=$(generate_secret)
    ADMIN_PASSWORD=$(generate_admin_password)

    # Create .env from .env.example
    cp .env.example .env

    # Update .env with generated secrets (cross-platform compatible)
    if sed --version >/dev/null 2>&1; then
        # GNU sed (Linux)
        sed -i "s/^JWT_SECRET=.*/JWT_SECRET=${JWT_SECRET}/" .env
        sed -i "s/^TOTP_ENCRYPTION_KEY=.*/TOTP_ENCRYPTION_KEY=${TOTP_ENCRYPTION_KEY}/" .env
        sed -i "s/^POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=${POSTGRES_PASSWORD}/" .env
        sed -i "s/^ADMIN_PASSWORD=.*/ADMIN_PASSWORD=${ADMIN_PASSWORD}/" .env
    else
        # BSD sed (macOS)
        sed -i '' "s/^JWT_SECRET=.*/JWT_SECRET=${JWT_SECRET}/" .env
        sed -i '' "s/^TOTP_ENCRYPTION_KEY=.*/TOTP_ENCRYPTION_KEY=${TOTP_ENCRYPTION_KEY}/" .env
        sed -i '' "s/^POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=${POSTGRES_PASSWORD}/" .env
        sed -i '' "s/^ADMIN_PASSWORD=.*/ADMIN_PASSWORD=${ADMIN_PASSWORD}/" .env
    fi
    if ! grep -q "^ADMIN_PASSWORD=" .env; then
        echo "ADMIN_PASSWORD=${ADMIN_PASSWORD}" >> .env
    fi

    # Create data directories
    print_info "Creating data directories..."
    mkdir -p data postgres_data redis_data
    init_directory_permissions
    print_success "Created data directories"

    # Set secure permissions for .env file (readable/writable only by owner)
    chmod 600 .env
    echo ""

    # Display completion message
    echo "=========================================="
    echo "  Preparation Complete!"
    echo "=========================================="
    echo ""
    echo "Generated secure credentials:"
    echo "  POSTGRES_PASSWORD:     ${POSTGRES_PASSWORD}"
    echo "  JWT_SECRET:            ${JWT_SECRET}"
    echo "  TOTP_ENCRYPTION_KEY:   ${TOTP_ENCRYPTION_KEY}"
    echo "  ADMIN_PASSWORD:        ${ADMIN_PASSWORD}"
    echo ""
    print_warning "These credentials have been saved to .env file."
    print_warning "Please keep them secure and do not share publicly!"
    echo ""
    echo "Directory structure:"
    echo "  docker-compose.yml        - Docker Compose configuration"
    echo "  .env                      - Environment variables (generated secrets)"
    echo "  .env.example              - Example template (for reference)"
    echo "  upgrade_main.sh           - Safe upgrade / restore script"
    echo "  data/                     - Application data (will be created on first run)"
    echo "  postgres_data/            - PostgreSQL data"
    echo "  redis_data/               - Redis data"
    echo ""
    echo "Next steps:"
    echo "  1. (Optional) Edit .env to customize configuration"
    echo "  2. Start services:"
    echo "     docker-compose up -d"
    echo ""
    echo "  3. Future upgrades:"
    echo "     bash upgrade_main.sh"
    echo ""
    echo "  4. View logs:"
    echo "     docker-compose logs -f sub2api"
    echo ""
    echo "  5. Access Web UI:"
    echo "     http://localhost:8080"
    echo ""
    print_info "Admin password has been written into .env as ADMIN_PASSWORD."
    print_info "You can login directly with ADMIN_EMAIL/ADMIN_PASSWORD after startup."
    echo ""

    run_self_check_snapshot
}

# Run main function
main "$@"
