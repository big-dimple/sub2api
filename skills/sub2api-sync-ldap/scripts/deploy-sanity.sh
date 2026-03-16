#!/usr/bin/env bash

set -euo pipefail

if [[ ! -f deploy/docker-compose.yml ]]; then
    echo "ERROR: run this script in sub2api repository root."
    exit 1
fi

fail() {
    echo "ERROR: $1"
    exit 1
}

check_compose_file() {
    local file="$1"
    [[ -f "$file" ]] || fail "missing file: $file"

    rg -q "DATA_DIR=/app/data" "$file" || fail "$file missing DATA_DIR=/app/data"
    rg -q 'healthcheck:' "$file" || fail "$file missing healthcheck block"
    rg -q 'CMD-SHELL' "$file" || fail "$file healthcheck is not CMD-SHELL"
    rg -q 'wget -q -T 5 -O /dev/null http://localhost:8080/health' "$file" || fail "$file healthcheck missing wget probe"
    rg -q 'curl -fsS http://localhost:8080/health' "$file" || fail "$file healthcheck missing curl fallback"
}

echo "Sanity: compose files"
check_compose_file "deploy/docker-compose.yml"
check_compose_file "deploy/docker-compose.local.yml"
check_compose_file "deploy/docker-compose.standalone.yml"

echo "Sanity: dockerfiles"
rg -q 'HEALTHCHECK .*' Dockerfile || fail "Dockerfile missing HEALTHCHECK"
rg -q 'wget -q -T 5 -O /dev/null http://localhost:\$\{SERVER_PORT:-8080\}/health' Dockerfile || fail "Dockerfile healthcheck not using wget"
rg -q 'wget -q -T 5 -O /dev/null http://localhost:\$\{SERVER_PORT:-8080\}/health' deploy/Dockerfile || fail "deploy/Dockerfile healthcheck not using wget"

echo "Sanity: setup docker data dir logic"
rg -q 'if isContainerRuntime\(\)' backend/internal/setup/setup.go || fail "setup.go missing container runtime branch"
rg -q 'is not writable in container runtime' backend/internal/setup/setup.go || fail "setup.go missing clear /app/data permission error"

echo "Sanity: deploy script hardening"
rg -q 'init_directory_permissions\(\)' deploy/docker-deploy.sh || fail "docker-deploy.sh missing init_directory_permissions"
rg -q 'chown -R 1000:1000 data' deploy/docker-deploy.sh || fail "docker-deploy.sh missing data ownership fix"
rg -q 'generate_admin_password\(\)' deploy/docker-deploy.sh || fail "docker-deploy.sh missing admin password generation"
rg -q '\^ADMIN_PASSWORD=' deploy/docker-deploy.sh || fail "docker-deploy.sh missing ADMIN_PASSWORD write-back"
rg -q 'run_self_check_snapshot\(\)' deploy/docker-deploy.sh || fail "docker-deploy.sh missing self-check snapshot"

echo "Sanity: deploy docs"
[[ -f deploy/README_LDAP_ENTERPRISE.md ]] || fail "missing deploy/README_LDAP_ENTERPRISE.md"
rg -q 'sudo chown -R 1000:1000 data' deploy/README.md || fail "deploy/README.md missing data permission guidance"

echo "OK: deploy sanity checks passed."
