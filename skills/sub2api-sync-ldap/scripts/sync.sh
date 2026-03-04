#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
    cat <<'EOF'
Usage:
  bash sync.sh [--publish] [--full-test] [--patch-branch <branch>]

Options:
  --publish               Push feature/ldap-release only when branch actually changed.
  --full-test             Run full backend test suites in contract gate stage.
  --patch-branch <name>   Use specific patch branch (default auto detect).
  -h, --help              Show this help.
EOF
}

PUBLISH=0
FULL_TEST=0
PATCH_BRANCH=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --publish)
            PUBLISH=1
            shift
            ;;
        --full-test)
            FULL_TEST=1
            shift
            ;;
        --patch-branch)
            PATCH_BRANCH="${2:-}"
            if [[ -z "$PATCH_BRANCH" ]]; then
                echo "ERROR: --patch-branch requires a value."
                exit 1
            fi
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "ERROR: unknown argument: $1"
            usage
            exit 1
            ;;
    esac
done

if [[ ! -d backend || ! -f backend/internal/service/auth_service.go ]]; then
    echo "ERROR: run this script in sub2api repository root."
    exit 1
fi

if [[ -n "$(git status --porcelain)" ]]; then
    echo "ERROR: worktree is dirty. Commit or stash changes first."
    exit 1
fi

echo "[1/4] preflight"
if [[ -n "$PATCH_BRANCH" ]]; then
    bash "$SCRIPT_DIR/upstream-preflight.sh" --patch-branch "$PATCH_BRANCH"
else
    bash "$SCRIPT_DIR/upstream-preflight.sh"
fi

echo "[2/4] overlay"
if [[ -n "$PATCH_BRANCH" ]]; then
    bash "$SCRIPT_DIR/overlay-apply.sh" --patch-branch "$PATCH_BRANCH"
else
    bash "$SCRIPT_DIR/overlay-apply.sh"
fi

echo "[3/4] generated repair"
bash "$SCRIPT_DIR/generated-repair.sh"

echo "[4/4] contract gate"
if [[ "$FULL_TEST" -eq 1 ]]; then
    LDAP_SYNC_FULL_TESTS=1 bash "$SCRIPT_DIR/contract-gate.sh"
else
    bash "$SCRIPT_DIR/contract-gate.sh"
fi

if [[ "$PUBLISH" -eq 1 ]]; then
    echo "[publish] feature/ldap-release"
    bash "$SCRIPT_DIR/publish-release.sh"
fi

echo "DONE: LDAP sync workflow completed."
