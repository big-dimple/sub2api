#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
    cat <<'EOF'
Usage:
  bash sync.sh [--publish] [--full-test] [--patch-branch <branch>] [--backfill-branch <branch>] [--no-backfill] [--skip-deploy-sanity]

Options:
  --publish               Push main (and backfill branch) only when actually changed.
  --full-test             Run full backend test suites in contract gate stage.
  --patch-branch <name>   Use specific patch branch (default auto detect).
  --backfill-branch <name>  Target branch for backfill (default: patch branch or feature/ldap-support).
  --no-backfill           Disable automatic backfill.
  --skip-deploy-sanity    Skip deploy consistency checks.
  -h, --help              Show this help.
EOF
}

PUBLISH=0
FULL_TEST=0
PATCH_BRANCH=""
BACKFILL_BRANCH=""
DO_BACKFILL=1
DO_DEPLOY_SANITY=1

commit_generated_artifacts() {
    if [[ -z "$(git status --porcelain)" ]]; then
        echo "OK: no generated sync artifacts to commit."
        return 0
    fi

    git add -A
    git commit -m "chore(ldap): regenerate sync artifacts" >/dev/null
    echo "OK: committed generated sync artifacts."
}

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
        --backfill-branch)
            BACKFILL_BRANCH="${2:-}"
            if [[ -z "$BACKFILL_BRANCH" ]]; then
                echo "ERROR: --backfill-branch requires a value."
                exit 1
            fi
            shift 2
            ;;
        --no-backfill)
            DO_BACKFILL=0
            shift
            ;;
        --skip-deploy-sanity)
            DO_DEPLOY_SANITY=0
            shift
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

if [[ -z "$BACKFILL_BRANCH" ]]; then
    if [[ -n "$PATCH_BRANCH" ]]; then
        BACKFILL_BRANCH="$PATCH_BRANCH"
    else
        BACKFILL_BRANCH="feature/ldap-support"
    fi
fi

TOTAL_STEPS=4
if [[ "$DO_DEPLOY_SANITY" -eq 1 ]]; then
    TOTAL_STEPS=$((TOTAL_STEPS + 1))
fi
if [[ "$DO_BACKFILL" -eq 1 ]]; then
    TOTAL_STEPS=$((TOTAL_STEPS + 1))
fi
STEP=1

echo "[${STEP}/${TOTAL_STEPS}] preflight"
if [[ -n "$PATCH_BRANCH" ]]; then
    bash "$SCRIPT_DIR/upstream-preflight.sh" --patch-branch "$PATCH_BRANCH"
else
    bash "$SCRIPT_DIR/upstream-preflight.sh"
fi
STEP=$((STEP + 1))

echo "[${STEP}/${TOTAL_STEPS}] overlay"
if [[ -n "$PATCH_BRANCH" ]]; then
    bash "$SCRIPT_DIR/overlay-apply.sh" --patch-branch "$PATCH_BRANCH"
else
    bash "$SCRIPT_DIR/overlay-apply.sh"
fi
STEP=$((STEP + 1))

echo "[${STEP}/${TOTAL_STEPS}] generated repair"
bash "$SCRIPT_DIR/generated-repair.sh"
STEP=$((STEP + 1))

echo "[${STEP}/${TOTAL_STEPS}] contract gate"
if [[ "$FULL_TEST" -eq 1 ]]; then
    LDAP_SYNC_FULL_TESTS=1 bash "$SCRIPT_DIR/contract-gate.sh"
else
    bash "$SCRIPT_DIR/contract-gate.sh"
fi
STEP=$((STEP + 1))

if [[ "$DO_DEPLOY_SANITY" -eq 1 ]]; then
    echo "[${STEP}/${TOTAL_STEPS}] deploy sanity"
    bash "$SCRIPT_DIR/deploy-sanity.sh"
    STEP=$((STEP + 1))
fi

echo "[sync] finalize generated artifacts"
commit_generated_artifacts

if [[ "$DO_BACKFILL" -eq 1 ]]; then
    echo "[${STEP}/${TOTAL_STEPS}] backfill patch source branch (${BACKFILL_BRANCH})"
    bash "$SCRIPT_DIR/backfill-support.sh" --release-branch main --support-branch "$BACKFILL_BRANCH"
fi

if [[ "$PUBLISH" -eq 1 ]]; then
    echo "[publish] main"
    bash "$SCRIPT_DIR/publish-release.sh" --release-branch main --also-branch "$BACKFILL_BRANCH"
fi

echo "DONE: LDAP sync workflow completed."
