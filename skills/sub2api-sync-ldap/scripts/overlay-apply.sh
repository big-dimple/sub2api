#!/usr/bin/env bash

set -euo pipefail

if [[ ! -f backend/internal/service/auth_service.go ]]; then
    echo "ERROR: run this script in sub2api repository root."
    exit 1
fi

if [[ -n "$(git status --porcelain)" ]]; then
    echo "ERROR: worktree is dirty. Commit or stash changes first."
    exit 1
fi

PATCH_BRANCH=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --patch-branch)
            PATCH_BRANCH="${2:-}"
            [[ -n "$PATCH_BRANCH" ]] || { echo "ERROR: --patch-branch requires value."; exit 1; }
            shift 2
            ;;
        *)
            echo "ERROR: unknown argument: $1"
            exit 1
            ;;
    esac
done

if [[ -z "$PATCH_BRANCH" ]]; then
    if git show-ref --verify --quiet refs/heads/feature/ldap-patch; then
        PATCH_BRANCH="feature/ldap-patch"
    else
        PATCH_BRANCH="feature/ldap-support"
    fi
fi

if ! git show-ref --verify --quiet "refs/heads/${PATCH_BRANCH}"; then
    echo "ERROR: patch branch not found: ${PATCH_BRANCH}"
    exit 1
fi

if ! git remote | grep -qx upstream; then
    git remote add upstream https://github.com/Wei-Shaw/sub2api.git
fi

echo "Fetch upstream/main..."
if ! git fetch upstream main --quiet; then
    echo "ERROR: failed to fetch upstream/main."
    exit 1
fi
git branch -f upstream-mirror upstream/main >/dev/null

echo "Fetch origin/feature/ldap-release (optional)..."
git fetch origin feature/ldap-release:refs/remotes/origin/feature/ldap-release >/dev/null 2>&1 || true

UPSTREAM_SHA="$(git rev-parse upstream-mirror)"
PATCH_SHA="$(git rev-parse "${PATCH_BRANCH}")"

if git show-ref --verify --quiet refs/remotes/origin/feature/ldap-release; then
    ORIGIN_RELEASE="origin/feature/ldap-release"
    ORIGIN_P1="$(git rev-parse "${ORIGIN_RELEASE}^1" 2>/dev/null || true)"
    ORIGIN_P2="$(git rev-parse "${ORIGIN_RELEASE}^2" 2>/dev/null || true)"
    if [[ "$ORIGIN_P1" == "$UPSTREAM_SHA" && "$ORIGIN_P2" == "$PATCH_SHA" ]]; then
        echo "OK: origin/feature/ldap-release already matches current upstream+patch."
        git switch -C feature/ldap-release "$ORIGIN_RELEASE" >/dev/null
        exit 0
    fi
fi

echo "Create feature/ldap-release from upstream-mirror..."
git switch -C feature/ldap-release upstream-mirror >/dev/null

if git merge-base --is-ancestor "$PATCH_BRANCH" HEAD; then
    echo "OK: patch branch is already contained in upstream-mirror; no merge needed."
    exit 0
fi

echo "Merge patch branch: ${PATCH_BRANCH}"
if git merge --no-ff "$PATCH_BRANCH" -m "Merge LDAP patch (${PATCH_BRANCH}) into release"; then
    echo "OK: overlay merge completed."
else
    echo "ERROR: merge conflicts detected on feature/ldap-release."
    echo "Resolve conflicts, commit, then rerun sync.sh."
    exit 1
fi
