#!/usr/bin/env bash

set -euo pipefail

BRANCH="feature/ldap-release"

if [[ ! -f backend/internal/service/auth_service.go ]]; then
    echo "ERROR: run this script in sub2api repository root."
    exit 1
fi

if ! git show-ref --verify --quiet "refs/heads/${BRANCH}"; then
    echo "ERROR: local branch not found: ${BRANCH}"
    exit 1
fi

git fetch origin "${BRANCH}:refs/remotes/origin/${BRANCH}" >/dev/null 2>&1 || true

LOCAL_SHA="$(git rev-parse "${BRANCH}")"
if ! git show-ref --verify --quiet "refs/remotes/origin/${BRANCH}"; then
    echo "Publish: remote branch does not exist, push new."
    git push origin "${BRANCH}"
    exit 0
fi

REMOTE_SHA="$(git rev-parse "origin/${BRANCH}")"
if [[ "$LOCAL_SHA" == "$REMOTE_SHA" ]]; then
    echo "Publish: no changes. Skip push."
    exit 0
fi

if git diff --quiet "origin/${BRANCH}..${BRANCH}"; then
    echo "Publish: no diff from remote. Skip push."
    exit 0
fi

if git merge-base --is-ancestor "origin/${BRANCH}" "${BRANCH}"; then
    echo "Publish: fast-forward push."
    git push origin "${BRANCH}"
else
    echo "Publish: non-fast-forward update, use --force-with-lease."
    git push --force-with-lease origin "${BRANCH}"
fi
