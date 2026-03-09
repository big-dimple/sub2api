---
name: sub2api-sync-ldap
description: Synchronize LDAP customization onto latest Wei-Shaw/sub2api upstream and keep feature/ldap-release releasable. Use when asked to pull latest official code, re-apply LDAP patch branch, regenerate wire/ent, run LDAP regression checks, and publish only when there are real branch changes.
---

# Sub2API LDAP Sync Skill

Run in the `sub2api` repository root.

## Default

```bash
bash /root/.codex/skills/sub2api-sync-ldap/scripts/sync.sh
```

This runs:
1. upstream preflight
2. LDAP patch overlay
3. generated code repair
4. contract checks
5. deploy sanity checks (compose healthcheck/data dir, Dockerfile healthcheck, setup fallback, deploy script hardening, deploy docs)
6. backfill patch source branch from `feature/ldap-release` (default target: `feature/ldap-support`)

## Publish

```bash
bash /root/.codex/skills/sub2api-sync-ldap/scripts/sync.sh --publish
```

Publish behavior:
1. push `feature/ldap-release` only when it actually changed
2. push backfill branch (default `feature/ldap-support`) when changed
3. use fast-forward push when possible
4. use `--force-with-lease` only when branch history rewrites are required

## Options

```bash
# Override patch branch (default auto-detect: feature/ldap-patch -> feature/ldap-support)
bash /root/.codex/skills/sub2api-sync-ldap/scripts/sync.sh --patch-branch feature/ldap-support

# Override backfill target branch
bash /root/.codex/skills/sub2api-sync-ldap/scripts/sync.sh --backfill-branch feature/ldap-support

# Run full backend test suites in gate stage (slower)
bash /root/.codex/skills/sub2api-sync-ldap/scripts/sync.sh --full-test

# Disable backfill (not recommended)
bash /root/.codex/skills/sub2api-sync-ldap/scripts/sync.sh --no-backfill

# Skip deploy sanity checks (not recommended)
bash /root/.codex/skills/sub2api-sync-ldap/scripts/sync.sh --skip-deploy-sanity
```

## Rules

1. keep worktree clean before running
2. do not commit backups or package-manager cache
3. if overlay conflicts, resolve conflict in `feature/ldap-release`, commit, then continue `generated-repair.sh` -> `contract-gate.sh` -> `backfill-support.sh` -> publish
