---
name: sub2api-sync-ldap
description: Sync the LDAP fork of Wei-Shaw/sub2api onto the latest upstream, repair generated artifacts, run LDAP regression and deploy sanity checks, backfill feature/ldap-support, and publish the changed release branches to GitHub by default. Use when the user asks to pull the latest official code, rebuild the LDAP edition, resolve LDAP overlay conflicts, or push the refreshed fork to GitHub.
metadata:
  short-description: Sync and publish the LDAP fork safely.
---

# Sub2API LDAP Sync

Use this skill only in the `sub2api` repository root.

## Trigger

Use this skill when the user wants any of the following:

- pull or sync the latest official `Wei-Shaw/sub2api`
- rebuild or refresh the LDAP edition
- re-apply the LDAP patch branch onto upstream
- run the LDAP fork validation gate before release
- backfill `feature/ldap-support` from `main`
- publish the refreshed LDAP fork to GitHub

## Default Path

Default completion path:

```bash
bash skills/sub2api-sync-ldap/scripts/sync.sh
```

Use local-only mode only when the user explicitly says not to publish:

```bash
bash skills/sub2api-sync-ldap/scripts/sync.sh --no-publish
```

## Workflow

1. Confirm the worktree is clean before running anything.
2. Run `scripts/sync.sh` and treat GitHub publication as part of "done" unless the user explicitly asks for local-only work.
3. Let `sync.sh` drive the normal path: preflight, overlay, generated repair, contract gate, deploy sanity, support-branch backfill, and publish.
4. If the overlay merge conflicts, resolve them on `main`, commit the merge, then continue with `scripts/generated-repair.sh`, `scripts/contract-gate.sh`, `scripts/deploy-sanity.sh`, commit regenerated artifacts, `scripts/backfill-support.sh`, and finally `scripts/publish-release.sh`.
5. If you need manual conflict guidance, read [references/conflict-recovery.md](references/conflict-recovery.md).
6. If you need policy or merge-priority guidance, read [references/policies.md](references/policies.md).
7. If you need script-by-script behavior, options, or when to call a script directly, read [references/script-map.md](references/script-map.md).
8. If preflight stops on reviewed upstream churn, rerun with `scripts/sync.sh --change-threshold <percent>` instead of patching environment variables.

## Operating Rules

- Default to the orchestrator script instead of manually chaining sub-steps.
- Treat LDAP behavior as the required customization; prefer upstream plus LDAP-only changes, not unrelated fork drift.
- Keep generated artifacts and branch history releasable at every stop point.
- Treat "完成最新版本 LDAP 化" as including `origin/main` and `origin/feature/ldap-support` being updated unless the user explicitly says local-only.
- Publish only after validation passes or the user explicitly accepts an incomplete release.

## Validation

`scripts/contract-gate.sh` is the standard release gate. It covers:

- backend LDAP contract tests
- backend server compile check
- frontend typecheck
- frontend Vitest suite

`scripts/deploy-sanity.sh` checks the LDAP deploy surface before release. Read [references/script-map.md](references/script-map.md) only if you need the exact coverage.
