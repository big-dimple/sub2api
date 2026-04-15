# Script Map

Read this file when you need exact script behavior, non-default entry points, or command variants.

## Primary Entry Point

### `scripts/sync.sh`

Default orchestrator. Runs, in order:

1. `upstream-preflight.sh`
2. `overlay-apply.sh`
3. `generated-repair.sh`
4. `contract-gate.sh`
5. `deploy-sanity.sh` unless skipped
6. `backfill-support.sh` unless disabled
7. `publish-release.sh` when `--publish` is supplied

## Direct-Use Scripts

### `scripts/upstream-preflight.sh`

Use when you only need to verify that upstream drift is still small enough for the LDAP overlay flow.

- auto-detects patch branch: `feature/ldap-patch` then `feature/ldap-support`
- fails fast if upstream changed too much around the LDAP touch points

### `scripts/overlay-apply.sh`

Use when you need just the merge/overlay step.

- creates local `main` from upstream
- overlays the LDAP patch branch
- exits early if origin already matches the current upstream + patch state

### `scripts/generated-repair.sh`

Use after successful overlay or after manual conflict resolution.

- syncs embedded version
- runs Ent generation
- runs Wire generation
- repairs missing `go.sum` entries when possible

### `scripts/contract-gate.sh`

Standard LDAP release gate:

- backend LDAP contract tests
- backend compile check
- frontend typecheck
- frontend Vitest

Set `LDAP_SYNC_FULL_TESTS=1` or use `sync.sh --full-test` to run broader backend tests.

### `scripts/deploy-sanity.sh`

Checks the LDAP deploy surface:

- compose healthcheck and data-dir behavior
- Dockerfile healthcheck expectations
- setup fallback behavior
- single-script upgrade flow
- deploy docs consistency

### `scripts/backfill-support.sh`

Moves `feature/ldap-support` up to the release branch.

- fast-forwards when possible
- merges release into support only if the branches diverged

### `scripts/publish-release.sh`

Push helper for `main` plus one additional branch.

- pushes only when the remote differs
- uses fast-forward push when possible
- falls back to `--force-with-lease` only when branch history diverged

## Common Variants

```bash
# Publish after sync
bash skills/sub2api-sync-ldap/scripts/sync.sh --publish

# Specify the patch branch explicitly
bash skills/sub2api-sync-ldap/scripts/sync.sh --patch-branch feature/ldap-support

# Specify a different backfill target
bash skills/sub2api-sync-ldap/scripts/sync.sh --backfill-branch feature/ldap-support

# Run slower, broader backend tests in the gate
bash skills/sub2api-sync-ldap/scripts/sync.sh --full-test

# Skip deploy sanity only when the user explicitly accepts the risk
bash skills/sub2api-sync-ldap/scripts/sync.sh --skip-deploy-sanity

# Disable backfill only when the user explicitly asks
bash skills/sub2api-sync-ldap/scripts/sync.sh --no-backfill
```
