# Conflict Recovery SOP

Read this file only when `scripts/overlay-apply.sh` or `scripts/sync.sh` stops on merge conflicts.

## Goal

Finish with a releasable `main` that equals:

- latest upstream state
- plus required LDAP behavior
- plus regenerated artifacts

## Recovery Steps

1. Stay on `main`, which should already be based on upstream for the current sync attempt.
2. Inspect conflicted files with `git diff --name-only --diff-filter=U` and resolve each file to "official upstream + required LDAP changes only".
3. If a conflict is in generated output and the source-of-truth files are already correct, prefer a minimal temporary resolution that allows regeneration to succeed.
4. When all conflicts are resolved, `git add` the files and create the merge commit.
5. Resume the rest of the flow with:

```bash
bash skills/sub2api-sync-ldap/scripts/resume-after-conflict.sh
```
6. Use `--no-publish` only when the user explicitly asked for local-only work.

## Resolution Heuristics

- Keep LDAP login, sync, and admin-setting surfaces intact.
- Keep validation and deploy safety checks intact.
- Remove orphaned provider or generated-code references if upstream moved them and the implementation no longer exists.
- Prefer regenerating Wire/Ent output over hand-editing generated files beyond the minimum needed to unblock generation.
