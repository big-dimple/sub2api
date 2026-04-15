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
5. Run:

```bash
bash skills/sub2api-sync-ldap/scripts/generated-repair.sh
bash skills/sub2api-sync-ldap/scripts/contract-gate.sh
bash skills/sub2api-sync-ldap/scripts/deploy-sanity.sh
```

6. If those commands modify tracked files, commit the regenerated artifacts:

```bash
git add -A
git commit -m "chore(ldap): regenerate sync artifacts"
```

7. Backfill the support branch:

```bash
bash skills/sub2api-sync-ldap/scripts/backfill-support.sh --release-branch main --support-branch feature/ldap-support
```

8. Publish the release branches unless the user explicitly asked for local-only work:

```bash
bash skills/sub2api-sync-ldap/scripts/publish-release.sh --release-branch main --also-branch feature/ldap-support
```

## Resolution Heuristics

- Keep LDAP login, sync, and admin-setting surfaces intact.
- Keep validation and deploy safety checks intact.
- Remove orphaned provider or generated-code references if upstream moved them and the implementation no longer exists.
- Prefer regenerating Wire/Ent output over hand-editing generated files beyond the minimum needed to unblock generation.
