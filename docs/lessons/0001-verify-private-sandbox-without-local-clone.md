# 0001. Reject public family repository names in `verifyPrivateSandbox` even when not cloned locally

- **Date:** 2026-11-09

## What happened
`verifyPrivateSandbox('../avd-ops')` in `scripts/server.mjs` only inspected `.git/config` when `path.resolve(ROOT, sandboxDir)` already existed on disk. In CI or in workspaces where `../avd-ops` did not exist on disk, `verifyPrivateSandbox('../avd-ops')` returned `{ ok: true }` and allowed `/api/brief` to create `../avd-ops/inbox/` and write a brief there.

## Cause
The check relied solely on `fs.existsSync(path.join(resolved, '.git', 'config'))` and had no guard on the target directory name when the directory was absent or uninitialized.

## Fix
Added a `PUBLIC_FAMILY_REPOS` set in `scripts/server.mjs` (`avd-ops`, `avd-assess`, `avd-azure`, `avd-benchmark`, `avd-current-state`, `avd-entra`, `avd-intune`, `avd-landing-zone`, `avd-linecheck`, `avd-m365`, `avd-power-platform`, `avd-remediate`, `avd-second-brain`, `avd-swarm`, `avd-liquidware`) so `verifyPrivateSandbox()` rejects any public family repository by basename in addition to inspecting `.git/config`.

## Guard
`tests/security.test.mjs` verifies both the basename guard (`../avd-ops`, `../avd-current-state` without requiring a local sibling clone) and the `.git/config` remote URL guard.
