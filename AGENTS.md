# Instructions for AI agents (`avd-remediate`)

Read this file first, then [CLAUDE.md](CLAUDE.md) and [docs/guardrails.md](docs/guardrails.md).

## Family and repo rules

- **Private repo**: `avd-remediate` stays private and off `avd-ops` `repos.json`. Public family repos (`avd-ops`, `avd-assess`, `avd-current-state`, `avd-landing-zone`, `avd-second-brain`, `avd-swarm`) never depend on `avd-remediate`; dependencies point downward into published family contracts (`C6`, `C11`, `C15`, `C21`, `C24`).
- **No spend without the owner's exact go** (`go batch <id> $<total>`), **never leave the meter running**, and **never delete the last copy**.
- **No secrets, IDs or names** in this repo, commits, issues or PR text. Tenant incident bundles are written only to the adopter's private companion estate vault after verifying `PRIVATE` visibility.
- **Read first, remediate only with human approval**: Diagnostic probes in `rebuild/scope.json` are strictly read-only. Remediation plans always show preflight, blast radius, rollback, and verification.
- **American English** in docs, UI, and comments.

## Checks to run

```bash
node --test "tests/*.test.mjs"
```
