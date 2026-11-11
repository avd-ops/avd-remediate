@AGENTS.md

# CLAUDE.md

`avd-remediate`: the native Azure Virtual Desktop troubleshooting, diagnosis, and remediation workbench ([docs/spec.md](docs/spec.md)) for the `avd-ops` toolset. It vendors the `avd-ops` design system (`ds-v2.7.0`) and shared portal engine (`pe-v1.1.0`), reads from any adopter's private companion estate vault (`--vault <path>`) and pinned `avd-assess` / `avd-current-state` / `avd-second-brain` artifacts, runs read-only diagnostic probes (`rebuild/scope.json`), and produces human-approved remediation plans across all five control planes (`azure`, `entra`, `intune`, `m365`, `power-platform`).

## Validate before pushing

```bash
node --test "tests/*.test.mjs"
```

## Rules

- `site/assets/` and `site/assets/engine/` are vendored copies from `avd-ops`, verified by `tests/locks.test.mjs` against `site/assets/design-system.lock.json` and `site/assets/engine.lock.json`. Never edit vendored files by hand; put portal-specific styles in `site/portal/remediate.css` and logic in `site/portal/remediate-core.js` and `site/portal/remediate-page.js`.
- Every page keeps the research-only notice in `header.bar`, uses only `avd-ops.css` color tokens, and runs under a strict CSP with no inline `<script>` or `style="..."` attributes.
- Every live diagnostic probe must be registered in `rebuild/scope.json` and use only read-only transports (`GET`, KQL `project`/`summarize`, `Get-*`, `Test-*`).
- Personal project, not for production, as is, not affiliated with the author's employer, Liquidware or Microsoft.
