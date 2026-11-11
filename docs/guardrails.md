# Guardrails (`avd-remediate`)

These guardrails apply to every script, playbook, UI component, and commit in `avd-remediate`:

1. **Public repo, tenant-safe boundaries:**
   - `avd-remediate` is a public `avd-ops` repository (`avd-ops/avd-remediate`).
   - Never commit API keys, tokens, subscription IDs, tenant IDs, object GUIDs, customer/employer names, domains, emails, UNC paths, or real IP addresses into `avd-remediate`.
   - Tenant-specific incident records belong only in the operator's private companion estate vault (`--vault`), verified as `PRIVATE` before write-back.
2. **Read freely, remediate only with explicit human approval:**
   - Diagnostic probes in `rebuild/scope.json` and `scripts/Invoke-AvdDiagnosticProbe.ps1` must be 100% read-only (`GET`, KQL, `Get-*`, `Test-*`) and reject tokens carrying write scopes when running in restricted reader mode.
   - Remediation actions never run silently or automatically. Every remediation path (Day-2 script, C24 plan, or `avd-swarm` handoff) requires explicit operator review and approval, includes preflight and rollback steps, and verifies the outcome.
3. **No spend without exact owner approval:**
   - Never start, scale up, or create billable Azure resources without a written cost estimate and the owner typing `go batch <id> $<total>`.
   - Never leave the meter running (`-KeepRunning <until>` required for any temporary diagnostic VM or Bastion/capture resource).
4. **Never delete the last copy:**
   - Never delete logs, run journals, incident bundles, or VHDX backups without a verified copy in the private companion vault or explicit `-DiscardLastCopy`.
5. **Mandatory redaction before external LLM or upstream KB calls:**
   - All text sent to an external BYO-LLM endpoint or exported as a `known-errors.yaml` draft must pass through `AvdOpsEngine.redact.redact()` and `maskSecrets()`.
6. **Strict CSP and vendored `avd-ops` assets:**
   - No inline `<script>`, no `style="..."` attributes, no `eval()`, and no external font/script CDNs. All UI tokens and engine modules are vendored from `avd-ops` with SHA-256 lock verification (`tests/locks.test.mjs`).
