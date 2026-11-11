# avd-remediate

Part of [avd-ops](https://avd-ops.dev/), the open toolkit for Azure Virtual Desktop.

A native Azure Virtual Desktop troubleshooting, diagnosis, host-level telemetry collection, and remediation workbench in the `avd-ops` toolset. It combines a 5-step guided portal (`site/portal/`) in the `avd-ops` design system with a hybrid deterministic + BYO-LLM troubleshooting chatbot, grounded in `avd-assess` standards, `avd-current-state` facts (`C11`, `C21`, `C24`), `avd-second-brain` known errors, and any adopter's private companion estate vault (`--vault ../avd-vault`).

> [!WARNING]
> **Personal project. Research and learning only. Not for production. No warranty.**
>
> - This is my own personal project, built on my own time **for research and learning**. It is **not affiliated with, endorsed by or supported by my employer, Liquidware or Microsoft**, and it does not represent their views, products or guidance. It is not an official Microsoft product, and it is not a certified or supported tool.
> - **Don't run any of it in production** or against tenants that matter. Test in a dedicated lab subscription and tenant first. Output is not a production-readiness certification, a compliance attestation or a security audit.
> - It is provided **"as is", without warranty of any kind**, under the [MIT License](LICENSE). You use it at your own risk and own the Azure charges it incurs.
> - **Contributions and forks are welcome and encouraged.**

## Quick start (Azure Cloud Shell or local machine)

```powershell
# PowerShell 7 (Azure Cloud Shell or local workstation)
if (-not (Test-Path ~/avd-remediate)) { git clone https://github.com/avd-ops/avd-remediate.git ~/avd-remediate }
Set-Location ~/avd-remediate; git checkout -q main; git pull -q --ff-only
node ./scripts/server.mjs --vault ../avd-vault --port 8787
```

```bash
# Bash (Azure Cloud Shell, macOS, or Linux)
if [ ! -d "$HOME/avd-remediate" ]; then git clone https://github.com/avd-ops/avd-remediate.git "$HOME/avd-remediate"; fi
cd "$HOME/avd-remediate" && git checkout -q main && git pull -q --ff-only
node ./scripts/server.mjs --vault ../avd-vault --port 8787
```

Open `http://127.0.0.1:8787/portal/` (or use Cloud Shell's **Web preview** on port `8787`). You can also open `site/portal/index.html` directly as a static portal with zero backend and drop or paste `C11`, `C21`, `C24`, run journals, or log output in the browser.

## How it works

1. **Context & Symptom**: Connect your private companion estate vault (`--vault` / `--env`, or drop/paste `C11` facts, `C21` assessment reports, `C24` plans, and terminal logs) and pick or describe the symptom across five diagnostic domains:
   - **Session connectivity & protocol** (black screen, connection drops, RDP Shortpath / UDP fallback, gateway/broker errors, high RTT/jitter, `avd-linecheck` bundles)
   - **Logon & FSLogix profiles** (slow logons, VHDX attach/detach locks, Azure Files SMB / Entra Kerberos auth failures, Cloud Cache, storage throttling/latency)
   - **Session host health & capacity** (drain mode, SxS stack / Geneva / RDAgent unhealthy, CPU/memory/disk contention, WDOT regressions, scaling plan stalls)
   - **Identity, Intune & M365 VDI** (Entra join / SSO failures, Conditional Access blocks, Intune Settings Catalog / compliance drift, Teams SlimCore/WebRTC & OneDrive KFM)
   - **Control-plane deployment & day-2 drift** (failed Bicep/Graph/Power Platform runs from companion vault journals, `C21`/`C24` posture gaps across `azure`, `entra`, `intune`, `m365`, and `power-platform`)
2. **Evidence, Live Probes & Native Host Telemetry**: Correlates offline companion vault data, runs air-tight read-only live probes (Log Analytics / AVD Insights KQL, Azure Resource Graph, Session Host agent health, Microsoft Graph Entra/Intune/M365 `GET` checks, or pasted output), and exports native (non-Liquidware) host-level performance and usage telemetry via `scripts/Export-AvdHostTelemetry.ps1` (`Get-Counter`, `Get-WinEvent`, or Log Analytics KQL) into two schema-valid contracts:
   - **Contract `C25` (`avd-benchmark-result/v1`)** for `avd-benchmark` and `avd-assess`
   - **Measured Usage (`avd-measured-usage/v1`)** for `avd-migration-factory` and `avd-assess`
3. **Root Cause & Citations**: Ranks root causes deterministically against `playbooks/catalog.json`, `avd-assess` claims (`ref:` / `obs:`), and `avd-second-brain` known errors. The docked Chat Assistant works 100% offline/free via deterministic triage and upgrades to BYO-LLM reasoning (Azure OpenAI, GitHub Models, Anthropic, OpenAI, or local Ollama) with automatic `redact.js` scrubbing before any external call.
4. **Remediation Plan & Approval**: Generates three explicit, human-gated remediation outputs (never executing blind writes):
   - **Path A**: Copyable/runnable day-2 PowerShell/Bash fix block with preflight, rollback, and `<<<AVDREM-STATE ...>>>` verification output
   - **Path B**: Plane-routed `C24` (`avd-remediation-plan/v1`) JSON and parameter patches for `avd-landing-zone` (`avd-entra`, `avd-intune`, `avd-m365`, `avd-azure`, `avd-power-platform`)
   - **Path C**: `avd-swarm` plan handoff package for GitHub Environment approval
5. **Verify & Capture**: Verifies the fix, writes the incident bundle (`incident.json`, evidence, verification proof) back to the connected private companion vault (after verifying `PRIVATE` repository visibility), and drafts a redacted Known Error / Lesson entry for `avd-second-brain` or `avd-assess`.

## Upstream contracts & family locks (`contracts/PINS.json`)

`avd-remediate` vendors and SHA-256-verifies its upstream contracts in [`contracts/PINS.json`](contracts/PINS.json) (enforced by [`tests/locks.test.mjs`](tests/locks.test.mjs)):

- **`avd-assess`**: `contracts/fact-register.json` (`ref:` / `obs:` claim IDs), `contracts/schemas/remediation-plan.schema.json` (`avd-remediation-plan/v1` `C24`), `contracts/schemas/current-state-facts.schema.json` (`C11`), `contracts/schemas/assessment.schema.json` (`C21`), `contracts/schemas/benchmark-result.schema.json` (`C25`), and `contracts/schemas/measured-usage.schema.json` (`avd-measured-usage/v1`).
- **`avd-second-brain`**: `contracts/workload-tiers.json` (per-user vCPU, RAM, IOPS, and network budgets) and `contracts/calibration.json` (logon p95 <= 30s and RTT p95 <= 100ms envelopes).
- **`avd-current-state`**: `contracts/lz-parameters.json` (canonical `C11` fact-to-Bicep parameter map) and `C11` / `C21` / `C25` ingestion.
- **`avd-landing-zone`**: `contracts/control-planes.json` (3-stage `Invoke-AvdControlPlanes.ps1` orchestration across `avd-entra`, `avd-intune`, `avd-m365`, `avd-azure`, and `avd-power-platform`).
- **`avd-swarm`**: `catalog/actions/*.yml` (`host.drain`, `host.restart-agent`, `host.reregister`, `host.recycle-empty`, `host.resume`, `host.stop`) with all 9 mandatory §5a preconditions and `catalog/queries/wvd-*.kql`.
- **`avd-benchmark`**: `avd-benchmark-result/v1` (`C25`) p95 logon, profile attach, storage latency, RTT, and host CPU/RAM pressure metrics.

## Documentation & tests

- Full specification: [docs/spec.md](docs/spec.md)
- Guardrails: [docs/guardrails.md](docs/guardrails.md)
- Agent instructions: [AGENTS.md](AGENTS.md) and [CLAUDE.md](CLAUDE.md)

```bash
node --test "tests/*.test.mjs"
```
