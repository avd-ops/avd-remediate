# Lesson 0003: Native Host-Level Telemetry Belongs in `avd-remediate` with Dual-Contract Export (`C25` + `avd-measured-usage/v1`)

- **Date:** 2026-11-11
- **Status:** Adopted
- **Repos:** `avd-remediate`, `avd-current-state`, `avd-benchmark`, `avd-assess`

## Context

Within the `avd-ops` family, we needed a clean architectural boundary for collecting native (non-Liquidware) Windows session host performance counters (`Get-Counter` for CPU, memory, and disk IOPS/latency), Windows Operational event logs (`Get-WinEvent` on `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` and `Microsoft-FSLogix-Apps/Operational`), and Log Analytics KQL telemetry (`Perf`, `WVDConnections`, `WVDConnectionNetworkData`, `WVDCheckpoints`) to feed both:

1. Incident triage in `avd-remediate`
2. Empirical benchmarking (`avd-benchmark`)
3. Migration sizing and wave planning (`avd-migration-factory` and `avd-assess`)

## Decision & Lesson Learned

1. **Keep `avd-current-state` strictly Azure control-plane and `Reader`-only:**
   - `avd-current-state` collects control-plane posture across the five planes (`azure`, `entra`, `intune`, `m365`, `power-platform`) using ARM `Reader` and Graph `*Read.All` permissions without touching inside-the-guest session host OS state or requiring `Virtual Machine Contributor` (`runCommand`).
2. **`avd-remediate` owns native host-level collection and dual-contract export:**
   - Because `avd-remediate` already operates at the session host and Log Analytics KQL plane for incident triage (`probe-host-perf-counters`, `probe-conn-shortpath-transport`, `probe-conn-black-screen-events`, `probe-fsx-storage-latency`), extending it with [`scripts/Export-AvdHostTelemetry.ps1`](../../scripts/Export-AvdHostTelemetry.ps1) (`OfflineVault`, `LogAnalytics`, and `LocalHost` modes) and `POST /api/telemetry/export` avoids duplicating collectors across repos.
3. **Emit both upstream contracts from a single collection pass:**
   - **Contract `C25` (`avd-benchmark-result/v1`)**: Validated against `contracts/schemas/benchmark-result.schema.json` (`avd-assess`), capturing `logonDurationSec` (`p50`/`p95`/`p99`), `fslogixAttachDurationMs` (`p50`/`p95`), `storageLatencyMs` (`p50`/`p95`/`p99`), `cpuBusyPct` (`p50`/`p95`), `memoryAvailableMb` (`p50`/`p05`), `rdpRoundTripMs` (`p50`/`p95`), and threshold verdicts for `avd-benchmark`.
   - **Measured Usage (`avd-measured-usage/v1`)**: Validated against `contracts/schemas/measured-usage.schema.json` (`avd-assess`), capturing the 14-day/85%-coverage `measurementGate` and per-group `cpuPerUserCores`, `memoryPerUserGiB`, `steadyStateIopsPerUser`, `logonStormIopsPerUser`, `profileSizeGiB`, `logonDurationSeconds`, and `rttMsByRegion` (`p50`/`p95`) for `avd-migration-factory` when Liquidware Stratusphere UX (`tier-3-external`) is not present.
4. **Fail-closed privacy and companion vault guards:**
   - All exported JSON payloads pass a fail-closed leak check (blocking raw UUIDs, UPNs/emails, `/subscriptions/` resource IDs, and UNC paths) and refuse to write into any public `github.com/avd-ops/*` repository.
