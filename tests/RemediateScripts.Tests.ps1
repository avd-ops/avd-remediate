#requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
# Offline Pester tests for scripts/Invoke-AvdDiagnosticProbe.ps1 and scripts/Invoke-AvdRemediationPlan.ps1.

BeforeAll {
    $script:RepoRoot = Split-Path -Parent $PSScriptRoot
    $script:ProbeScript = Join-Path $script:RepoRoot 'scripts/Invoke-AvdDiagnosticProbe.ps1'
    $script:PlanScript = Join-Path $script:RepoRoot 'scripts/Invoke-AvdRemediationPlan.ps1'
    $script:TelemetryScript = Join-Path $script:RepoRoot 'scripts/Export-AvdHostTelemetry.ps1'
    $script:ScopePath = Join-Path $script:RepoRoot 'rebuild/scope.json'
    $script:CatalogPath = Join-Path $script:RepoRoot 'playbooks/catalog.json'
}

Describe 'Invoke-AvdDiagnosticProbe.ps1 allowlist and read-only enforcement' {
    It 'rejects unknown probe IDs not present in rebuild/scope.json' {
        {
            & $script:ProbeScript -ProbeId 'probe-unknown-not-in-scope' -OfflineDemo
        } | Should -Throw "*not listed in rebuild/scope.json*"
    }

    It 'blocks probes with non-GET methods or non-read-only commands/verbs' {
        $tamperedScopePath = Join-Path $TestDrive 'tampered-scope.json'
        $tamperedScope = [ordered]@{
            version              = '1.0.0'
            forbiddenTokenScopes = @('ReadWrite', 'Write')
            probes               = [ordered]@{
                'probe-bad-method' = [ordered]@{
                    plane     = 'azure'
                    domain    = 'hosts'
                    transport = 'arm-rest'
                    method    = 'POST'
                    command   = 'az rest --method get'
                }
                'probe-bad-verb'   = [ordered]@{
                    plane     = 'azure'
                    domain    = 'hosts'
                    transport = 'arm-rest'
                    method    = 'GET'
                    command   = 'Set-AzVM -Name vm-0'
                }
            }
        }
        ($tamperedScope | ConvertTo-Json -Depth 6) | Set-Content -LiteralPath $tamperedScopePath -Encoding utf8

        {
            & $script:ProbeScript -ProbeId 'probe-bad-method' -ScopePath $tamperedScopePath
        } | Should -Throw "*violates the read-only GET requirement*"

        {
            & $script:ProbeScript -ProbeId 'probe-bad-verb' -ScopePath $tamperedScopePath
        } | Should -Throw "*forbidden non-read-only verb*"
    }

    It 'blocks execution when write-capable token scopes are present' {
        {
            & $script:ProbeScript -ProbeId 'probe-fsx-storage-kerberos' -TokenScopes @('Directory.ReadWrite.All')
        } | Should -Throw "*write-capable token scope*"
    }

    It 'emits a valid AVDREM-STATE JSON line for domain <Domain> (<ProbeId>)' -ForEach @(
        @{ Domain = 'connectivity';   ProbeId = 'probe-conn-shortpath-transport'; Plane = 'azure' }
        @{ Domain = 'fslogix';        ProbeId = 'probe-fsx-storage-kerberos';     Plane = 'entra' }
        @{ Domain = 'hosts';          ProbeId = 'probe-host-health-checks';       Plane = 'azure' }
        @{ Domain = 'identity-m365';  ProbeId = 'probe-id-ca-sso-posture';        Plane = 'entra' }
        @{ Domain = 'control-planes'; ProbeId = 'probe-cp-power-platform-health'; Plane = 'power-platform' }
    ) {
        $sandboxDir = Join-Path $TestDrive "sandbox-$Domain"
        $envDir = Join-Path $sandboxDir 'environments/contoso-lab'
        New-Item -ItemType Directory -Path $envDir -Force | Out-Null
        $c21Fixture = [ordered]@{
            schema = 'avd-assessment-report/v1'
            checks = @(
                [ordered]@{ id = 'asm-entra-files-kerberos-ready'; outcome = 'pass'; evidence = 'Kerberos key active' }
                [ordered]@{ id = 'asm-intune-rdp-shortpath'; outcome = 'gap'; evidence = 'UDP 3390 policy missing' }
            )
        }
        ($c21Fixture | ConvertTo-Json -Depth 5) | Set-Content -LiteralPath (Join-Path $envDir 'c21-assessment-report.json') -Encoding utf8

        $outLine = & $script:ProbeScript -ProbeId $ProbeId -SandboxPath $sandboxDir -OfflineDemo
        $outLine | Should -Match '^<<<AVDREM-STATE (\{.*\}) AVDREM-STATE>>>$'
        $jsonText = [regex]::Match($outLine, '^<<<AVDREM-STATE (\{.*\}) AVDREM-STATE>>>$').Groups[1].Value
        $parsed = $jsonText | ConvertFrom-Json
        $parsed.v | Should -Be 1
        $parsed.stage | Should -Be 'probe'
        $parsed.probeId | Should -Be $ProbeId
        $parsed.domain | Should -Be $Domain
        $parsed.plane | Should -Be $Plane
        $parsed.status | Should -BeIn @('pass', 'gap')
    }
}

Describe 'Invoke-AvdRemediationPlan.ps1 preflight, approval gate, and rollback enforcement' {
    It 'defaults to DryRunPreflight, writes a rollback snapshot, and emits preflight AVDREM-STATE' {
        $snapPath = Join-Path $TestDrive 'rollback-shortpath.json'
        $outLine = & $script:PlanScript -PlaybookId 'pb-conn-shortpath-blocked' -SnapshotPath $snapPath
        (Test-Path -LiteralPath $snapPath) | Should -BeTrue

        $snap = Get-Content -LiteralPath $snapPath -Raw | ConvertFrom-Json
        $snap.schema | Should -Be 'avd-remediate-rollback/v1'
        $snap.playbookId | Should -Be 'pb-conn-shortpath-blocked'
        $snap.plane | Should -Be 'intune'

        $outLine | Should -Match '^<<<AVDREM-STATE (\{.*\}) AVDREM-STATE>>>$'
        $state = ([regex]::Match($outLine, '^<<<AVDREM-STATE (\{.*\}) AVDREM-STATE>>>$').Groups[1].Value) | ConvertFrom-Json
        $state.stage | Should -Be 'preflight'
        $state.mode | Should -Be 'DryRunPreflight'
        $state.status | Should -Be 'pass'
        $state.rollbackSnapshot | Should -Be $snapPath
    }

    It 'refuses unapproved cloud writes when preflight snapshot or -Approved is missing' {
        $missingSnap = Join-Path $TestDrive 'nonexistent-rollback.json'
        {
            & $script:PlanScript -PlaybookId 'pb-fsx-kerberos-smb-auth' -Mode 'ApplyApprovedFix' -SnapshotPath $missingSnap -Approved
        } | Should -Throw "*preflight rollback snapshot not found*"

        $snapPath = Join-Path $TestDrive 'rollback-kerberos.json'
        & $script:PlanScript -PlaybookId 'pb-fsx-kerberos-smb-auth' -Mode 'DryRunPreflight' -SnapshotPath $snapPath | Out-Null

        {
            & $script:PlanScript -PlaybookId 'pb-fsx-kerberos-smb-auth' -Mode 'ApplyApprovedFix' -SnapshotPath $snapPath
        } | Should -Throw "*explicit human approval (-Approved) is required*"
    }

    It 'applies approved remediation after preflight and supports Rollback from snapshot' {
        $snapPath = Join-Path $TestDrive 'rollback-approved.json'
        & $script:PlanScript -PlaybookId 'pb-host-unhealthy-agent' -Mode 'DryRunPreflight' -SnapshotPath $snapPath | Out-Null

        $applyLine = & $script:PlanScript -PlaybookId 'pb-host-unhealthy-agent' -Mode 'ApplyApprovedFix' -SnapshotPath $snapPath -Approved
        $applyState = ([regex]::Match($applyLine, '^<<<AVDREM-STATE (\{.*\}) AVDREM-STATE>>>$').Groups[1].Value) | ConvertFrom-Json
        $applyState.stage | Should -Be 'verify'
        $applyState.mode | Should -Be 'ApplyApprovedFix'
        $applyState.status | Should -Be 'pass'

        $rbLine = & $script:PlanScript -PlaybookId 'pb-host-unhealthy-agent' -Mode 'Rollback' -SnapshotPath $snapPath
        $rbState = ([regex]::Match($rbLine, '^<<<AVDREM-STATE (\{.*\}) AVDREM-STATE>>>$').Groups[1].Value) | ConvertFrom-Json
        $rbState.stage | Should -Be 'rollback'
        $rbState.mode | Should -Be 'Rollback'
        $rbState.status | Should -Be 'pass'
    }
}

Describe 'Export-AvdHostTelemetry.ps1 dual-contract export (C25 + avd-measured-usage/v1)' {
    It 'exports schema-valid benchmark-c25.json and measured-usage.json and emits host-telemetry AVDREM-STATE' {
        $vaultDir = Join-Path $TestDrive 'private-telemetry-vault'
        New-Item -ItemType Directory -Path (Join-Path $vaultDir 'environments/contoso-lab') -Force | Out-Null

        $outLine = & $script:TelemetryScript -Mode 'OfflineVault' -ProfileId 'multisession-density' -WorkloadClass 'medium' -VmSku 'Standard_D8s_v5' -VaultPath $vaultDir -Environment 'contoso-lab' -OfflineDemo
        $outLine | Should -Match '^<<<AVDREM-STATE (\{.*\}) AVDREM-STATE>>>$'
        $state = ([regex]::Match($outLine, '^<<<AVDREM-STATE (\{.*\}) AVDREM-STATE>>>$').Groups[1].Value) | ConvertFrom-Json
        $state.stage | Should -Be 'host-telemetry'
        $state.status | Should -Be 'pass'
        $state.measurementGate | Should -Be 'pass'
        (Test-Path -LiteralPath $state.c25Path) | Should -BeTrue
        (Test-Path -LiteralPath $state.measuredUsagePath) | Should -BeTrue

        $c25 = Get-Content -LiteralPath $state.c25Path -Raw | ConvertFrom-Json
        $c25.schema | Should -Be 'avd-benchmark-result/v1'
        $c25.profile.id | Should -Be 'multisession-density'
        $c25.verdict.experienceGate | Should -Be 'pass'

        $measured = Get-Content -LiteralPath $state.measuredUsagePath -Raw | ConvertFrom-Json
        $measured.schema | Should -Be 'avd-measured-usage/v1'
        $measured.tier | Should -Be 'tier-2-insights'
        $measured.producer.name | Should -Be 'avd-remediate'
        $measured.measurementGate.passed | Should -BeTrue
        @($measured.groups).Count | Should -Be 1
    }

    It 'refuses to write telemetry into a public avd-ops repository path' {
        $publicFake = Join-Path $TestDrive 'avd-remediate'
        New-Item -ItemType Directory -Path $publicFake -Force | Out-Null
        {
            & $script:TelemetryScript -VaultPath $publicFake -OfflineDemo
        } | Should -Throw "*Refusing to write telemetry into public avd-ops repository*"
    }
}

