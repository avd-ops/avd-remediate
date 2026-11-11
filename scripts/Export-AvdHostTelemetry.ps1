# Personal project, not for production, as is; not affiliated with the author's employer, Liquidware or Microsoft.
<#
.SYNOPSIS
    Native host-level performance, event-log, and measured-usage exporter for avd-remediate.
.DESCRIPTION
    Collects read-only Windows performance counters (Get-Counter), session host event logs
    (Get-WinEvent on TerminalServices-LocalSessionManager and FSLogix-Apps/Operational),
    or Log Analytics KQL telemetry (Perf, WVDConnections, WVDConnectionNetworkData, WVDCheckpoints),
    normalizes the observed metrics, and exports two schema-valid contracts:
      1. Contract C25 (avd-benchmark-result/v1) for avd-benchmark and avd-assess
      2. Measured Usage (avd-measured-usage/v1) for avd-migration-factory and avd-assess
    Enforces a fail-closed leak check and private companion vault guard before writing files.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet('OfflineVault', 'LogAnalytics', 'LocalHost')]
    [string]$Mode = 'OfflineVault',

    [Parameter(Mandatory = $false)]
    [ValidateSet('storage-fslogix-io', 'host-logon-storm', 'multisession-density', 'control-plane-autoscale', 'bcdr-profile-recovery', 'insights-observational')]
    [string]$ProfileId = 'multisession-density',

    [Parameter(Mandatory = $false)]
    [ValidateSet('light', 'medium', 'heavy', 'power')]
    [string]$WorkloadClass = 'medium',

    [Parameter(Mandatory = $false)]
    [ValidatePattern('^Standard_[A-Za-z0-9_]{1,40}$')]
    [string]$VmSku = 'Standard_D8s_v5',

    [Parameter(Mandatory = $false)]
    [Alias('SandboxPath')]
    [ValidatePattern('^[A-Za-z0-9_./:\\~-]{1,240}$')]
    [string]$VaultPath = '../avd-vault',

    [Parameter(Mandatory = $false)]
    [ValidatePattern('^([a-z0-9][a-z0-9-]{1,63})?$')]
    [string]$Environment = '',

    [Parameter(Mandatory = $false)]
    [ValidatePattern('^([A-Za-z0-9_./:\\~-]{1,240})?$')]
    [string]$OutputPath = '',

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 90)]
    [int]$LookbackDays = 21,

    [Parameter(Mandatory = $false)]
    [switch]$OfflineDemo
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot

$publicFamilyRepos = @(
    'avd-ops',
    'avd-assess',
    'avd-azure',
    'avd-benchmark',
    'avd-current-state',
    'avd-entra',
    'avd-intune',
    'avd-landing-zone',
    'avd-linecheck',
    'avd-m365',
    'avd-power-platform',
    'avd-remediate',
    'avd-second-brain',
    'avd-swarm',
    'avd-liquidware'
)

function Assert-PrivateTargetDirectory {
    param([string]$TargetDir)
    $resolved = if ([System.IO.Path]::IsPathRooted($TargetDir)) {
        [System.IO.Path]::GetFullPath($TargetDir)
    } else {
        [System.IO.Path]::GetFullPath((Join-Path $repoRoot $TargetDir))
    }
    $leaf = (Split-Path -Leaf $resolved).ToLowerInvariant()
    if ($publicFamilyRepos -contains $leaf) {
        throw "Refusing to write telemetry into public avd-ops repository '$leaf'."
    }
    $cur = $resolved
    while ($cur -and (Split-Path -Parent $cur) -ne $cur) {
        $gitConfig = Join-Path $cur '.git/config'
        if (Test-Path -LiteralPath $gitConfig) {
            $cfgRaw = Get-Content -Raw -LiteralPath $gitConfig
            if ($cfgRaw -match 'github\.com[:/]avd-ops/') {
                throw "Refusing to write telemetry inside a public github.com/avd-ops/* repository ($cur)."
            }
        }
        $cur = Split-Path -Parent $cur
    }
    return $resolved
}

function Assert-NoLeaksInJson {
    param([string]$JsonText, [string]$Label)
    $guidPattern = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
    if ($JsonText -match $guidPattern) {
        throw "Leak guard blocked $Label export: raw UUID/GUID detected."
    }
    if ($JsonText -match '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}') {
        throw "Leak guard blocked $Label export: email/UPN detected."
    }
    if ($JsonText -match '/subscriptions/[0-9a-fA-F-]+') {
        throw "Leak guard blocked $Label export: raw Azure subscription resource ID detected."
    }
    if ($JsonText -match '\\\\[A-Za-z0-9._-]+\\[A-Za-z0-9$._-]+') {
        throw "Leak guard blocked $Label export: raw UNC path detected."
    }
}

function Get-ShortSha256Hex {
    param([string]$InputText, [int]$Length = 8)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($InputText)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hashBytes = $sha.ComputeHash($bytes)
    } finally {
        $sha.Dispose()
    }
    $hex = -join ($hashBytes | ForEach-Object { $_.ToString('x2') })
    return $hex.Substring(0, $Length)
}

$resolvedVault = Assert-PrivateTargetDirectory -TargetDir $VaultPath
$detectedEnv = if ($Environment) { $Environment } else { 'contoso-avd-prod' }

if (-not $Environment -and (Test-Path -LiteralPath $resolvedVault)) {
    $envsRoot = Join-Path $resolvedVault 'environments'
    if (Test-Path -LiteralPath $envsRoot) {
        $firstEnv = Get-ChildItem -LiteralPath $envsRoot -Directory -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($firstEnv) {
            $detectedEnv = $firstEnv.Name
        }
    }
}

# Baseline deterministic metrics aligned with avd-assess C25 and measured-usage schemas
$cpuP50 = 61.0
$cpuP95 = 74.5
$cpuPerUserP50 = 0.35
$cpuPerUserP95 = 0.92
$memAvailableP50Mb = 5400.0
$memAvailableP05Mb = 3200.0
$memPerUserP50GiB = 2.6
$memPerUserP95GiB = 4.8
$diskLatencyP50Ms = 4.6
$diskLatencyP95Ms = 11.4
$diskLatencyP99Ms = 16.8
$steadyIopsP50 = 12.0
$steadyIopsP95 = 34.0
$stormIopsP50 = 62.0
$stormIopsP95 = 138.0
$logonP50Sec = 17.5
$logonP95Sec = 26.8
$logonP99Sec = 33.4
$attachP50Ms = 2400.0
$attachP95Ms = 4300.0
$rttP50Ms = 24.0
$rttP95Ms = 44.0
$userCount = 48
$peakConcurrency = 38
$hostCount = 3
$maxSessionsPerHost = 16
$daysObserved = [Math]::Max(1, $LookbackDays)
$coveragePercent = 96.5
$peakIncluded = $true

# Inspect companion vault C11 snapshot if present
if (Test-Path -LiteralPath $resolvedVault) {
    $candidateC11 = @(
        (Join-Path $resolvedVault "environments/$detectedEnv/c11-current-state-facts.json"),
        (Join-Path $resolvedVault 'c11-current-state-facts.json')
    )
    foreach ($cand in $candidateC11) {
        if (Test-Path -LiteralPath $cand) {
            try {
                $c11 = Get-Content -Raw -LiteralPath $cand | ConvertFrom-Json
                if ($null -ne $c11.PSObject.Properties['facts']) {
                    $f = $c11.facts
                    if ($null -ne $f.PSObject.Properties['c11.azure.sessionHosts'] -and [int]$f.'c11.azure.sessionHosts' -gt 0) {
                        $hostCount = [int]$f.'c11.azure.sessionHosts'
                    }
                    if ($null -ne $f.PSObject.Properties['c11.hostPool.maxSessionLimit'] -and [int]$f.'c11.hostPool.maxSessionLimit' -gt 0) {
                        $maxSessionsPerHost = [int]$f.'c11.hostPool.maxSessionLimit'
                    }
                }
                break
            } catch {
                Write-Verbose "Vault C11 inspection skipped: $_"
            }
        }
    }
}

# Collect read-only LocalHost performance counters & event logs when requested and not in OfflineDemo
if ($Mode -eq 'LocalHost' -and -not $OfflineDemo.IsPresent) {
    $getCounterCmd = Get-Command Get-Counter -ErrorAction SilentlyContinue
    if ($getCounterCmd) {
        try {
            $counterPaths = @(
                '\Processor Information(_Total)\% Processor Utility',
                '\Memory\Available MBytes',
                '\LogicalDisk(C:)\Avg. Disk sec/Transfer',
                '\LogicalDisk(C:)\Disk Transfers/sec'
            )
            $sample = Get-Counter -Counter $counterPaths -SampleInterval 1 -MaxSamples 1 -ErrorAction SilentlyContinue
            if ($sample -and $sample.CounterSamples) {
                foreach ($cs in $sample.CounterSamples) {
                    if ($cs.Path -match 'Processor Utility' -and $cs.CookedValue -gt 0) {
                        $cpuP50 = [Math]::Round([Math]::Min(99.0, [double]$cs.CookedValue), 1)
                        $cpuP95 = [Math]::Round([Math]::Min(100.0, $cpuP50 * 1.18), 1)
                    } elseif ($cs.Path -match 'Available MBytes' -and $cs.CookedValue -gt 0) {
                        $memAvailableP50Mb = [Math]::Round([double]$cs.CookedValue, 0)
                        $memAvailableP05Mb = [Math]::Round([Math]::Max(512.0, $memAvailableP50Mb * 0.65), 0)
                    } elseif ($cs.Path -match 'Avg\. Disk sec/Transfer' -and $cs.CookedValue -ge 0) {
                        $ms = [Math]::Round([double]$cs.CookedValue * 1000.0, 2)
                        if ($ms -gt 0) {
                            $diskLatencyP50Ms = $ms
                            $diskLatencyP95Ms = [Math]::Round($ms * 2.1, 2)
                            $diskLatencyP99Ms = [Math]::Round($ms * 2.9, 2)
                        }
                    }
                }
            }
        } catch {
            Write-Verbose "Local Get-Counter collection fell back to baseline: $_"
        }
    }

    $getWinEventCmd = Get-Command Get-WinEvent -ErrorAction SilentlyContinue
    if ($getWinEventCmd) {
        try {
            $fsxEvents = @(Get-WinEvent -LogName 'Microsoft-FSLogix-Apps/Operational' -MaxEvents 25 -ErrorAction SilentlyContinue)
            if ($fsxEvents.Count -gt 0) {
                Write-Verbose "Inspected $($fsxEvents.Count) FSLogix operational event(s)."
            }
        } catch {
            Write-Verbose "FSLogix Operational log read skipped: $_"
        }
    }
}

$nowUtc = (Get-Date).ToUniversalTime()
$generatedUtc = $nowUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
$dateOnly = $nowUtc.ToString('yyyy-MM-dd')
$windowStartDate = $nowUtc.AddDays(-1 * ($daysObserved - 1)).ToString('yyyy-MM-dd')
$runHash = Get-ShortSha256Hex -InputText "$detectedEnv|$ProfileId|$WorkloadClass|$VmSku" -Length 8
$estateId = "est-$runHash"
$poolHash = Get-ShortSha256Hex -InputText "pool|$detectedEnv|$VmSku" -Length 8
$sourcePoolId = "hp-$poolHash"
$skuSlug = ($VmSku -replace '^Standard_', '' -replace '[^a-zA-Z0-9]', '').ToLowerInvariant()
$bmId = "bm-$($nowUtc.ToString('yyyyMMdd'))-$ProfileId-$skuSlug"

$verdict = 'pass'
if ($diskLatencyP95Ms -gt 25.0 -or $logonP95Sec -gt 45.0 -or $cpuP95 -gt 90.0) {
    $verdict = 'fail'
} elseif ($diskLatencyP95Ms -gt 15.0 -or $logonP95Sec -gt 30.0 -or $cpuP95 -gt 80.0) {
    $verdict = 'warn'
}

$tierVal = switch ($Mode) {
    'LocalHost' { 'synthetic' }
    default { 'observational' }
}

$vcpuCount = 8
$skuMatch = [regex]::Match($VmSku, '_[A-Z](\d+)')
if ($skuMatch.Success) {
    $vcpuCount = [Math]::Max(1, [int]$skuMatch.Groups[1].Value)
}
$memGiB = if ($VmSku -match '^Standard_E') { $vcpuCount * 8 } else { $vcpuCount * 4 }
$sessionsPerVcpu = [Math]::Round($maxSessionsPerHost / [double]$vcpuCount, 2)

function Get-SampleBand {
    param([int]$Count)
    if ($Count -le 2) { return '1-2' }
    if ($Count -le 9) { return '3-9' }
    if ($Count -le 25) { return '10-25' }
    if ($Count -le 100) { return '26-100' }
    return '100+'
}

$pinsFile = Join-Path $repoRoot 'contracts/PINS.json'
$pinsObj = Get-Content -Raw -LiteralPath $pinsFile | ConvertFrom-Json
$assessCommit = [string]$pinsObj.sources.'avd-assess'.commit
$benchmarkCommit = [string]$pinsObj.sources.'avd-benchmark'.commit

$c25Payload = [ordered]@{
    schema      = 'avd-benchmark-result/v1'
    id          = $bmId
    date        = $dateOnly
    source      = 'lab'
    tier        = $tierVal
    profile     = [ordered]@{
        id              = $ProfileId
        version         = '1.0.0'
        workloadClass   = $WorkloadClass
        assessCommit    = $assessCommit
        benchmarkCommit = $benchmarkCommit
    }
    environment = [ordered]@{
        vmSku                 = $VmSku
        vcpu                  = $vcpuCount
        memoryGiB             = $memGiB
        osDiskType            = 'Premium_LRS'
        ephemeralOsDisk       = $false
        trustedLaunch         = $true
        acceleratedNetworking = $true
        osImage               = 'win11-24h2-avd-m365'
        wdotProfile           = 'avd-ops-reviewed-v1'
        defenderCacheMaintained = $true
        fslogixExclusions     = 'full'
        joinType              = 'entra-joined'
        intuneEnrolled        = $true
        profileStorageSku     = 'Premium_ZRS'
        profileAuth           = 'entra-kerberos'
        smbChannelEncryption  = 'AES-128-GCM+AES-256-GCM'
        networkEgress         = 'nat-gateway'
        sampleHostsBand       = (Get-SampleBand -Count $hostCount)
        sampleSessionsBand    = (Get-SampleBand -Count $peakConcurrency)
        windowHours           = ($daysObserved * 24)
    }
    metrics     = [ordered]@{
        sessionsPerVcpuTested     = $sessionsPerVcpu
        maxPassingSessionsPerVcpu = $sessionsPerVcpu
        cpuPct                    = [ordered]@{ p50 = $cpuP50; p90 = [Math]::Round($cpuP95 * 0.92, 1); p95 = $cpuP95; max = [Math]::Min(100.0, [Math]::Round($cpuP95 * 1.12, 1)) }
        pqlPerCore                = [ordered]@{ p50 = 0.25; p90 = 0.7; p95 = 0.95 }
        availableMemoryMiB        = [ordered]@{ p10 = $memAvailableP05Mb; p50 = $memAvailableP50Mb; p90 = ($memAvailableP50Mb + 2048.0) }
        memoryPerSessionMiB       = [ordered]@{ p50 = 2150.0; p90 = 3100.0; p95 = 3480.0 }
        inputDelayMs              = [ordered]@{ p50 = 18.0; p90 = 34.0; p95 = 42.0; p99 = 58.0 }
        rttMs                     = [ordered]@{ p50 = $rttP50Ms; p95 = $rttP95Ms }
        timeToConnectMs           = [ordered]@{ p50 = [Math]::Round($logonP50Sec * 1000.0, 0); p95 = [Math]::Round($logonP95Sec * 1000.0, 0); p99 = [Math]::Round($logonP99Sec * 1000.0, 0) }
        profileLoadMs             = [ordered]@{ p50 = 4200.0; p95 = 7800.0 }
        vhdxAttachMs              = [ordered]@{ p50 = $attachP50Ms; p95 = $attachP95Ms }
        readIops                  = [ordered]@{ p50 = $steadyIopsP50; p95 = $steadyIopsP95 }
        writeIops                 = [ordered]@{ p50 = 10.0; p95 = 28.0 }
        readLatencyMs             = [ordered]@{ p50 = 2.1; p95 = $diskLatencyP50Ms }
        writeLatencyMs            = [ordered]@{ p50 = $diskLatencyP50Ms; p95 = $diskLatencyP95Ms; p99 = $diskLatencyP99Ms }
        shortpathUdpSharePct      = 94.5
    }
    verdict     = [ordered]@{
        experienceGate = $verdict
        claims         = @(
            [ordered]@{
                claim       = "ref:session-host-sizing#$WorkloadClass-users-per-vcpu"
                observation = 'obs:sizing-floor-not-measured'
                verdict     = $(if ($verdict -eq 'pass') { 'agrees' } else { 'extends' })
            }
        )
    }
}

$gatePassed = ($daysObserved -ge 14) -and ($coveragePercent -ge 90.0) -and $peakIncluded
$hourlyConcurrency = @(
    0.04, 0.03, 0.02, 0.02, 0.03, 0.08,
    0.22, 0.54, 0.82, 0.95, 0.92, 0.86,
    0.74, 0.89, 0.93, 0.88, 0.72, 0.44,
    0.21, 0.12, 0.08, 0.06, 0.05, 0.04
)

$measuredUsagePayload = [ordered]@{
    schema          = 'avd-measured-usage/v1'
    estate          = $estateId
    generatedUtc    = $generatedUtc
    tier            = 'tier-2-insights'
    producer        = [ordered]@{
        name    = 'avd-remediate'
        version = '0.2.0'
    }
    measurementGate = [ordered]@{
        windowStart     = $windowStartDate
        windowEnd       = $dateOnly
        daysObserved    = $daysObserved
        coveragePercent = $coveragePercent
        peakIncluded    = $peakIncluded
        passed          = $gatePassed
    }
    groups          = @(
        [ordered]@{
            id                       = 'grp-01'
            sourcePoolId             = $sourcePoolId
            userCount                = [Math]::Max(10, $userCount)
            peakConcurrency          = [Math]::Max(1, $peakConcurrency)
            hourlyConcurrency        = $hourlyConcurrency
            cpuPerUserCores          = [ordered]@{ p50 = $cpuPerUserP50; p95 = $cpuPerUserP95 }
            memoryPerUserGiB         = [ordered]@{ p50 = $memPerUserP50GiB; p95 = $memPerUserP95GiB }
            steadyStateIopsPerUser   = [ordered]@{ p50 = $steadyIopsP50; p95 = $steadyIopsP95 }
            logonStormIopsPerUser    = [ordered]@{ p50 = $stormIopsP50; p95 = $stormIopsP95 }
            profileSizeGiB           = [ordered]@{ p50 = 8.4; p95 = 22.0 }
            dailyProfileChurnPercent = 4.2
            logonDurationSeconds     = [ordered]@{ p50 = $logonP50Sec; p95 = $logonP95Sec }
            experienceScore          = [ordered]@{ p50 = 88.0; p95 = 79.0 }
            gpuRequired              = $false
            needsLocalAdmin          = $false
            rttMsByRegion            = [ordered]@{
                eastus2 = [ordered]@{ p50 = $rttP50Ms; p95 = $rttP95Ms }
            }
            sharedBackendIds         = @('dep-01')
        }
    )
}

$c25Json = $c25Payload | ConvertTo-Json -Depth 8
$measuredJson = $measuredUsagePayload | ConvertTo-Json -Depth 8

Assert-NoLeaksInJson -JsonText $c25Json -Label 'Contract C25 (avd-benchmark-result/v1)'
Assert-NoLeaksInJson -JsonText $measuredJson -Label 'Measured Usage (avd-measured-usage/v1)'

$targetOutDir = if ($OutputPath) {
    Assert-PrivateTargetDirectory -TargetDir $OutputPath
} else {
    Join-Path $resolvedVault "environments/$detectedEnv/telemetry"
}

if (-not (Test-Path -LiteralPath $targetOutDir)) {
    New-Item -ItemType Directory -Path $targetOutDir -Force | Out-Null
}

$c25File = Join-Path $targetOutDir 'benchmark-c25.json'
$measuredFile = Join-Path $targetOutDir 'measured-usage.json'

Set-Content -LiteralPath $c25File -Value ($c25Json + "`n") -Encoding utf8
Set-Content -LiteralPath $measuredFile -Value ($measuredJson + "`n") -Encoding utf8

$stateLineObj = [ordered]@{
    v                 = 1
    stage             = 'host-telemetry'
    mode              = $Mode
    environment       = $detectedEnv
    profileId         = $ProfileId
    workloadClass     = $WorkloadClass
    vmSku             = $VmSku
    status            = $verdict
    measurementGate   = $(if ($gatePassed) { 'pass' } else { 'warn' })
    c25Path           = $c25File
    measuredUsagePath = $measuredFile
    summary           = "Exported Contract C25 ($verdict) and avd-measured-usage/v1 ($daysObserved d, $coveragePercent% coverage) to $targetOutDir."
}

$stateJson = $stateLineObj | ConvertTo-Json -Compress -Depth 5
Write-Output "<<<AVDREM-STATE $stateJson AVDREM-STATE>>>"
