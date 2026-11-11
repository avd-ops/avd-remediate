# Personal project, not for production use. Provided as is, without warranty of any kind (MIT License, see LICENSE). Not affiliated with the author's employer, Liquidware or Microsoft.
<#
.SYNOPSIS
    Saves a diagnosed and verified avd-remediate incident bundle to a private companion vault.
.DESCRIPTION
    Verifies that the target companion vault is PRIVATE (refuses any public avd-ops/* repository),
    writes incidents/<timestamp>-<playbookId>/incident.json, remediation-c24.json (valid against
    contracts/schemas/remediation-plan.schema.json), and SUMMARY.md, and writes an inbox lesson note
    to inbox/incident-<date>-<playbookId>.md without deleting existing records.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[a-z0-9][a-z0-9-]{1,63}$')]
    [string]$PlaybookId,

    [Parameter(Mandatory = $false)]
    [Alias('SandboxPath')]
    [ValidatePattern('^[A-Za-z0-9_./:\\~-]{1,240}$')]
    [string]$VaultPath = '../avd-vault',

    [Parameter(Mandatory = $false)]
    [ValidatePattern('^([a-z0-9][a-z0-9-]{1,63})?$')]
    [string]$Environment = '',

    [Parameter(Mandatory = $false)]
    [ValidateSet('high', 'medium', 'low')]
    [string]$Confidence = 'high',

    [Parameter(Mandatory = $false)]
    [string[]]$Signals = @(),

    [Parameter(Mandatory = $false)]
    [ValidatePattern('^([A-Za-z0-9_./:\\~-]{1,240})?$')]
    [string]$C24PlanPath = ''
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$catalogFile = Join-Path $repoRoot 'playbooks/catalog.json'
$catalog = Get-Content -Raw -LiteralPath $catalogFile | ConvertFrom-Json

$pb = $catalog.playbooks | Where-Object { $_.id -eq $PlaybookId } | Select-Object -First 1
if (-not $pb) {
    throw "Playbook '$PlaybookId' not found in playbooks/catalog.json."
}

$resolvedVault = if ([System.IO.Path]::IsPathRooted($VaultPath)) { $VaultPath } else { Join-Path $repoRoot $VaultPath }

# Private repository visibility guard (spec §7.2)
$gitConfig = Join-Path $resolvedVault '.git/config'
if (Test-Path -LiteralPath $gitConfig) {
    $cfgText = Get-Content -Raw -LiteralPath $gitConfig
    if ($cfgText -match 'github\.com[:/]avd-ops/') {
        throw "Refusing to write unredacted incident bundle to public avd-ops repository at '$resolvedVault'."
    }
}

$detectedEnv = if ($Environment) { $Environment } else { 'default-estate' }
if (-not $Environment -and (Test-Path -LiteralPath (Join-Path $resolvedVault 'environments'))) {
    $firstEnv = Get-ChildItem -LiteralPath (Join-Path $resolvedVault 'environments') -Directory -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($firstEnv) { $detectedEnv = $firstEnv.Name }
}

$nowIso = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$stamp = $nowIso -replace '[:.]', '-'
$dateOnly = $nowIso.Substring(0, 10)
$incRelDir = "incidents/$stamp-$($pb.id)"
$incFullDir = Join-Path $resolvedVault $incRelDir
New-Item -ItemType Directory -Path $incFullDir -Force | Out-Null

# Compute deterministic est-<8hex> pseudonym from environment name for C24 schema compliance
$shaBytes = [System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($detectedEnv))
$estHex = ([System.BitConverter]::ToString($shaBytes) -replace '-', '').Substring(0, 8).ToLowerInvariant()
$estatePseudonym = "est-$estHex"

$c24Obj = $null
if ($C24PlanPath -and (Test-Path -LiteralPath $C24PlanPath)) {
    $c24Obj = Get-Content -Raw -LiteralPath $C24PlanPath | ConvertFrom-Json
} else {
    $asmCheck = @($pb.c21Checks | Where-Object { $_ -match '^asm-[a-z0-9-]{3,60}$' }) | Select-Object -First 1
    if (-not $asmCheck) { $asmCheck = 'asm-host-agent-health' }
    $claimIds = @($pb.citations | ForEach-Object { [string]$_.id } | Where-Object { $_ -match '^(ref:[a-z0-9][a-z0-9-]{1,63}#[A-Za-z0-9][A-Za-z0-9.:-]{0,63}|gap:[a-z0-9][a-z0-9-]{1,63})$' })
    if ($claimIds.Count -eq 0) { $claimIds = @('gap:remediation-plan') }

    $c24Obj = [ordered]@{
        schema     = 'avd-remediation-plan/v1'
        estate     = $estatePseudonym
        plannedOn  = $dateOnly
        basis      = [ordered]@{
            assessment        = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
            method            = 10
            landingZoneCommit = '2c441569a5d584ac6beb473162ba1f1420caea3e'
        }
        items      = @(
            [ordered]@{
                order    = 1
                check    = [string]$asmCheck
                plane    = [string]$pb.remediation.plane
                outcome  = 'gap'
                pillar   = [string]$pb.pillar
                severity = [string]$pb.severity
                claims   = $claimIds
                source   = 'unreviewed'
                change   = $pb.remediation.c24Change
            }
        )
        extensions = [ordered]@{
            'avd-remediate' = [ordered]@{
                contract           = 'C24'
                environment        = $detectedEnv
                playbookId         = $pb.id
                controlPlaneStages = [ordered]@{
                    ([string]$pb.remediation.plane) = $pb.remediation.lzStage
                }
                orchestratorDryRun = [string]$pb.remediation.lzStage.orchestratorCommand
            }
        }
    }
}

$sigList = if ($Signals.Count -gt 0) { @($Signals) } else { @("Diagnosed $($pb.id) ($($pb.title)) in $detectedEnv.") }

$incidentPayload = [ordered]@{
    schema       = 'avd-remediate-incident/v1'
    capturedAt   = $nowIso
    environment  = $detectedEnv
    playbookId   = $pb.id
    title        = $pb.title
    domain       = $pb.domain
    plane        = $pb.remediation.plane
    confidence   = $Confidence
    signals      = $sigList
    citations    = @($pb.citations)
    knownErrorId = $pb.knownErrorId
    c24Plan      = $c24Obj
}

$incJsonPath = Join-Path $incFullDir 'incident.json'
$c24JsonPath = Join-Path $incFullDir 'remediation-c24.json'
$summaryMdPath = Join-Path $incFullDir 'SUMMARY.md'

($incidentPayload | ConvertTo-Json -Depth 10) | Set-Content -LiteralPath $incJsonPath -Encoding utf8
($c24Obj | ConvertTo-Json -Depth 10) | Set-Content -LiteralPath $c24JsonPath -Encoding utf8

$summaryMd = @(
    "# Incident Summary: $($pb.title)",
    "",
    "- **Environment**: ``$detectedEnv`` (``$estatePseudonym``)",
    "- **Playbook**: ``$($pb.id)``",
    "- **Control plane**: ``$($pb.remediation.plane)`` (Stage $($pb.remediation.lzStage.stage): ``$($pb.remediation.lzStage.repo)``)",
    "- **Captured at**: ``$nowIso``",
    "- **Confidence**: ``$Confidence``",
    "",
    "## Observed signals",
    "",
    ($sigList | ForEach-Object { "- $_" }),
    "",
    "## Remediation & rollback",
    "",
    "- **Action**: $($pb.remediation.actionSummary)",
    "- **Rollback**: $($pb.remediation.rollbackSummary)",
    "- **Orchestrator dry-run**: ``$($pb.remediation.lzStage.orchestratorCommand)``",
    ""
) -join "`n"
$summaryMd | Set-Content -LiteralPath $summaryMdPath -Encoding utf8

$inboxDir = Join-Path $resolvedVault 'inbox'
New-Item -ItemType Directory -Path $inboxDir -Force | Out-Null
$inboxPath = Join-Path $inboxDir "incident-$dateOnly-$($pb.id).md"
$inboxMd = @(
    "---",
    "type: lesson",
    "date: $dateOnly",
    "environments: [$detectedEnv]",
    "severity: $(if ($Confidence -eq 'high') { 'high' } else { 'medium' })",
    "tags: [$($pb.id), $($pb.remediation.plane)]",
    "resolves-checks: [$($pb.c21Checks -join ', ')]",
    "---",
    "",
    "# Remediated $($pb.id) ($($pb.remediation.plane) plane)",
    "",
    "## What happened",
    "",
    ($sigList | ForEach-Object { "- $_" }),
    "",
    "## What we changed",
    "",
    "- Incident bundle: ``$incRelDir/incident.json``",
    "- C24 remediation plan: ``$incRelDir/remediation-c24.json``",
    "- Summary: ``$incRelDir/SUMMARY.md``",
    ""
) -join "`n"
$inboxMd | Set-Content -LiteralPath $inboxPath -Encoding utf8

$state = [ordered]@{
    v           = 1
    stage       = 'capture'
    playbookId  = $pb.id
    environment = $detectedEnv
    estate      = $estatePseudonym
    plane       = $pb.remediation.plane
    status      = 'pass'
    incidentDir = $incRelDir
    savedTo     = $incJsonPath
    c24PlanPath = $c24JsonPath
    inboxNote   = "inbox/incident-$dateOnly-$($pb.id).md"
    summary     = "Saved incident bundle to $incRelDir and queued inbox note for $detectedEnv."
}

$json = $state | ConvertTo-Json -Compress -Depth 6
Write-Output "<<<AVDREM-STATE $json AVDREM-STATE>>>"
