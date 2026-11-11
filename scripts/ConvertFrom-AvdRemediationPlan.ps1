# Personal project, not for production use. Provided as is, without warranty of any kind (MIT License, see LICENSE). Not affiliated with the author's employer, Liquidware or Microsoft.
<#
.SYNOPSIS
    Converts a C24 (avd-remediation-plan/v1) remediation plan from avd-remediate or avd-current-state
    into the 3-stage avd-landing-zone control-plane orchestrator and Bicep parameter commands.
.DESCRIPTION
    Validates the input JSON against contracts/schemas/remediation-plan.schema.json, resolves each
    item's control plane against contracts/control-planes.json (Stage 1: entra -> Stage 2: intune, m365, azure
    -> Stage 3: power-platform) and contracts/lz-parameters.json, prints a self-contained Cloud Shell
    remediation block, and emits a machine-readable <<<AVDREM-STATE ...>>> line. Changes nothing in Azure.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9_./:\\~-]{1,240}$')]
    [string]$Path,

    [Parameter(Mandatory = $false)]
    [ValidatePattern('^[A-Za-z0-9_./:\\~-]{1,240}$')]
    [string]$LandingZonePath = '../avd-landing-zone',

    [Parameter(Mandatory = $false)]
    [ValidatePattern('^[A-Za-z0-9_./:\\~-]{1,240}$')]
    [string]$ParameterFile = 'parameters/dev.bicepparam'
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$schemaFile = Join-Path $repoRoot 'contracts/schemas/remediation-plan.schema.json'
$cpFile = Join-Path $repoRoot 'contracts/control-planes.json'

if (-not (Test-Path -LiteralPath $Path)) {
    throw "Remediation plan not found at '$Path'."
}

$rawJson = Get-Content -Raw -LiteralPath $Path
if (Get-Command Test-Json -ErrorAction SilentlyContinue) {
    $errs = $null
    if (-not (Test-Json -Json $rawJson -SchemaFile $schemaFile -ErrorAction SilentlyContinue -ErrorVariable errs)) {
        $msg = (@($errs) | ForEach-Object { $_.Exception.Message } | Select-Object -First 2) -join ' | '
        throw "C24 plan at '$Path' does not conform to remediation-plan.schema.json: $msg"
    }
}

$plan = $rawJson | ConvertFrom-Json
if ($plan.schema -ne 'avd-remediation-plan/v1') {
    throw "Expected schema 'avd-remediation-plan/v1', got '$($plan.schema)'."
}

$cp = Get-Content -Raw -LiteralPath $cpFile | ConvertFrom-Json
$planeMap = @{}
foreach ($prop in $cp.planes.PSObject.Properties) {
    $planeMap[[string]$prop.Name] = $prop.Value
}

$items = @(if ($null -ne $plan.PSObject.Properties['items']) { $plan.items })
$planesUsed = [System.Collections.Generic.List[string]]::new()
$bicepFlags = [System.Collections.Generic.List[string]]::new()
$stageCommands = [System.Collections.Generic.List[object]]::new()

foreach ($it in $items) {
    $itemPlane = if ($null -ne $it.PSObject.Properties['plane'] -and $it.plane) { [string]$it.plane } else { 'azure' }
    if (-not $planesUsed.Contains($itemPlane) -and $planeMap.ContainsKey($itemPlane)) {
        $planesUsed.Add($itemPlane)
        $pDef = $planeMap[$itemPlane]
        $stageNum = if ($itemPlane -eq 'entra') { 1 } elseif ($itemPlane -eq 'power-platform') { 3 } else { 2 }
        $stageCommands.Add([ordered]@{
            stage               = $stageNum
            plane               = $itemPlane
            repo                = [string]$pDef.repo
            deployEntrypoint    = [string]$pDef.entryPoint
            manifest            = [string]$pDef.handoffManifest
            orchestratorCommand = "./scripts/deploy/Invoke-AvdControlPlanes.ps1 -Planes $itemPlane -DryRun"
        })
    }

    if ($null -ne $it.PSObject.Properties['change'] -and $it.change) {
        $chg = $it.change
        if ($chg.kind -eq 'lz-parameter' -and $chg.name -and $null -ne $chg.PSObject.Properties['to']) {
            $paramName = [string]$chg.name
            $toVal = $chg.to
            switch ($paramName) {
                'sessionHostVmSize' { $bicepFlags.Add("--vm-size '$toVal'") }
                'sessionHostCount'  { $bicepFlags.Add("--host-count $toVal") }
                'maxSessionLimit'   { $bicepFlags.Add("--max-sessions $toVal") }
                'profileQuotaGiB'   { $bicepFlags.Add("--profile-quota-gib $toVal") }
                default             { $bicepFlags.Add("# parameter $paramName = $($toVal | ConvertTo-Json -Compress)") }
            }
        }
    }
}

$orderedStages = @($stageCommands | Sort-Object stage)
$orderedPlanes = @($orderedStages | ForEach-Object { $_.plane } | Select-Object -Unique)
$orchestratorDryRun = if ($orderedPlanes.Count -gt 0) {
    "./scripts/deploy/Invoke-AvdControlPlanes.ps1 -Planes $($orderedPlanes -join ',') -DryRun"
} else {
    './scripts/deploy/Invoke-AvdControlPlanes.ps1 -DryRun'
}

$lines = [System.Collections.Generic.List[string]]::new()
$lines.Add("# avd-landing-zone C24 remediation plan execution block (estate: $($plan.estate))")
$lines.Add("Set-Location '$LandingZonePath'")
$lines.Add($orchestratorDryRun)
foreach ($st in $orderedStages) {
    $lines.Add("# Stage $($st.stage) ($($st.plane) -> $($st.repo)): $($st.deployEntrypoint) (manifest: $($st.manifest))")
}
if ($bicepFlags.Count -gt 0) {
    $lines.Add("# Bicep parameter / deploy.sh overrides ($ParameterFile):")
    foreach ($flag in $bicepFlags) {
        $lines.Add("#   $flag")
    }
}

$blockText = $lines -join "`n"
Write-Output $blockText

$state = [ordered]@{
    v                  = 1
    stage              = 'c24-bridge'
    schema             = $plan.schema
    estate             = $plan.estate
    itemCount          = $items.Count
    planes             = $orderedPlanes
    controlPlaneStages = $orderedStages
    bicepOverrides     = @($bicepFlags)
    orchestratorDryRun = $orchestratorDryRun
    status             = 'pass'
    summary            = "Validated C24 plan for estate '$($plan.estate)' ($($items.Count) item(s) across plane(s): $($orderedPlanes -join ', '))."
}

$json = $state | ConvertTo-Json -Compress -Depth 6
Write-Output "<<<AVDREM-STATE $json AVDREM-STATE>>>"
