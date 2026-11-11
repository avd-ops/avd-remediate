# Personal project, not for production, as is; not affiliated with the author's employer, Liquidware or Microsoft.
<#
.SYNOPSIS
    Read-only diagnostic probe runner for avd-remediate across all 5 control planes.
.DESCRIPTION
    Executes only allowlisted read-only checks from rebuild/scope.json (GET, KQL project/summarize, Get-*),
    validates that no write scope is present, evaluates companion vault C11/C21/inventory state and optional live
    Azure CLI read-only queries, and emits a machine-readable <<<AVDREM-STATE ...>>> line.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[a-z0-9][a-z0-9-]{1,63}$')]
    [string]$ProbeId,

    [Parameter(Mandatory = $false)]
    [Alias('SandboxPath')]
    [ValidatePattern('^[A-Za-z0-9_./:\\~-]{1,240}$')]
    [string]$VaultPath = '../avd-vault',

    [Parameter(Mandatory = $false)]
    [ValidatePattern('^([a-z0-9][a-z0-9-]{1,63})?$')]
    [string]$Environment = '',

    [Parameter(Mandatory = $false)]
    [ValidatePattern('^([A-Za-z0-9_./:\\~-]{1,240})?$')]
    [string]$C11Path = '',

    [Parameter(Mandatory = $false)]
    [ValidatePattern('^([A-Za-z0-9_./:\\~-]{1,240})?$')]
    [string]$C21Path = '',

    [Parameter(Mandatory = $false)]
    [ValidatePattern('^([A-Za-z0-9_.-]{1,120})?$')]
    [string]$WorkspaceId = '',

    [Parameter(Mandatory = $false)]
    [string[]]$TokenScopes = @(),

    [Parameter(Mandatory = $false)]
    [string]$ScopePath = '',

    [Parameter(Mandatory = $false)]
    [switch]$OfflineDemo
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$scopeFile = if ($ScopePath) { $ScopePath } else { Join-Path $repoRoot 'rebuild/scope.json' }
$catalogFile = Join-Path $repoRoot 'playbooks/catalog.json'
$scope = Get-Content -Raw -LiteralPath $scopeFile | ConvertFrom-Json
$catalog = Get-Content -Raw -LiteralPath $catalogFile | ConvertFrom-Json

if (-not ($scope.probes.PSObject.Properties.Name -contains $ProbeId)) {
    throw "Probe '$ProbeId' is not listed in rebuild/scope.json."
}

$probeMeta = $scope.probes.$ProbeId
$matchedPlaybook = $catalog.playbooks | Where-Object { $_.probeId -eq $ProbeId } | Select-Object -First 1
$playbookId = if ($matchedPlaybook) { [string]$matchedPlaybook.id } else { '' }

# 1. Read-only method and command verb assertions
if ($probeMeta.method -ne 'GET') {
    throw "Probe '$ProbeId' violates the read-only GET requirement."
}
if ($probeMeta.command -match '\b(post|put|patch|delete|set-|new-|remove-|update-|invoke-wmimethod)\b') {
    throw "Probe '$ProbeId' command '$($probeMeta.command)' contains a forbidden non-read-only verb."
}

# 2. Forbidden write-scope guard
foreach ($forbidden in $scope.forbiddenTokenScopes) {
    foreach ($activeScope in $TokenScopes) {
        if ($activeScope -match [regex]::Escape($forbidden)) {
            throw "Refusing to run diagnostic probe '$ProbeId' with write-capable token scope '$activeScope' (forbidden: $forbidden)."
        }
    }
}

$legacyCheckAliases = @{
    'asm-intune-rdp-shortpath'           = 'CP-INTUNE-002'
    'asm-net-shortpath'                  = 'UX-001'
    'asm-entra-files-kerberos-ready'     = 'CP-ENTRA-001'
    'asm-intune-session-limits'          = 'CP-INTUNE-002'
    'asm-m365-outlook-cache'             = 'CP-M365-002'
    'asm-host-pool-capacity'             = 'RES-004'
    'asm-entra-sso-enabled'              = 'SEC-002'
    'asm-intune-hosts-compliant'         = 'CP-INTUNE-003'
    'asm-intune-hosts-managed'           = 'CP-INTUNE-001'
    'asm-intune-fslogix-catalog-profile' = 'CP-INTUNE-002'
    'asm-m365-teams-vdi-optimization'    = 'CP-M365-003'
    'asm-m365-onedrive-kfm'              = 'CP-M365-002'
    'asm-m365-shared-computer-activation'= 'CP-M365-001'
    'asm-pp-dedicated-environment'       = 'CP-PP-001'
    'asm-pp-dlp-blocks-unapproved'       = 'CP-PP-002'
    'asm-pp-vnet-enterprise-policy'      = 'CP-PP-003'
}

function Get-FactValue {
    param($C11Obj, [string]$FactPath)
    if ($null -eq $C11Obj) { return $null }
    if ($null -ne $C11Obj.PSObject.Properties[$FactPath]) { return $C11Obj.$FactPath }
    if ($null -ne $C11Obj.PSObject.Properties['facts'] -and $null -ne $C11Obj.facts -and $null -ne $C11Obj.facts.PSObject.Properties[$FactPath]) {
        return $C11Obj.facts.$FactPath
    }
    if ($null -ne $C11Obj.PSObject.Properties['subscriptions'] -and @($C11Obj.subscriptions).Count -gt 0) {
        $sub0 = @($C11Obj.subscriptions)[0]
        $hp0 = if ($null -ne $sub0.PSObject.Properties['hostPools'] -and @($sub0.hostPools).Count -gt 0) { @($sub0.hostPools)[0] } else { [pscustomobject]@{} }
        $pp = if ($null -ne $sub0.PSObject.Properties['powerPlatform']) { $sub0.powerPlatform } else { [pscustomobject]@{} }
        switch ($FactPath) {
            'c11.hostPool.name' { return $hp0.name }
            'c11.hostPool.type' { return $hp0.type }
            'c11.hostPool.loadBalancerType' { return $hp0.loadBalancer }
            'c11.hostPool.maxSessionLimit' { return $hp0.maxSessionLimit }
            'c11.hostPool.startVmOnConnect' { return $hp0.startVmOnConnect }
            'c11.hostPool.entraSso' { return $hp0.entraSso }
            'c11.intune.rdpShortpathConfigured' { if ($null -ne $hp0.PSObject.Properties['udpShortpath']) { return [bool]$hp0.udpShortpath.configured } }
            'c11.intune.sessionTimeLimitsConfigured' { if ($null -ne $hp0.PSObject.Properties['sessionLimits']) { return [bool]($hp0.sessionLimits.disconnectedMinutes -or $hp0.sessionLimits.idleMinutes) } }
            'c11.entra.kerberosStoragePrincipalsReady' { if ($null -ne $hp0.PSObject.Properties['entra'] -and $null -ne $hp0.entra.PSObject.Properties['kerberosStoragePrincipalsReady']) { return $hp0.entra.kerberosStoragePrincipalsReady } }
            'c11.entra.caAvdRequiresCompliantDevice' { if ($null -ne $hp0.PSObject.Properties['entra']) { return $hp0.entra.caAvdRequiresCompliantDevice } }
            'c11.hostPool.sessionHosts.unhealthy' { if ($null -ne $hp0.PSObject.Properties['sessionHosts']) { return $hp0.sessionHosts.unhealthy } }
            'c11.hostPool.sessionHosts.drained' { if ($null -ne $hp0.PSObject.Properties['sessionHosts']) { return $hp0.sessionHosts.drained } }
            'c11.hostPool.sessionHosts.intuneNoncompliant' { if ($null -ne $hp0.PSObject.Properties['sessionHosts']) { return $hp0.sessionHosts.intuneNoncompliant } }
            'c11.hostPool.sessionHosts.intuneConfigErrors' { if ($null -ne $hp0.PSObject.Properties['sessionHosts']) { return $hp0.sessionHosts.intuneConfigErrors } }
            'c11.intune.multiSessionCatalogProfiles' { if ($null -ne $hp0.PSObject.Properties['intune']) { return $hp0.intune.multiSessionCatalogProfiles } }
            'c11.m365.teamsMediaOptimizationState' { if ($null -ne $hp0.PSObject.Properties['m365']) { return $hp0.m365.teamsMediaOptimizationState } }
            'c11.m365.oneDriveKfmState' { if ($null -ne $hp0.PSObject.Properties['m365']) { return $hp0.m365.oneDriveKfmState } }
            'c11.m365.m365AppsSharedComputerActivation' { if ($null -ne $hp0.PSObject.Properties['m365']) { return $hp0.m365.m365AppsSharedComputerActivation } }
            'c11.m365.outlookCachedModeConfigured' { if ($null -ne $hp0.PSObject.Properties['m365']) { return $hp0.m365.outlookCachedModeConfigured } }
            'c11.powerPlatform.avdDay2FlowsActive.suspended' { if ($null -ne $pp.PSObject.Properties['avdDay2FlowsActive']) { return $pp.avdDay2FlowsActive.suspended } }
            'c11.powerPlatform.dlpPoliciesCoveringAvdEnv' { return $pp.dlpPoliciesCoveringAvdEnv }
        }
    }
    $parts = ($FactPath -replace '^c11\.', '') -split '\.'
    $cur = if ($null -ne $C11Obj.PSObject.Properties['c11']) { $C11Obj.c11 } else { $C11Obj }
    foreach ($part in $parts) {
        if ($null -eq $cur -or $null -eq $cur.PSObject.Properties[$part]) { return $null }
        $cur = $cur.$part
    }
    return $cur
}

function Convert-InventorySnapshotToC11 {
    param($Inv, [bool]$HasKerberosLesson = $false)
    if ($null -eq $Inv) { return $null }
    $ds = if ($null -ne $Inv.PSObject.Properties['Datasets']) { $Inv.Datasets } else { [pscustomobject]@{} }
    $hpList = @(if ($null -ne $Inv.PSObject.Properties['HostPools']) { $Inv.HostPools })
    $hp = if ($hpList.Count -gt 0) { $hpList[0] } else { [pscustomobject]@{} }
    $hpName = if ($null -ne $hp.PSObject.Properties['Name'] -and $hp.Name) { [string]$hp.Name } else { 'hostpool' }
    $sh = if ($null -ne $Inv.PSObject.Properties['SessionHosts'] -and $null -ne $Inv.SessionHosts.PSObject.Properties[$hpName]) {
        $Inv.SessionHosts.$hpName
    } else {
        [pscustomobject]@{}
    }
    $peCount = if ($null -ne $ds.PSObject.Properties['private-endpoints']) { [int]$ds.'private-endpoints' } else { 0 }
    $shCount = if ($null -ne $sh.PSObject.Properties['Count']) { [int]$sh.Count } else { 0 }
    $availCount = if ($null -ne $sh.PSObject.Properties['ByStatus'] -and $null -ne $sh.ByStatus.PSObject.Properties['Available']) { [int]$sh.ByStatus.Available } else { 0 }
    $aadJoined = @($(if ($null -ne $Inv.PSObject.Properties['Resources']) { $Inv.Resources }) | Where-Object { $_.Type -eq 'microsoft.compute/virtualmachines/extensions' -and $_.Name -match 'AADLogin' }).Count
    $vmSize = if ($null -ne $Inv.PSObject.Properties['VmBySize']) {
        $sizeNames = @($Inv.VmBySize.PSObject.Properties.Name | Where-Object { $_ -match '^Standard_[ED]' })
        if ($sizeNames.Count -gt 0) { [string]$sizeNames[0] } else { [string]($Inv.VmBySize.PSObject.Properties.Name | Select-Object -First 1) }
    } else { 'Standard_E4as_v5' }
    return [pscustomobject]@{
        schema   = 'avd-current-state-facts/v1'
        contract = 'C11'
        facts    = [pscustomobject]@{
            'c11.azure.armResources'                    = $(if ($null -ne $ds.PSObject.Properties['arm-resources']) { [int]$ds.'arm-resources' } else { 0 })
            'c11.azure.hostPools'                       = $hpList.Count
            'c11.azure.sessionHosts'                    = $shCount
            'c11.network.privateEndpoints'              = $peCount
            'c11.hostPool.name'                         = $hpName
            'c11.hostPool.vmSize'                       = $vmSize
            'c11.hostPool.maxSessionLimit'              = $(if ($null -ne $hp.PSObject.Properties['MaxSessionLimit']) { [int]$hp.MaxSessionLimit } else { 8 })
            'c11.hostPool.sessionHosts.entraJoined'     = $(if ($aadJoined -gt 0) { $aadJoined } else { $shCount })
            'c11.hostPool.sessionHosts.unhealthy'       = [Math]::Max(0, $shCount - $availCount)
            'c11.entra.kerberosStoragePrincipalsReady'  = $(if ($HasKerberosLesson) { 0 } else { 1 })
        }
    }
}

# 3. Resolve companion vault and C11 / C21 artifacts across any environment
$resolvedVault = if ([System.IO.Path]::IsPathRooted($VaultPath)) { $VaultPath } else { Join-Path $repoRoot $VaultPath }

$c11Obj = $null
$c21Obj = $null
$detectedEnv = if ($Environment) { $Environment } else { 'default-estate' }

if ($C11Path -and (Test-Path -LiteralPath $C11Path)) {
    $c11Obj = Get-Content -Raw -LiteralPath $C11Path | ConvertFrom-Json
}
if ($C21Path -and (Test-Path -LiteralPath $C21Path)) {
    $c21Obj = Get-Content -Raw -LiteralPath $C21Path | ConvertFrom-Json
}

if (Test-Path -LiteralPath $resolvedVault) {
    $envsRoot = Join-Path $resolvedVault 'environments'
    if (-not $Environment -and (Test-Path -LiteralPath $envsRoot)) {
        $firstEnvDir = Get-ChildItem -LiteralPath $envsRoot -Directory -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($firstEnvDir) { $detectedEnv = $firstEnvDir.Name }
    }

    $hasKerberosLesson = $false
    $lessonsDir = Join-Path $resolvedVault 'lessons'
    if (Test-Path -LiteralPath $lessonsDir) {
        $kerbFiles = @(Get-ChildItem -LiteralPath $lessonsDir -Filter '*fslogix-entra-kerberos*.md' -File -ErrorAction SilentlyContinue)
        if ($kerbFiles.Count -gt 0) { $hasKerberosLesson = $true }
    }

    if ($null -eq $c21Obj) {
        $candidateC21 = @(
            (Join-Path $resolvedVault "environments/$detectedEnv/c21-assessment-report.json"),
            (Join-Path $resolvedVault 'c21-assessment-report.json')
        )
        foreach ($cand in $candidateC21) {
            if (Test-Path -LiteralPath $cand) {
                try { $c21Obj = Get-Content -Raw -LiteralPath $cand | ConvertFrom-Json; break } catch { Write-Verbose "C21 parse skipped: $_" }
            }
        }
    }

    if ($null -eq $c11Obj) {
        $candidateC11 = @(
            (Join-Path $resolvedVault "environments/$detectedEnv/c11-current-state-facts.json"),
            (Join-Path $resolvedVault 'c11-current-state-facts.json')
        )
        foreach ($cand in $candidateC11) {
            if (Test-Path -LiteralPath $cand) {
                try { $c11Obj = Get-Content -Raw -LiteralPath $cand | ConvertFrom-Json; break } catch { Write-Verbose "C11 parse skipped: $_" }
            }
        }
    }

    if ($null -eq $c11Obj) {
        $snapDir = Join-Path $resolvedVault "environments/$detectedEnv/snapshots"
        if (Test-Path -LiteralPath $snapDir) {
            $latestInv = Get-ChildItem -LiteralPath $snapDir -Filter '*-inventory.json' -File -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending | Select-Object -First 1
            if ($latestInv) {
                try {
                    $rawInv = Get-Content -Raw -LiteralPath $latestInv.FullName | ConvertFrom-Json
                    if ($null -ne $rawInv.PSObject.Properties['facts'] -or $null -ne $rawInv.PSObject.Properties['contract']) {
                        $c11Obj = $rawInv
                    } else {
                        $c11Obj = Convert-InventorySnapshotToC11 -Inv $rawInv -HasKerberosLesson $hasKerberosLesson
                    }
                } catch { Write-Verbose "Inventory snapshot skipped: $_" }
            }
        }
    }
}

$status = 'gap'
$modeSuffix = if ($OfflineDemo.IsPresent) { ' [offline-fixture]' } else { '' }
$summary = "Read-only probe $ProbeId checked ($($probeMeta.transport) on plane $($probeMeta.plane))$modeSuffix."
$observed = [ordered]@{}
if ($WorkspaceId) {
    $observed['workspaceId'] = $WorkspaceId
}

# 4. Evaluate C21 check outcomes (canonical avd-assessment/v1 results[] and legacy checks[]) and C11 triggers across all 14 probes
if ($matchedPlaybook) {
    $c21Matched = $false
    $c21List = @()
    if ($null -ne $c21Obj) {
        if ($null -ne $c21Obj.PSObject.Properties['results']) { $c21List += @($c21Obj.results) }
        if ($null -ne $c21Obj.PSObject.Properties['checks']) { $c21List += @($c21Obj.checks) }
    }
    if ($c21List.Count -gt 0) {
        $pbChecks = @($matchedPlaybook.c21Checks)
        foreach ($chk in $c21List) {
            $rawId = if ($null -ne $chk.PSObject.Properties['check'] -and $chk.check) { [string]$chk.check } else { [string]$chk.id }
            $mappedId = if ($legacyCheckAliases.ContainsKey($rawId)) { [string]$legacyCheckAliases[$rawId] } else { '' }
            if (($pbChecks -contains $rawId) -or ($mappedId -and ($pbChecks -contains $mappedId))) {
                $out = if ($null -ne $chk.PSObject.Properties['outcome'] -and $chk.outcome) { [string]$chk.outcome } else { [string]$chk.status }
                $observed[$rawId] = $out
                $c21Matched = $true
                $evText = if ($null -ne $chk.PSObject.Properties['evidence'] -and $chk.evidence -is [string] -and $chk.evidence) {
                    ": $($chk.evidence)"
                } elseif ($null -ne $chk.PSObject.Properties['summary'] -and $chk.summary) {
                    ": $($chk.summary)"
                } else { '' }
                if ($out -in @('gap', 'fail')) {
                    $status = 'gap'
                    $summary = "Probe $ProbeId verified against C21 ($rawId = $out)$evText"
                    break
                } elseif ($out -eq 'warn') {
                    $status = 'warn'
                    $summary = "Probe $ProbeId verified against C21 ($rawId = warn)$evText"
                } elseif ($out -eq 'pass' -and $status -ne 'warn') {
                    $status = 'pass'
                    $summary = "Probe $ProbeId verified against C21 ($rawId = pass)$evText"
                }
            }
        }
    }

    if (-not $c21Matched -and $null -ne $c11Obj) {
        $triggered = $false
        foreach ($trig in @($matchedPlaybook.c11Triggers)) {
            $val = Get-FactValue -C11Obj $c11Obj -FactPath ([string]$trig.path)
            if ($null -ne $val) {
                $observed[[string]$trig.path] = $val
                if ($null -ne $trig.PSObject.Properties['equals'] -and $val -eq $trig.equals) {
                    $status = 'gap'
                    $summary = "Probe $ProbeId confirmed C11 trigger $($trig.path) = $val ($($matchedPlaybook.title))."
                    $triggered = $true
                    break
                }
                if ($null -ne $trig.PSObject.Properties['gt'] -and [double]$val -gt [double]$trig.gt) {
                    $status = 'gap'
                    $summary = "Probe $ProbeId confirmed C11 trigger $($trig.path) = $val > $($trig.gt) ($($matchedPlaybook.title))."
                    $triggered = $true
                    break
                }
            }
        }
        if (-not $triggered) {
            foreach ($fPath in @($probeMeta.facts)) {
                $fVal = Get-FactValue -C11Obj $c11Obj -FactPath ([string]$fPath)
                if ($null -ne $fVal) {
                    $observed[[string]$fPath] = $fVal
                }
            }
            if ($observed.Count -gt 0) {
                $status = 'pass'
                $summary = "Probe $ProbeId evaluated $($observed.Count) C11 fact(s) in $detectedEnv with no gap triggers."
            }
        }
    }
}

# 5. Live read-only Azure CLI execution when -OfflineDemo is not set and az CLI is available
if (-not $OfflineDemo) {
    $azCmd = Get-Command az -ErrorAction SilentlyContinue
    if ($azCmd) {
        try {
            switch ($ProbeId) {
                'probe-conn-private-dns' {
                    $raw = & az graph query -q "Resources | where type =~ 'microsoft.network/privatednszones' and name has 'wvd.microsoft.com' | project name, resourceGroup" -o json 2>$null
                    if ($LASTEXITCODE -eq 0 -and $raw) {
                        $parsed = $raw | ConvertFrom-Json
                        $cnt = @($parsed.data).Count
                        $observed['livePrivateDnsZones'] = $cnt
                        $status = if ($cnt -gt 0) { 'pass' } else { 'gap' }
                        $summary = "Live Resource Graph query found $cnt AVD Private DNS zone(s)."
                    }
                }
                'probe-host-pool-capacity' {
                    $raw = & az graph query -q "Resources | where type =~ 'microsoft.desktopvirtualization/hostpools' | project name, resourceGroup, maxSessionLimit=properties.maxSessionLimit, hostPoolType=properties.hostPoolType" -o json 2>$null
                    if ($LASTEXITCODE -eq 0 -and $raw) {
                        $parsed = $raw | ConvertFrom-Json
                        $cnt = @($parsed.data).Count
                        $observed['liveHostPools'] = $cnt
                        if ($cnt -gt 0) {
                            $status = 'pass'
                            $summary = "Live Resource Graph query inspected $cnt host pool(s)."
                        }
                    }
                }
                'probe-fsx-storage-kerberos' {
                    $raw = & az rest --method get --url 'https://graph.microsoft.com/v1.0/servicePrincipals?$top=5&$select=id,displayName,servicePrincipalNames' -o json 2>$null
                    if ($LASTEXITCODE -eq 0 -and $raw) {
                        $observed['liveGraphReachable'] = $true
                    }
                }
                'probe-id-ca-sso-posture' {
                    $raw = & az rest --method get --url 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?$top=10&$select=id,displayName,state' -o json 2>$null
                    if ($LASTEXITCODE -eq 0 -and $raw) {
                        $parsed = $raw | ConvertFrom-Json
                        $observed['liveCaPoliciesCount'] = @($parsed.value).Count
                    }
                }
                'probe-id-intune-device-states' {
                    $raw = & az rest --method get --url 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$top=10&$select=id,deviceName,complianceState' -o json 2>$null
                    if ($LASTEXITCODE -eq 0 -and $raw) {
                        $parsed = $raw | ConvertFrom-Json
                        $nonComp = @($parsed.value | Where-Object { $_.complianceState -ne 'compliant' }).Count
                        $observed['liveNoncompliantDevices'] = $nonComp
                        $status = if ($nonComp -gt 0) { 'gap' } else { 'pass' }
                        $summary = "Live Graph managedDevices check found $nonComp noncompliant device(s)."
                    }
                }
            }
        } catch {
            Write-Verbose "Live Azure CLI probe skipped: $_"
        }
    }
}

$state = [ordered]@{
    v           = 1
    stage       = 'probe'
    probeId     = $ProbeId
    playbookId  = $playbookId
    environment = $detectedEnv
    plane       = $probeMeta.plane
    domain      = $probeMeta.domain
    transport   = $probeMeta.transport
    status      = $status
    observed    = $observed
    summary     = $summary
}

$json = $state | ConvertTo-Json -Compress -Depth 6
Write-Output "<<<AVDREM-STATE $json AVDREM-STATE>>>"
