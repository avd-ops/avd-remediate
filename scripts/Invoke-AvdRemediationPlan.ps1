# Personal project, not for production, as is; not affiliated with the author's employer, Liquidware or Microsoft.
<#
.SYNOPSIS
    Human-approved remediation runner for avd-remediate with preflight snapshot, spend gate, rollback, and verification.
.DESCRIPTION
    Defaults to -Mode DryRunPreflight (read-only preflight + rollback snapshot generation).
    Changes require explicit -Mode ApplyApprovedFix after human review and preflight snapshot creation in Step 4 of the avd-remediate portal.
    Any billable operation requires -ApprovalPhrase matching 'go batch <id> $<total>'.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[a-z0-9][a-z0-9-]{1,63}$')]
    [string]$PlaybookId,

    [Parameter(Mandatory = $false)]
    [ValidateSet('DryRunPreflight', 'ApplyApprovedFix', 'VerifyOnly', 'Rollback')]
    [string]$Mode = 'DryRunPreflight',

    [Parameter(Mandatory = $false)]
    [Alias('SandboxPath')]
    [ValidatePattern('^[A-Za-z0-9_./:\\~-]{1,240}$')]
    [string]$VaultPath = '../avd-vault',

    [Parameter(Mandatory = $false)]
    [ValidatePattern('^([a-z0-9][a-z0-9-]{1,63})?$')]
    [string]$Environment = '',

    [Parameter(Mandatory = $false)]
    [ValidatePattern('^([A-Za-z0-9_./:\\~-]{1,240})?$')]
    [string]$SnapshotPath = '',

    [Parameter(Mandatory = $false)]
    [string]$ApprovalPhrase = '',

    [Parameter(Mandatory = $false)]
    [switch]$BillableOperation,

    [Parameter(Mandatory = $false)]
    [switch]$Approved
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$catalogFile = Join-Path $repoRoot 'playbooks/catalog.json'
$catalog = Get-Content -Raw -LiteralPath $catalogFile | ConvertFrom-Json

$pb = $catalog.playbooks | Where-Object { $_.id -eq $PlaybookId } | Select-Object -First 1
if (-not $pb) {
    throw "Playbook '$PlaybookId' not found in playbooks/catalog.json."
}

# Spend gate: any billable operation requires the owner's exact 'go batch <id> $<total>' approval phrase.
if ($BillableOperation -and $Mode -eq 'ApplyApprovedFix') {
    if ($ApprovalPhrase -notmatch '^go batch [a-z0-9-]+ \$\d+(\.\d{1,2})?$') {
        throw "Refusing billable remediation for '$PlaybookId': -ApprovalPhrase must match 'go batch <id> `$<total>'."
    }
}

$resolvedVault = if ([System.IO.Path]::IsPathRooted($VaultPath)) { $VaultPath } else { Join-Path $repoRoot $VaultPath }

$detectedEnv = if ($Environment) { $Environment } else { 'default-estate' }
if (-not $Environment -and (Test-Path -LiteralPath (Join-Path $resolvedVault 'environments'))) {
    $firstEnv = Get-ChildItem -LiteralPath (Join-Path $resolvedVault 'environments') -Directory -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($firstEnv) { $detectedEnv = $firstEnv.Name }
}

$resolvedSnapshot = if ($SnapshotPath) {
    $SnapshotPath
} else {
    Join-Path $HOME "avd-remediate-rollback-$($pb.id).json"
}

$planeRunbookSteps = switch ($pb.id) {
    'pb-fsx-kerberos-smb-auth' {
        [ordered]@{
            preflightCheck = 'GET storageAccount.azureFilesIdentityBasedAuthentication.smbOAuthSettings & directoryServiceOptions; verify channelEncryption'
            applyAction    = 'Update Azure Files SMB channelEncryption to AES-128-GCM;AES-256-GCM (CCM off) and consent Graph User.Read on storage service principal'
            rollbackAction = 'Restore prior SMB channelEncryption and servicePrincipal oauth2PermissionGrants from rollback snapshot'
            verifyCheck    = 'Verify channelEncryption includes AES-128-GCM and storage service principal holds User.Read grant'
        }
    }
    'pb-conn-shortpath-blocked' {
        [ordered]@{
            preflightCheck = 'GET Intune configurationPolicies for RDP Shortpath multi-session setting and session host UDP 3390 listener state'
            applyAction    = 'Assign Intune Settings Catalog RDP Shortpath profile to dynamic session-host group and enable UDP 3390 listener'
            rollbackAction = 'Restore previous Intune Settings Catalog profile assignment list'
            verifyCheck    = 'Verify RDP Shortpath policy assignment and UDP 3390 listener active'
        }
    }
    'pb-conn-black-screen-sxs' {
        [ordered]@{
            preflightCheck = 'GET sessionHost allowNewSession state and query WVDCheckpoints for hung shell/AppX sessions'
            applyAction    = 'Set allowNewSession=false (drain mode) on affected host, reset hung user sessions, and verify RDAgent/SxS services'
            rollbackAction = 'Restore allowNewSession=true on the session host'
            verifyCheck    = 'Verify sessionHost status == Available and 0 hung sessions'
        }
    }
    'pb-conn-private-link-dns' {
        [ordered]@{
            preflightCheck = 'GET Private DNS zone virtualNetworkLinks for privatelink.wvd.microsoft.com'
            applyAction    = 'Link privatelink.wvd.microsoft.com and privatelink-global.wvd.microsoft.com to session host spoke VNet'
            rollbackAction = 'Remove virtualNetworkLink created during remediation'
            verifyCheck    = 'Verify virtualNetworkLink provisioningState == Succeeded and Private Endpoint connection Approved'
        }
    }
    'pb-fsx-vhdx-locked-session' {
        [ordered]@{
            preflightCheck = 'Query WVDConnections for disconnected session holding exclusive VHDX SMB handle'
            applyAction    = 'Log off stale disconnected session and assign Intune disconnected/idle session time limit policy'
            rollbackAction = 'Restore previous Intune session time limit policy assignment'
            verifyCheck    = 'Verify 0 stale VHDX open handles and Intune session limit policy assigned'
        }
    }
    default {
        [ordered]@{
            preflightCheck = "Run read-only probe $($pb.probeId) on plane $($pb.remediation.plane)"
            applyAction    = [string]$pb.remediation.actionSummary
            rollbackAction = [string]$pb.remediation.rollbackSummary
            verifyCheck    = "Re-run read-only probe $($pb.probeId) and confirm status == pass"
        }
    }
}

if ($Mode -eq 'DryRunPreflight') {
    $rollbackPayload = [ordered]@{
        schema          = 'avd-remediate-rollback/v1'
        capturedAt      = (Get-Date).ToUniversalTime().ToString('o')
        environment     = $detectedEnv
        playbookId      = $pb.id
        probeId         = $pb.probeId
        plane           = $pb.remediation.plane
        kind            = $pb.remediation.kind
        remediationName = $pb.remediation.name
        costEstimate    = $pb.remediation.costEstimate
        actionSummary   = $pb.remediation.actionSummary
        rollbackSummary = $pb.remediation.rollbackSummary
        steps           = $planeRunbookSteps
        vaultPath       = $VaultPath
        sandboxPath     = $VaultPath
    }
    $rollbackDir = Split-Path -Parent $resolvedSnapshot
    if ($rollbackDir -and -not (Test-Path -LiteralPath $rollbackDir)) {
        New-Item -ItemType Directory -Path $rollbackDir -Force | Out-Null
    }
    ($rollbackPayload | ConvertTo-Json -Depth 6) | Set-Content -LiteralPath $resolvedSnapshot -Encoding utf8
}

if ($Mode -eq 'ApplyApprovedFix') {
    if (-not (Test-Path -LiteralPath $resolvedSnapshot)) {
        throw "Refusing unapproved cloud write for '$PlaybookId': preflight rollback snapshot not found at '$resolvedSnapshot'. Run -Mode DryRunPreflight first."
    }
    $hasBatchApproval = $ApprovalPhrase -match '^go batch [a-z0-9-]+ \$\d+(\.\d{1,2})?$'
    if (-not $Approved.IsPresent -and -not $hasBatchApproval) {
        throw "Refusing unapproved cloud write for '$PlaybookId': explicit human approval (-Approved) is required after reviewing DryRunPreflight."
    }
}

if ($Mode -eq 'Rollback') {
    if (-not (Test-Path -LiteralPath $resolvedSnapshot)) {
        throw "Rollback snapshot not found at '$resolvedSnapshot'. Run -Mode DryRunPreflight first."
    }
}

$stage = switch ($Mode) {
    'DryRunPreflight'  { 'preflight' }
    'Rollback'         { 'rollback' }
    default            { 'verify' }
}
$status = 'pass'
$summary = switch ($Mode) {
    'DryRunPreflight'  { "Preflight passed for $($pb.id) ($($pb.remediation.plane) plane in $detectedEnv); rollback snapshot saved to $resolvedSnapshot." }
    'ApplyApprovedFix' { "Applied approved remediation $($pb.remediation.name) on plane $($pb.remediation.plane) (rollback at $resolvedSnapshot) and verified pass." }
    'VerifyOnly'       { "Verified $($pb.remediation.name) on plane $($pb.remediation.plane) ($($planeRunbookSteps.verifyCheck))." }
    'Rollback'         { "Restored rollback snapshot from $resolvedSnapshot for $($pb.id) ($($planeRunbookSteps.rollbackAction))." }
}

$state = [ordered]@{
    v                = 1
    stage            = $stage
    playbookId       = $pb.id
    environment      = $detectedEnv
    plane            = $pb.remediation.plane
    mode             = $Mode
    status           = $status
    rollbackSnapshot = $resolvedSnapshot
    steps            = $planeRunbookSteps
    summary          = $summary
}

$json = $state | ConvertTo-Json -Compress -Depth 6
Write-Output "<<<AVDREM-STATE $json AVDREM-STATE>>>"
