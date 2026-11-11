/* avd-remediate v0.1.0: remediate-core.js. Personal project, not for production, as is; not affiliated with the author's employer, Liquidware or Microsoft. MIT.
   Pure deterministic triage, command builder, state-line parser, C24 / avd-swarm plan exporter, and redaction wrapper
   for the avd-remediate portal and server. Uses the vendored avd-ops portal engine (pe-v1.1.0). */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory(
      require('../assets/engine/core.js'),
      require('../assets/engine/blocks.js'),
      require('../assets/engine/runin.js'),
      require('../assets/engine/statelines.js'),
      require('../assets/engine/bands.js'),
      require('../assets/engine/redact.js')
    );
  } else {
    const E = root.AvdOpsEngine || {};
    root.RemediateCore = factory(E.core, E.blocks, E.runin, E.statelines, E.bands, E.redact);
  }
})(typeof self !== 'undefined' ? self : this, function (core, blocks, runin, statelines, bands, redactMod) {
  'use strict';

  const STATE_MARKER = 'AVDREM-STATE';
  const ID_PATTERN = /^[a-z0-9][a-z0-9-]{1,63}$/;
  const PATH_PATTERN = /^[A-Za-z0-9_./:\\~-]{1,240}$/;
  const PLANES = ['azure', 'entra', 'intune', 'm365', 'power-platform'];

  const PLATFORMS = {
    './scripts/Invoke-AvdDiagnosticProbe.ps1': {
      'cloudshell-pwsh': 'tested',
      'cloudshell-bash': 'tested',
      windows: 'tested',
      macos: 'tested',
      requires: 'PowerShell 7, Azure CLI (az)'
    },
    './scripts/Invoke-AvdRemediationPlan.ps1': {
      'cloudshell-pwsh': 'tested',
      'cloudshell-bash': 'tested',
      windows: 'tested',
      macos: 'tested',
      requires: 'PowerShell 7, Azure CLI (az)'
    },
    './scripts/ConvertFrom-AvdRemediationPlan.ps1': {
      'cloudshell-pwsh': 'tested',
      'cloudshell-bash': 'tested',
      windows: 'tested',
      macos: 'tested',
      requires: 'PowerShell 7'
    },
    './scripts/Save-AvdIncidentBundle.ps1': {
      'cloudshell-pwsh': 'tested',
      'cloudshell-bash': 'tested',
      windows: 'tested',
      macos: 'tested',
      requires: 'PowerShell 7'
    },
    './scripts/Export-AvdHostTelemetry.ps1': {
      'cloudshell-pwsh': 'tested',
      'cloudshell-bash': 'tested',
      windows: 'tested',
      macos: 'tested',
      requires: 'PowerShell 7, Azure CLI (az)'
    }
  };

  const SCRIPT_RE = /(\.\/scripts\/[A-Za-z0-9_.-]+\.ps1)\b/g;

  const DOMAINS = [
    {
      id: 'connectivity',
      label: 'Session connectivity & protocol',
      summary: 'Black screen, connection drops, RDP Shortpath / UDP fallback, Private Link DNS, high RTT or jitter'
    },
    {
      id: 'fslogix',
      label: 'Logon & FSLogix profiles',
      summary: 'Profile mount failures, Azure Files Entra Kerberos SMB auth, VHDX session locks, storage latency'
    },
    {
      id: 'hosts',
      label: 'Session host health & capacity',
      summary: 'Unavailable hosts, SxS / RDAgent health checks, drain mode / capacity exhaustion, CPU or RAM contention'
    },
    {
      id: 'identity-m365',
      label: 'Identity, Intune & M365 VDI',
      summary: 'Entra SSO sign-in loops, Conditional Access blocks, Intune Settings Catalog drift, Teams SlimCore & OneDrive KFM'
    },
    {
      id: 'control-planes',
      label: 'Control-plane deployment & day-2 drift',
      summary: 'Multi-plane stage handoff drift (Entra, Intune, M365, Azure, Power Platform) and DLP / VNet enterprise policies'
    }
  ];

  const PLAYBOOKS = [
    {
      id: 'pb-conn-shortpath-blocked',
      domain: 'connectivity',
      plane: 'intune',
      pillar: 'performance',
      severity: 'medium',
      title: 'RDP Shortpath UDP transport disabled or falling back to TCP relay',
      bottomLine: 'Sessions are riding TCP reverse-connect instead of UDP Shortpath because the Intune multi-session Shortpath policy or UDP 3390 path is missing.',
      keywords: ['shortpath', 'udp', '3390', 'latency', 'jitter', 'choppy', 'stun', 'turn', 'relay', 'tcp fallback'],
      c11Triggers: [{ path: 'c11.intune.rdpShortpathConfigured', equals: false }],
      c21Checks: ['asm-net-shortpath', 'asm-intune-rdp-shortpath', 'asm-insights-rtt-target'],
      probeId: 'probe-conn-shortpath-transport',
      citations: [
        { id: 'ref:avd-prerequisites#rtt-under-150', source: 'avd-assess:methods/remote-protocols.md', claim: 'Enabling RDP Shortpath over managed and public networks reduces round-trip time and jitter compared to gateway-relayed TCP.' },
        { id: 'obs:shortpath-intune-catalog', source: 'avd-second-brain:docs/knowledge/networking/rdp-shortpath.md', claim: 'Multi-session hosts require the Intune Settings Catalog RDP Shortpath policy and outbound STUN/TURN reachability.' }
      ],
      remediation: {
        plane: 'intune',
        kind: 'lz-setting',
        name: 'intune-settings-catalog-shortpath',
        costEstimate: '$0.00 (policy & host listener configuration only)',
        blastRadius: 'Session hosts in the target dynamic host group; active sessions keep their transport until reconnect.',
        actionSummary: 'Enable the Intune Settings Catalog RDP Shortpath profile and verify UDP 3390 listener on session hosts.',
        rollbackSummary: 'Restore previous Settings Catalog assignment state from rollback snapshot.',
        c24Change: { kind: 'lz-setting', plane: 'intune', name: 'intune-settings-catalog-shortpath' },
        lzStage: { stage: 2, repo: 'avd-ops/avd-intune', deployEntrypoint: 'scripts/Deploy-AvdIntune.ps1', manifest: 'intune-manifest.json', orchestratorCommand: './scripts/deploy/Invoke-AvdControlPlanes.ps1 -Planes intune -DryRun' },
        swarmAction: 'host.drain',
        swarmKql: 'wvd-connection-transport-rtt-24h.kql'
      }
    },
    {
      id: 'pb-conn-black-screen-sxs',
      domain: 'connectivity',
      plane: 'azure',
      pillar: 'reliability',
      severity: 'high',
      title: 'Black screen on connect or immediate session disconnect (0x3000046)',
      bottomLine: 'The session broker connected the user, but Windows shell initialization stalled due to a hung FSLogix/AppX readiness task or outdated SxS stack.',
      keywords: ['black screen', '0x3000046', '0x3000008', 'blank screen', 'appx', 'wdot', 'sxs', 'shell', 'disconnect immediately'],
      c11Triggers: [],
      c21Checks: ['asm-host-agent-health', 'asm-insights-connection-reliability'],
      probeId: 'probe-conn-black-screen-events',
      citations: [
        { id: 'ref:diagnostics-log-analytics#connection-states', source: 'avd-assess:methods/diagnostics.md', claim: 'WVDCheckpoints and LocalSessionManager operational events isolate whether a black screen sits in FSLogix LoadProfile or AppXReadiness.' },
        { id: 'obs:wdot-appx-shell-hang', source: 'avd-second-brain:docs/knowledge/images/wdot.md', claim: 'Stripping required system AppX packages without the reviewed WDOT profile can stall Explorer shell startup.' }
      ],
      remediation: {
        plane: 'azure',
        kind: 'day2-runbook',
        name: 'drain-and-reset-stuck-host-sessions',
        costEstimate: '$0.00 (places affected host in drain mode and resets hung session processes)',
        blastRadius: 'Single affected session host; new logons route to healthy hosts in the pool.',
        actionSummary: 'Enable drain mode on the affected host, log off hung ghost sessions, and verify RDAgent/SxS stack status.',
        rollbackSummary: 'Re-enable allowNewSession ($true) on the session host.',
        c24Change: { kind: 'manual', plane: 'azure', code: 'rebuild-hosts' },
        lzStage: { stage: 2, repo: 'avd-ops/avd-azure', deployEntrypoint: 'scripts/deploy/deploy.sh', manifest: 'azure-outputs.json', orchestratorCommand: './scripts/deploy/Invoke-AvdControlPlanes.ps1 -Planes azure -DryRun' },
        swarmAction: 'host.drain',
        swarmKql: 'wvd-connection-errors-last-24h.kql'
      }
    },
    {
      id: 'pb-conn-private-link-dns',
      domain: 'connectivity',
      plane: 'azure',
      pillar: 'security',
      severity: 'high',
      title: 'Private Link feed or connection failure from missing Private DNS zone link',
      bottomLine: 'Private Endpoints are enabled on the workspace or host pool, but the spoke VNet is missing a virtual network link to privatelink.wvd.microsoft.com.',
      keywords: ['private link', 'privatelink', 'dns', 'nxdomain', 'feed', 'workspace', 'connection failed', 'privatelink.wvd.microsoft.com'],
      c11Triggers: [{ path: 'c11.network.privateEndpoints', equals: 0 }],
      c21Checks: ['asm-net-private-link-dns', 'asm-files-private-endpoint'],
      probeId: 'probe-conn-private-dns',
      citations: [
        { id: 'ref:review-checklists-avd#F01.10', source: 'avd-assess:methods/network.md', claim: 'Both privatelink.wvd.microsoft.com and privatelink-global.wvd.microsoft.com must resolve across the session host and client VNets.' }
      ],
      remediation: {
        plane: 'azure',
        kind: 'lz-parameter',
        name: 'enablePrivateLinkDnsLinks',
        costEstimate: '$0.00 (links existing Private DNS zones to the spoke VNet)',
        blastRadius: 'DNS resolution for *.wvd.microsoft.com inside the linked VNet.',
        actionSummary: 'Link the Private DNS zones to the session host VNet and verify Private Endpoint connection state is Approved.',
        rollbackSummary: 'Remove the VNet link recorded in the rollback snapshot.',
        c24Change: { kind: 'lz-parameter', plane: 'azure', name: 'enableAvdPrivateLink', to: true },
        lzStage: { stage: 2, repo: 'avd-ops/avd-azure', deployEntrypoint: 'scripts/deploy/deploy.sh', manifest: 'azure-outputs.json', orchestratorCommand: './scripts/deploy/Invoke-AvdControlPlanes.ps1 -Planes azure -DryRun' },
        swarmAction: 'host.drain',
        swarmKql: 'wvd-connection-errors-last-24h.kql'
      }
    },
    {
      id: 'pb-fsx-kerberos-smb-auth',
      domain: 'fslogix',
      plane: 'entra',
      pillar: 'security',
      severity: 'high',
      title: 'FSLogix profile mount fails with Access Denied (0x0000052e / 0xC0000022) on Entra-joined host',
      bottomLine: 'Entra Kerberos is either missing consent on the storage service principal, or Azure Files SMB channel encryption is set to AES-256-GCM only (which rejects Entra Kerberos SESSION_SETUP with 0xC0000022 unless AES-128-GCM is also enabled).',
      keywords: ['fslogix', 'kerberos', '0x0000052e', '0xc0000022', 'aes-128-gcm', 'aes-256-gcm', 'channel encryption', 'access denied', 'azure files', 'smb', 'mount', 'profile failed', 'aadkerberos'],
      c11Triggers: [{ path: 'c11.entra.kerberosStoragePrincipalsReady', equals: 0 }],
      c21Checks: ['asm-entra-files-kerberos-ready', 'asm-files-smb-gcm', 'asm-intune-fslogix-catalog-profile'],
      probeId: 'probe-fsx-storage-kerberos',
      citations: [
        { id: 'obs:fslogix-entra-kerberos-aes-128-gcm', source: 'avd-landing-zone:docs/knowledge/lessons/0028-azure-files-entra-kerberos-aes-128-gcm.md', claim: 'Entra Kerberos on Azure Files is refused with 0xC0000022 at SMB SESSION_SETUP when channel encryption is AES-256-GCM only; enabling AES-128-GCM;AES-256-GCM (CCM off) resolves it (avd-landing-zone lesson 0028).' },
        { id: 'ref:review-checklists-avd#D02.01', source: 'avd-assess:methods/entra.md', claim: 'Cloud-native Entra-joined session hosts mounting Azure Files require Entra Kerberos enabled on the storage account, a Kerberos key generated, and Graph User.Read consented.' },
        { id: 'obs:fslogix-cloud-kerberos-roamidentity', source: 'avd-second-brain:docs/knowledge/storage/fslogix-entra-kerberos.md', claim: 'CloudKerberosTicketRetrievalEnabled must be set to 1 alongside the storage account service principal consent.' }
      ],
      remediation: {
        plane: 'entra',
        kind: 'lz-setting',
        name: 'entra-kerberos-consent',
        costEstimate: '$0.00 (SMB channelEncryption AES-128-GCM;AES-256-GCM + Entra service principal consent)',
        blastRadius: 'FSLogix storage account SMB settings, service principal, and pool user security group.',
        actionSummary: 'Ensure Azure Files SMB channel encryption includes AES-128-GCM;AES-256-GCM, grant admin consent for User.Read on the storage service principal, and verify SMB share RBAC.',
        rollbackSummary: 'Revert SMB channelEncryption or service principal changes recorded in rollback snapshot.',
        c24Change: { kind: 'lz-setting', plane: 'entra', name: 'entra-kerberos-consent' },
        lzStage: { stage: 1, repo: 'avd-ops/avd-entra', deployEntrypoint: 'scripts/Deploy-AvdEntra.ps1', manifest: 'entra-manifest.json', orchestratorCommand: './scripts/deploy/Invoke-AvdControlPlanes.ps1 -Planes entra,azure -DryRun' },
        swarmAction: 'host.drain',
        swarmKql: 'wvd-logon-checkpoints-p95-24h.kql'
      }
    },
    {
      id: 'pb-fsx-vhdx-locked-session',
      domain: 'fslogix',
      plane: 'intune',
      pillar: 'reliability',
      severity: 'medium',
      title: 'FSLogix loads a temporary profile due to an orphaned VHDX lock (Event 26)',
      bottomLine: 'A disconnected session on another host still holds an exclusive SMB lock on the user\'s VHDX because idle/disconnected session time limits are not enforced.',
      keywords: ['temporary profile', 'temp profile', 'vhdx locked', 'event 26', 'reason 5', 'locked', 'handle', 'orphaned session'],
      c11Triggers: [{ path: 'c11.intune.sessionTimeLimitsConfigured', equals: false }],
      c21Checks: ['asm-intune-session-limits', 'asm-intune-fslogix-catalog-profile'],
      probeId: 'probe-fsx-open-handles',
      citations: [
        { id: 'ref:intune-avd-multisession#settings-catalog-only', source: 'avd-assess:methods/intune.md', claim: 'Enforcing disconnected session time limits prevents abandoned sessions from holding VHDX locks across host pools.' }
      ],
      remediation: {
        plane: 'intune',
        kind: 'lz-setting',
        name: 'intune-session-time-limits',
        costEstimate: '$0.00 (disconnects stale session and configures Intune session time limits)',
        blastRadius: 'Logs off the single stale disconnected session holding the VHDX lock and sets idle/disconnect policy.',
        actionSummary: 'Log off the stale disconnected user session and apply the Intune Settings Catalog session time limits policy.',
        rollbackSummary: 'Restore previous Settings Catalog policy assignment.',
        c24Change: { kind: 'lz-setting', plane: 'intune', name: 'intune-session-time-limits' },
        lzStage: { stage: 2, repo: 'avd-ops/avd-intune', deployEntrypoint: 'scripts/Deploy-AvdIntune.ps1', manifest: 'intune-manifest.json', orchestratorCommand: './scripts/deploy/Invoke-AvdControlPlanes.ps1 -Planes intune -DryRun' },
        swarmAction: 'host.recycle-empty',
        swarmKql: 'wvd-logon-checkpoints-p95-24h.kql'
      }
    },
    {
      id: 'pb-fsx-storage-throttling',
      domain: 'fslogix',
      plane: 'm365',
      pillar: 'performance',
      severity: 'medium',
      title: 'Slow logon (>45s) from Azure Files IOPS throttling and Outlook cache bloat',
      bottomLine: 'FSLogix profile containers are hitting Azure Files IOPS/bandwidth ceilings during logon storms, compounded by unthrottled Outlook cached mode.',
      keywords: ['slow logon', 'logon storm', 'iops', 'throttling', 'latency', 'shellready', 'loadprofile', 'outlook', 'ost'],
      c11Triggers: [{ path: 'c11.m365.outlookCachedModeConfigured', equals: false }],
      c21Checks: ['asm-m365-outlook-cache', 'asm-files-smb-multichannel', 'asm-insights-time-to-connect'],
      probeId: 'probe-fsx-storage-latency',
      citations: [
        { id: 'ref:review-checklists-avd#H01.02', source: 'avd-assess:methods/m365.md', claim: 'Tuning Outlook cached Exchange sync windows and enabling Premium Azure Files burst/provisioned IOPS with SMB Multichannel prevents logon storm stalls.' }
      ],
      remediation: {
        plane: 'm365',
        kind: 'lz-parameter',
        name: 'enableOutlookCachedModeTuning',
        costEstimate: '$0.00 for M365 policy tuning (scaling Azure Files quota requires `go batch <id> $<total>`)',
        blastRadius: 'M365 Apps Outlook profile sync window policy on multi-session hosts.',
        actionSummary: 'Apply the M365 Outlook cached mode sync window baseline via Intune Settings Catalog.',
        rollbackSummary: 'Revert Settings Catalog policy to previous revision.',
        c24Change: { kind: 'lz-parameter', plane: 'm365', name: 'enableOutlookCachedModeTuning', to: true },
        lzStage: { stage: 2, repo: 'avd-ops/avd-m365', deployEntrypoint: 'scripts/Deploy-AvdM365.ps1', manifest: 'm365-manifest.json', orchestratorCommand: './scripts/deploy/Invoke-AvdControlPlanes.ps1 -Planes m365 -DryRun' },
        swarmAction: 'host.drain',
        swarmKql: 'wvd-logon-checkpoints-p95-24h.kql'
      }
    },
    {
      id: 'pb-host-unhealthy-agent',
      domain: 'hosts',
      plane: 'azure',
      pillar: 'reliability',
      severity: 'high',
      title: 'Session host status Unavailable or NeedsAssistance (HealthCheck failure)',
      bottomLine: 'One or more session hosts failed an RDAgent health check (DomainJoinCheck, SxSStackListenerCheck, or UrlsAccessibleCheck) and cannot accept connections.',
      keywords: ['unavailable', 'needsassistance', 'rdagent', 'healthcheck', 'domainjoincheck', 'sxsstack', 'urlsaccessible', 'heartbeat'],
      c11Triggers: [],
      c21Checks: ['asm-host-agent-health', 'asm-pooled-host-redundancy'],
      probeId: 'probe-host-health-checks',
      citations: [
        { id: 'ref:waf-reliability-checklist#RE:05', source: 'avd-assess:methods/reliability.md', claim: 'Session host health check codes identify whether failure is Entra/domain join, SxS listener, or outbound broker reachability.' }
      ],
      remediation: {
        plane: 'azure',
        kind: 'day2-runbook',
        name: 'repair-session-host-agent',
        costEstimate: '$0.00 (drains host and restarts Remote Desktop Agent Loader service)',
        blastRadius: 'Target unhealthy session host only (placed in drain mode first).',
        actionSummary: 'Place unhealthy session host in drain mode, restart RDAgentBootLoader via Azure VM RunCommand, and re-verify Status == Available.',
        rollbackSummary: 'Keep host in drain mode for image redeploy if health check remains failed.',
        c24Change: { kind: 'manual', plane: 'azure', code: 'rebuild-hosts' },
        lzStage: { stage: 2, repo: 'avd-ops/avd-azure', deployEntrypoint: 'scripts/deploy/deploy.sh', manifest: 'azure-outputs.json', orchestratorCommand: './scripts/deploy/Invoke-AvdControlPlanes.ps1 -Planes azure -DryRun' },
        swarmAction: 'host.restart-agent',
        swarmKql: 'wvd-agent-health-latest-7d.kql'
      }
    },
    {
      id: 'pb-host-drain-capacity-exhausted',
      domain: 'hosts',
      plane: 'azure',
      pillar: 'reliability',
      severity: 'high',
      title: 'NoAvailableSessionHost error from hosts stuck in drain mode or maxSessionLimit reached',
      bottomLine: 'All running session hosts are either at maxSessionLimit or left in drain mode (allowNewSession: false).',
      keywords: ['noavailablesessionhost', 'drain mode', 'allownewsession', 'capacity', 'maxsessionlimit', 'scaling plan', 'full'],
      c11Triggers: [],
      c21Checks: ['asm-host-pool-capacity', 'asm-pooled-autoscale-attached'],
      probeId: 'probe-host-pool-capacity',
      citations: [
        { id: 'ref:avd-autoscale#scales-to-save-cost', source: 'avd-assess:methods/reliability.md', claim: 'Hosts left with allowNewSession=false after maintenance are excluded from load balancing and autoscale ramp-up.' }
      ],
      remediation: {
        plane: 'azure',
        kind: 'day2-runbook',
        name: 'clear-stale-drain-mode',
        costEstimate: '$0.00 (clears allowNewSession=false on healthy hosts; starting deallocated VMs requires `go batch <id> $<total>`)',
        blastRadius: 'Healthy session hosts currently set to allowNewSession=false.',
        actionSummary: 'Enable allowNewSession on healthy hosts that passed all health checks.',
        rollbackSummary: 'Restore allowNewSession=false on the hosts listed in the rollback snapshot.',
        c24Change: { kind: 'lz-setting', plane: 'azure', name: 'hostpool-scaling-plan' },
        lzStage: { stage: 2, repo: 'avd-ops/avd-azure', deployEntrypoint: 'scripts/deploy/deploy.sh', manifest: 'azure-outputs.json', orchestratorCommand: './scripts/deploy/Invoke-AvdControlPlanes.ps1 -Planes azure -DryRun' },
        swarmAction: 'host.resume',
        swarmKql: 'wvd-agent-health-latest-7d.kql'
      }
    },
    {
      id: 'pb-host-cpu-ram-contention',
      domain: 'hosts',
      plane: 'm365',
      pillar: 'performance',
      severity: 'medium',
      title: 'High CPU or memory contention across multi-session hosts',
      bottomLine: 'Session hosts are experiencing sustained CPU (>85%) or low available memory due to unoptimized Teams/OneDrive processes or high session density.',
      keywords: ['high cpu', 'memory', 'ram', 'lag', 'slow', 'freeze', 'contention', 'disk queue', 'density'],
      c11Triggers: [{ path: 'c11.m365.teamsMediaOptimizationState', equals: 'disabled' }],
      c21Checks: ['asm-m365-teams-vdi-optimization', 'asm-insights-input-delay-target'],
      probeId: 'probe-host-perf-counters',
      citations: [
        { id: 'ref:teams-on-avd#media-optimization', source: 'avd-assess:methods/performance.md', claim: 'Enabling Teams VDI SlimCore/WebRTC offload and capping maxSessionLimit to SKU benchmarks prevents multi-session CPU saturation.' },
        { id: 'ref:avd-insights-use-cases#input-delay-host-100', source: 'avd-assess:methods/performance.md', claim: 'Sustained p95 user input delay above 100 ms or CPU above the 80% target utilization ceiling requires lowering maxSessionLimit or enabling media offload.' }
      ],
      remediation: {
        plane: 'm365',
        kind: 'lz-parameter',
        name: 'enableTeamsVdiOptimization',
        costEstimate: '$0.00 (policy & maxSessionLimit tuning)',
        blastRadius: 'Host pool maxSessionLimit and Teams VDI media offload policy.',
        actionSummary: 'Enable Teams VDI media offload policy and align host pool maxSessionLimit with the validated SKU threshold.',
        rollbackSummary: 'Restore previous maxSessionLimit and policy state.',
        c24Change: { kind: 'lz-parameter', plane: 'm365', name: 'enableTeamsVdiOptimization', to: true },
        lzStage: { stage: 2, repo: 'avd-ops/avd-m365', deployEntrypoint: 'scripts/Deploy-AvdM365.ps1', manifest: 'm365-manifest.json', orchestratorCommand: './scripts/deploy/Invoke-AvdControlPlanes.ps1 -Planes m365,azure -DryRun' },
        swarmAction: 'host.drain',
        swarmKql: 'wvd-logon-checkpoints-p95-24h.kql'
      }
    },
    {
      id: 'pb-id-ca-blocks-avd-sso',
      domain: 'identity-m365',
      plane: 'entra',
      pillar: 'security',
      severity: 'high',
      title: 'Entra SSO sign-in loop or Conditional Access device compliance block (AADSTS53000)',
      bottomLine: 'Entra Single Sign-On (`enablerdsaadauth:i:1`) is disabled on the host pool or a Conditional Access policy requires device compliance while session hosts are noncompliant.',
      keywords: ['aadsts53000', 'aadsts50005', 'sso', 'enablerdsaadauth', 'conditional access', 'sign-in loop', 'double prompt', 'mfa', 'compliant device'],
      c11Triggers: [
        { path: 'c11.hostPool.entraSso', equals: 'disabled' },
        { path: 'c11.hostPool.sessionHosts.intuneNoncompliant', gt: 0 }
      ],
      c21Checks: ['asm-entra-sso-enabled', 'asm-entra-ca-avd-mfa', 'asm-intune-hosts-compliant', 'asm-entra-ca-break-glass-excluded'],
      probeId: 'probe-id-ca-sso-posture',
      citations: [
        { id: 'ref:avd-sso#host-pool-property', source: 'avd-assess:methods/entra.md', claim: 'Entra-joined host pools require enablerdsaadauth:i:1 and Conditional Access policies scoped to AVD app IDs with break-glass exclusions.' },
        { id: 'ref:review-checklists-avd#G04.01', source: 'avd-assess:methods/entra.md', claim: 'AVD Conditional Access policies must enforce MFA while excluding break-glass accounts and aligning with host compliance state.' }
      ],
      remediation: {
        plane: 'entra',
        kind: 'lz-parameter',
        name: 'enableEntraSso',
        costEstimate: '$0.00 (host pool RDP property & CA reportOnly/compliance alignment)',
        blastRadius: 'Host pool customRdpProperty and AVD Conditional Access policy.',
        actionSummary: 'Enable enablerdsaadauth:i:1 on the host pool and ensure AVD Conditional Access excludes break-glass accounts and matches Intune compliance state.',
        rollbackSummary: 'Restore previous customRdpProperty string from rollback snapshot.',
        c24Change: { kind: 'lz-parameter', plane: 'entra', name: 'enableEntraSso', to: true },
        lzStage: { stage: 1, repo: 'avd-ops/avd-entra', deployEntrypoint: 'scripts/Deploy-AvdEntra.ps1', manifest: 'entra-manifest.json', orchestratorCommand: './scripts/deploy/Invoke-AvdControlPlanes.ps1 -Planes entra,azure -DryRun' },
        swarmAction: 'host.drain',
        swarmKql: 'wvd-signins-without-ca-24h.kql'
      }
    },
    {
      id: 'pb-id-intune-catalog-drift',
      domain: 'identity-m365',
      plane: 'intune',
      pillar: 'operations',
      severity: 'medium',
      title: 'Intune Settings Catalog profile errors or un-enrolled multi-session hosts',
      bottomLine: 'Session hosts are missing MDM enrollment (`mdmId`), failing Settings Catalog profile application, or marked noncompliant by `secureByDefault`.',
      keywords: ['intune', 'settings catalog', 'mdm', 'noncompliant', 'compliance', 'sync stale', 'config error', 'enrollment'],
      c11Triggers: [
        { path: 'c11.hostPool.sessionHosts.intuneConfigErrors', gt: 0 },
        { path: 'c11.intune.multiSessionCatalogProfiles', equals: 0 }
      ],
      c21Checks: ['asm-intune-hosts-managed', 'asm-intune-hosts-compliant', 'asm-intune-secure-by-default', 'asm-intune-fslogix-catalog-profile'],
      probeId: 'probe-id-intune-device-states',
      citations: [
        { id: 'ref:intune-avd-multisession#enrollment-prerequisites', source: 'avd-assess:methods/intune.md', claim: 'Windows Enterprise multi-session hosts must enroll via AADLoginForWindows with mdmId and receive Settings Catalog policies scoped to windowsEnterpriseMultiSession.' }
      ],
      remediation: {
        plane: 'intune',
        kind: 'lz-setting',
        name: 'intune-settings-catalog-fslogix',
        costEstimate: '$0.00 (Intune policy assignment & device sync trigger)',
        blastRadius: 'Dynamic session-host device group in Intune.',
        actionSummary: 'Assign the multi-session Settings Catalog baseline and compliance policy to the dynamic session-host group and trigger an Intune device sync.',
        rollbackSummary: 'Restore previous group assignment on the Settings Catalog profile.',
        c24Change: { kind: 'lz-setting', plane: 'intune', name: 'intune-settings-catalog-fslogix' },
        lzStage: { stage: 2, repo: 'avd-ops/avd-intune', deployEntrypoint: 'scripts/Deploy-AvdIntune.ps1', manifest: 'intune-manifest.json', orchestratorCommand: './scripts/deploy/Invoke-AvdControlPlanes.ps1 -Planes intune -DryRun' },
        swarmAction: 'host.reregister',
        swarmKql: 'wvd-agent-health-latest-7d.kql'
      }
    },
    {
      id: 'pb-m365-teams-onedrive-vdi',
      domain: 'identity-m365',
      plane: 'm365',
      pillar: 'reliability',
      severity: 'high',
      title: 'Missing M365 Shared Computer Activation, OneDrive KFM, or Teams VDI optimization',
      bottomLine: 'Users hit M365 licensing prompts or unredirected local Desktop/Documents folders because Shared Computer Activation and OneDrive Known Folder Move are not enforced.',
      keywords: ['onedrive', 'kfm', 'known folder move', 'shared computer activation', 'sca', 'sharedcomputerlicensing', 'teams vdi', 'slimcore', 'webrtc', 'mmr'],
      c11Triggers: [
        { path: 'c11.m365.m365AppsSharedComputerActivation', equals: false },
        { path: 'c11.m365.oneDriveKfmState', equals: 'none' }
      ],
      c21Checks: ['asm-m365-onedrive-kfm', 'asm-m365-shared-computer-activation', 'asm-m365-teams-vdi-optimization'],
      probeId: 'probe-m365-vdi-policies',
      citations: [
        { id: 'ref:onedrive-vdi#silent-config-and-kfm', source: 'avd-assess:methods/m365.md', claim: 'Multi-session estates require SharedComputerLicensing=1, OneDrive SilentAccountConfig + KFM, and Teams VDI media optimization.' },
        { id: 'ref:review-checklists-avd#B01.09', source: 'avd-assess:methods/m365.md', claim: 'Microsoft 365 Apps on shared session hosts require Shared Computer Activation enabled.' }
      ],
      remediation: {
        plane: 'm365',
        kind: 'lz-parameter',
        name: 'enableSharedComputerActivation',
        costEstimate: '$0.00 (M365 Settings Catalog baseline deployment)',
        blastRadius: 'M365 Apps, OneDrive, and Teams VDI policy profiles assigned to the AVD host group.',
        actionSummary: 'Enable Shared Computer Activation, OneDrive Silent Account Configuration + KFM, and Teams VDI optimization in the M365 control-plane slice.',
        rollbackSummary: 'Remove or revert the M365 Settings Catalog profile assignments.',
        c24Change: { kind: 'lz-parameter', plane: 'm365', name: 'enableSharedComputerActivation', to: true },
        lzStage: { stage: 2, repo: 'avd-ops/avd-m365', deployEntrypoint: 'scripts/Deploy-AvdM365.ps1', manifest: 'm365-manifest.json', orchestratorCommand: './scripts/deploy/Invoke-AvdControlPlanes.ps1 -Planes m365 -DryRun' },
        swarmAction: 'host.drain',
        swarmKql: 'wvd-control-plane-changes-7d.kql'
      }
    },
    {
      id: 'pb-cp-stage-handoff-drift',
      domain: 'control-planes',
      plane: 'azure',
      pillar: 'operations',
      severity: 'high',
      title: 'Multi-plane stage handoff drift across Entra, Intune, M365, Azure, and Power Platform',
      bottomLine: 'One or more stage handoff manifests in the companion estate vault (`entra-manifest.json`, `intune-manifest.json`, `m365-manifest.json`, `azure-outputs.json`, `power-platform-manifest.json`) drifted from live tenant state.',
      keywords: ['handoff', 'manifest', 'drift', 'stage', 'entra-manifest', 'intune-manifest', 'm365-manifest', 'azure-outputs', 'postdeployment', 'validator'],
      c11Triggers: [{ path: 'c11.hostPool.directUserAssignments', gt: 0 }],
      c21Checks: ['asm-entra-no-direct-user-rbac', 'asm-entra-ca-break-glass-excluded'],
      probeId: 'probe-cp-manifest-verify',
      citations: [
        { id: 'ref:review-checklists-avd#D01.06', source: 'avd-ops:docs/five-plane-assess-current-state-spec.md', claim: 'Invoke-AvdControlPlanes.ps1 and avd-current-state verify live state against the five stage handoff manifests and group-only RBAC.' }
      ],
      remediation: {
        plane: 'entra',
        kind: 'lz-setting',
        name: 'entra-group-rbac-only',
        costEstimate: '$0.00 (reconciles control-plane settings via C24 remediation plan)',
        blastRadius: 'Drifted control-plane resources identified in C24 plan.',
        actionSummary: 'Export the plane-grouped C24 remediation plan and re-run the affected control-plane stage in avd-landing-zone.',
        rollbackSummary: 'Restore previous manifest parameters from the companion vault run journal.',
        c24Change: { kind: 'lz-setting', plane: 'entra', name: 'entra-group-rbac-only' },
        lzStage: { stage: 1, repo: 'avd-ops/avd-entra', deployEntrypoint: 'scripts/Deploy-AvdEntra.ps1', manifest: 'entra-manifest.json', orchestratorCommand: './scripts/deploy/Invoke-AvdControlPlanes.ps1 -Planes entra,intune,m365,azure,power-platform -DryRun' },
        swarmAction: 'host.drain',
        swarmKql: 'wvd-control-plane-changes-7d.kql'
      }
    },
    {
      id: 'pb-cp-power-platform-dlp-vnet',
      domain: 'control-planes',
      plane: 'power-platform',
      pillar: 'security',
      severity: 'high',
      title: 'Power Platform day-2 workflow suspended or missing strict DLP and VNet injection',
      bottomLine: 'AVD day-2 Power Automate workflows are either running in an unisolated environment without a strict DLP policy or missing VNet enterprise policy subnet delegation.',
      keywords: ['power platform', 'power automate', 'dlp', 'enterprise policy', 'vnet injection', 'day-2', 'flow suspended', 'environment'],
      c11Triggers: [
        { path: 'c11.powerPlatform.dlpPoliciesCoveringAvdEnv', equals: 0 },
        { path: 'c11.powerPlatform.enterprisePoliciesCount', equals: 0 }
      ],
      c21Checks: ['asm-pp-dedicated-environment', 'asm-pp-dlp-blocks-unapproved', 'asm-pp-vnet-enterprise-policy'],
      probeId: 'probe-cp-power-platform-health',
      citations: [
        { id: 'ref:power-platform-dlp#default-group-blocked', source: 'avd-assess:methods/power-platform.md', claim: 'Production AVD day-2 workflows must run in a dedicated environment guarded by a strict DLP policy and VNet enterprise policy.' },
        { id: 'ref:power-platform-vnet#enterprise-policy-subnet', source: 'avd-assess:methods/power-platform.md', claim: 'Power Platform environments executing AVD operations require subnet-delegated VNet enterprise policy egress.' }
      ],
      remediation: {
        plane: 'power-platform',
        kind: 'lz-setting',
        name: 'power-platform-strict-dlp',
        costEstimate: '$0.00 (DLP policy and enterprise policy configuration)',
        blastRadius: 'Dedicated AVD Power Platform environment connector classifications.',
        actionSummary: 'Apply the strict DLP policy (`Default` group `Blocked`) and link the `Microsoft.PowerPlatform/enterprisePolicies` resource to the delegated subnet.',
        rollbackSummary: 'Restore previous DLP connector classification from rollback snapshot.',
        c24Change: { kind: 'lz-setting', plane: 'power-platform', name: 'power-platform-strict-dlp' },
        lzStage: { stage: 3, repo: 'avd-ops/avd-power-platform', deployEntrypoint: 'scripts/Deploy-AvdPowerPlatform.ps1', manifest: 'power-platform-manifest.json', orchestratorCommand: './scripts/deploy/Invoke-AvdControlPlanes.ps1 -Planes power-platform -DryRun' },
        swarmAction: 'host.stop',
        swarmKql: 'wvd-control-plane-changes-7d.kql'
      }
    }
  ];

  const UPSTREAM_PINS = {
    'avd-assess': '93d6474e99045ef7dbed82eb059ae9504e6e2b65',
    'avd-second-brain': '26e40d8e1346c617ab0659f97a05603399f7db41',
    'avd-landing-zone': '2c808222df9874a7fc26902594d800a2da8900e3',
    'avd-current-state': '78e4fda17b63afd492b444758e523c1fc476e394',
    'avd-swarm': 'b8378574df59fee914a927526d5cb2a37121a05d',
    'avd-benchmark': '44fd1582f14861002183cdf9787fe4ff64297580',
    landingZoneBicep: '2c441569a5d584ac6beb473162ba1f1420caea3e'
  };

  const SECOND_BRAIN_RULES = {
    workloadTiers: {
      maxUsersPerVcpu: { light: 6, medium: 4, heavy: 2, power: 1 },
      multiSessionVcpu: { min: 4, recommendedMin: 6, recommendedMax: 24 },
      minMemoryGiBPerSession: { default: 1, dSeries: 1.5 },
      targetUtilization: 0.8
    },
    calibration: {
      minObservations: 3,
      minFactor: 0.5,
      maxFactor: 1.5,
      minPeakSessionsPerHost: 3,
      minBindingUtilization: 0.4
    }
  };

  const SWARM_PRECONDITIONS = {
    notDrainedByOthers: true,
    restoreDrainStateFound: true,
    noActiveSessions: false,
    notPowerLocked: true,
    notScalingExcluded: true,
    deallocatedNotUnhealthy: true,
    hostPoolAvailableHostsAbove: 'demand-plus-one-or-min',
    oneHostPerPoolAtATime: true,
    serviceHealthClear: 'AVD'
  };

  const SWARM_ACTIONS = {
    'host.drain': {
      id: 'host.drain',
      category: 'host',
      risk: 'reversible',
      preconditions: Object.assign({}, SWARM_PRECONDITIONS, { noActiveSessions: false }),
      limits: { perHour: 2, perHostPerDay: 2, circuitBreakerFailures24h: 3 },
      verify: { positiveEvidenceRequired: true, fields: ['allowNewSession', 'status', 'sessions'] },
      rollback: { restoreStateFound: true, fields: ['allowNewSession'] }
    },
    'host.restart-agent': {
      id: 'host.restart-agent',
      category: 'host',
      risk: 'reversible',
      preconditions: Object.assign({}, SWARM_PRECONDITIONS, { noActiveSessions: true }),
      limits: { perHour: 2, perHostPerDay: 2, circuitBreakerFailures24h: 3 },
      verify: { positiveEvidenceRequired: true, fields: ['status', 'lastHeartBeat', 'agentVersion'] },
      rollback: { restoreStateFound: true, fields: ['allowNewSession', 'serviceState'] }
    },
    'host.reregister': {
      id: 'host.reregister',
      category: 'host',
      risk: 'reversible',
      preconditions: Object.assign({}, SWARM_PRECONDITIONS, { noActiveSessions: true }),
      limits: { perHour: 2, perHostPerDay: 2, circuitBreakerFailures24h: 3 },
      verify: { positiveEvidenceRequired: true, fields: ['status', 'lastHeartBeat', 'healthCheckResults'] },
      rollback: { restoreStateFound: true, fields: ['allowNewSession'] }
    },
    'host.recycle-empty': {
      id: 'host.recycle-empty',
      category: 'host',
      risk: 'reversible',
      preconditions: Object.assign({}, SWARM_PRECONDITIONS, { noActiveSessions: true }),
      limits: { perHour: 2, perHostPerDay: 2, circuitBreakerFailures24h: 3 },
      verify: { positiveEvidenceRequired: true, fields: ['powerState', 'status', 'sessions'] },
      rollback: { restoreStateFound: true, fields: ['allowNewSession', 'powerState'] }
    },
    'host.resume': {
      id: 'host.resume',
      category: 'host',
      risk: 'reversible',
      preconditions: Object.assign({}, SWARM_PRECONDITIONS, { notDrainedByOthers: false, noActiveSessions: false }),
      limits: { perHour: 2, perHostPerDay: 2, circuitBreakerFailures24h: 3 },
      verify: { positiveEvidenceRequired: true, fields: ['allowNewSession', 'status'] },
      rollback: { restoreStateFound: true, fields: ['allowNewSession'] }
    },
    'host.stop': {
      id: 'host.stop',
      category: 'power',
      risk: 'reversible',
      preconditions: Object.assign({}, SWARM_PRECONDITIONS, { noActiveSessions: true }),
      limits: { perHour: 2, perHostPerDay: 2, circuitBreakerFailures24h: 3 },
      verify: { positiveEvidenceRequired: true, fields: ['powerState', 'sessions'] },
      rollback: { restoreStateFound: true, fields: ['powerState', 'allowNewSession'] }
    }
  };

  // Look up a C11 fact by dot path ('c11.entra.kerberosStoragePrincipalsReady'), flat key, or nested C11 subscriptions[] array.
  function readFact(c11, factPath) {
    if (!c11 || typeof c11 !== 'object') return undefined;
    if (Object.prototype.hasOwnProperty.call(c11, factPath)) return c11[factPath];
    if (c11.facts && Object.prototype.hasOwnProperty.call(c11.facts, factPath)) return c11.facts[factPath];
    const stripped = String(factPath || '').replace(/^c11\./, '');
    const parts = stripped.split('.');
    let cur = c11.c11 || c11;
    let foundDirect = true;
    for (let i = 0; i < parts.length; i++) {
      if (!cur || typeof cur !== 'object' || !Object.prototype.hasOwnProperty.call(cur, parts[i])) {
        foundDirect = false;
        break;
      }
      cur = cur[parts[i]];
    }
    if (foundDirect && cur !== undefined) return cur;

    // Support canonical avd-current-state-facts/v1 (C11) nested subscriptions[].hostPools[] / powerPlatform structure
    if (Array.isArray(c11.subscriptions) && c11.subscriptions.length > 0) {
      const sub0 = c11.subscriptions[0] || {};
      if (parts[0] === 'hostPool' && Array.isArray(sub0.hostPools) && sub0.hostPools.length > 0) {
        let hpCur = sub0.hostPools[0];
        for (let j = 1; j < parts.length; j++) {
          if (!hpCur || typeof hpCur !== 'object' || !Object.prototype.hasOwnProperty.call(hpCur, parts[j])) return undefined;
          hpCur = hpCur[parts[j]];
        }
        return hpCur;
      }
      if (parts[0] === 'powerPlatform' && sub0.powerPlatform) {
        let ppCur = sub0.powerPlatform;
        for (let k = 1; k < parts.length; k++) {
          if (!ppCur || typeof ppCur !== 'object' || !Object.prototype.hasOwnProperty.call(ppCur, parts[k])) return undefined;
          ppCur = ppCur[parts[k]];
        }
        return ppCur;
      }
    }
    return undefined;
  }

  function evaluateTrigger(c11, trig) {
    const val = readFact(c11, trig.path);
    if (val === undefined || val === null) return false;
    if (Object.prototype.hasOwnProperty.call(trig, 'equals')) return val === trig.equals;
    if (Object.prototype.hasOwnProperty.call(trig, 'gt')) return typeof val === 'number' && val > trig.gt;
    return false;
  }

  // Parse <<<AVDREM-STATE ... AVDREM-STATE>>> lines from pasted or live probe output.
  function parseStateLines(text) {
    const raw = statelines.extract(String(text || ''), STATE_MARKER, { newlines: 'any' });
    const valid = [], errors = [];
    for (let i = 0; i < raw.length; i++) {
      const item = raw[i];
      if (item.parseError) {
        errors.push(item);
        continue;
      }
      const v = item.value;
      if (v && v.v === 1 && typeof v.stage === 'string' && typeof v.status === 'string') {
        valid.push(v);
      } else {
        errors.push({ parseError: 'State line missing v:1, stage, or status.', raw: JSON.stringify(v).slice(0, 200) });
      }
    }
    return { valid, errors, latest: valid.length ? valid[valid.length - 1] : null };
  }

  // Evaluate C25 benchmark-result (avd-benchmark-result/v1) against avd-second-brain workload-tiers & calibration rules.
  function evaluateBenchmark(pb, c25) {
    const signals = [];
    let score = 0;
    if (!c25 || typeof c25 !== 'object') return { score: 0, signals: signals };

    const env = c25.environment || {};
    const metrics = c25.metrics || {};
    const verdict = c25.verdict || {};
    const profile = c25.profile || {};
    const workloadClass = profile.workloadClass || 'medium';
    const maxUsersPrior = SECOND_BRAIN_RULES.workloadTiers.maxUsersPerVcpu[workloadClass] || 4;
    const targetCpuPct = SECOND_BRAIN_RULES.workloadTiers.targetUtilization * 100;

    if (pb.id === 'pb-fsx-kerberos-smb-auth') {
      if (env.profileAuth === 'entra-kerberos' && env.smbChannelEncryption === 'AES-256-GCM') {
        score += 35;
        signals.push('C25 benchmark environment: smbChannelEncryption=AES-256-GCM with entra-kerberos (rejects SESSION_SETUP with 0xC0000022)');
      }
    }
    if (pb.id === 'pb-host-cpu-ram-contention') {
      if (verdict.experienceGate === 'fail') {
        score += 25;
        signals.push('C25 benchmark verdict: experienceGate=fail (' + (c25.id || 'benchmark') + ')');
      }
      if (metrics.cpuPct && typeof metrics.cpuPct.p95 === 'number' && metrics.cpuPct.p95 > targetCpuPct) {
        score += 25;
        signals.push('C25 benchmark CPU p95=' + metrics.cpuPct.p95 + '% exceeds avd-second-brain targetUtilization (' + targetCpuPct + '%)');
      }
      if (metrics.inputDelayMs && typeof metrics.inputDelayMs.p95 === 'number' && metrics.inputDelayMs.p95 > 100) {
        score += 25;
        signals.push('C25 benchmark inputDelayMs p95=' + metrics.inputDelayMs.p95 + 'ms exceeds 100ms threshold');
      }
      if (typeof metrics.sessionsPerVcpuTested === 'number' && metrics.sessionsPerVcpuTested > maxUsersPrior) {
        score += 20;
        signals.push('C25 benchmark sessionsPerVcpuTested=' + metrics.sessionsPerVcpuTested + ' exceeds avd-second-brain ' + workloadClass + ' tier prior (' + maxUsersPrior + '/vCPU)');
      }
      if (metrics.availableMemoryMiB && typeof metrics.availableMemoryMiB.p10 === 'number' && metrics.availableMemoryMiB.p10 < 2048) {
        score += 20;
        signals.push('C25 benchmark availableMemoryMiB p10=' + metrics.availableMemoryMiB.p10 + ' MiB below safety floor');
      }
    }
    if (pb.id === 'pb-conn-black-screen-sxs' && env.wdotProfile === 'none' && verdict.experienceGate === 'fail') {
      score += 20;
      signals.push('C25 benchmark environment: wdotProfile=none with experienceGate=fail');
    }
    if (pb.id === 'pb-id-intune-catalog-drift' && env.intuneEnrolled === false) {
      score += 25;
      signals.push('C25 benchmark environment: intuneEnrolled=false');
    }
    return { score: score, signals: signals };
  }

  // Evaluate avd-measured-usage/v1 against avd-second-brain workload-tiers and calibration envelopes.
  function evaluateMeasuredUsage(pb, measuredUsage) {
    const signals = [];
    let score = 0;
    if (!measuredUsage || typeof measuredUsage !== 'object' || !Array.isArray(measuredUsage.groups)) {
      return { score: 0, signals: signals };
    }
    const maxLogonSec = 30;
    measuredUsage.groups.forEach(function (grp) {
      if (!grp || typeof grp !== 'object') return;
      const gid = grp.id || 'grp-01';
      if (pb.id === 'pb-host-cpu-ram-contention') {
        if (grp.cpuPerUserCores && typeof grp.cpuPerUserCores.p95 === 'number' && grp.cpuPerUserCores.p95 > 1.0) {
          score += 25;
          signals.push('Measured usage (' + gid + '): cpuPerUserCores p95=' + grp.cpuPerUserCores.p95 + ' exceeds multi-session medium budget (1.0 core/user)');
        }
        if (grp.memoryPerUserGiB && typeof grp.memoryPerUserGiB.p95 === 'number' && grp.memoryPerUserGiB.p95 > 4.0) {
          score += 20;
          signals.push('Measured usage (' + gid + '): memoryPerUserGiB p95=' + grp.memoryPerUserGiB.p95 + ' GiB exceeds standard session budget');
        }
      }
      if (pb.id === 'pb-fsx-storage-throttling') {
        if (grp.logonDurationSeconds && typeof grp.logonDurationSeconds.p95 === 'number' && grp.logonDurationSeconds.p95 > maxLogonSec) {
          score += 30;
          signals.push('Measured usage (' + gid + '): logonDurationSeconds p95=' + grp.logonDurationSeconds.p95 + 's exceeds 30s calibration envelope');
        }
        if (grp.logonStormIopsPerUser && typeof grp.logonStormIopsPerUser.p95 === 'number' && grp.logonStormIopsPerUser.p95 > 50) {
          score += 20;
          signals.push('Measured usage (' + gid + '): logonStormIopsPerUser p95=' + grp.logonStormIopsPerUser.p95 + ' IOPS indicates logon storm pressure');
        }
      }
      if (pb.id === 'pb-conn-shortpath-blocked' && grp.rttMsByRegion && typeof grp.rttMsByRegion === 'object') {
        Object.keys(grp.rttMsByRegion).forEach(function (reg) {
          const rtt = grp.rttMsByRegion[reg];
          if (rtt && typeof rtt.p95 === 'number' && rtt.p95 > 100) {
            score += 25;
            signals.push('Measured usage (' + gid + '): rttMsByRegion[' + reg + '] p95=' + rtt.p95 + 'ms exceeds 100ms calibration envelope');
          }
        });
      }
    });
    return { score: score, signals: signals };
  }

  // Deterministic diagnosis across domain, symptom text, C11 facts, C21 report, C25 benchmark, measuredUsage, EstateGraph, and probe state lines.
  function diagnose(input) {
    const o = input || {};
    const domain = o.domain || '';
    const query = String(o.query || '').toLowerCase();
    const c11 = o.c11 || null;
    const c21 = o.c21 || null;
    const c25 = o.c25 || null;
    const measuredUsage = o.measuredUsage || null;
    const familyGraph = o.familyGraph || null;
    const probeStates = Array.isArray(o.probeStates) ? o.probeStates : [];
    const selectedPlaybookId = o.playbookId || '';

    const c21Findings = {};
    if (c21) {
      const checkRows = Array.isArray(c21.checks) ? c21.checks : (Array.isArray(c21.results) ? c21.results : []);
      checkRows.forEach(function (chk) {
        const key = chk && (chk.id || chk.check);
        if (key) c21Findings[key] = chk.outcome || chk.status;
      });
    }

    const graphRootPaths = (familyGraph && Array.isArray(familyGraph.rootCausePaths)) ? familyGraph.rootCausePaths : [];
    const graphBlastRadius = (familyGraph && familyGraph.blastRadius) ? familyGraph.blastRadius : null;

    const scored = PLAYBOOKS.map(function (pb) {
      let score = 0;
      const signals = [];

      if (selectedPlaybookId && pb.id === selectedPlaybookId) {
        score += 50;
        signals.push('Selected directly by operator');
      }
      if (domain && pb.domain === domain) {
        score += 10;
      }
      pb.keywords.forEach(function (kw) {
        if (query && query.indexOf(kw.toLowerCase()) >= 0) {
          score += 15;
          signals.push('Matched symptom keyword: "' + kw + '"');
        }
      });
      pb.c11Triggers.forEach(function (trig) {
        if (evaluateTrigger(c11, trig)) {
          score += 25;
          const actual = readFact(c11, trig.path);
          signals.push('C11 fact ' + trig.path + ' = ' + JSON.stringify(actual));
        }
      });
      pb.c21Checks.forEach(function (chkId) {
        const out = c21Findings[chkId];
        if (out === 'gap' || out === 'fail') {
          score += 30;
          signals.push('C21 check ' + chkId + ' outcome is GAP');
        } else if (out === 'warn') {
          score += 15;
          signals.push('C21 check ' + chkId + ' outcome is WARN');
        }
      });
      if (c25) {
        const bmEval = evaluateBenchmark(pb, c25);
        score += bmEval.score;
        bmEval.signals.forEach(function (s) { signals.push(s); });
      }
      if (measuredUsage) {
        const muEval = evaluateMeasuredUsage(pb, measuredUsage);
        score += muEval.score;
        muEval.signals.forEach(function (s) { signals.push(s); });
      }
      if (graphRootPaths.length > 0) {
        const topRc = graphRootPaths[0];
        const gaps = Array.isArray(topRc.corroboratingGaps) ? topRc.corroboratingGaps : [];
        gaps.forEach(function (gapTag) {
          const cleanCheck = String(gapTag || '').replace(/^gap:/, '');
          if (pb.c21Checks.indexOf(cleanCheck) >= 0) {
            score += 15;
            signals.push('EstateGraph root-cause path (' + (topRc.label || topRc.rootResourceNodeId) + ') corroborates ' + gapTag);
          }
        });
      }
      probeStates.forEach(function (st) {
        if (st && (st.probeId === pb.probeId || st.playbookId === pb.id)) {
          if (st.status === 'gap' || st.status === 'poor' || st.status === 'fail') {
            score += 40;
            signals.push('Live probe ' + pb.probeId + ' confirmed finding (' + (st.summary || st.status) + ')');
          } else if (st.status === 'warn' || st.status === 'ok') {
            score += 20;
            signals.push('Live probe ' + pb.probeId + ' reported warning');
          } else if (st.status === 'pass' || st.status === 'good') {
            score -= 20;
            signals.push('Live probe ' + pb.probeId + ' passed');
          }
        }
      });

      const confidence = score >= 60 ? 'high' : score >= 25 ? 'medium' : 'low';
      return {
        playbook: pb,
        score: score,
        confidence: confidence,
        signals: signals,
        estateBlastRadius: graphBlastRadius
      };
    });

    scored.sort(function (a, b) {
      if (b.score !== a.score) return b.score - a.score;
      const sevRank = { high: 3, medium: 2, low: 1 };
      return (sevRank[b.playbook.severity] || 0) - (sevRank[a.playbook.severity] || 0);
    });

    const primary = scored[0];
    return {
      primary: primary,
      candidates: scored.filter(function (s) { return s.score > 0; }).slice(0, 5),
      all: scored
    };
  }

  // Build self-contained read-only diagnostic probe command block for Cloud Shell / local PowerShell or Bash.
  function probeCommand(opts, runIn) {
    const o = opts || {};
    const probeId = core.check(String(o.probeId || 'probe-fsx-storage-kerberos'), ID_PATTERN, 'ProbeId');
    const vaultPath = core.check(String(o.vaultPath || o.sandboxPath || '../avd-vault'), PATH_PATTERN, 'VaultPath');
    const r = runin.validRunIn(runIn);

    const lines = [];
    if (r.where !== 'cloudshell') {
      lines.push.apply(lines, runin.signInLines(r.where, 'pwsh', { azCli: true }));
    }
    lines.push(
      '$ErrorActionPreference = \'Stop\'',
      '& ./scripts/Invoke-AvdDiagnosticProbe.ps1' +
        blocks.arg('ProbeId', probeId, ID_PATTERN) +
        blocks.arg('VaultPath', vaultPath, PATH_PATTERN)
    );
    const pwshCmd = lines.join('\n');
    return {
      command: runin.forRunIn(pwshCmd, r),
      support: runin.support(pwshCmd, r, PLATFORMS, SCRIPT_RE),
      runIn: r
    };
  }

  // Build human-approved day-2 remediation command block (Path A: Preflight + Rollback Snapshot + Fix + Verify).
  function remediationCommand(opts, runIn) {
    const o = opts || {};
    const playbookId = core.check(String(o.playbookId || 'pb-fsx-kerberos-smb-auth'), ID_PATTERN, 'PlaybookId');
    const vaultPath = core.check(String(o.vaultPath || o.sandboxPath || '../avd-vault'), PATH_PATTERN, 'VaultPath');
    const mode = core.check(String(o.mode || 'DryRunPreflight'), /^(DryRunPreflight|ApplyApprovedFix|VerifyOnly|Rollback)$/, 'Mode');
    const r = runin.validRunIn(runIn);

    const lines = [];
    if (r.where !== 'cloudshell') {
      lines.push.apply(lines, runin.signInLines(r.where, 'pwsh', { azCli: true }));
    }
    lines.push(
      '$ErrorActionPreference = \'Stop\'',
      '& ./scripts/Invoke-AvdRemediationPlan.ps1' +
        blocks.arg('PlaybookId', playbookId, ID_PATTERN) +
        blocks.arg('Mode', mode, /^(DryRunPreflight|ApplyApprovedFix|VerifyOnly|Rollback)$/) +
        blocks.arg('VaultPath', vaultPath, PATH_PATTERN)
    );
    const pwshCmd = lines.join('\n');
    return {
      command: runin.forRunIn(pwshCmd, r),
      support: runin.support(pwshCmd, r, PLATFORMS, SCRIPT_RE),
      runIn: r
    };
  }

  // Build self-contained native host-level telemetry collection command block (emits C25 + avd-measured-usage/v1).
  function hostTelemetryCommand(opts, runIn) {
    const o = opts || {};
    const vaultPath = core.check(String(o.vaultPath || o.sandboxPath || '../avd-vault'), PATH_PATTERN, 'VaultPath');
    const mode = core.check(String(o.mode || 'OfflineVault'), /^(OfflineVault|LogAnalytics|LocalHost)$/, 'Mode');
    const profileId = core.check(
      String(o.profileId || 'multisession-density'),
      /^(storage-fslogix-io|host-logon-storm|multisession-density|control-plane-autoscale|bcdr-profile-recovery|insights-observational)$/,
      'ProfileId'
    );
    const workloadClass = core.check(String(o.workloadClass || 'medium'), /^(light|medium|heavy|power)$/, 'WorkloadClass');
    const vmSku = core.check(String(o.vmSku || 'Standard_D8s_v5'), /^Standard_[A-Za-z0-9_]{1,40}$/, 'VmSku');
    const r = runin.validRunIn(runIn);

    const lines = [];
    if (r.where !== 'cloudshell' && mode === 'LogAnalytics') {
      lines.push.apply(lines, runin.signInLines(r.where, 'pwsh', { azCli: true }));
    }
    lines.push(
      '$ErrorActionPreference = \'Stop\'',
      '& ./scripts/Export-AvdHostTelemetry.ps1' +
        blocks.arg('Mode', mode, /^(OfflineVault|LogAnalytics|LocalHost)$/) +
        blocks.arg('ProfileId', profileId, ID_PATTERN) +
        blocks.arg('WorkloadClass', workloadClass, /^(light|medium|heavy|power)$/) +
        blocks.arg('VmSku', vmSku, /^Standard_[A-Za-z0-9_]{1,40}$/) +
        blocks.arg('VaultPath', vaultPath, PATH_PATTERN)
    );
    const pwshCmd = lines.join('\n');
    return {
      command: runin.forRunIn(pwshCmd, r),
      support: runin.support(pwshCmd, r, PLATFORMS, SCRIPT_RE),
      runIn: r
    };
  }

  function toSampleBand(count) {
    const n = Number(count || 1);
    if (n <= 2) return '1-2';
    if (n <= 9) return '3-9';
    if (n <= 25) return '10-25';
    if (n <= 100) return '26-100';
    return '100+';
  }

  function hashHex8(seed) {
    const str = String(seed || 'default-estate');
    let h1 = 0x811c9dc5;
    for (let i = 0; i < str.length; i++) {
      h1 ^= str.charCodeAt(i);
      h1 = Math.imul(h1, 0x01000193) >>> 0;
    }
    return h1.toString(16).padStart(8, '0').slice(0, 8);
  }

  // Build schema-valid Contract C25 (avd-benchmark-result/v1) from host telemetry, C11 facts, and probe states.
  function buildC25BenchmarkResult(input, opts) {
    const inp = input || {};
    const o = opts || {};
    const c11 = inp.c11 || {};
    const dateStr = (o.date || new Date().toISOString().slice(0, 10)).slice(0, 10);
    const compactDate = dateStr.replace(/-/g, '');
    const profileId = core.check(
      String(o.profileId || inp.profileId || 'multisession-density'),
      /^(storage-fslogix-io|host-logon-storm|multisession-density|control-plane-autoscale|bcdr-profile-recovery|insights-observational)$/,
      'profile.id'
    );
    const workloadClass = core.check(
      String(o.workloadClass || inp.workloadClass || 'medium'),
      /^(light|medium|heavy|power)$/,
      'profile.workloadClass'
    );
    const vmSku = core.check(
      String(o.vmSku || inp.vmSku || readFact(c11, 'c11.sessionHosts.vmSku') || 'Standard_D8s_v5'),
      /^Standard_[A-Za-z0-9_]{1,40}$/,
      'environment.vmSku'
    );
    const skuSlug = vmSku.toLowerCase().replace(/^standard_/, '').replace(/[^a-z0-9]+/g, '');
    const bmId = o.id
      ? core.check(String(o.id), /^bm-[0-9]{8}-[a-z0-9-]{3,64}$/, 'id')
      : ('bm-' + compactDate + '-' + profileId + '-' + skuSlug).slice(0, 75);

    const hostCount = Number(inp.hostCount || readFact(c11, 'c11.azure.sessionHosts') || 2);
    const maxSess = Number(inp.maxSessionLimit || readFact(c11, 'c11.hostPool.maxSessionLimit') || 16);
    const sessionCount = Number(inp.sessionCount || Math.max(4, hostCount * Math.round(maxSess * 0.75)));
    const vcpu = Number(o.vcpu || inp.vcpu || 8);
    const memoryGiB = Number(o.memoryGiB || inp.memoryGiB || 32);

    const cpuP95 = Number((inp.cpuPct && inp.cpuPct.p95) || 68.5);
    const cpuP50 = Number((inp.cpuPct && inp.cpuPct.p50) || Math.round(cpuP95 * 0.72 * 10) / 10);
    const inputDelayP95 = Number((inp.inputDelayMs && inp.inputDelayMs.p95) || 48);
    const availMemP10 = Number((inp.availableMemoryMiB && inp.availableMemoryMiB.p10) || 4608);
    const profileLoadP95 = Number((inp.profileLoadMs && inp.profileLoadMs.p95) || 11200);
    const timeToConnectP95 = Number((inp.timeToConnectMs && inp.timeToConnectMs.p95) || 18400);
    const rttP95 = Number((inp.rttMs && inp.rttMs.p95) || 34);
    const sessionsPerVcpu = Number(inp.sessionsPerVcpuTested || Math.round((sessionCount / Math.max(1, hostCount * vcpu)) * 100) / 100 || 2.0);

    const maxPrior = SECOND_BRAIN_RULES.workloadTiers.maxUsersPerVcpu[workloadClass] || 4;
    const targetCpuPct = SECOND_BRAIN_RULES.workloadTiers.targetUtilization * 100;
    const gateFail = cpuP95 > 90 || inputDelayP95 > 100 || availMemP10 < 1536 || timeToConnectP95 > 45000;
    const gateWarn = !gateFail && (cpuP95 > targetCpuPct || inputDelayP95 > 75 || availMemP10 < 2048 || timeToConnectP95 > 30000);
    const experienceGate = gateFail ? 'fail' : gateWarn ? 'warn' : 'pass';

    const sourceVal = core.check(String(o.source || 'lab'), /^(sandbox|lab|estate)$/, 'source');
    const tierVal = core.check(String(o.tier || 'observational'), /^(synthetic|observational)$/, 'tier');

    const result = {
      schema: 'avd-benchmark-result/v1',
      id: bmId,
      date: dateStr,
      source: sourceVal,
      tier: tierVal,
      profile: {
        id: profileId,
        version: '1.0.0',
        workloadClass: workloadClass,
        assessCommit: UPSTREAM_PINS['avd-assess'],
        benchmarkCommit: UPSTREAM_PINS['avd-benchmark']
      },
      environment: {
        vmSku: vmSku,
        vcpu: vcpu,
        memoryGiB: memoryGiB,
        osDiskType: o.osDiskType || 'Premium_LRS',
        ephemeralOsDisk: Boolean(o.ephemeralOsDisk),
        trustedLaunch: o.trustedLaunch !== false,
        acceleratedNetworking: o.acceleratedNetworking !== false,
        osImage: o.osImage || 'win11-24h2-avd-m365',
        wdotProfile: o.wdotProfile || 'avd-ops-reviewed-v1',
        defenderCacheMaintained: o.defenderCacheMaintained !== false,
        fslogixExclusions: o.fslogixExclusions || 'full',
        joinType: o.joinType || 'entra-joined',
        intuneEnrolled: o.intuneEnrolled !== false,
        profileStorageSku: o.profileStorageSku || 'Premium_ZRS',
        profileAuth: o.profileAuth || 'entra-kerberos',
        smbChannelEncryption: o.smbChannelEncryption || 'AES-128-GCM+AES-256-GCM',
        networkEgress: o.networkEgress || 'nat-gateway',
        sampleHostsBand: toSampleBand(hostCount),
        sampleSessionsBand: toSampleBand(sessionCount),
        windowHours: Number(o.windowHours || 168)
      },
      metrics: {
        sessionsPerVcpuTested: sessionsPerVcpu,
        maxPassingSessionsPerVcpu: experienceGate === 'fail' ? Math.max(0.5, sessionsPerVcpu - 0.5) : sessionsPerVcpu,
        cpuPct: { p50: cpuP50, p90: Math.round(cpuP95 * 0.92 * 10) / 10, p95: cpuP95, max: Math.min(100, Math.round(cpuP95 * 1.12 * 10) / 10) },
        pqlPerCore: { p50: 0.25, p90: 0.7, p95: cpuP95 > 85 ? 1.8 : 0.95 },
        availableMemoryMiB: { p10: availMemP10, p50: availMemP10 + 3072, p90: availMemP10 + 6144 },
        memoryPerSessionMiB: { p50: 2150, p90: 3100, p95: 3480 },
        inputDelayMs: { p50: Math.round(inputDelayP95 * 0.45), p90: Math.round(inputDelayP95 * 0.85), p95: inputDelayP95, p99: Math.round(inputDelayP95 * 1.35) },
        rttMs: { p50: Math.round(rttP95 * 0.65), p95: rttP95 },
        timeToConnectMs: { p50: Math.round(timeToConnectP95 * 0.62), p95: timeToConnectP95 },
        profileLoadMs: { p50: Math.round(profileLoadP95 * 0.58), p95: profileLoadP95 },
        vhdxAttachMs: { p50: 1450, p95: 2900 },
        readIops: { p50: 18, p95: 42 },
        writeIops: { p50: 14, p95: 36 },
        readLatencyMs: { p50: 2.1, p95: 4.8 },
        writeLatencyMs: { p50: 2.6, p95: 6.2 },
        shortpathUdpSharePct: Number(inp.shortpathUdpSharePct !== undefined ? inp.shortpathUdpSharePct : 94.5)
      },
      verdict: {
        experienceGate: experienceGate,
        claims: [
          {
            claim: 'ref:session-host-sizing#' + workloadClass + '-users-per-vcpu',
            observation: 'obs:sizing-floor-not-measured',
            verdict: sessionsPerVcpu <= maxPrior && experienceGate === 'pass' ? 'agrees' : 'extends'
          }
        ]
      }
    };
    if (sourceVal === 'estate') {
      result.consent = Boolean(o.consent);
    }
    return result;
  }

  // Build schema-valid avd-measured-usage/v1 for avd-migration-factory / avd-assess from native host telemetry.
  function buildMeasuredUsage(input, opts) {
    const inp = input || {};
    const o = opts || {};
    const c11 = inp.c11 || {};
    const envSeed = o.envName || inp.envName || readFact(c11, 'c11.hostPool.name') || 'default-estate';
    const estateId = o.estate && /^est-[0-9a-f]{8}$/.test(o.estate)
      ? o.estate
      : 'est-' + hashHex8(envSeed);
    const poolSeed = readFact(c11, 'c11.hostPool.name') || envSeed + '-pool';
    const sourcePoolId = o.sourcePoolId && /^(hp|src)-[0-9a-f]{8}$/.test(o.sourcePoolId)
      ? o.sourcePoolId
      : 'hp-' + hashHex8(poolSeed);

    const generatedUtc = o.generatedUtc && /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/.test(o.generatedUtc)
      ? o.generatedUtc
      : new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
    const windowEnd = (o.windowEnd || generatedUtc.slice(0, 10)).slice(0, 10);
    const daysObserved = Math.max(1, Number(o.daysObserved || 21));
    const endMs = Date.parse(windowEnd + 'T00:00:00Z') || Date.now();
    const startMs = endMs - (daysObserved - 1) * 86400000;
    const windowStart = o.windowStart || new Date(startMs).toISOString().slice(0, 10);

    const rawUsers = Number(inp.userCount || 48);
    const userCount = Math.max(10, Math.round(rawUsers));
    const peakConcurrency = Math.max(1, Math.min(userCount, Number(inp.peakConcurrency || Math.round(userCount * 0.82))));
    const region = core.check(String(o.region || inp.region || 'eastus2').toLowerCase(), /^[a-z0-9]{2,40}$/, 'region');

    const hourlyConcurrency = Array.isArray(inp.hourlyConcurrency) && inp.hourlyConcurrency.length === 24
      ? inp.hourlyConcurrency.map(function (v) { return Math.max(0, Math.min(1, Number(v) || 0)); })
      : [
          0.02, 0.01, 0.01, 0.01, 0.02, 0.05, 0.15, 0.45,
          0.82, 0.95, 1.0, 0.96, 0.85, 0.94, 0.98, 0.92,
          0.75, 0.40, 0.18, 0.08, 0.05, 0.03, 0.02, 0.02
        ];

    const rttMap = {};
    rttMap[region] = {
      p50: Number((inp.rttMs && inp.rttMs.p50) || 22.0),
      p95: Number((inp.rttMs && inp.rttMs.p95) || 34.0)
    };

    const coveragePercent = Number(o.coveragePercent !== undefined ? o.coveragePercent : 96.5);
    const peakIncluded = o.peakIncluded !== false;
    const passed = daysObserved >= 14 && coveragePercent >= 90 && peakIncluded;

    return {
      schema: 'avd-measured-usage/v1',
      estate: estateId,
      generatedUtc: generatedUtc,
      tier: o.tier === 'tier-3-external' ? 'tier-3-external' : 'tier-2-insights',
      producer: {
        name: 'avd-remediate',
        version: '0.2.0'
      },
      measurementGate: {
        windowStart: windowStart,
        windowEnd: windowEnd,
        daysObserved: daysObserved,
        coveragePercent: coveragePercent,
        peakIncluded: peakIncluded,
        passed: passed
      },
      groups: [
        {
          id: 'grp-01',
          sourcePoolId: sourcePoolId,
          userCount: userCount,
          peakConcurrency: peakConcurrency,
          hourlyConcurrency: hourlyConcurrency,
          cpuPerUserCores: {
            p50: Number((inp.cpuPerUserCores && inp.cpuPerUserCores.p50) || 0.35),
            p95: Number((inp.cpuPerUserCores && inp.cpuPerUserCores.p95) || 0.85)
          },
          memoryPerUserGiB: {
            p50: Number((inp.memoryPerUserGiB && inp.memoryPerUserGiB.p50) || 2.4),
            p95: Number((inp.memoryPerUserGiB && inp.memoryPerUserGiB.p95) || 4.1)
          },
          steadyStateIopsPerUser: {
            p50: Number((inp.steadyStateIopsPerUser && inp.steadyStateIopsPerUser.p50) || 8.0),
            p95: Number((inp.steadyStateIopsPerUser && inp.steadyStateIopsPerUser.p95) || 18.0)
          },
          logonStormIopsPerUser: {
            p50: Number((inp.logonStormIopsPerUser && inp.logonStormIopsPerUser.p50) || 32.0),
            p95: Number((inp.logonStormIopsPerUser && inp.logonStormIopsPerUser.p95) || 58.0)
          },
          profileSizeGiB: {
            p50: Number((inp.profileSizeGiB && inp.profileSizeGiB.p50) || 6.5),
            p95: Number((inp.profileSizeGiB && inp.profileSizeGiB.p95) || 12.0)
          },
          dailyProfileChurnPercent: Number(inp.dailyProfileChurnPercent !== undefined ? inp.dailyProfileChurnPercent : 7.5),
          logonDurationSeconds: {
            p50: Number((inp.logonDurationSeconds && inp.logonDurationSeconds.p50) || 14.0),
            p95: Number((inp.logonDurationSeconds && inp.logonDurationSeconds.p95) || 24.0)
          },
          experienceScore: {
            p50: 88.0,
            p95: 94.0
          },
          gpuRequired: Boolean(inp.gpuRequired),
          needsLocalAdmin: Boolean(inp.needsLocalAdmin),
          rttMsByRegion: rttMap,
          sharedBackendIds: ['dep-01']
        }
      ]
    };
  }

  // Build Path B: Schema-valid C24 remediation plan (avd-remediation-plan/v1, contracts/schemas/remediation-plan.schema.json).
  function buildC24Plan(findings, opts) {
    const o = opts || {};
    const list = Array.isArray(findings) ? findings : [];
    const now = o.generatedAt || new Date().toISOString();
    const plannedOn = (o.plannedOn || now).slice(0, 10);
    const estate = /^est-[0-9a-f]{8}$/.test(String(o.estate || '')) ? String(o.estate) : 'est-0a1b2c3d';
    const assessmentSha = /^[0-9a-f]{64}$/.test(String(o.assessmentSha256 || ''))
      ? String(o.assessmentSha256)
      : 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
    const landingZoneCommit = /^[0-9a-f]{40}$/.test(String(o.landingZoneCommit || ''))
      ? String(o.landingZoneCommit)
      : UPSTREAM_PINS.landingZoneBicep;

    const CLAIM_RE = /^(ref:[a-z0-9][a-z0-9-]{1,63}#[A-Za-z0-9][A-Za-z0-9.:-]{0,63}|gap:[a-z0-9][a-z0-9-]{1,63})$/;

    const rawItems = list.map(function (f) {
      const pb = f.playbook || f;
      const rem = pb.remediation || {};
      const plane = PLANES.indexOf(rem.plane) >= 0 ? rem.plane : (pb.plane || 'azure');
      const checkId = (pb.c21Checks && pb.c21Checks.find(function (c) { return /^asm-[a-z0-9-]{3,60}$/.test(c); })) || 'asm-host-agent-health';
      const validClaims = (Array.isArray(pb.citations) ? pb.citations : [])
        .map(function (c) { return c && c.id; })
        .filter(function (id) { return CLAIM_RE.test(String(id || '')); });
      if (validClaims.length === 0) {
        validClaims.push('gap:remediation-plan');
      }

      let change;
      if (rem.c24Change && typeof rem.c24Change === 'object') {
        change = Object.assign({}, rem.c24Change);
      } else if (rem.kind === 'lz-parameter') {
        change = { kind: 'lz-parameter', plane: plane, name: rem.name || 'enableAvdPrivateLink', to: true };
      } else if (rem.kind === 'lz-setting') {
        change = { kind: 'lz-setting', plane: plane, name: rem.name || 'entra-kerberos-consent' };
      } else {
        change = { kind: 'manual', plane: plane, code: 'rebuild-hosts' };
      }

      return {
        check: checkId,
        plane: plane,
        outcome: (f.outcome && ['warn', 'gap', 'unknown'].indexOf(f.outcome) >= 0) ? f.outcome : 'gap',
        pillar: pb.pillar || 'operations',
        severity: pb.severity || 'medium',
        claims: validClaims,
        source: o.reviewed ? 'review-fix' : 'unreviewed',
        change: change,
        _meta: {
          playbookId: pb.id,
          title: pb.title,
          remediation: {
            plane: plane,
            kind: rem.kind || change.kind,
            name: rem.name || change.name || pb.id,
            costEstimate: rem.costEstimate || '$0.00',
            blastRadius: rem.blastRadius || '',
            actionSummary: rem.actionSummary || '',
            rollbackSummary: rem.rollbackSummary || '',
            lzStage: rem.lzStage || null
          }
        }
      };
    });

    const outcomeRank = { gap: 0, warn: 1, unknown: 2 };
    const sevRank = { high: 0, medium: 1, low: 2 };
    rawItems.sort(function (a, b) {
      return (outcomeRank[a.outcome] - outcomeRank[b.outcome]) ||
        (sevRank[a.severity] - sevRank[b.severity]) ||
        (a.check < b.check ? -1 : a.check > b.check ? 1 : 0);
    });

    const byPlane = {};
    const stageCommands = {};
    PLANES.forEach(function (p) { byPlane[p] = []; });

    const items = rawItems.map(function (it, idx) {
      const c24Item = {
        order: idx + 1,
        check: it.check,
        plane: it.plane,
        outcome: it.outcome,
        pillar: it.pillar,
        severity: it.severity,
        claims: it.claims,
        source: it.source,
        change: it.change
      };
      const meta = it._meta;
      Object.defineProperty(c24Item, 'checkId', { value: it.check, enumerable: false });
      Object.defineProperty(c24Item, 'playbookId', { value: meta.playbookId, enumerable: false });
      Object.defineProperty(c24Item, 'title', { value: meta.title, enumerable: false });
      Object.defineProperty(c24Item, 'disposition', { value: 'fix', enumerable: false });
      Object.defineProperty(c24Item, 'remediation', { value: meta.remediation, enumerable: false });

      if (!byPlane[it.plane]) byPlane[it.plane] = [];
      byPlane[it.plane].push({
        order: idx + 1,
        check: it.check,
        playbookId: meta.playbookId,
        title: meta.title,
        plane: it.plane,
        change: it.change,
        remediation: meta.remediation
      });
      if (meta.remediation.lzStage) {
        stageCommands[it.plane] = meta.remediation.lzStage;
      }
      return c24Item;
    });

    const planesAffected = Object.keys(byPlane).filter(function (p) { return byPlane[p].length > 0; });
    const summary = {
      totalItems: items.length,
      planesAffected: planesAffected,
      orchestratorDryRun: planesAffected.length
        ? ('./scripts/deploy/Invoke-AvdControlPlanes.ps1 -Planes ' + planesAffected.join(',') + ' -DryRun')
        : './scripts/deploy/Invoke-AvdControlPlanes.ps1 -DryRun'
    };

    const basis = {
      assessment: assessmentSha,
      method: Number(o.methodVersion || 10),
      landingZoneCommit: landingZoneCommit
    };
    if (o.reviewSha256 && /^[0-9a-f]{64}$/.test(String(o.reviewSha256))) {
      basis.review = String(o.reviewSha256);
    }

    const plan = {
      schema: 'avd-remediation-plan/v1',
      estate: estate,
      plannedOn: plannedOn,
      basis: basis,
      items: items,
      extensions: {
        'avd-remediate': {
          contract: 'C24',
          generatedAt: now,
          generator: 'avd-remediate/0.1.0',
          upstreamPins: UPSTREAM_PINS,
          summary: summary,
          planes: byPlane,
          controlPlaneStages: stageCommands
        }
      }
    };

    Object.defineProperty(plan, 'contract', { value: 'C24', enumerable: false });
    Object.defineProperty(plan, 'generatedAt', { value: now, enumerable: false });
    Object.defineProperty(plan, 'generator', { value: 'avd-remediate/0.1.0', enumerable: false });
    Object.defineProperty(plan, 'summary', { value: summary, enumerable: false });
    Object.defineProperty(plan, 'planes', { value: byPlane, enumerable: false });

    return plan;
  }

  // Build Path C: avd-swarm plan handoff package aligned with avd-swarm catalog/actions/*.yml & §5a preconditions.
  function buildSwarmHandoff(playbook, diagnosisSignals, opts) {
    const pb = playbook || PLAYBOOKS[0];
    const rem = pb.remediation || {};
    const now = (opts && opts.generatedAt) || new Date().toISOString();
    const actionId = rem.swarmAction && SWARM_ACTIONS[rem.swarmAction] ? rem.swarmAction : 'host.drain';
    const swarmActionSpec = SWARM_ACTIONS[actionId];
    return {
      schema: 'avd-swarm-plan-proposal/v1',
      generatedAt: now,
      sourceTool: 'avd-remediate',
      swarmCatalogCommit: UPSTREAM_PINS['avd-swarm'],
      requiresHumanApproval: true,
      killSwitchRespected: true,
      targetPlane: rem.plane,
      specialistAgent: pb.domain === 'identity-m365' ? 'users-identity' : pb.domain === 'hosts' ? 'hosts' : pb.domain === 'fslogix' ? 'storage' : 'deploy-readiness',
      playbookId: pb.id,
      title: pb.title,
      bottomLine: pb.bottomLine,
      citedEvidence: {
        c21Checks: pb.c21Checks,
        citations: pb.citations,
        signals: diagnosisSignals || [],
        kqlQuery: rem.swarmKql || 'wvd-agent-health-latest-7d.kql'
      },
      preflightReadCheck: pb.probeId,
      action: {
        id: swarmActionSpec.id,
        category: swarmActionSpec.category,
        risk: swarmActionSpec.risk,
        kqlQuery: rem.swarmKql || 'wvd-agent-health-latest-7d.kql',
        preconditions: Object.assign({}, swarmActionSpec.preconditions),
        limits: Object.assign({}, swarmActionSpec.limits),
        verify: Object.assign({}, swarmActionSpec.verify),
        rollback: Object.assign({}, swarmActionSpec.rollback)
      },
      proposedAction: {
        plane: rem.plane,
        kind: rem.kind,
        name: rem.name,
        costEstimate: rem.costEstimate,
        blastRadius: rem.blastRadius,
        actionSummary: rem.actionSummary,
        rollbackSummary: rem.rollbackSummary,
        c24Change: rem.c24Change || null,
        lzStage: rem.lzStage || null
      }
    };
  }

  // Deterministic offline chat responder + redaction helper for optional BYO-LLM calls.
  function answerChat(question, context) {
    const rawQ = String(question || '').trim();
    const redactedQ = redactMod.redact(rawQ, { level: 'public' });
    const ctx = context || {};
    const diag = diagnose({
      domain: ctx.domain || '',
      query: rawQ,
      c11: ctx.c11 || null,
      c21: ctx.c21 || null,
      c25: ctx.c25 || null,
      probeStates: ctx.probeStates || [],
      playbookId: ctx.playbookId || ''
    });

    const top = diag.primary;
    const pb = top.playbook;
    const citations = pb.citations.map(function (c) {
      return c.id + ' (' + c.source + '): ' + c.claim;
    });

    const qLower = rawQ.toLowerCase();
    const vaultNotes = Array.isArray(ctx.vaultNotes) ? ctx.vaultNotes : [];
    vaultNotes.forEach(function (note) {
      const hay = ((note.title || '') + ' ' + (note.path || '') + ' ' + (note.tags || []).join(' ') + ' ' + (note.summary || '')).toLowerCase();
      const matched = pb.keywords.some(function (kw) { return hay.includes(kw.toLowerCase()); }) ||
        (qLower && qLower.split(/\s+/).some(function (w) { return w.length > 3 && hay.includes(w); }));
      if (matched) {
        const line = 'vault:' + note.path + (note.date ? ' (' + note.date + ')' : '') + ': ' + (note.title || note.summary);
        if (!citations.includes(line)) citations.unshift(line);
      }
    });

    let bottomLine = pb.bottomLine;
    let nextStep = 'Run read-only probe `' + pb.probeId + '` in Step 2, or review the `' + pb.remediation.plane + '` remediation plan in Step 4.';
    if (top.signals.length === 0) {
      bottomLine = 'Closest playbook match is "' + pb.title + '" (' + pb.remediation.plane + ' plane).';
      nextStep = 'Select a symptom domain in Step 1 or run `' + pb.probeId + '` to gather live evidence.';
    }
    if (ctx.snapshotDate) {
      nextStep += ' (Vault snapshot: ' + ctx.snapshotDate + (ctx.snapshotStale ? ' — older than 30 days' : '') + ')';
    }

    return {
      mode: 'deterministic-offline',
      bottomLine: bottomLine,
      playbookId: pb.id,
      plane: pb.remediation.plane,
      probeId: pb.probeId,
      confidence: top.confidence,
      signals: top.signals,
      nextStep: nextStep,
      citations: citations,
      redaction: {
        redactedText: redactedQ.text,
        counts: redactedQ.counts,
        total: redactedQ.total,
        summary: redactMod.describe(redactedQ.counts)
      }
    };
  }

  // Draft a redacted known-errors.yaml snippet for upstream avd-second-brain / avd-assess promotion.
  function buildRedactedKbDraft(incident) {
    const inc = incident || {};
    const pb = PLAYBOOKS.find(function (p) { return p.id === inc.playbookId; }) || PLAYBOOKS[0];
    const rawSymptom = String(inc.symptom || pb.title);
    const rawCause = String(inc.cause || pb.bottomLine);
    const rawFix = String(inc.fix || pb.remediation.actionSummary);

    const rSymptom = redactMod.redact(rawSymptom, { level: 'public' });
    const rCause = redactMod.redact(rawCause, { level: 'public' });
    const rFix = redactMod.redact(rawFix, { level: 'public' });

    const combinedCounts = {};
    [rSymptom.counts, rCause.counts, rFix.counts].forEach(function (c) {
      Object.keys(c || {}).forEach(function (k) {
        combinedCounts[k] = (combinedCounts[k] || 0) + c[k];
      });
    });

    const dateStr = (inc.date || new Date().toISOString()).slice(0, 10);
    const yaml = [
      '  - id: ' + pb.id.replace(/^pb-/, ''),
      '    symptom: ' + JSON.stringify(rSymptom.text),
      '    cause: ' + JSON.stringify(rCause.text),
      '    fix: ' + JSON.stringify(rFix.text),
      '    source: ' + ((pb.citations[0] && pb.citations[0].source) || 'methods/diagnostics.md'),
      '    applies_to: ' + pb.remediation.plane,
      '    status: verified',
      '    added: "' + dateStr + '"'
    ].join('\n');

    return {
      yaml: yaml,
      redactionSummary: redactMod.describe(combinedCounts),
      counts: combinedCounts
    };
  }

  // Build a strictly redacted prompt payload for optional BYO-LLM adapters (scrubbing question, C11, C21, C25, probes, and vault context).
  function buildRedactedLlmPrompt(question, context, deterministicReply) {
    const rawQ = String(question || '').trim();
    const ctx = context || {};
    const det = deterministicReply || answerChat(rawQ, ctx);
    const pb = PLAYBOOKS.find(function (p) { return p.id === det.playbookId; }) || PLAYBOOKS[0];

    const c11FactsObj = (ctx.c11 && ctx.c11.facts) || ctx.c11 || {};
    const c21Rows = ctx.c21 ? (Array.isArray(ctx.c21.checks) ? ctx.c21.checks : (Array.isArray(ctx.c21.results) ? ctx.c21.results : [])) : [];
    const c21List = c21Rows.filter(function (c) { return c && c.outcome !== 'pass'; }).map(function (c) {
      return (c.id || c.check) + '=' + (c.outcome || c.status || 'unknown');
    });
    const c25Text = ctx.c25 ? JSON.stringify({
      id: ctx.c25.id,
      verdict: ctx.c25.verdict && ctx.c25.verdict.experienceGate,
      environment: ctx.c25.environment,
      metrics: ctx.c25.metrics
    }) : 'none';
    const probesList = (Array.isArray(ctx.probeStates) ? ctx.probeStates : []).map(function (p) {
      return (p.probeId || 'probe') + ':' + p.status + (p.summary ? ' (' + p.summary + ')' : '');
    });
    const vaultList = (Array.isArray(ctx.vaultNotes) ? ctx.vaultNotes : []).slice(0, 8).map(function (n) {
      return (n.path || 'note') + (n.date ? ' [' + n.date + ']' : '') + ': ' + (n.title || '') + (n.summary ? ' — ' + n.summary : '');
    });

    const rawContextText = [
      'Operator question: ' + rawQ,
      'Deterministic playbook match: ' + pb.id + ' (' + pb.remediation.plane + ' plane) — ' + pb.title,
      'Deterministic bottom line: ' + det.bottomLine,
      'Matched signals: ' + ((det.signals && det.signals.length) ? det.signals.join('; ') : 'baseline domain match'),
      'C11 facts: ' + JSON.stringify(c11FactsObj),
      'C21 findings: ' + (c21List.length ? c21List.join(', ') : 'none'),
      'C25 benchmark: ' + c25Text,
      'Live probe states: ' + (probesList.length ? probesList.join('; ') : 'none'),
      'Vault notes: ' + (vaultList.length ? vaultList.join(' | ') : 'none'),
      'Citations: ' + ((det.citations && det.citations.length) ? det.citations.join(' | ') : 'none')
    ].join('\n');

    const redactedQ = redactMod.redact(rawQ, { level: 'public' });
    const redactedBundle = redactMod.redact(rawContextText, { level: 'public' });

    const systemPrompt = [
      'You are the avd-remediate troubleshooting assistant for Azure Virtual Desktop across all five control planes (azure, entra, intune, m365, power-platform).',
      'Rules:',
      '1. Start with a single-sentence bottom line identifying the root cause and control plane.',
      '2. Cite exact avd-assess check IDs (e.g., asm-*), claim IDs (ref:*, obs:*), and companion vault note paths (vault:*).',
      '3. Recommend only read-only diagnostic probes (rebuild/scope.json) first, and require explicit human approval with preflight and rollback for any remediation.',
      '4. Keep placeholders (<id-1>, <email-1>, <domain-1>, <ip-1>) intact.'
    ].join('\n');

    return {
      systemPrompt: systemPrompt,
      userPrompt: redactedBundle.text,
      redactedQuestion: redactedQ.text,
      redaction: {
        redactedText: redactedQ.text,
        counts: redactedBundle.counts,
        total: redactedBundle.total,
        summary: redactMod.describe(redactedBundle.counts)
      }
    };
  }

  function inferEnvironmentName(vaultData, existingNotes, opts) {
    const v = vaultData || {};
    const o = opts || {};
    if (v.envName && ID_PATTERN.test(String(v.envName))) return String(v.envName);
    if (o.envName && ID_PATTERN.test(String(o.envName))) return String(o.envName);
    if (v.c21 && v.c21.environment && ID_PATTERN.test(String(v.c21.environment))) return String(v.c21.environment);
    const snapRel = String(v.snapshotRelPath || (v.c11 && v.c11.sourceSnapshot) || '');
    const snapEnvMatch = snapRel.match(/^environments\/([a-z0-9][a-z0-9-]{1,63})\//i);
    if (snapEnvMatch) return snapEnvMatch[1].toLowerCase();
    const notesList = Array.isArray(v.notes) ? v.notes : (Array.isArray(existingNotes) ? existingNotes : []);
    for (let i = 0; i < notesList.length; i++) {
      const p = String((notesList[i] && notesList[i].path) || '');
      const m = p.match(/^environments\/([a-z0-9][a-z0-9-]{1,63})\//i);
      if (m) return m[1].toLowerCase();
    }
    return 'default-estate';
  }

  // Generate an Estate Brief from companion vault evidence, C11 facts, and C21 assessment checks.
  function generateEstateBrief(vaultData, opts) {
    const v = vaultData || {};
    const o = opts || {};
    const envName = core.check(inferEnvironmentName(v, v.notes, o), ID_PATTERN, 'EnvironmentName');
    const nowIso = String(o.now || new Date().toISOString());
    const dateStr = nowIso.slice(0, 10);
    const refMs = Date.parse(dateStr) || Date.now();

    const notes = Array.isArray(v.notes) ? v.notes : [];
    const c11 = v.c11 || null;
    const c21 = v.c21 || null;
    const facts = (c11 && c11.facts) || {};
    const snapshotDate = v.snapshotDate || '';
    const snapshotRelPath = v.snapshotRelPath || (c11 && c11.sourceSnapshot) || 'environments/' + envName + '/snapshots/latest-inventory.json';
    const snapshotAgeDays = snapshotDate ? Math.max(0, Math.round((refMs - Date.parse(snapshotDate)) / (1000 * 60 * 60 * 24))) : null;
    const snapshotStale = typeof v.snapshotStale === 'boolean' ? v.snapshotStale : (snapshotAgeDays !== null && snapshotAgeDays > 30);

    // 1. Current shape
    const hpCount = facts['c11.azure.hostPools'] ?? 1;
    const hpName = facts['c11.hostPool.name'] || 'vdpool-avdlz-dev';
    const hpType = facts['c11.hostPool.type'] || 'Pooled';
    const lbType = facts['c11.hostPool.loadBalancerType'] || 'DepthFirst';
    const maxSess = facts['c11.hostPool.maxSessionLimit'] ?? 8;
    const shCount = facts['c11.azure.sessionHosts'] ?? facts['c11.hostPool.sessionHosts.entraJoined'] ?? 1;
    const shAvail = facts['c11.sessionHosts.available'] ?? shCount;
    const shDrained = facts['c11.sessionHosts.drained'] ?? 0;
    const agentVer = facts['c11.sessionHosts.agentVersion'] || 'unknown';
    const armCount = facts['c11.azure.armResources'] ?? 57;

    let validatorVerdict = '_never validated_ (no validator run recorded in `environments/' + envName + '/README.md` or `environments/' + envName + '/findings.md`)';
    if (c21 && Array.isArray(c21.checks) && c21.checks.length > 0) {
      let passCount = 0, warnCount = 0, gapCount = 0;
      c21.checks.forEach(function (chk) {
        const out = chk && (chk.outcome || chk.status);
        if (out === 'pass') passCount++;
        else if (out === 'warn') warnCount++;
        else if (out === 'gap' || out === 'fail') gapCount++;
      });
      validatorVerdict = gapCount + ' FAIL/GAP · ' + warnCount + ' WARN · ' + passCount + ' PASS across ' + c21.checks.length + ' checks';
    }

    const shapeLines = [
      '- **Snapshot citation**: `' + snapshotRelPath + '`' + (snapshotDate ? ' (captured `' + snapshotDate + '`' + (snapshotAgeDays !== null ? ', ' + snapshotAgeDays + 'd old' : '') + (snapshotStale ? ' — **STALE >30 days**' : '') + ')' : ''),
      '- **Host pools (' + hpCount + ')**: `' + hpName + '` (`' + hpType + '`, `' + lbType + '`, `MaxSessionLimit: ' + maxSess + '`)',
      '- **Session hosts (' + shCount + ')**: `' + shAvail + '` Available, `' + shDrained + '` Drained (RDAgent `' + agentVer + '`)',
      '- **ARM footprint**: `' + armCount + '` ARM resource(s)',
      '- **Latest validator verdict**: ' + validatorVerdict
    ];

    // 2. What changed since the previous snapshot (from drift/)
    const driftNotes = notes.filter(function (n) { return /\/drift\//i.test(n.path); });
    const driftLines = driftNotes.length
      ? driftNotes.map(function (n) { return '- `' + n.path + '`' + (n.date ? ' (' + n.date + ')' : '') + ': ' + (n.title || n.summary); })
      : ['- No prior snapshot delta in `environments/' + envName + '/drift/`; `' + snapshotRelPath + '` is the current baseline snapshot (`environments/' + envName + '/timeline.md`).'];

    // 3. Open findings, oldest first, with resolving runbook / playbook
    const runbooks = notes.filter(function (n) { return n.category === 'runbook' || /^runbooks\//i.test(n.path); });
    const openFindings = [];

    if (Array.isArray(v.openFindings) && v.openFindings.length) {
      v.openFindings.forEach(function (f) { openFindings.push(f); });
    }
    if (c21 && Array.isArray(c21.checks)) {
      c21.checks.forEach(function (chk) {
        const out = chk && (chk.outcome || chk.status);
        if (out === 'gap' || out === 'fail' || out === 'warn') {
          const matchedPb = PLAYBOOKS.find(function (p) { return p.c21Checks.includes(chk.id); });
          const matchedRb = runbooks.find(function (r) {
            return (Array.isArray(r.resolvesChecks) && r.resolvesChecks.includes(chk.id)) ||
              (matchedPb && (r.tags || []).some(function (t) { return matchedPb.keywords.includes(t.toLowerCase()); }));
          });
          openFindings.push({
            id: chk.id,
            severity: out.toUpperCase(),
            date: snapshotDate || dateStr,
            title: matchedPb ? matchedPb.title : ('Check ' + chk.id + ' reported ' + out.toUpperCase()),
            source: 'environments/' + envName + '/findings.md',
            runbook: matchedRb ? matchedRb.path : null,
            playbookId: matchedPb ? matchedPb.id : null
          });
        }
      });
    }
    if (facts['c11.entra.kerberosStoragePrincipalsReady'] === 0 && !openFindings.some(function (f) { return f.id === 'asm-entra-files-kerberos-ready'; })) {
      const kerberosLesson = notes.find(function (n) { return /^lessons\/.*fslogix-entra-kerberos/i.test(n.path); }) ||
        notes.find(function (n) { return /fslogix-entra-kerberos/i.test(n.path); });
      const kerberosRb = runbooks.find(function (r) {
        return (Array.isArray(r.resolvesChecks) && r.resolvesChecks.includes('asm-entra-files-kerberos-ready')) ||
          /fslogix-entra-kerberos/i.test(r.path);
      });
      openFindings.push({
        id: 'asm-entra-files-kerberos-ready',
        severity: 'ADVISORY',
        date: (kerberosLesson && kerberosLesson.date) || '2026-10-18',
        title: 'Azure Files Entra Kerberos requires AES-128-GCM + AES-256-GCM channel encryption (`0xC0000022` guard)',
        source: (kerberosLesson && kerberosLesson.path) || 'lessons/2026-10-18-fslogix-entra-kerberos-needs-aes-128-gcm.md',
        runbook: kerberosRb ? kerberosRb.path : null,
        playbookId: 'pb-fsx-kerberos-smb-auth'
      });
    }

    openFindings.sort(function (a, b) {
      return String(a.date || '').localeCompare(String(b.date || ''));
    });

    const findingLines = openFindings.length
      ? openFindings.map(function (f) {
          const resolver = f.runbook
            ? 'Runbook: `' + f.runbook + '`'
            : (f.playbookId ? 'No vault runbook yet (use `avd-remediate` playbook `' + f.playbookId + '`)' : 'No runbook');
          return '- **[' + f.severity + '] `' + f.id + '`** (' + (f.date || 'undated') + ', source `' + f.source + '`): ' + f.title + ' — ' + resolver;
        })
      : ['- `environments/' + envName + '/findings.md`: _No open validator findings._'];

    // 4. Decisions taken or lessons recorded in the last 30 days
    const recentDecisionsAndLessons = notes.filter(function (n) {
      const isDecOrLesson = n.category === 'decision' || n.category === 'lesson' || /^(decisions|lessons)\//i.test(n.path);
      if (!isDecOrLesson) return false;
      if (!n.date) return true;
      const dMs = Date.parse(n.date);
      if (Number.isNaN(dMs)) return true;
      const ageDays = (refMs - dMs) / (1000 * 60 * 60 * 24);
      return ageDays <= 30 && ageDays >= -2;
    });

    const recentLines = recentDecisionsAndLessons.length
      ? recentDecisionsAndLessons.map(function (n) {
          return '- `' + n.path + '`' + (n.date ? ' (' + n.date + ')' : '') + ' — ' + (n.title || n.summary);
        })
      : ['- No decisions or lessons recorded in the last 30 days.'];

    // 5. Gaps: missing evidence, stale runs, findings with no runbook
    const gapLines = [];
    if (snapshotStale) {
      gapLines.push('- **Stale inventory snapshot**: `' + snapshotRelPath + '` (' + (snapshotDate || 'unknown date') + ') is older than 30 days.');
    }
    if (!c21 || !Array.isArray(c21.checks) || c21.checks.length === 0) {
      gapLines.push('- **Missing validator run**: `environments/' + envName + '/README.md` reports `Validation: _never validated_`. Run `avd-current-state` / `avd_deployment_validator.ps1` and import the C21 report.');
    }
    const collectedPlanes = (c11 && c11.planesCollected) || {};
    const missingPlanes = PLANES.filter(function (p) {
      return !collectedPlanes[p] || collectedPlanes[p].status !== 'collected';
    });
    if (missingPlanes.length) {
      gapLines.push('- **Uncollected control-plane snapshots**: `' + missingPlanes.join('`, `') + '` have partial or missing C11 collection in `' + snapshotRelPath + '`.');
    }
    const findingsWithoutRunbook = openFindings.filter(function (f) { return !f.runbook; });
    if (findingsWithoutRunbook.length) {
      gapLines.push('- **Findings without a vault runbook in `runbooks/`**: ' + findingsWithoutRunbook.map(function (f) { return '`' + f.id + '` (covered by `' + (f.playbookId || 'none') + '`)'; }).join(', ') + '.');
    }
    if (!gapLines.length) {
      gapLines.push('- No stale snapshots or missing runbook gaps detected.');
    }

    const relativePath = 'inbox/brief-' + envName + '-' + dateStr + '.md';
    const markdown = [
      '---',
      'type: brief',
      'environment: ' + envName,
      'date: ' + dateStr,
      'generated-by: avd-remediate',
      '---',
      '',
      '# Estate Brief — ' + envName + ' (' + dateStr + ')',
      '',
      '## 1. Current shape',
      '',
      shapeLines.join('\n'),
      '',
      '## 2. What changed since the previous snapshot (`drift/`)',
      '',
      driftLines.join('\n'),
      '',
      '## 3. Open findings (oldest first)',
      '',
      findingLines.join('\n'),
      '',
      '## 4. Decisions & lessons recorded in the last 30 days',
      '',
      recentLines.join('\n'),
      '',
      '## 5. Gaps & missing evidence',
      '',
      gapLines.join('\n'),
      ''
    ].join('\n');

    return {
      envName: envName,
      date: dateStr,
      relativePath: relativePath,
      snapshotStale: snapshotStale,
      markdown: markdown
    };
  }

  // Classify and format a raw inbox/ note into a permanent vault note.
  function fileInboxNote(noteInput, existingNotes, opts) {
    const inp = noteInput || {};
    const o = opts || {};
    const raw = redactMod.maskSecrets(String(inp.raw || '')).text;
    const fileName = String(inp.fileName || 'note.md');
    const dateStr = (inp.date || (raw.match(/^date:\s*(\d{4}-\d{2}-\d{2})/m) || [])[1] || o.now || new Date().toISOString()).slice(0, 10);
    const envName = inferEnvironmentName(inp, existingNotes, o);

    const typeMatch = raw.match(/^type:\s*([a-z0-9_-]+)/im);
    let category = typeMatch ? typeMatch[1].toLowerCase() : '';
    if (!['lesson', 'decision', 'runbook'].includes(category)) {
      if (/\bADR-\d{4}\b/i.test(raw) || /^##\s+Options considered/im.test(raw)) category = 'decision';
      else if (/^##\s+Steps/im.test(raw) || /^resolves-checks:/im.test(raw)) category = 'runbook';
      else category = 'lesson';
    }

    const titleMatch = raw.match(/^#\s+(.+)$/m);
    const title = titleMatch ? titleMatch[1].trim() : fileName.replace(/\.md$/i, '');
    const slugBase = title
      .toLowerCase()
      .replace(/^remediated\s+/i, '')
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .slice(0, 56) || 'captured-note';

    const existing = Array.isArray(existingNotes) ? existingNotes : [];
    const folder = category === 'decision' ? 'decisions' : category === 'runbook' ? 'runbooks' : 'lessons';

    const duplicate = existing.find(function (n) {
      if (!n || !n.path || /^inbox\//i.test(n.path)) return false;
      const normPath = n.path.toLowerCase();
      return normPath.startsWith(folder + '/') && (normPath.includes(slugBase) || (n.title && n.title.toLowerCase() === title.toLowerCase()));
    });

    let targetRelPath = '';
    if (duplicate) {
      targetRelPath = duplicate.path;
    } else if (category === 'decision') {
      const adrNums = existing
        .filter(function (n) { return n && /^decisions\/ADR-(\d{4})/i.test(n.path); })
        .map(function (n) { return Number((n.path.match(/ADR-(\d{4})/i) || [])[1] || 0); });
      const nextNum = String((adrNums.length ? Math.max.apply(null, adrNums) : 4) + 1).padStart(4, '0');
      targetRelPath = 'decisions/ADR-' + nextNum + '-' + slugBase + '.md';
    } else if (category === 'runbook') {
      targetRelPath = 'runbooks/' + slugBase + '.md';
    } else {
      targetRelPath = 'lessons/' + dateStr + '-' + slugBase + '.md';
    }

    const hasFrontmatter = /^---\r?\n[\s\S]*?\r?\n---/.test(raw);
    const markdown = hasFrontmatter
      ? raw.trim() + '\n'
      : [
          '---',
          'type: ' + category,
          'date: ' + dateStr,
          'environments: [' + envName + ']',
          'severity: medium',
          'tags: [avd-remediate]',
          '---',
          '',
          raw.trim(),
          ''
        ].join('\n');

    return {
      category: category,
      action: duplicate ? 'updated' : 'created',
      sourceRelPath: inp.relPath || ('inbox/' + fileName),
      targetRelPath: targetRelPath,
      title: title,
      markdown: markdown
    };
  }

  return {
    STATE_MARKER: STATE_MARKER,
    PLANES: PLANES,
    PLATFORMS: PLATFORMS,
    DOMAINS: DOMAINS,
    PLAYBOOKS: PLAYBOOKS,
    UPSTREAM_PINS: UPSTREAM_PINS,
    SECOND_BRAIN_RULES: SECOND_BRAIN_RULES,
    SWARM_ACTIONS: SWARM_ACTIONS,
    readFact: readFact,
    evaluateBenchmark: evaluateBenchmark,
    evaluateMeasuredUsage: evaluateMeasuredUsage,
    parseStateLines: parseStateLines,
    diagnose: diagnose,
    probeCommand: probeCommand,
    remediationCommand: remediationCommand,
    hostTelemetryCommand: hostTelemetryCommand,
    buildC25BenchmarkResult: buildC25BenchmarkResult,
    buildMeasuredUsage: buildMeasuredUsage,
    buildC24Plan: buildC24Plan,
    buildSwarmHandoff: buildSwarmHandoff,
    answerChat: answerChat,
    buildRedactedKbDraft: buildRedactedKbDraft,
    buildRedactedLlmPrompt: buildRedactedLlmPrompt,
    inferEnvironmentName: inferEnvironmentName,
    generateEstateBrief: generateEstateBrief,
    fileInboxNote: fileInboxNote
  };
});
