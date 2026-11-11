import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const ROOT = fileURLToPath(new URL('../', import.meta.url));
const Core = require(path.join(ROOT, 'site/portal/remediate-core.js'));
const Catalog = JSON.parse(fs.readFileSync(path.join(ROOT, 'playbooks/catalog.json'), 'utf8'));
const Platforms = JSON.parse(fs.readFileSync(path.join(ROOT, 'scripts/platforms.json'), 'utf8'));

test('remediate-core.js PLAYBOOKS and DOMAINS match playbooks/catalog.json and contain zero hardcoded avd-sandbox strings', () => {
  assert.deepEqual(Core.DOMAINS, Catalog.domains);
  assert.deepEqual(Core.PLAYBOOKS, Catalog.playbooks);
  assert.equal(Core.PLAYBOOKS.length, 14);
  const rawCatalog = fs.readFileSync(path.join(ROOT, 'playbooks/catalog.json'), 'utf8');
  assert.doesNotMatch(rawCatalog, /avd-sandbox/i, 'playbooks/catalog.json must be tenant-agnostic');
});

test('remediate-core.js PLATFORMS matches scripts/platforms.json', () => {
  for (const [scriptPath, entry] of Object.entries(Platforms.scripts)) {
    const inlined = Core.PLATFORMS[scriptPath];
    assert.ok(inlined, `Missing ${scriptPath} in Core.PLATFORMS`);
    assert.equal(inlined['cloudshell-pwsh'], entry['cloudshell:pwsh'].status);
    assert.equal(inlined['cloudshell-bash'], entry['cloudshell:bash'].status);
    assert.equal(inlined.windows, entry['windows:pwsh'].status);
    assert.equal(inlined.macos, entry['macos:pwsh'].status);
  }
});

test('diagnose() ranks playbooks deterministically across C11 facts, C21 checks, keywords, and probe states', () => {
  const diag = Core.diagnose({
    domain: 'fslogix',
    query: 'FSLogix profile mount fails with 0x0000052e Access Denied',
    c11: {
      facts: {
        'c11.entra.kerberosStoragePrincipalsReady': 0
      }
    },
    c21: {
      checks: [
        { id: 'asm-entra-files-kerberos-ready', outcome: 'gap' }
      ]
    },
    probeStates: [
      { v: 1, stage: 'probe', probeId: 'probe-fsx-storage-kerberos', status: 'gap', summary: 'Missing User.Read grant' }
    ]
  });

  assert.equal(diag.primary.playbook.id, 'pb-fsx-kerberos-smb-auth');
  assert.equal(diag.primary.confidence, 'high');
  assert.ok(diag.primary.score >= 100);
  assert.ok(diag.primary.signals.some((s) => s.includes('c11.entra.kerberosStoragePrincipalsReady')));
});

test('probeCommand() and remediationCommand() rewrite cleanly across all 5 Run in combinations and block injection', () => {
  const combos = [
    { where: 'cloudshell', shell: 'pwsh' },
    { where: 'cloudshell', shell: 'bash' },
    { where: 'windows', shell: 'pwsh' },
    { where: 'macos', shell: 'pwsh' },
    { where: 'macos', shell: 'bash' }
  ];

  for (const r of combos) {
    const p = Core.probeCommand({ probeId: 'probe-fsx-storage-kerberos', sandboxPath: '../avd-vault' }, r);
    assert.equal(p.support.status, 'tested');
    if (r.shell === 'bash') {
      assert.match(p.command, /cat > "\$f" <<'AVD_PS'/);
    } else {
      assert.match(p.command, /Invoke-AvdDiagnosticProbe\.ps1 -ProbeId 'probe-fsx-storage-kerberos'/);
    }

    const rem = Core.remediationCommand({
      playbookId: 'pb-fsx-kerberos-smb-auth',
      sandboxPath: '../avd-vault',
      mode: 'DryRunPreflight'
    }, r);
    assert.equal(rem.support.status, 'tested');
  }

  // Command injection attempts must throw
  assert.throws(() => Core.probeCommand({ probeId: 'bad; rm -rf /', sandboxPath: '../avd-vault' }));
  assert.throws(() => Core.remediationCommand({ playbookId: 'pb-fsx-kerberos-smb-auth', mode: 'InvalidMode' }));
});

test('buildC24Plan() and buildSwarmHandoff() generate schema-valid plans across all 5 planes', () => {
  const diag = Core.diagnose({ playbookId: 'pb-id-ca-blocks-avd-sso' });
  const c24 = Core.buildC24Plan([diag.primary]);
  assert.equal(c24.schema, 'avd-remediation-plan/v1');
  assert.equal(c24.contract, 'C24');
  assert.equal(c24.planes.entra.length, 1);
  assert.equal(c24.items[0].remediation.plane, 'entra');

  const swarm = Core.buildSwarmHandoff(diag.primary.playbook, diag.primary.signals);
  assert.equal(swarm.schema, 'avd-swarm-plan-proposal/v1');
  assert.equal(swarm.requiresHumanApproval, true);
  assert.equal(swarm.killSwitchRespected, true);
  assert.equal(swarm.targetPlane, 'entra');
  assert.equal(swarm.swarmCatalogCommit, Core.UPSTREAM_PINS['avd-swarm']);
  assert.equal(swarm.action.id, 'host.drain');
  assert.equal(swarm.action.kqlQuery, 'wvd-signins-without-ca-24h.kql');
  assert.equal(Object.keys(swarm.action.preconditions).length, 9);
  assert.equal(swarm.action.preconditions.serviceHealthClear, 'AVD');
  assert.equal(swarm.action.limits.perHour, 2);
});

test('diagnose() ingests C25 benchmark-result (avd-benchmark-result/v1), avd-second-brain workload-tiers, and canonical C11/C21 schemas', () => {
  const perfDiag = Core.diagnose({
    c25: {
      schema: 'avd-benchmark-result/v1',
      id: 'bm-20261111-multisession-density-d4sv5',
      profile: { id: 'multisession-density', workloadClass: 'medium' },
      environment: { vmSku: 'Standard_D4s_v5', wdotProfile: 'avd-ops-reviewed-v1', profileAuth: 'entra-kerberos', smbChannelEncryption: 'AES-128-GCM+AES-256-GCM' },
      metrics: {
        sessionsPerVcpuTested: 5.5,
        cpuPct: { p50: 71, p90: 88, p95: 92.4, max: 99 },
        inputDelayMs: { p50: 45, p90: 98, p95: 142, p99: 210 },
        availableMemoryMiB: { p50: 3200, p10: 1450, min: 900 }
      },
      verdict: { experienceGate: 'fail' }
    }
  });

  assert.equal(perfDiag.primary.playbook.id, 'pb-host-cpu-ram-contention');
  assert.equal(perfDiag.primary.confidence, 'high');
  assert.ok(perfDiag.primary.signals.some((s) => s.includes('experienceGate=fail')));
  assert.ok(perfDiag.primary.signals.some((s) => s.includes('targetUtilization (80%)')));
  assert.ok(perfDiag.primary.signals.some((s) => s.includes('medium tier prior (4/vCPU)')));

  // Canonical C11 subscriptions[].hostPools[] + canonical C21 results[] + C25 AES-256-GCM only
  const krbDiag = Core.diagnose({
    c11: {
      schema: 'avd-current-state-facts/v1',
      estate: 'est-12345678',
      subscriptions: [
        {
          id: 'sub-12345678',
          hostPools: [{ id: 'hp-12345678', entraSso: 'disabled', sessionHosts: { intuneNoncompliant: 2 } }]
        }
      ]
    },
    c21: {
      schema: 'avd-assessment/v1',
      estate: 'est-12345678',
      results: [{ check: 'asm-entra-files-kerberos-ready', plane: 'entra', outcome: 'gap' }]
    },
    c25: {
      schema: 'avd-benchmark-result/v1',
      id: 'bm-20261111-krb',
      environment: { profileAuth: 'entra-kerberos', smbChannelEncryption: 'AES-256-GCM' },
      metrics: {},
      verdict: { experienceGate: 'fail' }
    }
  });
  assert.equal(krbDiag.primary.playbook.id, 'pb-fsx-kerberos-smb-auth');
  assert.ok(krbDiag.primary.signals.some((s) => s.includes('smbChannelEncryption=AES-256-GCM')));
  assert.equal(Core.readFact(krbDiag.c11 || {
    subscriptions: [{ hostPools: [{ entraSso: 'disabled' }] }]
  }, 'c11.hostPool.entraSso'), 'disabled');
});

test('answerChat() and buildRedactedKbDraft() scrub tenant IDs, emails, domains, and IPs via redact.js', () => {
  const chat = Core.answerChat(
    'User alice@contoso.com in tenant 11111111-2222-3333-4444-555555555555 from 203.0.113.45 hit 0x0000052e on FSLogix',
    {}
  );
  assert.equal(chat.playbookId, 'pb-fsx-kerberos-smb-auth');
  assert.ok(!chat.redaction.redactedText.includes('alice@contoso.com'));
  assert.ok(!chat.redaction.redactedText.includes('11111111-2222-3333-4444-555555555555'));
  assert.ok(!chat.redaction.redactedText.includes('203.0.113.45'));
  assert.match(chat.redaction.redactedText, /<email-1>/);
  assert.match(chat.redaction.redactedText, /<id-1>/);
  assert.match(chat.redaction.redactedText, /<ip-1>/);

  const kb = Core.buildRedactedKbDraft({
    playbookId: 'pb-fsx-kerberos-smb-auth',
    symptom: 'Mount failed for bob@contoso.com on subscription aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
    cause: 'Missing Kerberos key',
    fix: 'Consented principal'
  });
  assert.ok(!kb.yaml.includes('bob@contoso.com'));
  assert.ok(!kb.yaml.includes('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'));
});

test('buildRedactedLlmPrompt() scrubs prompts, C11/C21 facts, and vault notes at public redaction level', () => {
  const bundle = Core.buildRedactedLlmPrompt(
    'Why did carol@contoso.com fail FSLogix mount on sub 22222222-3333-4444-5555-666666666666?',
    {
      c11: {
        facts: {
          'c11.entra.kerberosStoragePrincipalsReady': 0,
          'c11.subscriptionId': '22222222-3333-4444-5555-666666666666',
          'c11.adminContact': 'admin@contoso.com'
        }
      },
      c21: {
        checks: [{ id: 'asm-entra-files-kerberos-ready', outcome: 'gap' }]
      },
      vaultNotes: [
        {
          path: 'lessons/2026-10-18-fslogix-entra-kerberos-needs-aes-128-gcm.md',
          date: '2026-10-18',
          title: 'Entra Kerberos on Azure Files needs AES-128-GCM',
          summary: 'Subscription 33333333-4444-5555-6666-777777777777 and user dave@contoso.com tested from 198.51.100.77.'
        }
      ]
    }
  );

  assert.doesNotMatch(bundle.userPrompt, /carol@contoso\.com/i);
  assert.doesNotMatch(bundle.userPrompt, /admin@contoso\.com/i);
  assert.doesNotMatch(bundle.userPrompt, /dave@contoso\.com/i);
  assert.doesNotMatch(bundle.userPrompt, /contoso\.com/i);
  assert.doesNotMatch(bundle.userPrompt, /22222222-3333-4444-5555-666666666666/i);
  assert.doesNotMatch(bundle.userPrompt, /33333333-4444-5555-6666-777777777777/i);
  assert.doesNotMatch(bundle.userPrompt, /198\.51\.100\.77/);
  assert.match(bundle.userPrompt, /<email-1>/);
  assert.match(bundle.userPrompt, /<id-1>/);
  assert.match(bundle.userPrompt, /<ip-1>/);
  assert.ok(bundle.redaction.total >= 5);
  assert.match(bundle.redaction.summary, /^Redacted /);
});

test('generateEstateBrief() summarizes shape, drift, findings, last-30d notes, and gaps per brief.md', () => {
  const brief = Core.generateEstateBrief({
    envName: 'contoso-lab',
    snapshotDate: '2026-10-21',
    snapshotStale: false,
    snapshotRelPath: 'environments/contoso-lab/snapshots/20261021T032412-inventory.json',
    c11: {
      planesCollected: { azure: { status: 'collected' }, entra: { status: 'partial' } },
      facts: {
        'c11.azure.armResources': 57,
        'c11.azure.hostPools': 1,
        'c11.azure.sessionHosts': 1,
        'c11.hostPool.name': 'vdpool-contoso-lab',
        'c11.hostPool.type': 'Pooled',
        'c11.hostPool.loadBalancerType': 'DepthFirst',
        'c11.hostPool.maxSessionLimit': 8,
        'c11.sessionHosts.available': 1,
        'c11.sessionHosts.drained': 0,
        'c11.sessionHosts.agentVersion': '1.0.15732.100',
        'c11.entra.kerberosStoragePrincipalsReady': 0
      }
    },
    notes: [
      {
        path: 'lessons/2026-10-18-fslogix-entra-kerberos-needs-aes-128-gcm.md',
        category: 'lesson',
        date: '2026-10-18',
        title: 'Entra Kerberos on Azure Files needs AES-128-GCM'
      },
      {
        path: 'decisions/ADR-0001-sandbox-spend-needs-an-estimate-and-a-go.md',
        category: 'decision',
        date: '2026-10-20',
        title: 'ADR-0001: Sandbox spend needs an estimate and a go'
      },
      {
        path: 'runbooks/demo-domain-and-demo-account.md',
        category: 'runbook',
        date: '2026-10-21',
        title: 'Add the demo domain contoso.com'
      }
    ]
  }, { now: '2026-10-28T00:00:00Z' });

  assert.equal(brief.relativePath, 'inbox/brief-contoso-lab-2026-10-28.md');
  assert.match(brief.markdown, /## 1\. Current shape/);
  assert.match(brief.markdown, /vdpool-contoso-lab/);
  assert.match(brief.markdown, /57` ARM resource\(s\)/);
  assert.match(brief.markdown, /## 2\. What changed since the previous snapshot/);
  assert.match(brief.markdown, /## 3\. Open findings/);
  assert.match(brief.markdown, /pb-fsx-kerberos-smb-auth/);
  assert.match(brief.markdown, /## 4\. Decisions & lessons recorded in the last 30 days/);
  assert.match(brief.markdown, /lessons\/2026-10-18-fslogix-entra-kerberos-needs-aes-128-gcm\.md/);
  assert.match(brief.markdown, /decisions\/ADR-0001-sandbox-spend-needs-an-estimate-and-a-go\.md/);
  assert.match(brief.markdown, /## 5\. Gaps & missing evidence/);
  assert.match(brief.markdown, /Missing validator run/);
});

test('fileInboxNote() classifies raw inbox notes and updates existing vault notes instead of duplicating per capture.md', () => {
  const existing = [
    {
      path: 'lessons/2026-10-18-fslogix-entra-kerberos-needs-aes-128-gcm.md',
      category: 'lesson',
      title: 'Entra Kerberos on Azure Files needs AES-128-GCM'
    },
    {
      path: 'decisions/ADR-0004-demo-identity-lives-under-contoso.md',
      category: 'decision',
      title: 'ADR-0004: Demo identity lives under contoso.com'
    }
  ];

  // 1. New lesson note
  const createdLesson = Core.fileInboxNote({
    fileName: 'incident-2026-10-28-pb-conn-shortpath-blocked.md',
    raw: '# Remediated pb-conn-shortpath-blocked (intune plane)\n\n## What happened\n- Shortpath UDP 3390 blocked.'
  }, existing, { now: '2026-10-28' });
  assert.equal(createdLesson.category, 'lesson');
  assert.equal(createdLesson.action, 'created');
  assert.match(createdLesson.targetRelPath, /^lessons\/2026-10-28-pb-conn-shortpath-blocked/);

  // 2. Existing lesson note -> updates in place instead of duplicating
  const updatedLesson = Core.fileInboxNote({
    fileName: 'note.md',
    raw: '# Entra Kerberos on Azure Files needs AES-128-GCM\n\nUpdated verification note.'
  }, existing, { now: '2026-10-28' });
  assert.equal(updatedLesson.action, 'updated');
  assert.equal(updatedLesson.targetRelPath, 'lessons/2026-10-18-fslogix-entra-kerberos-needs-aes-128-gcm.md');

  // 3. New decision note -> auto-increments ADR number to ADR-0005 and infers environment dynamically
  const createdDecision = Core.fileInboxNote({
    fileName: 'adr-draft.md',
    envName: 'contoso-prod',
    raw: '# Keep C21 baseline inside environments/contoso-prod\n\n## Options considered\n| Option | Pros | Cons |'
  }, existing, { now: '2026-10-28' });
  assert.equal(createdDecision.category, 'decision');
  assert.equal(createdDecision.action, 'created');
  assert.match(createdDecision.targetRelPath, /^decisions\/ADR-0005-/);
  assert.match(createdDecision.markdown, /environments: \[contoso-prod\]/);
});

test('inferEnvironmentName() resolves environment from explicit envName, C21, snapshotRelPath, or vault notes without hardcoding avd-sandbox', () => {
  assert.equal(Core.inferEnvironmentName({ envName: 'fabrikam-prod' }, [], {}), 'fabrikam-prod');
  assert.equal(Core.inferEnvironmentName({ snapshotRelPath: 'environments/northwind-dev/snapshots/20261021T032412-inventory.json' }, [], {}), 'northwind-dev');
  assert.equal(Core.inferEnvironmentName({ c21: { environment: 'usgov-avd' } }, [], {}), 'usgov-avd');
  assert.equal(Core.inferEnvironmentName({}, [{ path: 'environments/tailspin-stage/findings.md' }], {}), 'tailspin-stage');
  assert.equal(Core.inferEnvironmentName({}, [], {}), 'default-estate');
});
