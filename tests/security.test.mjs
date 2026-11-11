import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { verifyPrivateVault, verifyPrivateSandbox, loadEstateVault, createRemediationServer } from '../scripts/server.mjs';

const ROOT = fileURLToPath(new URL('../', import.meta.url));

test('rebuild/scope.json allows only read-only GET probes and forbids write verbs', () => {
  const scope = JSON.parse(fs.readFileSync(path.join(ROOT, 'rebuild/scope.json'), 'utf8'));
  const catalog = JSON.parse(fs.readFileSync(path.join(ROOT, 'playbooks/catalog.json'), 'utf8'));

  for (const pb of catalog.playbooks) {
    assert.ok(scope.probes[pb.probeId], `Playbook ${pb.id} probe ${pb.probeId} must be in rebuild/scope.json`);
  }

  for (const [id, probe] of Object.entries(scope.probes)) {
    assert.equal(probe.method, 'GET', `Probe ${id} must use GET`);
    assert.doesNotMatch(probe.command, /\b(post|put|patch|delete|set-|new-|remove-|update-)\b/i);
  }
});

test('portal HTML and CSS enforce strict CSP, token-only colors, and research notice in header.bar', () => {
  const html = fs.readFileSync(path.join(ROOT, 'site/portal/index.html'), 'utf8');
  const css = fs.readFileSync(path.join(ROOT, 'site/portal/remediate.css'), 'utf8');

  // Research-only notice inside header.bar
  assert.match(html, /<header class="bar">[\s\S]*?<details class="notice">/);
  assert.match(html, /Personal project\. Research and learning only\. Not for production\. No warranty\./);

  // Strict CSP meta tag, no inline style="" attributes, no inline <script> blocks
  assert.match(html, /http-equiv="Content-Security-Policy"/);
  assert.doesNotMatch(html, /\sstyle=/i);
  const scripts = html.match(/<script\b[^>]*>([\s\S]*?)<\/script>/gi) || [];
  for (const s of scripts) {
    assert.match(s, /\bsrc="/, `Inline script prohibited: ${s}`);
  }

  // Dev mode toggle button and friendly contract labels
  assert.match(html, /class="iconbtn dev"/);
  assert.match(html, /Estate Facts: none/);
  assert.match(html, /Path B: Plane-Routed Remediation Plan<span class="dev-id"> \(C24\)<\/span>/);

  // No hex colors in portal stylesheet (colors come only from avd-ops.css tokens)
  assert.doesNotMatch(css, /#[0-9a-fA-F]{3,8}\b/);
});

test('verifyPrivateSandbox() rejects public avd-ops repositories and accepts private sandboxes', () => {
  const pubCheck = verifyPrivateSandbox('../avd-ops');
  assert.equal(pubCheck.ok, false);
  assert.equal(verifyPrivateSandbox('../avd-current-state').ok, false);

  const tmpDir = fs.mkdtempSync(path.join(ROOT, 'tmp-sandbox-'));
  try {
    const privCheck = verifyPrivateSandbox(tmpDir);
    assert.equal(privCheck.ok, true);

    fs.mkdirSync(path.join(tmpDir, '.git'), { recursive: true });
    fs.writeFileSync(path.join(tmpDir, '.git', 'config'), '[remote "origin"]\n\turl = https://github.com/avd-ops/avd-ops.git\n', 'utf8');
    assert.equal(verifyPrivateSandbox(tmpDir).ok, false);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('local server serves portal and enforces CSRF token on /api/chat and /api/capture', async () => {
  const tmpDir = fs.mkdtempSync(path.join(ROOT, 'tmp-srv-'));
  const srv = createRemediationServer({ sandboxPath: tmpDir });
  await new Promise((resolve) => srv.listen(0, '127.0.0.1', resolve));
  const addr = srv.address();
  const base = `http://127.0.0.1:${addr.port}`;

  try {
    const statusRes = await fetch(`${base}/api/status`);
    assert.equal(statusRes.status, 200);
    const statusJson = await statusRes.json();
    assert.equal(statusJson.ok, true);
    assert.ok(statusJson.csrfToken);

    // Without CSRF header -> 403
    const badRes = await fetch(`${base}/api/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ question: 'FSLogix 0x0000052e' })
    });
    assert.equal(badRes.status, 403);

    // With CSRF header -> 200
    const chatRes = await fetch(`${base}/api/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-AVD-CSRF': statusJson.csrfToken },
      body: JSON.stringify({ question: 'FSLogix 0x0000052e' })
    });
    assert.equal(chatRes.status, 200);
    const chatJson = await chatRes.json();
    assert.equal(chatJson.playbookId, 'pb-fsx-kerberos-smb-auth');

    // Root URL redirects to /portal/ so relative portal assets resolve cleanly
    const rootRedirect = await fetch(`${base}/`, { redirect: 'manual' });
    assert.equal(rootRedirect.status, 302);
    assert.equal(rootRedirect.headers.get('location'), '/portal/');

    // Portal assets load with 200 OK both from /portal/* and root fallback
    for (const asset of ['/portal/remediate.css', '/portal/remediate-core.js', '/portal/remediate-page.js', '/remediate.css']) {
      const assetRes = await fetch(`${base}${asset}`);
      assert.equal(assetRes.status, 200, `Expected 200 OK for ${asset}`);
    }

    // /api/brief rejects public avd-ops repo and writes inbox/brief-<envName>-YYYY-MM-DD.md for any private companion vault
    const badBriefRes = await fetch(`${base}/api/brief`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-AVD-CSRF': statusJson.csrfToken },
      body: JSON.stringify({ vaultPath: '../avd-ops' })
    });
    assert.equal(badBriefRes.status, 400);

    const briefRes = await fetch(`${base}/api/brief`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-AVD-CSRF': statusJson.csrfToken },
      body: JSON.stringify({ vaultPath: tmpDir, envName: 'contoso-prod', now: '2026-10-28T00:00:00Z' })
    });
    assert.equal(briefRes.status, 200);
    const briefJson = await briefRes.json();
    assert.equal(briefJson.ok, true);
    assert.equal(briefJson.envName, 'contoso-prod');
    assert.equal(briefJson.relativePath, 'inbox/brief-contoso-prod-2026-10-28.md');
    assert.ok(fs.existsSync(path.join(tmpDir, 'inbox', 'brief-contoso-prod-2026-10-28.md')));

    // /api/remediate runs DryRunPreflight and writes a rollback snapshot
    const rollbackFile = path.join(tmpDir, 'rollback-test.json');
    const remRes = await fetch(`${base}/api/remediate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-AVD-CSRF': statusJson.csrfToken },
      body: JSON.stringify({
        playbookId: 'pb-fsx-kerberos-smb-auth',
        mode: 'DryRunPreflight',
        vaultPath: tmpDir,
        snapshotPath: rollbackFile
      })
    });
    assert.equal(remRes.status, 200);
    const remJson = await remRes.json();
    assert.equal(remJson.ok, true);
    assert.equal(remJson.state.stage, 'preflight');
    assert.equal(remJson.state.status, 'pass');
    assert.ok(fs.existsSync(rollbackFile));
  } finally {
    await new Promise((resolve) => srv.close(resolve));
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('BYO-LLM adapter in /api/chat scrubs all tenant data before outbound call, never leaks API keys, and falls back offline on failure', async () => {
  const tmpDir = fs.mkdtempSync(path.join(ROOT, 'tmp-llm-'));
  let capturedLlmRequest = null;
  let shouldFailLlm = false;

  const mockLlmFetch = async (url, init) => {
    capturedLlmRequest = { url, headers: init.headers, body: JSON.parse(init.body) };
    if (shouldFailLlm) {
      throw new Error('Simulated local LLM timeout');
    }
    return {
      ok: true,
      status: 200,
      async json() {
        return {
          choices: [
            {
              message: {
                content: 'Bottom line: Enable AES-128-GCM + AES-256-GCM on <id-1> for <email-1> (pb-fsx-kerberos-smb-auth, asm-entra-files-kerberos-ready).'
              }
            }
          ]
        };
      }
    };
  };

  const srv = createRemediationServer({
    sandboxPath: tmpDir,
    llmEnv: {
      AVD_LLM_PROVIDER: 'ollama',
      AVD_LLM_ENDPOINT: 'http://127.0.0.1:11434/v1/chat/completions',
      AVD_LLM_MODEL: 'llama3.2',
      AVD_LLM_API_KEY: 'super-secret-env-key-never-expose'
    },
    llmFetch: mockLlmFetch
  });

  await new Promise((resolve) => srv.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${srv.address().port}`;

  try {
    const statusRes = await fetch(`${base}/api/status`);
    const statusJson = await statusRes.json();
    const rawStatusStr = JSON.stringify(statusJson);
    assert.doesNotMatch(rawStatusStr, /super-secret-env-key-never-expose/);
    assert.equal(statusJson.llm.enabled, true);
    assert.equal(statusJson.llm.provider, 'ollama');

    const chatRes = await fetch(`${base}/api/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-AVD-CSRF': statusJson.csrfToken },
      body: JSON.stringify({
        question: 'User jane@contoso.com on subscription 99999999-aaaa-bbbb-cccc-dddddddddddd from 203.0.113.99 got 0x0000052e on FSLogix',
        c11: {
          facts: {
            'c11.entra.kerberosStoragePrincipalsReady': 0,
            'c11.subscriptionId': '99999999-aaaa-bbbb-cccc-dddddddddddd'
          }
        }
      })
    });
    assert.equal(chatRes.status, 200);
    const chatJson = await chatRes.json();
    assert.equal(chatJson.mode, 'byo-llm-redacted');
    assert.equal(chatJson.llmProvider, 'ollama');
    assert.ok(capturedLlmRequest, 'Expected BYO-LLM adapter to invoke llmFetch');

    const sentText = JSON.stringify(capturedLlmRequest.body);
    assert.doesNotMatch(sentText, /jane@contoso\.com/i);
    assert.doesNotMatch(sentText, /contoso\.com/i);
    assert.doesNotMatch(sentText, /99999999-aaaa-bbbb-cccc-dddddddddddd/i);
    assert.doesNotMatch(sentText, /203\.0\.113\.99/);
    assert.match(sentText, /<email-1>/);
    assert.match(sentText, /<id-1>/);
    assert.match(sentText, /<ip-1>/);

    // Now simulate LLM failure -> automatic fallback to deterministic-offline
    shouldFailLlm = true;
    const fallbackRes = await fetch(`${base}/api/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-AVD-CSRF': statusJson.csrfToken },
      body: JSON.stringify({ question: 'FSLogix 0x0000052e' })
    });
    assert.equal(fallbackRes.status, 200);
    const fallbackJson = await fallbackRes.json();
    assert.equal(fallbackJson.mode, 'deterministic-offline');
    assert.equal(fallbackJson.playbookId, 'pb-fsx-kerberos-smb-auth');
    assert.match(fallbackJson.fallbackReason, /Simulated local LLM timeout/);

    // /api/inbox/file promotes raw inbox notes to lessons/ and removes the filed inbox item
    const inboxDir = path.join(tmpDir, 'inbox');
    fs.mkdirSync(inboxDir, { recursive: true });
    const rawInboxFile = path.join(inboxDir, 'incident-2026-10-28-pb-conn-shortpath-blocked.md');
    fs.writeFileSync(rawInboxFile, '# Remediated pb-conn-shortpath-blocked\n\n## What happened\n- UDP 3390 blocked.\n', 'utf8');

    const fileRes = await fetch(`${base}/api/inbox/file`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-AVD-CSRF': statusJson.csrfToken },
      body: JSON.stringify({ sandboxPath: tmpDir, now: '2026-10-28' })
    });
    assert.equal(fileRes.status, 200);
    const fileJson = await fileRes.json();
    assert.equal(fileJson.ok, true);
    assert.equal(fileJson.filedCount, 1);
    assert.equal(fileJson.filed[0].targetRelPath, 'lessons/2026-10-28-pb-conn-shortpath-blocked.md');
    assert.ok(fs.existsSync(path.join(tmpDir, 'lessons', '2026-10-28-pb-conn-shortpath-blocked.md')));
    assert.ok(!fs.existsSync(rawInboxFile), 'Filed inbox note should be removed after verified write to lessons/');
  } finally {
    await new Promise((resolve) => srv.close(resolve));
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('loadEstateVault(), Invoke-AvdDiagnosticProbe.ps1, and Invoke-AvdRemediationPlan.ps1 work across arbitrary environment names and enforce spend gate', () => {
  const tmpVault = fs.mkdtempSync(path.join(ROOT, 'tmp-vault-'));
  try {
    const envSnapDir = path.join(tmpVault, 'environments', 'fabrikam-prod', 'snapshots');
    fs.mkdirSync(envSnapDir, { recursive: true });
    fs.writeFileSync(
      path.join(envSnapDir, '20261025T120000-inventory.json'),
      JSON.stringify({
        Datasets: { 'arm-resources': 42, 'avd-host-pools': 2, 'avd-session-hosts': 4, 'private-endpoints': 2 },
        HostPools: [{ Name: 'vdpool-fab-prod', HostPoolType: 'Pooled', LoadBalancerType: 'BreadthFirst', MaxSessionLimit: 12 }],
        SessionHosts: { 'vdpool-fab-prod': { Count: 4, ByStatus: { Available: 4 } } }
      }),
      'utf8'
    );

    const loaded = loadEstateVault(tmpVault);
    assert.equal(loaded.envName, 'fabrikam-prod');
    assert.deepEqual(loaded.environments, ['fabrikam-prod']);
    assert.equal(loaded.derivedC11.facts['c11.azure.armResources'], 42);
    assert.equal(loaded.derivedC11.facts['c11.hostPool.name'], 'vdpool-fab-prod');

    // Run Invoke-AvdDiagnosticProbe.ps1 against the fabrikam-prod vault
    const probeScript = path.join(ROOT, 'scripts', 'Invoke-AvdDiagnosticProbe.ps1');
    const probeOut = execFileSync('pwsh', [
      '-NoLogo', '-NoProfile', '-File', probeScript,
      '-ProbeId', 'probe-conn-private-dns',
      '-VaultPath', tmpVault,
      '-OfflineDemo'
    ], { encoding: 'utf8', timeout: 15000 });
    assert.match(probeOut, /"environment":"fabrikam-prod"/);
    assert.match(probeOut, /"probeId":"probe-conn-private-dns"/);
    assert.match(probeOut, /"status":"pass"/);

    // Run Invoke-AvdRemediationPlan.ps1 DryRunPreflight -> ApplyApprovedFix -> Rollback
    const remScript = path.join(ROOT, 'scripts', 'Invoke-AvdRemediationPlan.ps1');
    const snapFile = path.join(tmpVault, 'rollback-shortpath.json');
    const preOut = execFileSync('pwsh', [
      '-NoLogo', '-NoProfile', '-File', remScript,
      '-PlaybookId', 'pb-conn-shortpath-blocked',
      '-Mode', 'DryRunPreflight',
      '-VaultPath', tmpVault,
      '-SnapshotPath', snapFile
    ], { encoding: 'utf8', timeout: 15000 });
    assert.match(preOut, /"stage":"preflight"/);
    assert.match(preOut, /"environment":"fabrikam-prod"/);
    assert.ok(fs.existsSync(snapFile));

    const rbOut = execFileSync('pwsh', [
      '-NoLogo', '-NoProfile', '-File', remScript,
      '-PlaybookId', 'pb-conn-shortpath-blocked',
      '-Mode', 'Rollback',
      '-VaultPath', tmpVault,
      '-SnapshotPath', snapFile
    ], { encoding: 'utf8', timeout: 15000 });
    assert.match(rbOut, /"stage":"rollback"/);
    assert.match(rbOut, /"status":"pass"/);

    // Billable operation without exact 'go batch <id> $<total>' approval phrase must fail
    assert.throws(() => {
      execFileSync('pwsh', [
        '-NoLogo', '-NoProfile', '-File', remScript,
        '-PlaybookId', 'pb-host-drain-capacity-exhausted',
        '-Mode', 'ApplyApprovedFix',
        '-VaultPath', tmpVault,
        '-SnapshotPath', snapFile,
        '-BillableOperation',
        '-ApprovalPhrase', 'go'
      ], { encoding: 'utf8', stdio: 'pipe', timeout: 15000 });
    });

    // Billable operation with exact 'go batch <id> $<total>' approval phrase succeeds
    const approvedOut = execFileSync('pwsh', [
      '-NoLogo', '-NoProfile', '-File', remScript,
      '-PlaybookId', 'pb-host-drain-capacity-exhausted',
      '-Mode', 'ApplyApprovedFix',
      '-VaultPath', tmpVault,
      '-SnapshotPath', snapFile,
      '-BillableOperation',
      '-ApprovalPhrase', 'go batch b20261111-01 $1.50'
    ], { encoding: 'utf8', timeout: 15000 });
    assert.match(approvedOut, /"stage":"verify"/);
    assert.match(approvedOut, /"status":"pass"/);

    // Save-AvdIncidentBundle.ps1 writes incident.json, schema-valid remediation-c24.json, SUMMARY.md, and inbox note
    const saveScript = path.join(ROOT, 'scripts', 'Save-AvdIncidentBundle.ps1');
    const saveOut = execFileSync('pwsh', [
      '-NoLogo', '-NoProfile', '-File', saveScript,
      '-PlaybookId', 'pb-conn-shortpath-blocked',
      '-VaultPath', tmpVault,
      '-Confidence', 'high'
    ], { encoding: 'utf8', timeout: 15000 });
    assert.match(saveOut, /"stage":"capture"/);
    assert.match(saveOut, /"environment":"fabrikam-prod"/);
    const saveStateMatch = saveOut.match(/<<<AVDREM-STATE\s+(\{.*\})\s+AVDREM-STATE>>>/);
    assert.ok(saveStateMatch, 'Save-AvdIncidentBundle.ps1 must emit AVDREM-STATE');
    const saveState = JSON.parse(saveStateMatch[1]);
    assert.ok(fs.existsSync(saveState.savedTo));
    assert.ok(fs.existsSync(saveState.c24PlanPath));

    // ConvertFrom-AvdRemediationPlan.ps1 validates remediation-c24.json against C24 schema and emits Invoke-AvdControlPlanes.ps1 command
    const convertScript = path.join(ROOT, 'scripts', 'ConvertFrom-AvdRemediationPlan.ps1');
    const convOut = execFileSync('pwsh', [
      '-NoLogo', '-NoProfile', '-File', convertScript,
      '-Path', saveState.c24PlanPath
    ], { encoding: 'utf8', timeout: 15000 });
    assert.match(convOut, /Invoke-AvdControlPlanes\.ps1 -Planes intune -DryRun/);
    assert.match(convOut, /"stage":"c24-bridge"/);
    assert.match(convOut, /"status":"pass"/);
  } finally {
    fs.rmSync(tmpVault, { recursive: true, force: true });
  }
});
