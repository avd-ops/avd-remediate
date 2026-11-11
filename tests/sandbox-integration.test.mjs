import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { loadEstateVault, createRemediationServer } from '../scripts/server.mjs';

const require = createRequire(import.meta.url);
const ROOT = fileURLToPath(new URL('../', import.meta.url));
const Core = require(path.join(ROOT, 'site/portal/remediate-core.js'));

test('end-to-end companion vault integration: vault discovery, EstateGraph correlation, 5-plane probes, C24 bridge, and dry-run remediation', async () => {
  const tmpVault = fs.mkdtempSync(path.join(ROOT, 'tmp-e2e-vault-'));
  try {
    const envDir = path.join(tmpVault, 'environments', 'contoso-lab');
    const snapDir = path.join(envDir, 'snapshots');
    const lessonsDir = path.join(tmpVault, 'lessons');
    fs.mkdirSync(snapDir, { recursive: true });
    fs.mkdirSync(lessonsDir, { recursive: true });

    fs.writeFileSync(
      path.join(snapDir, '20261021T032412-inventory.json'),
      JSON.stringify({
        Datasets: { 'arm-resources': 57, 'avd-host-pools': 1, 'avd-session-hosts': 1, 'private-endpoints': 2 },
        HostPools: [{ Name: 'vdpool-contoso-lab', HostPoolType: 'Pooled', LoadBalancerType: 'DepthFirst', MaxSessionLimit: 8 }],
        SessionHosts: { 'vdpool-contoso-lab': { Count: 1, ByStatus: { Available: 1 } } }
      }),
      'utf8'
    );

    fs.writeFileSync(
      path.join(envDir, 'c21-assessment-report.json'),
      JSON.stringify({
        schema: 'avd-assessment-report/v1',
        environment: 'contoso-lab',
        checks: [
          { id: 'asm-entra-files-kerberos-ready', plane: 'entra', outcome: 'pass', evidence: 'Kerberos key active' },
          { id: 'asm-intune-rdp-shortpath', plane: 'intune', outcome: 'warn', evidence: 'UDP 3390 policy not assigned' }
        ]
      }),
      'utf8'
    );

    fs.writeFileSync(
      path.join(envDir, 'family-graph-report.json'),
      JSON.stringify({
        schema: 'family-graph-report/v1',
        estate: 'est-12345678',
        rootCausePaths: [
          {
            label: 'vdpool-contoso-lab',
            corroboratingGaps: ['gap:asm-intune-rdp-shortpath']
          }
        ],
        blastRadius: {
          affectedUsersEstimated: 8
        }
      }),
      'utf8'
    );

    fs.writeFileSync(
      path.join(lessonsDir, '2026-10-18-shortpath-udp.md'),
      '# UDP Shortpath requires port 3390\n\nVerified on contoso-lab.\n',
      'utf8'
    );

    // 1. Load synthetic companion vault and verify discovered artifacts
    const vault = loadEstateVault(tmpVault);
    assert.ok(vault, 'Expected loadEstateVault(tmpVault) to succeed');
    assert.equal(vault.envName, 'contoso-lab');
    assert.ok(vault.environments.includes('contoso-lab'));
    assert.ok(vault.notes.length >= 1);
    assert.equal(vault.derivedC11.facts['c11.azure.armResources'], 57);
    assert.equal(vault.derivedC11.facts['c11.hostPool.name'], 'vdpool-contoso-lab');
    assert.equal(vault.derivedC11.facts['c11.hostPool.maxSessionLimit'], 8);

    // 2. Spin up local server pointed at tmpVault and verify /api/status loads C11, C21, and EstateGraph
    const srv = createRemediationServer({ vaultPath: tmpVault });
    await new Promise((resolve) => srv.listen(0, '127.0.0.1', resolve));
    const base = `http://127.0.0.1:${srv.address().port}`;

    try {
      const statusRes = await fetch(`${base}/api/status`);
      assert.equal(statusRes.status, 200);
      const status = await statusRes.json();
      assert.equal(status.ok, true);
      assert.equal(status.vaultExists, true);
      assert.equal(status.envName, 'contoso-lab');
      assert.equal(status.visibility, 'PRIVATE');
      assert.ok(status.c11, 'Expected C11 from companion vault');
      assert.ok(status.c21, 'Expected C21 from companion vault');
      assert.ok(status.familyGraph, 'Expected family-graph-report.json from companion vault');
      assert.equal(status.familyGraph.schema, 'family-graph-report/v1');

      // 3. Run read-only probes via /api/probe against C21 & C11 state
      const probeShortpathRes = await fetch(`${base}/api/probe`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-AVD-CSRF': status.csrfToken },
        body: JSON.stringify({ probeId: 'probe-conn-shortpath-transport', vaultPath: tmpVault, live: false })
      });
      assert.equal(probeShortpathRes.status, 200);
      const probeShortpathJson = await probeShortpathRes.json();
      const parsedShortpath = Core.parseStateLines(probeShortpathJson.output).latest;
      assert.equal(parsedShortpath.probeId, 'probe-conn-shortpath-transport');
      assert.equal(parsedShortpath.environment, 'contoso-lab');
      assert.equal(parsedShortpath.status, 'warn');
      assert.equal(parsedShortpath.observed['asm-intune-rdp-shortpath'], 'warn');

      const probeKerberosRes = await fetch(`${base}/api/probe`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-AVD-CSRF': status.csrfToken },
        body: JSON.stringify({ probeId: 'probe-fsx-storage-kerberos', vaultPath: tmpVault, live: false })
      });
      const parsedKerberos = Core.parseStateLines((await probeKerberosRes.json()).output).latest;
      assert.equal(parsedKerberos.status, 'pass');
      assert.equal(parsedKerberos.observed['asm-entra-files-kerberos-ready'], 'pass');

      // 4. Diagnose open warnings with EstateGraph correlation
      const diag = Core.diagnose({
        domain: 'connectivity',
        c11: status.c11,
        c21: status.c21,
        familyGraph: status.familyGraph,
        probeStates: [parsedShortpath]
      });
      assert.equal(diag.primary.playbook.id, 'pb-conn-shortpath-blocked');
      assert.equal(diag.primary.confidence, 'high');
      assert.ok(
        diag.primary.signals.some((s) => /EstateGraph root-cause path \(vdpool-contoso-lab\) corroborates gap:asm-intune-rdp-shortpath/.test(s)),
        `Expected EstateGraph corroboration signal in [${diag.primary.signals.join('; ')}]`
      );
      assert.ok(diag.primary.estateBlastRadius, 'Expected estateBlastRadius from family-graph-report.json');
      assert.equal(diag.primary.estateBlastRadius.affectedUsersEstimated, 8);

      // 5. Generate C24 plan for two open warnings and run ConvertFrom-AvdRemediationPlan.ps1
      const c24Plan = Core.buildC24Plan(
        [
          { playbook: Core.PLAYBOOKS.find((p) => p.id === 'pb-conn-shortpath-blocked'), outcome: 'warn' },
          { playbook: Core.PLAYBOOKS.find((p) => p.id === 'pb-fsx-vhdx-locked-session'), outcome: 'warn' }
        ],
        { estate: 'est-12345678', plannedOn: '2026-11-11' }
      );
      assert.equal(c24Plan.schema, 'avd-remediation-plan/v1');
      assert.equal(c24Plan.items.length, 2);

      const tmpPlanFile = path.join(tmpVault, 'tmp-c24.json');
      fs.writeFileSync(tmpPlanFile, JSON.stringify(c24Plan, null, 2), 'utf8');
      const convertScript = path.join(ROOT, 'scripts', 'ConvertFrom-AvdRemediationPlan.ps1');
      const convOut = execFileSync('pwsh', ['-NoLogo', '-NoProfile', '-File', convertScript, '-Path', tmpPlanFile], {
        encoding: 'utf8',
        timeout: 15000
      });
      assert.match(convOut, /Invoke-AvdControlPlanes\.ps1 -Planes intune -DryRun/);
      const convState = Core.parseStateLines(convOut).latest;
      assert.equal(convState.stage, 'c24-bridge');
      assert.equal(convState.status, 'pass');
      assert.equal(convState.itemCount, 2);
      assert.deepEqual(convState.planes, ['intune']);

      // 6. Run DryRunPreflight via /api/remediate against tmpVault
      const tmpSnap = path.join(tmpVault, 'tmp-rollback.json');
      const remRes = await fetch(`${base}/api/remediate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-AVD-CSRF': status.csrfToken },
        body: JSON.stringify({
          playbookId: 'pb-conn-shortpath-blocked',
          mode: 'DryRunPreflight',
          vaultPath: tmpVault,
          snapshotPath: tmpSnap
        })
      });
      assert.equal(remRes.status, 200);
      const remJson = await remRes.json();
      assert.equal(remJson.ok, true);
      assert.equal(remJson.state.environment, 'contoso-lab');
      assert.equal(remJson.state.stage, 'preflight');
      assert.equal(remJson.state.status, 'pass');
    } finally {
      await new Promise((resolve) => srv.close(resolve));
    }
  } finally {
    fs.rmSync(tmpVault, { recursive: true, force: true });
  }
});
