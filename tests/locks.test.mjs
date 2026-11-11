import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const ROOT = fileURLToPath(new URL('../', import.meta.url));
const Core = require(path.join(ROOT, 'site/portal/remediate-core.js'));
const Pins = JSON.parse(fs.readFileSync(path.join(ROOT, 'contracts/PINS.json'), 'utf8'));
const ControlPlanes = JSON.parse(fs.readFileSync(path.join(ROOT, 'contracts/control-planes.json'), 'utf8'));
const LzParameters = JSON.parse(fs.readFileSync(path.join(ROOT, 'contracts/lz-parameters.json'), 'utf8'));
const WorkloadTiers = JSON.parse(fs.readFileSync(path.join(ROOT, 'contracts/workload-tiers.json'), 'utf8'));
const Calibration = JSON.parse(fs.readFileSync(path.join(ROOT, 'contracts/calibration.json'), 'utf8'));

test('contracts/PINS.json verifies SHA-256 hashes of all vendored upstream contract files', () => {
  assert.equal(Pins.schema, 'avd-contract-pins/v1');
  assert.equal(Pins.consumer, 'avd-remediate');

  for (const [repoName, source] of Object.entries(Pins.sources)) {
    assert.match(source.commit, /^[0-9a-f]{40}$/, `Invalid commit SHA for ${repoName}`);
    assert.equal(Core.UPSTREAM_PINS[repoName], source.commit, `Core.UPSTREAM_PINS[${repoName}] must match contracts/PINS.json`);
    if (source.files) {
      for (const [relPath, expectedSha] of Object.entries(source.files)) {
        const fullPath = path.join(ROOT, relPath);
        assert.ok(fs.existsSync(fullPath), `Missing vendored contract file ${relPath}`);
        const normalizedText = fs.readFileSync(fullPath, 'utf8').replace(/\r\n/g, '\n');
        const actualSha = crypto.createHash('sha256').update(normalizedText, 'utf8').digest('hex');
        assert.equal(actualSha, expectedSha, `SHA-256 mismatch for ${relPath}`);
      }
    }
  }
});

test('remediate-core.js SECOND_BRAIN_RULES match vendored avd-second-brain workload-tiers.json and calibration.json', () => {
  assert.deepEqual(Core.SECOND_BRAIN_RULES.workloadTiers.maxUsersPerVcpu, WorkloadTiers.values.maxUsersPerVcpu);
  assert.deepEqual(Core.SECOND_BRAIN_RULES.workloadTiers.multiSessionVcpu, WorkloadTiers.values.multiSessionVcpu);
  assert.deepEqual(Core.SECOND_BRAIN_RULES.workloadTiers.minMemoryGiBPerSession, WorkloadTiers.values.minMemoryGiBPerSession);
  assert.equal(Core.SECOND_BRAIN_RULES.workloadTiers.targetUtilization, WorkloadTiers.values.targetUtilization);

  assert.equal(Core.SECOND_BRAIN_RULES.calibration.minObservations, Calibration.values.minObservations);
  assert.equal(Core.SECOND_BRAIN_RULES.calibration.minFactor, Calibration.values.minFactor);
  assert.equal(Core.SECOND_BRAIN_RULES.calibration.maxFactor, Calibration.values.maxFactor);
  assert.equal(Core.SECOND_BRAIN_RULES.calibration.minPeakSessionsPerHost, Calibration.values.minPeakSessionsPerHost);
  assert.equal(Core.SECOND_BRAIN_RULES.calibration.minBindingUtilization, Calibration.values.minBindingUtilization);
});

test('every playbook wires to avd-landing-zone control-planes.json stages, avd-swarm actions/KQL, and C24 schema constraints', () => {
  const swarmActionsAllowed = new Set(Pins.sources['avd-swarm'].actions);
  const swarmKqlAllowed = new Set(Pins.sources['avd-swarm'].kql);
  const azureLzParamNames = new Set(LzParameters.parameters.map((p) => p.name));
  const claimRegex = /^(ref:[a-z0-9][a-z0-9-]{1,63}#[A-Za-z0-9][A-Za-z0-9.:-]{0,63}|gap:[a-z0-9][a-z0-9-]{1,63})$/;

  for (const pb of Core.PLAYBOOKS) {
    const rem = pb.remediation;
    assert.ok(rem.c24Change, `${pb.id} missing remediation.c24Change`);
    assert.ok(rem.lzStage, `${pb.id} missing remediation.lzStage`);
    assert.ok(swarmActionsAllowed.has(rem.swarmAction), `${pb.id} has unknown swarmAction ${rem.swarmAction}`);
    assert.ok(swarmKqlAllowed.has(rem.swarmKql), `${pb.id} has unknown swarmKql ${rem.swarmKql}`);

    // At least one citation must be a valid C24 ref:# or gap: claim
    assert.ok(
      pb.citations.some((c) => claimRegex.test(c.id)),
      `${pb.id} must have at least one C24-valid ref:<src>#<anchor> citation`
    );

    // Verify lzStage matches avd-landing-zone contracts/control-planes.json
    const cpPlane = ControlPlanes.planes[rem.plane];
    assert.ok(cpPlane, `${pb.id} plane ${rem.plane} missing in contracts/control-planes.json`);
    assert.equal(rem.lzStage.repo, cpPlane.repo);
    assert.equal(rem.lzStage.deployEntrypoint, cpPlane.entryPoint);
    assert.equal(rem.lzStage.manifest, cpPlane.handoffManifest);

    // If azure plane lz-parameter, verify parameter exists in avd-current-state rebuild/lz-parameters.json
    if (rem.c24Change.kind === 'lz-parameter' && rem.c24Change.plane === 'azure') {
      assert.ok(
        azureLzParamNames.has(rem.c24Change.name),
        `${pb.id} azure lz-parameter ${rem.c24Change.name} must exist in contracts/lz-parameters.json`
      );
    }
  }
});

test('buildC24Plan() JSON output conforms strictly to avd-assess contracts/schemas/remediation-plan.schema.json', () => {
  const allFindings = Core.PLAYBOOKS.map((pb) => ({ playbook: pb, outcome: 'gap' }));
  const planObj = Core.buildC24Plan(allFindings, {
    estate: 'est-deadbeef',
    plannedOn: '2026-11-11',
    assessmentSha256: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
    methodVersion: 10
  });

  // Serialize and re-parse to inspect exact JSON wire format
  const plan = JSON.parse(JSON.stringify(planObj));

  const allowedTopKeys = new Set(['schema', 'estate', 'plannedOn', 'basis', 'items', 'extensions']);
  for (const k of Object.keys(plan)) {
    assert.ok(allowedTopKeys.has(k), `Unexpected top-level C24 property: ${k}`);
  }
  assert.equal(plan.schema, 'avd-remediation-plan/v1');
  assert.match(plan.estate, /^est-[0-9a-f]{8}$/);
  assert.match(plan.plannedOn, /^[0-9]{4}-[0-9]{2}-[0-9]{2}$/);
  assert.match(plan.basis.assessment, /^[0-9a-f]{64}$/);
  assert.equal(plan.basis.method, 10);
  assert.match(plan.basis.landingZoneCommit, /^[0-9a-f]{40}$/);

  const allowedItemKeys = new Set(['order', 'check', 'plane', 'outcome', 'pillar', 'severity', 'claims', 'source', 'change']);
  const claimRegex = /^(ref:[a-z0-9][a-z0-9-]{1,63}#[A-Za-z0-9][A-Za-z0-9.:-]{0,63}|gap:[a-z0-9][a-z0-9-]{1,63})$/;

  assert.equal(plan.items.length, 14);
  plan.items.forEach((item, idx) => {
    for (const k of Object.keys(item)) {
      assert.ok(allowedItemKeys.has(k), `Unexpected C24 item property: ${k}`);
    }
    assert.equal(item.order, idx + 1);
    assert.match(item.check, /^asm-[a-z0-9-]{3,60}$/);
    assert.ok(['azure', 'entra', 'intune', 'm365', 'power-platform', 'orchestrator'].includes(item.plane));
    assert.ok(['warn', 'gap', 'unknown'].includes(item.outcome));
    assert.ok(['reliability', 'security', 'cost', 'operations', 'performance'].includes(item.pillar));
    assert.ok(['high', 'medium', 'low'].includes(item.severity));
    assert.ok(Array.isArray(item.claims) && item.claims.length >= 1);
    item.claims.forEach((cl) => assert.match(cl, claimRegex));
    assert.ok(['review-fix', 'unreviewed'].includes(item.source));

    const ch = item.change;
    assert.ok(['lz-parameter', 'lz-setting', 'manual'].includes(ch.kind));
    if (ch.kind === 'manual') {
      assert.ok(['collect-evidence', 'rebuild-hosts', 'remove-orphaned-devices', 'private-value', 'outside-landing-zone', 'process', 'no-known-change'].includes(ch.code));
      assert.equal(ch.name, undefined);
      assert.equal(ch.from, undefined);
      assert.equal(ch.to, undefined);
    } else if (ch.kind === 'lz-setting') {
      assert.match(ch.name, /^[a-z][A-Za-z0-9-]{2,60}$/);
      assert.equal(ch.code, undefined);
      assert.equal(ch.from, undefined);
      assert.equal(ch.to, undefined);
    } else if (ch.kind === 'lz-parameter') {
      assert.match(ch.name, /^[a-z][A-Za-z0-9-]{2,60}$/);
      assert.equal(ch.code, undefined);
    }
  });

  assert.ok(plan.extensions && plan.extensions['avd-remediate']);
  assert.equal(plan.extensions['avd-remediate'].summary.totalItems, 14);
});
