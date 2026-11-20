import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { createTicketAdapter, triageTicket } from '../scripts/ticket-adapter.mjs';

const require = createRequire(import.meta.url);
const ROOT = fileURLToPath(new URL('../', import.meta.url));
const Core = require(path.join(ROOT, 'site/portal/remediate-core.js'));

test('buildC24Plan and buildSwarmHandoff attach normalized ticketRef without breaking schema', () => {
  const ref = { provider: 'jira-jsm', ticketId: 'AVD-101', correlationId: 'corr-101' };
  const c24 = Core.buildC24Plan([Core.PLAYBOOKS[0]], { ticketRef: ref });
  assert.equal(c24.extensions['avd-ops-ticket'].schema, 'avd-ticket-ref/v1');
  assert.equal(c24.extensions['avd-ops-ticket'].ticketId, 'AVD-101');

  const handoff = Core.buildSwarmHandoff(Core.PLAYBOOKS[0], [], { ticketRef: ref });
  assert.equal(handoff.ticketRef.provider, 'jira-jsm');
  assert.equal(handoff.ticketRef.ticketId, 'AVD-101');
});

test('triageTicket diagnoses ticket, posts internal work note, and transitions to awaiting_approval', async () => {
  const adapter = createTicketAdapter({ provider: 'mock' });
  const created = await adapter.createTicket({
    title: 'FSLogix temporary profile on pooled desktop',
    description: 'User received Event ID 26 temporary profile after reconnect.',
  });

  const result = await triageTicket(adapter, created.id);
  assert.equal(result.ticketRef.ticketId, created.id);
  assert.equal(result.c24Plan.extensions['avd-ops-ticket'].ticketId, created.id);
  assert.equal(result.swarmHandoff.ticketRef.ticketId, created.id);

  const updated = await adapter.getTicket(created.id);
  assert.equal(updated.status, 'awaiting_approval');
  assert.equal(updated.comments.length, 1);
  assert.equal(updated.comments[0].internal, true);
  assert.match(updated.comments[0].body, /\[avd-remediate triage\]/);
});

test('servicenow provider is reserved for avd-servicenow', () => {
  assert.throws(() => createTicketAdapter({ provider: 'servicenow' }), /avd-servicenow/);
});
