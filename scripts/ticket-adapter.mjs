import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const ROOT = fileURLToPath(new URL('../', import.meta.url));
const Core = require(path.join(ROOT, 'site/portal/remediate-core.js'));

const DEFAULT_JIRA_STATUS_MAP = {
  new: 'Waiting for support',
  triaging: 'In Progress',
  awaiting_approval: 'Pending',
  resolved: 'Resolved',
};

/**
 * Create a normalized 5-method ticket adapter for avd-remediate.
 * Supports "mock" ($0 offline) and "jira-jsm" (Jira Service Management Cloud Free).
 * "servicenow" is reserved for avd-servicenow.
 */
export function createTicketAdapter(options = {}) {
  const provider = (options.provider || process.env.HELPDESK_PROVIDER || 'mock').toLowerCase();
  if (provider === 'mock') return createMockTicketAdapter(options);
  if (provider === 'jira-jsm') return createJiraJsmTicketAdapter(options);
  if (provider === 'servicenow') {
    throw new Error('Provider "servicenow" is reserved for avd-servicenow.');
  }
  throw new Error(`Unsupported ticket provider: ${provider}`);
}

/**
 * Triage one ticket through avd-remediate (read-only diagnose + redact + C24/C9 proposal)
 * and post an internal work note before transitioning to awaiting_approval.
 */
export async function triageTicket(adapter, ticketId, opts = {}) {
  const ticket = await adapter.getTicket(ticketId);
  const ticketRef = Core.normalizeTicketRef({
    provider: adapter.provider,
    ticketId: ticket.id,
    correlationId: opts.correlationId || `${adapter.provider}-${ticket.id}`,
  });

  await adapter.transitionTicket(ticket.id, 'triaging');

  const rawText = `${ticket.title || ''}\n${ticket.description || ''}`;
  const redactedPrompt = Core.buildRedactedLlmPrompt
    ? Core.buildRedactedLlmPrompt(rawText, { c11: opts.c11 || null, c21: opts.c21 || null })
    : null;
  const safeSymptom = (redactedPrompt && redactedPrompt.prompt) ? redactedPrompt.prompt : rawText;

  const diag = Core.diagnose({
    symptomText: safeSymptom,
    c11: opts.c11 || null,
    c21: opts.c21 || null,
  });

  const top = (diag.matches && diag.matches[0]) || { playbook: Core.PLAYBOOKS[0], score: 0 };
  const c24Plan = Core.buildC24Plan([top], { ticketRef, reviewed: false });
  const swarmHandoff = Core.buildSwarmHandoff(top.playbook, diag.signals || [], { ticketRef });

  const workNote = [
    `[avd-remediate triage]`,
    `Ticket: ${ticketRef.ticketId} (${ticketRef.provider})`,
    `Matched Playbook: ${top.playbook.id} — ${top.playbook.title}`,
    `Plane: ${swarmHandoff.targetPlane} | Action: ${swarmHandoff.action.id} (${swarmHandoff.action.risk})`,
    `Preflight Probe: ${swarmHandoff.preflightReadCheck}`,
    `C24 Items: ${c24Plan.items.length} | Requires Human Approval: true`,
  ].join('\n');

  await adapter.addWorkNote(ticket.id, workNote, { internal: true });
  await adapter.transitionTicket(ticket.id, 'awaiting_approval');

  return { ticketRef, c24Plan, swarmHandoff, workNote };
}

function createMockTicketAdapter(options = {}) {
  let seq = 0;
  const tickets = new Map();
  for (const t of options.initialTickets || []) {
    tickets.set(t.id, structuredClone(t));
    seq += 1;
  }

  return {
    provider: 'mock',
    async createTicket(payload) {
      const id = payload.id || `AVD-${++seq}`;
      const ticket = {
        id,
        title: payload.title || '',
        description: payload.description || '',
        status: 'new',
        comments: [],
      };
      tickets.set(id, ticket);
      return structuredClone(ticket);
    },
    async listOpenTickets(filter = {}) {
      const want = filter.status || 'new';
      return [...tickets.values()].filter((t) => t.status === want).map((t) => structuredClone(t));
    },
    async getTicket(id) {
      const t = tickets.get(id);
      if (!t) throw new Error(`Ticket not found: ${id}`);
      return structuredClone(t);
    },
    async addWorkNote(id, body, { internal = true } = {}) {
      const t = tickets.get(id);
      if (!t) throw new Error(`Ticket not found: ${id}`);
      const note = { id: `note-${t.comments.length + 1}`, internal: Boolean(internal), body };
      t.comments.push(note);
      return structuredClone(note);
    },
    async transitionTicket(id, targetState) {
      const t = tickets.get(id);
      if (!t) throw new Error(`Ticket not found: ${id}`);
      t.status = targetState;
      return structuredClone(t);
    },
  };
}

function createJiraJsmTicketAdapter(options = {}) {
  const baseUrl = (options.baseUrl || process.env.JIRA_BASE_URL || '').replace(/\/+$/, '');
  const email = options.email || process.env.JIRA_USER_EMAIL || '';
  const apiToken = options.apiToken || process.env.JIRA_API_TOKEN || '';
  const projectKey = options.projectKey || process.env.JIRA_PROJECT_KEY || 'AVD';
  const statusMap = { ...DEFAULT_JIRA_STATUS_MAP, ...(options.statusMap || {}) };
  const fetchImpl = options.fetch || globalThis.fetch;

  if (!baseUrl || !email || !apiToken) {
    throw new Error('jira-jsm adapter requires JIRA_BASE_URL, JIRA_USER_EMAIL, and JIRA_API_TOKEN.');
  }
  const auth = `Basic ${Buffer.from(`${email}:${apiToken}`).toString('base64')}`;

  async function req(method, apiPath, body) {
    const res = await fetchImpl(`${baseUrl}${apiPath}`, {
      method,
      headers: {
        Authorization: auth,
        Accept: 'application/json',
        ...(body ? { 'Content-Type': 'application/json' } : {}),
      },
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
    if (!res.ok) throw new Error(`Jira ${method} ${apiPath} failed (${res.status})`);
    return res.status === 204 ? null : res.json();
  }

  return {
    provider: 'jira-jsm',
    async createTicket(payload) {
      const res = await req('POST', '/rest/api/3/issue', {
        fields: {
          project: { key: projectKey },
          summary: payload.title,
          issuetype: { name: payload.issueType || process.env.JIRA_ISSUE_TYPE || '[System] Service request' },
          description: { type: 'doc', version: 1, content: [{ type: 'paragraph', content: [{ type: 'text', text: payload.description || '' }] }] },
        },
      });
      return { id: res.key, status: 'new' };
    },
    async listOpenTickets(filter = {}) {
      const jiraStatus = statusMap[filter.status || 'new'] || 'Waiting for support';
      const data = await req('POST', '/rest/api/3/search/jql', {
        jql: `project = "${projectKey}" AND status = "${jiraStatus}" ORDER BY created ASC`,
        maxResults: filter.limit || 25,
        fields: ['summary', 'description', 'status'],
      });
      return (data.issues || []).map((i) => ({ id: i.key, title: i.fields?.summary || '', description: '' }));
    },
    async getTicket(id) {
      const i = await req('GET', `/rest/api/3/issue/${encodeURIComponent(id)}`);
      const text = (i.fields?.description?.content || [])
        .flatMap((n) => (n.content || []).map((c) => c.text || ''))
        .join('\n');
      return { id: i.key, title: i.fields?.summary || '', description: text, status: i.fields?.status?.name || 'new' };
    },
    async addWorkNote(id, body, { internal = true } = {}) {
      return req('POST', `/rest/api/3/issue/${encodeURIComponent(id)}/comment`, {
        body: { type: 'doc', version: 1, content: [{ type: 'paragraph', content: [{ type: 'text', text: String(body) }] }] },
        properties: [{ key: 'sd.public.comment', value: { internal: Boolean(internal) } }],
      });
    },
    async transitionTicket(id, targetState) {
      const want = (statusMap[targetState] || targetState).toLowerCase();
      const data = await req('GET', `/rest/api/3/issue/${encodeURIComponent(id)}/transitions`);
      const match = (data.transitions || []).find((t) => t.name.toLowerCase() === want || t.to?.name?.toLowerCase() === want);
      if (!match) throw new Error(`No Jira transition "${want}" on ${id}`);
      await req('POST', `/rest/api/3/issue/${encodeURIComponent(id)}/transitions`, { transition: { id: match.id } });
      return { id, status: targetState };
    },
  };
}
