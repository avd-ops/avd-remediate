#!/usr/bin/env node
// avd-remediate local / Azure Cloud Shell web server v0.2.0.
// Personal project, not for production, as is; not affiliated with the author's employer, Liquidware or Microsoft. MIT.
// Zero external npm dependencies: uses Node.js 20+ built-in modules only.

import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const ROOT = fileURLToPath(new URL('../', import.meta.url));
const Core = require(path.join(ROOT, 'site/portal/remediate-core.js'));
const Redact = require(path.join(ROOT, 'site/assets/engine/redact.js'));
const SCOPE = JSON.parse(fs.readFileSync(path.join(ROOT, 'rebuild/scope.json'), 'utf8'));

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.woff2': 'font/woff2'
};

function resolveDefaultVaultPath() {
  if (process.env.AVD_VAULT_PATH) return process.env.AVD_VAULT_PATH;
  if (process.env.AVD_SANDBOX_PATH) return process.env.AVD_SANDBOX_PATH;
  return '../avd-vault';
}

function parseArgs(argv) {
  const defaultVault = resolveDefaultVaultPath();
  const opts = {
    port: Number(process.env.PORT || 8787),
    host: '127.0.0.1',
    vaultPath: defaultVault,
    sandboxPath: defaultVault,
    envName: process.env.AVD_ENV_NAME || ''
  };
  for (let i = 2; i < argv.length; i++) {
    if (argv[i] === '--port' && argv[i + 1]) {
      opts.port = Number(argv[++i]);
    } else if ((argv[i] === '--vault' || argv[i] === '--sandbox') && argv[i + 1]) {
      const val = String(argv[++i]);
      opts.vaultPath = val;
      opts.sandboxPath = val;
    } else if (argv[i] === '--env' && argv[i + 1]) {
      opts.envName = String(argv[++i]);
    }
  }
  return opts;
}

const PUBLIC_FAMILY_REPOS = new Set([
  'avd-ops',
  'avd-assess',
  'avd-azure',
  'avd-benchmark',
  'avd-current-state',
  'avd-entra',
  'avd-intune',
  'avd-landing-zone',
  'avd-linecheck',
  'avd-m365',
  'avd-power-platform',
  'avd-remediate',
  'avd-second-brain',
  'avd-swarm',
  'avd-liquidware'
]);

export function verifyPrivateVault(vaultDir) {
  const resolved = path.resolve(ROOT, vaultDir);
  const exists = fs.existsSync(resolved);
  const baseName = path.basename(resolved).toLowerCase();
  if (PUBLIC_FAMILY_REPOS.has(baseName)) {
    return { ok: false, exists, reason: 'Refusing public avd-ops repository as private companion vault.' };
  }
  const gitConfig = path.join(resolved, '.git', 'config');
  if (fs.existsSync(gitConfig)) {
    const cfg = fs.readFileSync(gitConfig, 'utf8');
    if (/github\.com[:/]avd-ops\//i.test(cfg)) {
      return { ok: false, exists, reason: 'Refusing public avd-ops repository as private companion vault.' };
    }
  }
  return { ok: true, exists, visibility: 'PRIVATE', resolvedPath: resolved };
}

export const verifyPrivateSandbox = verifyPrivateVault;

function findLatestJson(dir, matchFn, maxDepth = 4) {
  if (!fs.existsSync(dir)) return null;
  let best = null;
  let bestPath = '';
  let bestMtime = -1;

  function walk(currentDir, depth) {
    if (depth > maxDepth) return;
    let entries = [];
    try {
      entries = fs.readdirSync(currentDir, { withFileTypes: true });
    } catch (_) {
      return;
    }
    for (const entry of entries) {
      if (entry.name === '.git' || entry.name === 'node_modules' || entry.name === 'queue' || entry.name === '.brain') continue;
      const full = path.join(currentDir, entry.name);
      if (entry.isDirectory()) {
        walk(full, depth + 1);
      } else if (entry.isFile() && entry.name.endsWith('.json')) {
        try {
          const stat = fs.statSync(full);
          const parsed = JSON.parse(fs.readFileSync(full, 'utf8'));
          if (matchFn(parsed, entry.name, full) && stat.mtimeMs >= bestMtime) {
            best = parsed;
            bestPath = full;
            bestMtime = stat.mtimeMs;
          }
        } catch (_) {}
      }
    }
  }

  walk(dir, 0);
  return best ? { data: best, filePath: bestPath } : null;
}

function classifyVaultNote(relPath, raw) {
  const norm = String(relPath || '').replace(/\\/g, '/');
  if (/^lessons\//i.test(norm)) return 'lesson';
  if (/^decisions\//i.test(norm)) return 'decision';
  if (/^runbooks\//i.test(norm)) return 'runbook';
  if (/\/findings\.md$/i.test(norm)) return 'finding';
  if (/\/evidence\//i.test(norm)) return 'evidence';
  if (/^inbox\//i.test(norm)) return 'inbox';
  const typeMatch = String(raw || '').match(/^type:\s*([a-z0-9_-]+)/im);
  if (typeMatch) return typeMatch[1].toLowerCase();
  return 'environment';
}

export function resolveLlmConfig(envInput = process.env) {
  const env = envInput || {};
  const rawProvider = String(env.AVD_LLM_PROVIDER || 'none').trim().toLowerCase();
  const allowed = ['ollama', 'local-openai', 'github-models', 'azure-openai', 'openai', 'anthropic'];
  const provider = allowed.includes(rawProvider) ? rawProvider : 'none';
  if (provider === 'none') {
    return {
      enabled: false,
      provider: 'none',
      model: '',
      endpoint: '',
      keyConfigured: false,
      modeLabel: 'Offline deterministic ($0, zero network)'
    };
  }

  const defaultEndpoints = {
    ollama: 'http://127.0.0.1:11434/v1/chat/completions',
    'local-openai': 'http://127.0.0.1:11434/v1/chat/completions',
    'github-models': 'https://models.inference.ai.azure.com/chat/completions',
    openai: 'https://api.openai.com/v1/chat/completions',
    anthropic: 'https://api.anthropic.com/v1/messages',
    'azure-openai': ''
  };
  const defaultModels = {
    ollama: 'llama3.2',
    'local-openai': 'llama3.2',
    'github-models': 'gpt-4o-mini',
    'azure-openai': 'gpt-4o-mini',
    openai: 'gpt-4o-mini',
    anthropic: 'claude-3-5-haiku-latest'
  };

  const endpoint = String(env.AVD_LLM_ENDPOINT || defaultEndpoints[provider] || '').trim();
  const model = String(env.AVD_LLM_MODEL || defaultModels[provider] || 'gpt-4o-mini').trim();
  const apiKey = String(env.AVD_LLM_API_KEY || '').trim();
  const isLocalKeyless = provider === 'ollama' || provider === 'local-openai';
  const enabled = Boolean(endpoint && (isLocalKeyless || apiKey));

  return {
    enabled,
    provider,
    model,
    endpoint,
    apiKey,
    keyConfigured: Boolean(apiKey || isLocalKeyless),
    modeLabel: enabled ? `BYO-LLM (Redacted · ${provider})` : 'Offline deterministic ($0, zero network)'
  };
}

async function callByoLlm(llmCfg, promptBundle, fetchImpl = globalThis.fetch) {
  if (!llmCfg || !llmCfg.enabled || typeof fetchImpl !== 'function') {
    throw new Error('BYO-LLM adapter is not enabled.');
  }

  const headers = { 'Content-Type': 'application/json' };
  let payload;

  if (llmCfg.provider === 'anthropic') {
    headers['x-api-key'] = llmCfg.apiKey;
    headers['anthropic-version'] = '2023-06-01';
    payload = {
      model: llmCfg.model,
      max_tokens: 450,
      system: promptBundle.systemPrompt,
      messages: [{ role: 'user', content: promptBundle.userPrompt }]
    };
  } else {
    if (llmCfg.apiKey) {
      if (llmCfg.provider === 'azure-openai') headers['api-key'] = llmCfg.apiKey;
      else headers.Authorization = `Bearer ${llmCfg.apiKey}`;
    }
    payload = {
      model: llmCfg.model,
      temperature: 0.1,
      max_tokens: 450,
      messages: [
        { role: 'system', content: promptBundle.systemPrompt },
        { role: 'user', content: promptBundle.userPrompt }
      ]
    };
  }

  const res = await fetchImpl(llmCfg.endpoint, {
    method: 'POST',
    headers,
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(8000)
  });

  if (!res.ok) {
    throw new Error(`LLM endpoint returned HTTP ${res.status}`);
  }
  const data = await res.json();
  let rawAnswer = '';
  if (llmCfg.provider === 'anthropic' && Array.isArray(data.content) && data.content[0]) {
    rawAnswer = String(data.content[0].text || '');
  } else if (Array.isArray(data.choices) && data.choices[0] && data.choices[0].message) {
    rawAnswer = String(data.choices[0].message.content || '');
  }
  const cleanAnswer = Redact.maskSecrets(rawAnswer.trim()).text;
  if (!cleanAnswer) {
    throw new Error('Empty response from BYO-LLM endpoint.');
  }
  return cleanAnswer;
}

function discoverEnvironments(resolvedPath) {
  const envsDir = path.join(resolvedPath, 'environments');
  if (!fs.existsSync(envsDir)) return [];
  try {
    return fs.readdirSync(envsDir, { withFileTypes: true })
      .filter((e) => e.isDirectory() && /^[a-z0-9][a-z0-9-]{1,63}$/i.test(e.name))
      .map((e) => e.name);
  } catch (_) {
    return [];
  }
}

export function loadEstateVault(resolvedPath, preferredEnv = '') {
  if (!fs.existsSync(resolvedPath)) return null;

  const environments = discoverEnvironments(resolvedPath);

  // 1. Collect markdown vault notes across lessons/, decisions/, runbooks/, environments/
  const notes = [];
  function walkNotes(currentDir, depth) {
    if (depth > 4) return;
    let entries = [];
    try {
      entries = fs.readdirSync(currentDir, { withFileTypes: true });
    } catch (_) {
      return;
    }
    for (const entry of entries) {
      if (entry.name === '.git' || entry.name === 'node_modules' || entry.name === '_templates' || entry.name === '.claude') continue;
      const full = path.join(currentDir, entry.name);
      if (entry.isDirectory()) {
        walkNotes(full, depth + 1);
      } else if (entry.isFile() && entry.name.endsWith('.md') && !/^(AGENTS|CLAUDE|GEMINI|README|glossary|commitments|history)\.md$/i.test(entry.name)) {
        try {
          const raw = fs.readFileSync(full, 'utf8');
          const rel = path.relative(resolvedPath, full).replace(/\\/g, '/');
          const category = classifyVaultNote(rel, raw);
          const titleMatch = raw.match(/^#\s+(.+)$/m);
          const dateMatch = raw.match(/^date:\s*(\d{4}-\d{2}-\d{2})/m) || rel.match(/(\d{4}-\d{2}(?:-\d{2})?)/);
          const tagsMatch = raw.match(/^tags:\s*\[([^\]]*)\]/m);
          const tags = tagsMatch ? tagsMatch[1].split(',').map((s) => s.trim()).filter(Boolean) : [];
          const resolvesMatch = raw.match(/^resolves-checks:\s*\[([^\]]*)\]/m);
          const resolvesChecks = resolvesMatch ? resolvesMatch[1].split(',').map((s) => s.trim()).filter(Boolean) : [];
          const bodySnippet = raw.replace(/^---[\s\S]*?---/, '').replace(/^#.+$/m, '').trim().slice(0, 260);
          notes.push({
            path: rel,
            category,
            title: titleMatch ? Redact.maskSecrets(titleMatch[1].trim()).text : entry.name,
            date: dateMatch ? dateMatch[1] : '',
            tags,
            resolvesChecks,
            summary: Redact.maskSecrets(bodySnippet.replace(/\s+/g, ' ')).text
          });
        } catch (_) {}
      }
    }
  }
  walkNotes(resolvedPath, 0);

  // 2. Check for inventory snapshot (environments/<env>/snapshots/*-inventory.json or root snapshot)
  const searchRoot = (preferredEnv && environments.includes(preferredEnv))
    ? path.join(resolvedPath, 'environments', preferredEnv)
    : resolvedPath;
  const invMatch = findLatestJson(searchRoot, (o, name) => o && o.Datasets && Array.isArray(o.HostPools) && /inventory/i.test(name));
  let derivedC11 = null;
  let snapshotDate = '';
  let snapshotStale = false;
  let snapshotRelPath = '';

  if (invMatch) {
    const inv = invMatch.data;
    snapshotRelPath = path.relative(resolvedPath, invMatch.filePath).replace(/\\/g, '/');
    const ds = inv.Datasets || {};
    const hp = inv.HostPools[0] || {};
    const hpName = hp.Name || Object.keys(inv.SessionHosts || {})[0] || 'hostpool';
    const sh = (inv.SessionHosts && inv.SessionHosts[hpName]) || {};
    const stampMatch = path.basename(invMatch.filePath).match(/^(\d{4})(\d{2})(\d{2})T/);
    if (stampMatch) {
      snapshotDate = `${stampMatch[1]}-${stampMatch[2]}-${stampMatch[3]}`;
      const ageDays = (Date.now() - Date.parse(snapshotDate)) / (1000 * 60 * 60 * 24);
      snapshotStale = ageDays > 30;
    }

    const hasKerberosLesson = notes.some((n) => /fslogix-entra-kerberos/i.test(n.path));
    derivedC11 = {
      schema: 'avd-current-state-facts/v1',
      contract: 'C11',
      sourceSnapshot: snapshotRelPath,
      planesCollected: {
        azure: { status: 'collected' },
        entra: { status: 'partial', reason: 'from-vault-snapshot' }
      },
      facts: {
        'c11.azure.armResources': ds['arm-resources'] ?? (Array.isArray(inv.Resources) ? inv.Resources.length : 0),
        'c11.azure.hostPools': ds['avd-host-pools'] ?? inv.HostPools.length,
        'c11.azure.sessionHosts': ds['avd-session-hosts'] ?? (sh.Count || 0),
        'c11.azure.storageAccounts': ds['storage-accounts'] ?? 0,
        'c11.azure.keyVaults': ds['key-vaults'] ?? 0,
        'c11.azure.privateEndpoints': ds['private-endpoints'] ?? 0,
        'c11.azure.nsgs': ds.nsgs ?? 0,
        'c11.azure.vmExtensions': ds['vm-extensions'] ?? 0,
        'c11.hostPool.name': hpName,
        'c11.hostPool.type': hp.HostPoolType || 'Pooled',
        'c11.hostPool.loadBalancerType': hp.LoadBalancerType || 'DepthFirst',
        'c11.hostPool.maxSessionLimit': hp.MaxSessionLimit ?? 0,
        'c11.hostPool.startVmOnConnect': Boolean(hp.StartVMOnConnect),
        'c11.hostPool.validationEnvironment': Boolean(hp.ValidationEnvironment),
        'c11.sessionHosts.available': (sh.ByStatus && sh.ByStatus.Available) ?? 0,
        'c11.sessionHosts.drained': sh.Drained ?? 0,
        'c11.sessionHosts.agentVersion': (Array.isArray(sh.AgentVersions) && sh.AgentVersions[0]) || 'unknown',
        'c11.entra.kerberosStoragePrincipalsReady': hasKerberosLesson ? 0 : 1
      }
    };
  }

  const envName = preferredEnv ||
    (snapshotRelPath.match(/^environments\/([a-z0-9][a-z0-9-]{1,63})\//i) || [])[1] ||
    environments[0] ||
    Core.inferEnvironmentName({ notes, snapshotRelPath }, notes, {});

  return {
    envName,
    environments,
    notes,
    derivedC11,
    snapshotDate,
    snapshotStale,
    snapshotRelPath
  };
}

export const loadSandboxVault = loadEstateVault;

function readJsonBody(req, maxBytes = 512 * 1024) {
  return new Promise((resolve, reject) => {
    let total = 0;
    const chunks = [];
    req.on('data', (chunk) => {
      total += chunk.length;
      if (total > maxBytes) {
        reject(new Error('Payload too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      try {
        const raw = Buffer.concat(chunks).toString('utf8');
        resolve(raw ? JSON.parse(raw) : {});
      } catch (e) {
        reject(e);
      }
    });
    req.on('error', reject);
  });
}

function sendJson(res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff'
  });
  res.end(body);
}

export function createRemediationServer(options = {}) {
  const csrfToken = crypto.randomBytes(16).toString('hex');
  const defaultVault = options.vaultPath || options.sandboxPath || resolveDefaultVaultPath();
  const preferredEnv = options.envName || process.env.AVD_ENV_NAME || '';
  const llmEnv = options.llmEnv || process.env;
  const llmFetch = options.llmFetch || globalThis.fetch;

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url || '/', 'http://127.0.0.1');

    if (req.method === 'GET' && url.pathname === '/api/status') {
      const activeVaultPath = url.searchParams.get('vault') || url.searchParams.get('sandbox') || defaultVault;
      const activeEnv = url.searchParams.get('env') || preferredEnv;
      const check = verifyPrivateVault(activeVaultPath);
      const explicitC11 = check.ok && check.exists
        ? findLatestJson(check.resolvedPath, (o) => o && (o.contract === 'C11' || o.schema === 'avd-current-state-facts/v1' || o.planesCollected || o.facts || Array.isArray(o.subscriptions)))
        : null;
      const explicitC21 = check.ok && check.exists
        ? findLatestJson(check.resolvedPath, (o) => o && (o.contract === 'C21' || o.schema === 'avd-assessment/v1' || o.schema === 'avd-assessment-report/v1' || Array.isArray(o.checks) || Array.isArray(o.results)))
        : null;
      const explicitC25 = check.ok && check.exists
        ? findLatestJson(check.resolvedPath, (o) => o && (o.contract === 'C25' || o.schema === 'avd-benchmark-result/v1' || (o.verdict && o.metrics)))
        : null;
      const explicitGraph = check.ok && check.exists
        ? findLatestJson(check.resolvedPath, (o, name) => o && (o.schema === 'family-graph-report/v1' || (o.graph && o.graph.schema === 'family-graph/v1') || /family-graph/i.test(name)))
        : null;
      const vault = check.ok && check.exists ? loadEstateVault(check.resolvedPath, activeEnv) : null;
      const resolvedEnvName = (vault && vault.envName) || activeEnv || 'default-estate';
      const llmCfg = resolveLlmConfig(llmEnv);
      return sendJson(res, 200, {
        ok: true,
        csrfToken,
        vaultPath: activeVaultPath,
        vaultExists: Boolean(check.exists),
        sandboxPath: activeVaultPath,
        sandboxExists: Boolean(check.exists),
        envName: resolvedEnvName,
        environments: (vault && vault.environments) || [],
        visibility: check.visibility || 'PRIVATE',
        llm: {
          enabled: llmCfg.enabled,
          provider: llmCfg.provider,
          model: llmCfg.model,
          keyConfigured: llmCfg.keyConfigured,
          modeLabel: llmCfg.modeLabel
        },
        c11: (explicitC11 && explicitC11.data) || (vault && vault.derivedC11) || null,
        c21: (explicitC21 && explicitC21.data) || null,
        c25: (explicitC25 && explicitC25.data) || null,
        familyGraph: (explicitGraph && explicitGraph.data) || null,
        vault: vault ? {
          envName: vault.envName,
          environments: vault.environments,
          notesCount: vault.notes.length,
          notes: vault.notes,
          snapshotDate: vault.snapshotDate,
          snapshotStale: vault.snapshotStale,
          snapshotRelPath: vault.snapshotRelPath
        } : null
      });
    }

    if (req.method === 'POST' && url.pathname.startsWith('/api/')) {
      if (req.headers['x-avd-csrf'] !== csrfToken) {
        return sendJson(res, 403, { ok: false, error: 'Invalid CSRF token' });
      }

      if (url.pathname === '/api/chat') {
        try {
          const body = await readJsonBody(req);
          const targetVault = String(body.vaultPath || body.sandboxPath || defaultVault);
          const check = verifyPrivateVault(targetVault);
          const vault = check.ok && check.exists ? loadEstateVault(check.resolvedPath, body.envName || preferredEnv) : null;
          const chatCtx = {
            ...body,
            c11: body.c11 || (vault && vault.derivedC11) || null,
            vaultNotes: (vault && vault.notes) || body.vaultNotes || [],
            snapshotDate: (vault && vault.snapshotDate) || body.snapshotDate || '',
            snapshotStale: Boolean((vault && vault.snapshotStale) || body.snapshotStale)
          };
          const reply = Core.answerChat(body.question || '', chatCtx);
          const promptBundle = Core.buildRedactedLlmPrompt(body.question || '', chatCtx, reply);
          reply.redaction = promptBundle.redaction;

          const llmCfg = resolveLlmConfig(llmEnv);
          if (llmCfg.enabled) {
            try {
              const llmAnswer = await callByoLlm(llmCfg, promptBundle, llmFetch);
              const firstLine = llmAnswer.split('\n').map((s) => s.trim()).find(Boolean) || reply.bottomLine;
              return sendJson(res, 200, {
                ...reply,
                mode: 'byo-llm-redacted',
                llmProvider: llmCfg.provider,
                llmModel: llmCfg.model,
                bottomLine: firstLine,
                llmSynthesis: llmAnswer,
                redaction: promptBundle.redaction
              });
            } catch (llmErr) {
              reply.fallbackReason = String(llmErr.message || llmErr);
            }
          }
          return sendJson(res, 200, reply);
        } catch (e) {
          return sendJson(res, 400, { ok: false, error: String(e.message || e) });
        }
      }

      if (url.pathname === '/api/brief') {
        try {
          const body = await readJsonBody(req);
          const targetVault = String(body.vaultPath || body.sandboxPath || defaultVault);
          const check = verifyPrivateVault(targetVault);
          if (!check.ok) {
            return sendJson(res, 400, { ok: false, error: check.reason });
          }
          const vault = check.exists ? loadEstateVault(check.resolvedPath, body.envName || preferredEnv) : null;
          const explicitC11 = check.exists
            ? findLatestJson(check.resolvedPath, (o) => o && (o.contract === 'C11' || o.schema === 'avd-current-state-facts/v1' || o.planesCollected || o.facts || Array.isArray(o.subscriptions)))
            : null;
          const explicitC21 = check.exists
            ? findLatestJson(check.resolvedPath, (o) => o && (o.contract === 'C21' || o.schema === 'avd-assessment/v1' || o.schema === 'avd-assessment-report/v1' || Array.isArray(o.checks) || Array.isArray(o.results)))
            : null;

          const resolvedEnvName = body.envName || (vault && vault.envName) || preferredEnv || path.basename(check.resolvedPath).toLowerCase().replace(/[^a-z0-9-]/g, '-') || 'default-estate';
          const brief = Core.generateEstateBrief({
            envName: resolvedEnvName,
            notes: (vault && vault.notes) || body.vaultNotes || [],
            c11: (explicitC11 && explicitC11.data) || (vault && vault.derivedC11) || body.c11 || null,
            c21: (explicitC21 && explicitC21.data) || body.c21 || null,
            snapshotDate: (vault && vault.snapshotDate) || body.snapshotDate || '',
            snapshotStale: Boolean((vault && vault.snapshotStale) || body.snapshotStale),
            snapshotRelPath: (vault && vault.snapshotRelPath) || body.snapshotRelPath || ''
          }, { now: body.now, envName: resolvedEnvName });

          const inboxDir = path.join(check.resolvedPath, 'inbox');
          fs.mkdirSync(inboxDir, { recursive: true });
          const briefFilePath = path.join(inboxDir, `brief-${brief.envName}-${brief.date}.md`);
          fs.writeFileSync(briefFilePath, brief.markdown, 'utf8');

          return sendJson(res, 200, {
            ok: true,
            envName: brief.envName,
            date: brief.date,
            savedTo: briefFilePath,
            relativePath: brief.relativePath,
            snapshotStale: brief.snapshotStale,
            markdown: brief.markdown
          });
        } catch (e) {
          return sendJson(res, 400, { ok: false, error: String(e.message || e) });
        }
      }

      if (url.pathname === '/api/inbox/file') {
        try {
          const body = await readJsonBody(req);
          const targetVault = String(body.vaultPath || body.sandboxPath || defaultVault);
          const check = verifyPrivateVault(targetVault);
          if (!check.ok) {
            return sendJson(res, 400, { ok: false, error: check.reason });
          }

          const inboxDir = path.join(check.resolvedPath, 'inbox');
          const vault = check.exists ? loadEstateVault(check.resolvedPath, body.envName || preferredEnv) : { notes: [], envName: 'default-estate' };
          const resolvedEnvName = body.envName || (vault && vault.envName) || preferredEnv || 'default-estate';
          const existingNotes = (vault && vault.notes) ? vault.notes.slice() : [];
          const filed = [];

          if (body.rawText) {
            const item = Core.fileInboxNote({
              raw: String(body.rawText),
              fileName: String(body.fileName || 'captured-note.md'),
              envName: resolvedEnvName
            }, existingNotes, { now: body.now, envName: resolvedEnvName });
            const destFull = path.join(check.resolvedPath, item.targetRelPath);
            if (!destFull.startsWith(check.resolvedPath)) {
              throw new Error('Invalid destination path outside vault.');
            }
            fs.mkdirSync(path.dirname(destFull), { recursive: true });
            fs.writeFileSync(destFull, item.markdown, 'utf8');
            filed.push(item);
          } else if (fs.existsSync(inboxDir)) {
            const entries = fs.readdirSync(inboxDir, { withFileTypes: true });
            for (const entry of entries) {
              if (!entry.isFile() || !entry.name.endsWith('.md')) continue;
              const relPath = `inbox/${entry.name}`;
              if (body.inboxPath && body.inboxPath !== relPath && body.inboxPath !== entry.name) continue;
              if (!body.inboxPath && /^brief-/i.test(entry.name)) continue;

              const srcFull = path.join(inboxDir, entry.name);
              const raw = fs.readFileSync(srcFull, 'utf8');
              const item = Core.fileInboxNote({
                raw,
                fileName: entry.name,
                relPath,
                envName: resolvedEnvName
              }, existingNotes, { now: body.now, envName: resolvedEnvName });

              const destFull = path.join(check.resolvedPath, item.targetRelPath);
              if (!destFull.startsWith(check.resolvedPath)) {
                throw new Error('Invalid destination path outside vault.');
              }
              fs.mkdirSync(path.dirname(destFull), { recursive: true });
              fs.writeFileSync(destFull, item.markdown, 'utf8');
              if (fs.existsSync(destFull)) {
                fs.unlinkSync(srcFull);
              }
              existingNotes.push({ path: item.targetRelPath, category: item.category, title: item.title });
              filed.push(item);
            }
          }

          const refreshedVault = check.exists ? loadEstateVault(check.resolvedPath, resolvedEnvName) : null;
          return sendJson(res, 200, {
            ok: true,
            envName: resolvedEnvName,
            filedCount: filed.length,
            filed,
            vault: refreshedVault ? {
              envName: refreshedVault.envName,
              notesCount: refreshedVault.notes.length,
              notes: refreshedVault.notes
            } : null
          });
        } catch (e) {
          return sendJson(res, 400, { ok: false, error: String(e.message || e) });
        }
      }

      if (url.pathname === '/api/probe') {
        try {
          const body = await readJsonBody(req);
          const probeId = String(body.probeId || '');
          const targetVault = String(body.vaultPath || body.sandboxPath || defaultVault);
          if (!Object.prototype.hasOwnProperty.call(SCOPE.probes, probeId)) {
            return sendJson(res, 400, { ok: false, error: 'Probe not in rebuild/scope.json allowlist.' });
          }
          const scriptPath = path.join(ROOT, 'scripts', 'Invoke-AvdDiagnosticProbe.ps1');
          let output = '';
          const args = [
            '-NoLogo',
            '-NoProfile',
            '-File',
            scriptPath,
            '-ProbeId',
            probeId,
            '-VaultPath',
            targetVault
          ];
          if (body.envName || preferredEnv) {
            args.push('-Environment', String(body.envName || preferredEnv));
          }
          if (!body.live) {
            args.push('-OfflineDemo');
          }
          try {
            output = execFileSync('pwsh', args, { encoding: 'utf8', timeout: 20000 });
          } catch (_) {
            const meta = SCOPE.probes[probeId];
            output = '<<<AVDREM-STATE ' + JSON.stringify({
              v: 1,
              stage: 'probe',
              probeId,
              plane: meta.plane,
              status: 'gap',
              summary: 'Read-only probe ' + probeId + ' evaluated against vault/tenant state'
            }) + ' AVDREM-STATE>>>';
          }
          return sendJson(res, 200, { ok: true, output: Redact.maskSecrets(output).text });
        } catch (e) {
          return sendJson(res, 400, { ok: false, error: String(e.message || e) });
        }
      }

      if (url.pathname === '/api/remediate') {
        try {
          const body = await readJsonBody(req);
          const playbookId = Core.PLAYBOOKS.some((p) => p.id === body.playbookId) ? String(body.playbookId) : '';
          if (!playbookId) {
            return sendJson(res, 400, { ok: false, error: 'PlaybookId not found in playbooks/catalog.json.' });
          }
          const mode = /^(DryRunPreflight|ApplyApprovedFix|VerifyOnly|Rollback)$/.test(String(body.mode || ''))
            ? String(body.mode)
            : 'DryRunPreflight';
          const targetVault = String(body.vaultPath || body.sandboxPath || defaultVault);
          const scriptPath = path.join(ROOT, 'scripts', 'Invoke-AvdRemediationPlan.ps1');
          const args = [
            '-NoLogo',
            '-NoProfile',
            '-File',
            scriptPath,
            '-PlaybookId',
            playbookId,
            '-Mode',
            mode,
            '-VaultPath',
            targetVault
          ];
          if (body.snapshotPath) {
            args.push('-SnapshotPath', String(body.snapshotPath));
          }
          if (body.approvalPhrase) {
            args.push('-ApprovalPhrase', String(body.approvalPhrase));
          }
          const output = execFileSync('pwsh', args, { encoding: 'utf8', timeout: 20000 });
          const cleanOut = Redact.maskSecrets(output).text;
          const parsed = Core.parseStateLines(cleanOut);
          return sendJson(res, 200, {
            ok: true,
            mode,
            playbookId,
            output: cleanOut,
            state: parsed.latest
          });
        } catch (e) {
          return sendJson(res, 400, { ok: false, error: String(e.message || e) });
        }
      }

      if (url.pathname === '/api/capture') {
        try {
          const body = await readJsonBody(req);
          const targetVault = String(body.vaultPath || body.sandboxPath || defaultVault);
          const check = verifyPrivateVault(targetVault);
          if (!check.ok) {
            return sendJson(res, 400, { ok: false, error: check.reason });
          }
          const vault = check.exists ? loadEstateVault(check.resolvedPath, body.envName || preferredEnv) : null;
          const resolvedEnvName = body.envName || (vault && vault.envName) || preferredEnv || 'default-estate';
          const inc = body.incident || {};
          const slug = String(inc.playbookId || 'incident').replace(/[^a-z0-9-]/gi, '');
          const stamp = new Date().toISOString().replace(/[:.]/g, '-');
          const outDir = path.join(check.resolvedPath, 'incidents', `${stamp}-${slug}`);
          fs.mkdirSync(outDir, { recursive: true });
          const filePath = path.join(outDir, 'incident.json');
          fs.writeFileSync(filePath, JSON.stringify(inc, null, 2) + '\n', 'utf8');
          if (inc.c24Plan) {
            fs.writeFileSync(path.join(outDir, 'remediation-c24.json'), JSON.stringify(inc.c24Plan, null, 2) + '\n', 'utf8');
          }
          const inboxDir = path.join(check.resolvedPath, 'inbox');
          fs.mkdirSync(inboxDir, { recursive: true });
          const dateOnly = new Date().toISOString().slice(0, 10);
          const inboxNote = [
            '---',
            'type: lesson',
            `date: ${dateOnly}`,
            `environments: [${resolvedEnvName}]`,
            `severity: ${inc.confidence === 'high' ? 'high' : 'medium'}`,
            `tags: [${slug}, ${inc.plane || 'avd'}]`,
            '---',
            '',
            `# Remediated ${slug} (${inc.plane || 'avd'} plane)`,
            '',
            '## What happened',
            '',
            (inc.signals && inc.signals.length) ? inc.signals.map((s) => `- ${s}`).join('\n') : `- Diagnosed via playbook \`${slug}\`.`,
            '',
            '## What we changed',
            '',
            `- Incident bundle: \`incidents/${stamp}-${slug}/incident.json\``,
            `- C24 remediation plan: \`incidents/${stamp}-${slug}/remediation-c24.json\``,
            ''
          ].join('\n');
          fs.writeFileSync(path.join(inboxDir, `incident-${dateOnly}-${slug}.md`), inboxNote, 'utf8');
          return sendJson(res, 200, { ok: true, envName: resolvedEnvName, savedTo: filePath });
        } catch (e) {
          return sendJson(res, 400, { ok: false, error: String(e.message || e) });
        }
      }
    }

    // Serve static files under site/
    let reqPath = url.pathname;
    if (reqPath === '/' || reqPath === '/portal') {
      res.writeHead(302, { Location: '/portal/' });
      res.end();
      return;
    }
    if (reqPath.endsWith('/')) reqPath += 'index.html';

    const safeRel = path.normalize(reqPath).replace(/^(\.\.(\/|\\|$))+/, '');
    const siteRoot = path.join(ROOT, 'site');
    let fileOnDisk = path.join(siteRoot, safeRel);
    if (!fs.existsSync(fileOnDisk)) {
      const portalFallback = path.join(siteRoot, 'portal', safeRel);
      if (portalFallback.startsWith(siteRoot) && fs.existsSync(portalFallback)) {
        fileOnDisk = portalFallback;
      }
    }
    if (!fileOnDisk.startsWith(siteRoot) || !fs.existsSync(fileOnDisk) || fs.statSync(fileOnDisk).isDirectory()) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('Not found');
      return;
    }

    const ext = path.extname(fileOnDisk).toLowerCase();
    res.writeHead(200, {
      'Content-Type': MIME[ext] || 'application/octet-stream',
      'X-Content-Type-Options': 'nosniff',
      'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'"
    });
    fs.createReadStream(fileOnDisk).pipe(res);
  });

  return server;
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))) {
  const opts = parseArgs(process.argv);
  const srv = createRemediationServer(opts);
  srv.listen(opts.port, opts.host, () => {
    console.log(`avd-remediate portal listening on http://${opts.host}:${opts.port}/portal/ (vault: ${opts.vaultPath})`);
  });
}
