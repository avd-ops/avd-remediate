import fs from 'node:fs';
import path from 'node:path';

const STOPWORDS = new Set([
  'the', 'and', 'for', 'with', 'how', 'why', 'what', 'when', 'where', 'which',
  'from', 'that', 'this', 'these', 'those', 'are', 'was', 'were', 'not', 'can',
  'does', 'did', 'have', 'has', 'had', 'into', 'your', 'our', 'their', 'about',
  'should', 'could', 'would', 'will', 'there', 'here', 'issue', 'problem'
]);

export function tokenizeQuery(query) {
  const raw = String(query || '').toLowerCase();
  const matches = raw.match(/[a-z0-9][a-z0-9._:-]{1,}/g) || [];
  const seen = new Set();
  const tokens = [];
  for (const tok of matches) {
    const clean = tok.replace(/^[._:-]+|[._:-]+$/g, '');
    if (clean.length < 3 || STOPWORDS.has(clean) || seen.has(clean)) continue;
    seen.add(clean);
    tokens.push(clean);
  }
  return tokens;
}

function scoreText(tokens, weightedFields) {
  if (!tokens.length) return 0;
  let score = 0;
  for (const { text, weight } of weightedFields) {
    if (!text) continue;
    const hay = String(text).toLowerCase();
    for (const tok of tokens) {
      if (hay.includes(tok)) score += weight;
    }
  }
  return score;
}

export function queryAvdAssess(query, assessDir, limit = 3) {
  if (!assessDir || !fs.existsSync(assessDir)) {
    return { available: false, hits: [] };
  }
  const tokens = tokenizeQuery(query);
  if (!tokens.length) return { available: true, hits: [] };

  const hits = [];
  const indexPath = path.join(assessDir, 'index.json');
  if (fs.existsSync(indexPath)) {
    try {
      const idx = JSON.parse(fs.readFileSync(indexPath, 'utf8'));
      const refs = Array.isArray(idx.references) ? idx.references : [];
      for (const ref of refs) {
        const claimsText = Array.isArray(ref.claims)
          ? ref.claims.map((c) => `${c.id || ''} ${c.says || ''}`).join(' ')
          : '';
        const score = scoreText(tokens, [
          { text: ref.id, weight: 4 },
          { text: ref.title, weight: 3 },
          { text: ref.notes, weight: 2 },
          { text: claimsText, weight: 1 }
        ]);
        if (score > 0) {
          const matchedClaim = Array.isArray(ref.claims)
            ? ref.claims.find((c) => tokens.some((t) => String(c.says || '').toLowerCase().includes(t)))
            : null;
          hits.push({
            source: 'avd-assess',
            id: `ref:${ref.id}`,
            title: ref.title || ref.id,
            url: ref.url || '',
            snippet: (matchedClaim && matchedClaim.says) || ref.notes || '',
            score
          });
        }
      }
    } catch {
      // Ignore malformed index.json
    }
  }

  const methodsDir = path.join(assessDir, 'methods');
  if (fs.existsSync(methodsDir)) {
    try {
      for (const entry of fs.readdirSync(methodsDir, { withFileTypes: true })) {
        if (!entry.isFile() || !entry.name.endsWith('.md')) continue;
        const full = path.join(methodsDir, entry.name);
        const raw = fs.readFileSync(full, 'utf8');
        const heading = (raw.match(/^#\s+(.+)$/m) || [])[1] || entry.name.replace(/\.md$/, '');
        const score = scoreText(tokens, [
          { text: entry.name, weight: 4 },
          { text: heading, weight: 3 },
          { text: raw.slice(0, 4000), weight: 1 }
        ]);
        if (score > 0) {
          hits.push({
            source: 'avd-assess',
            id: `methods/${entry.name}`,
            title: heading.trim(),
            url: '',
            snippet: `avd-assess method guide (${entry.name})`,
            score
          });
        }
      }
    } catch {
      // Ignore unreadable methods directory
    }
  }

  hits.sort((a, b) => b.score - a.score);
  return { available: true, hits: hits.slice(0, limit) };
}

function unquoteYaml(val) {
  const s = String(val || '').trim();
  if ((s.startsWith("'") && s.endsWith("'")) || (s.startsWith('"') && s.endsWith('"'))) {
    return s.slice(1, -1).replace(/''/g, "'");
  }
  return s;
}

export function parseKnownErrorsYaml(raw) {
  const items = [];
  let current = null;
  let activeKey = '';
  for (const line of String(raw || '').split(/\r?\n/)) {
    if (!line.trim() || line.trim().startsWith('#')) continue;
    const idMatch = line.match(/^-\s+id:\s*(.+)$/);
    if (idMatch) {
      if (current) items.push(current);
      current = { id: unquoteYaml(idMatch[1]) };
      activeKey = '';
      continue;
    }
    if (!current) continue;
    const kvMatch = line.match(/^\s{2}([a-zA-Z_]+):\s*(.*)$/);
    if (kvMatch) {
      activeKey = kvMatch[1];
      current[activeKey] = unquoteYaml(kvMatch[2]);
    } else if (activeKey && /^\s{4,}/.test(line)) {
      current[activeKey] = `${current[activeKey] || ''} ${unquoteYaml(line)}`.trim();
    }
  }
  if (current) items.push(current);
  return items;
}

function walkMarkdownFiles(dir, baseDir, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name.startsWith('.') || entry.name === 'schema') continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walkMarkdownFiles(full, baseDir, out);
    } else if (entry.isFile() && entry.name.endsWith('.md')) {
      out.push({ full, rel: path.relative(baseDir, full).replace(/\\/g, '/') });
    }
  }
  return out;
}

export function queryAvdSecondBrain(query, brainDir, limit = 3) {
  if (!brainDir || !fs.existsSync(brainDir)) {
    return { available: false, hits: [] };
  }
  const tokens = tokenizeQuery(query);
  if (!tokens.length) return { available: true, hits: [] };

  const hits = [];
  const kbRoot = path.join(brainDir, 'docs', 'knowledge');

  const knownErrorsPath = path.join(kbRoot, 'troubleshooting', 'known-errors.yaml');
  if (fs.existsSync(knownErrorsPath)) {
    try {
      const entries = parseKnownErrorsYaml(fs.readFileSync(knownErrorsPath, 'utf8'));
      for (const item of entries) {
        const score = scoreText(tokens, [
          { text: item.id, weight: 4 },
          { text: item.symptom, weight: 3 },
          { text: item.cause, weight: 2 },
          { text: item.fix, weight: 1 }
        ]);
        if (score > 0) {
          hits.push({
            source: 'avd-second-brain',
            id: `known-error:${item.id}`,
            title: item.symptom || item.id,
            url: item.source || '',
            snippet: [item.cause, item.fix ? `Fix: ${item.fix}` : ''].filter(Boolean).join(' — '),
            score
          });
        }
      }
    } catch {
      // Ignore malformed known-errors.yaml
    }
  }

  if (fs.existsSync(kbRoot)) {
    try {
      for (const file of walkMarkdownFiles(kbRoot, brainDir)) {
        const raw = fs.readFileSync(file.full, 'utf8');
        const fmMatch = raw.match(/^---\r?\n([\s\S]*?)\r?\n---/);
        let title = path.basename(file.rel, '.md');
        let summary = '';
        if (fmMatch) {
          const t = fmMatch[1].match(/^title:\s*(.+)$/m);
          const s = fmMatch[1].match(/^summary:\s*(.+)$/m);
          if (t) title = unquoteYaml(t[1]);
          if (s) summary = unquoteYaml(s[1]);
        }
        const score = scoreText(tokens, [
          { text: file.rel, weight: 3 },
          { text: title, weight: 3 },
          { text: summary, weight: 2 },
          { text: raw.slice(0, 3000), weight: 1 }
        ]);
        if (score > 0) {
          hits.push({
            source: 'avd-second-brain',
            id: file.rel,
            title,
            url: '',
            snippet: summary || title,
            score
          });
        }
      }
    } catch {
      // Ignore unreadable knowledge directory
    }
  }

  hits.sort((a, b) => b.score - a.score);
  return { available: true, hits: hits.slice(0, limit) };
}

export async function queryMicrosoftLearn(redactedQuery, options = {}) {
  const enabled = options.enabled !== false;
  if (!enabled) {
    return { available: false, disabled: true, hits: [] };
  }
  const cleanQuery = String(redactedQuery || '')
    .replace(/<[a-z]+-\d+>/gi, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  const tokens = tokenizeQuery(cleanQuery);
  if (!tokens.length) {
    return { available: true, hits: [] };
  }

  const fetchImpl = options.fetchImpl || globalThis.fetch;
  if (typeof fetchImpl !== 'function') {
    return { available: false, hits: [] };
  }

  const limit = Number(options.limit || 3);
  const timeoutMs = Number(options.timeoutMs || 2500);
  const searchUrl =
    `https://learn.microsoft.com/api/search?search=${encodeURIComponent(cleanQuery)}` +
    `&locale=en-us&$top=${limit}`;

  try {
    const res = await fetchImpl(searchUrl, {
      method: 'GET',
      headers: { Accept: 'application/json' },
      signal: typeof AbortSignal !== 'undefined' && AbortSignal.timeout ? AbortSignal.timeout(timeoutMs) : undefined
    });
    if (!res || !res.ok) {
      return { available: false, hits: [], error: `HTTP ${res ? res.status : 'unknown'}` };
    }
    const data = await res.json();
    const results = Array.isArray(data && data.results) ? data.results : [];
    const hits = results.slice(0, limit).map((item) => ({
      source: 'microsoft-learn',
      id: 'learn',
      title: String(item.title || '').trim(),
      url: String(item.url || '').trim(),
      snippet: String(item.description || '').replace(/\s+/g, ' ').trim()
    })).filter((h) => h.title && h.url);
    return { available: true, hits };
  } catch (err) {
    return { available: false, hits: [], error: String((err && err.message) || err) };
  }
}

export async function queryMechanicalSources(rawQuestion, redactedQuestion, opts = {}) {
  const assess = queryAvdAssess(rawQuestion, opts.assessDir, opts.limit || 3);
  const secondBrain = queryAvdSecondBrain(rawQuestion, opts.secondBrainDir, opts.limit || 3);
  const microsoftLearn = await queryMicrosoftLearn(redactedQuestion, {
    enabled: opts.learnEnabled,
    fetchImpl: opts.learnFetch,
    limit: opts.limit || 3,
    timeoutMs: opts.learnTimeoutMs || 2500
  });

  const citationLines = [];
  for (const h of assess.hits) {
    citationLines.push(
      `avd-assess:${h.id} — ${h.title}${h.url ? ` (${h.url})` : ''}${h.snippet ? `: ${h.snippet}` : ''}`
    );
  }
  for (const h of secondBrain.hits) {
    citationLines.push(
      `avd-second-brain:${h.id} — ${h.title}${h.url ? ` (${h.url})` : ''}${h.snippet ? `: ${h.snippet}` : ''}`
    );
  }
  for (const h of microsoftLearn.hits) {
    citationLines.push(
      `learn:${h.title} (${h.url})${h.snippet ? ` — ${h.snippet}` : ''}`
    );
  }

  return {
    assess,
    secondBrain,
    microsoftLearn,
    citationLines
  };
}
