/* avd-ops portal engine v1.1.0: redact.js. Personal project, not for production, as is; not affiliated with the author's employer or Microsoft. MIT.
   Redaction for issue reports a portal prefills (docs/portal-engine-spec.md, section 6.2): secrets, the
   operator's own terms, emails, tenant and domain names, IDs, public IP addresses and user names in paths, plus
   the patterns a portal passes. Taken from the deployment portal's report.js (avd-landing-zone decision 0008).
   Each distinct value becomes a numbered placeholder (<email-1>, <id-2>, ...) so a report still shows which
   values match. That format is frozen: portals read it after redaction. Pure: no DOM, no network. */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory(require('./core.js'));
  else root.AvdOpsEngine.redact = factory(root.AvdOpsEngine.core);
})(typeof self !== 'undefined' ? self : this, function (core) {
  'use strict';

  // IDs that are the same in every tenant and help diagnosis. A portal adds its own (built-in roles it assigns).
  const PUBLIC_IDS = [
    '00000000-0000-0000-0000-000000000000',
    '00000003-0000-0000-c000-000000000000', // Microsoft Graph
    '9cdead84-a844-4324-93f2-b2e6bb768d07', // Azure Virtual Desktop
    'acdd72a7-3385-48ef-bd42-f606fba81ae7' // Reader
  ];
  // Domains that are not the operator's.
  const PUBLIC_DOMAINS = ['microsoft.com', 'windows.net', 'azure.com', 'azure.net', 'contoso.com', 'example.com', 'github.com', 'github.io', 'cloud.microsoft', 'microsoftonline.com'];
  const LABELS = {
    secret: 'secret or token', email: 'email address / UPN', domain: 'domain', tenant: 'tenant name', id: 'ID',
    ip: 'public IP address', user: 'user name in a path', name: 'name from your settings', custom: 'term you added'
  };
  const KIND = /^[a-z]+$/;
  const PLACEHOLDER = /^<[a-z]+-\d+>$/;
  // In an issue link, a line longer than this is shortened before whole lines are cut.
  const LONG_LINE = 400;

  function escapeRe(s) { return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

  // Only the secrets: tokens, keys, SAS signatures, passwords, device codes. A portal runs it on pasted output
  // before showing or reading it, so a secret is never on screen or kept; IDs and names stay. redact() starts with it.
  function maskSecrets(text) {
    let count = 0;
    const fixed = (placeholder) => () => { count++; return placeholder; };
    const keep = (placeholder) => (a, p) => { count++; return p + placeholder; };
    const out = String(text || '')
      .replace(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*/g, fixed('<token>'))
      .replace(/\b(Bearer\s+)(?!<)[A-Za-z0-9._~+/=-]{16,}/gi, keep('<token>'))
      .replace(/([?&]sig=)(?!<)[^&\s"']+/gi, keep('<secret>'))
      .replace(/(AccountKey=)(?!<)[^;\s"']+/gi, keep('<secret>'))
      .replace(/((?:password|passwd|pwd|secret|client_secret|apikey|api_key)["']?\s*[=:]\s*["']?)(?!<)[^\s"',;]+/gi, keep('<secret>'))
      .replace(/(enter the code\s+)[A-Z0-9]{6,12}\b/gi, keep('<device-code>'))
      // Static Web Apps deployment tokens: the publish scripts never print one; this catches one that was.
      .replace(/((?:deployment[_ -]?token|SWA_CLI_DEPLOYMENT_TOKEN)["']?\s*[=:\s]\s*["']?)(?!<)[^\s"',;]{16,}/gi, keep('<secret>'))
      .replace(/[A-Za-z0-9+/]{40,}={0,2}/g, (s) => {
        // Keys and tokens: long, mixed-case, with digits. Paths (with / between words) are not.
        const keyLike = /[0-9]/.test(s) && /[a-z]/.test(s) && /[A-Z]/.test(s) && (/=$/.test(s) || !/\//.test(s));
        if (!keyLike) return s;
        count++; return '<secret>';
      });
    return { text: out, count };
  }

  /*
   * redact(text, options) -> { text, counts {kind: n}, total }
   *   known        [{ kind, value }]: values from the operator's settings (kind defaults to name)
   *   extraTerms   [string]: anything else the operator wants removed (kind custom)
   *   patterns     [{ kind, re }]: the portal's own, run after emails and before IDs. re is global; its named
   *                group value is what is replaced (the whole match when it has none), and the named groups
   *                pre and post around it are kept.
   *   publicIds, publicDomains, keepValues: added to the lists that are never redacted
   *   level        'public' (the default, all of the above) or 'private' (secrets only)
   */
  function redact(text, options) {
    const o = options || {};
    let t = String(text || '');
    const counts = {}, maps = {}, offset = {};
    const publicIds = PUBLIC_IDS.concat(o.publicIds || []).map((g) => String(g).toLowerCase());
    const publicDomains = PUBLIC_DOMAINS.concat(o.publicDomains || []).map((d) => String(d).toLowerCase());
    const keepValues = (o.keepValues || []).map((v) => String(v).toLowerCase());
    // Text that was redacted before (an edited report): number new values after the old ones.
    const placeholderRe = /<([a-z]+)-(\d+)>/g;
    let pm;
    while ((pm = placeholderRe.exec(t)) !== null) offset[pm[1]] = Math.max(offset[pm[1]] || 0, Number(pm[2]));
    const count = (kind) => { counts[kind] = (counts[kind] || 0) + 1; };
    function token(kind, value) {
      const m = maps[kind] = maps[kind] || {}, key = String(value).toLowerCase();
      if (!m[key]) m[key] = `<${kind}-${(offset[kind] || 0) + Object.keys(m).length + 1}>`;
      count(kind);
      return m[key];
    }
    function replaceTerms(kind, values) {
      values.filter((v, i, a) => v && v.length >= 3 && a.indexOf(v) === i && keepValues.indexOf(v.toLowerCase()) < 0 && !PLACEHOLDER.test(v))
        .sort((a, b) => b.length - a.length)
        .forEach((v) => {
          // Short values only as whole words, so a 3-letter prefix does not eat ordinary words.
          const re = v.length < 5 ? new RegExp(`(^|[^A-Za-z0-9])(${escapeRe(v)})(?![A-Za-z0-9])`, 'gi') : new RegExp(`()(${escapeRe(v)})`, 'gi');
          t = t.replace(re, (all, pre, hit) => pre + token(kind, hit));
        });
    }
    function finish() {
      let total = 0;
      Object.keys(counts).forEach((k) => { if (counts[k] > 0) total += counts[k]; else delete counts[k]; });
      return { text: t, counts, total };
    }

    // 1. Secrets: gone entirely, never numbered.
    const masked = maskSecrets(t);
    t = masked.text;
    if (masked.count) counts.secret = masked.count;
    if (o.level === 'private') return finish();

    // 2. Emails and UPNs (guest UPNs contain #EXT#), then their domains wherever else they appear. Before the
    //    operator's terms, so a term inside an address doesn't break it up and leave the rest of it.
    const domains = [];
    t = t.replace(/[A-Za-z0-9._%+#-]+@((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,})\b/g, (all, domain) => {
      const d = domain.toLowerCase();
      if (!/onmicrosoft\.com$/.test(d) && publicDomains.indexOf(d) < 0 && domains.indexOf(d) < 0) domains.push(d);
      return token('email', all);
    });
    t = t.replace(/\b([A-Za-z0-9-]+)(\.onmicrosoft\.com)\b/gi, (all, name, rest) => token('tenant', name) + rest);
    replaceTerms('domain', domains);

    // 3. The operator's own terms and settings. A UPN in the settings was an email above.
    replaceTerms('custom', (o.extraTerms || []).map((s) => String(s).trim()));
    const known = (o.known || []).filter((k) => k && typeof k.value === 'string' && !/@/.test(k.value));
    const kinds = [...new Set(known.map((k) => (KIND.test(k.kind || '') ? k.kind : 'name')))];
    kinds.forEach((kind) => replaceTerms(kind, known.filter((k) => (KIND.test(k.kind || '') ? k.kind : 'name') === kind).map((k) => k.value.trim())));

    // 4. The portal's own patterns.
    (o.patterns || []).forEach((p) => {
      if (!p || !KIND.test(p.kind || '') || !(p.re instanceof RegExp) || !p.re.global) throw new Error('A redaction pattern needs a kind and a global regular expression.');
      t = t.replace(p.re, function () {
        const args = Array.prototype.slice.call(arguments), groups = typeof args[args.length - 1] === 'object' ? args[args.length - 1] : null;
        if (!groups || groups.value === undefined) return PLACEHOLDER.test(args[0]) ? args[0] : token(p.kind, args[0]);
        if (PLACEHOLDER.test(groups.value) || !groups.value) return args[0];
        return (groups.pre || '') + token(p.kind, groups.value) + (groups.post || '');
      });
    });

    // 5. IDs (subscription, tenant, object): every GUID except the public ones.
    t = t.replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, (g) => (publicIds.indexOf(g.toLowerCase()) >= 0 ? g : token('id', g)));

    // 6. Public IPv4 addresses. Private ranges and Azure's platform address help diagnosis.
    t = t.replace(/\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b/g, (ip, a, b, c, d) => {
      const n = [a, b, c, d].map(Number);
      if (n.some((x) => x > 255)) return ip;
      const priv = n[0] === 10 || n[0] === 127 || n[0] === 0 || (n[0] === 172 && n[1] >= 16 && n[1] <= 31) || (n[0] === 192 && n[1] === 168) ||
        (n[0] === 169 && n[1] === 254) || (n[0] === 100 && n[1] >= 64 && n[1] <= 127) || ip === '168.63.129.16';
      return priv ? ip : token('ip', ip);
    });

    // 7. User names in home paths.
    t = t
      .replace(/(\/home\/)(?!<)([A-Za-z0-9._-]+)/g, (a, p, u) => p + token('user', u))
      .replace(/([A-Za-z]:\\Users\\)(?!<)([^\\\s"']+)/g, (a, p, u) => p + token('user', u));

    return finish();
  }

  // 'Redacted 2 x ID, 1 x email address / UPN.' with the portal's own labels for its own kinds.
  function describe(counts, labels) {
    const l = Object.assign({}, LABELS, labels || {}), keys = Object.keys(counts || {});
    if (!keys.length) return 'Nothing found to redact.';
    return `Redacted ${keys.map((k) => `${counts[k]} x ${l[k] || k}`).join(', ')}.`;
  }

  // A code fence longer than any backtick run in the text, so pasted output can't close it.
  function fence(text) {
    let longest = 2;
    (String(text).match(/`+/g) || []).forEach((r) => { longest = Math.max(longest, r.length); });
    return '`'.repeat(longest + 1);
  }

  /*
   * issueUrl(repoUrl, title, body, { label, maxLength }) -> { url, trimmed }
   * The prefilled new-issue link. GitHub rejects very long URLs, so a long body is cut: lines over 400 characters
   * are shortened, then the middle goes, keeping the start (the description) and as much of the end (the output's
   * last lines) as fits. trimmed counts the lines cut or shortened; 0 means the whole body is in the link.
   */
  function issueUrl(repoUrl, title, body, opts) {
    const o = opts || {};
    const repo = core.check(String(repoUrl || '').replace(/\/+$/, ''), /^https:\/\/github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/, 'The repo URL');
    const maxLength = o.maxLength || 7500;
    const label = o.label === undefined ? 'portal-report' : core.check(String(o.label), /^[a-z0-9-]{0,50}$/, 'The label');
    const base = `${repo}/issues/new?${label ? `labels=${label}&` : ''}title=${encodeURIComponent(title)}&body=`;
    const fits = (b) => (base + encodeURIComponent(b)).length <= maxLength;
    if (fits(String(body))) return { url: base + encodeURIComponent(body), trimmed: 0 };
    // Too long: first shorten very long lines (one pasted line of JSON can fill the link by itself), then keep
    // as many lines from the start (up to 30) and then from the end as fit, with a marker for the cut.
    let shortened = 0;
    const all = String(body).split('\n').map((l) => {
      if (l.length <= LONG_LINE) return l;
      shortened++;
      return `${l.slice(0, LONG_LINE)} [... ${l.length - LONG_LINE} characters cut]`;
    });
    const build = (head, tail) => {
      const cut = all.length - head - tail;
      return cut > 0 ? all.slice(0, head).concat([`[... ${cut} lines cut to fit a GitHub link. Paste the copied full report here if they matter ...]`], all.slice(all.length - tail)).join('\n') : all.join('\n');
    };
    if (fits(build(all.length, 0))) return { url: base + encodeURIComponent(build(all.length, 0)), trimmed: shortened };
    let head = Math.min(all.length - 1, 30);
    while (head > 0 && !fits(build(head, 0))) head--;
    // The most lines from the end that still fit, always leaving at least one line cut.
    let lo = 0, hi = all.length - head - 1;
    while (lo < hi) {
      const mid = Math.ceil((lo + hi) / 2);
      if (fits(build(head, mid))) lo = mid; else hi = mid - 1;
    }
    return { url: base + encodeURIComponent(build(head, lo)), trimmed: all.length - head - lo + shortened };
  }

  return { PUBLIC_IDS, PUBLIC_DOMAINS, LABELS, maskSecrets, redact, describe, fence, issueUrl };
});
