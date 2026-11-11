/* avd-ops portal engine v1.1.0: statelines.js. Personal project, not for production, as is; not affiliated with the author's employer or Microsoft. MIT.
   Finds the machine-readable lines the family's scripts end with, <<<MARKER {json} MARKER>>> (avd-landing-zone
   decision 0007). Pure. A paste is untrusted: this only parses; each portal checks the result against its own
   schema and keeps its own policy for lines that don't parse. */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory(require('./core.js'));
  else root.AvdOpsEngine.statelines = factory(root.AvdOpsEngine.core);
})(typeof self !== 'undefined' ? self : this, function (core) {
  'use strict';

  // How each portal drops the line breaks a terminal copy adds inside a long line: 'any' drops every run of CR
  // and LF (the deployment portal), 'lf' drops LF and CRLF only (the assessment portal). JSON strings hold no raw
  // line breaks, so either is safe; they differ only on a lone CR.
  const NEWLINES = { any: /[\r\n]+/g, lf: /\r?\n/g };

  // Every block between <<<MARKER and MARKER>>>, oldest first: { value } when its JSON parses, otherwise
  // { parseError, raw } with raw cut at 200 characters (part of the contract: a portal may show it).
  function extract(text, marker, opts) {
    core.check(marker, /^[A-Z][A-Z0-9-]{1,30}$/, 'The marker');
    const newlines = NEWLINES[(opts && opts.newlines) || 'any'];
    if (!newlines) throw new Error('newlines is any or lf.');
    const re = new RegExp(`<<<${marker}([\\s\\S]*?)${marker}>>>`, 'g'), out = [];
    let m;
    while ((m = re.exec(String(text || '')))) {
      const raw = m[1].replace(newlines, '').trim();
      try { out.push({ value: JSON.parse(raw) }); } catch (e) { out.push({ parseError: String((e && e.message) || e), raw: raw.slice(0, 200) }); }
    }
    return out;
  }

  return { extract };
});
