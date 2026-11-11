/* avd-ops portal engine v1.1.0: bands.js. Personal project, not for production, as is; not affiliated with the author's employer or Microsoft. MIT.
   Bands and worst-of verdicts from a portal's own threshold table. Pure. Fails closed: no answer is never a pass. */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory(require('./core.js'));
  else root.AvdOpsEngine.bands = factory(root.AvdOpsEngine.core);
})(typeof self !== 'undefined' ? self : this, function (core) {
  'use strict';

  const BOUNDS = ['lt', 'le', 'otherwise'];
  const strip = (row) => { const o = {}; for (const k of Object.keys(row)) if (!BOUNDS.includes(k)) o[k] = row[k]; return o; };

  // table: { noAnswer: row, rows: [{ lt | le: n, ...row }, ..., { otherwise: true, ...row }] }. Rows are read in
  // order with rising bounds; every row, noAnswer included, carries a claim (the source of its threshold). The
  // result is the row without its bound. null, undefined, NaN and anything not a number are no answer.
  function checkTable(table) {
    const t = table || {}, rows = Array.isArray(t.rows) ? t.rows : [];
    if (!t.noAnswer || !rows.length || rows[rows.length - 1].otherwise !== true) throw new Error('A band table needs noAnswer and rows ending with otherwise.');
    let last = -Infinity;
    rows.forEach((row, i) => {
      const n = row.lt !== undefined ? row.lt : row.le;
      if (i < rows.length - 1) {
        if ((row.lt === undefined) === (row.le === undefined) || typeof n !== 'number' || !isFinite(n) || n < last) throw new Error(`Band ${i + 1} needs one rising bound, lt or le.`);
        last = n;
      } else if (row.lt !== undefined || row.le !== undefined) throw new Error('The otherwise band has no bound.');
    });
    for (const row of [t.noAnswer].concat(rows)) if (typeof row.claim !== 'string' || !row.claim) throw new Error('Every band carries a claim.');
    return t;
  }
  function band(value, table) {
    const t = checkTable(table);
    if (typeof value !== 'number' || isNaN(value)) return strip(t.noAnswer);
    for (const row of t.rows) {
      if (row.otherwise === true) return strip(row);
      if (row.lt !== undefined ? value < row.lt : value <= row.le) return strip(row);
    }
    return strip(t.rows[t.rows.length - 1]);
  }

  // The worst of several states, given their order from best to worst. A state not in the order counts as the
  // worst (fail closed); no states at all is null, which the portal reads as not checked.
  function worst(states, order) {
    if (!Array.isArray(order) || !order.length) throw new Error('worst needs the states in order, best first.');
    const list = Array.isArray(states) ? states : [];
    if (!list.length) return null;
    let at = 0;
    for (const s of list) { const i = order.indexOf(s); at = Math.max(at, i < 0 ? order.length - 1 : i); }
    return order[at];
  }

  // results: [{ host, median }] from a probe (one phase of probe.run); hosts: [{ host, ... }], the portal's list. A
  // host missing from the results, or one the probe marks notTested or cut short by a deadline, was not tested
  // (reached null); a median that is not a number is no answer (reached false). Status:
  // unknown (nothing tested), reachable (every host reached), partial, or blocked (none reached).
  function classifyHosts(results, hosts) {
    const list = Array.isArray(results) ? results : [];
    const out = (Array.isArray(hosts) ? hosts : []).map((h) => {
      const r = list.filter((x) => x && x.host === h.host)[0];
      const tested = !!r && r.notTested !== true && r.deadline !== true, reached = tested && typeof r.median === 'number' && !isNaN(r.median);
      return Object.assign({}, h, { reached: tested ? reached : null, median: reached ? r.median : null });
    });
    const ok = out.filter((h) => h.reached === true).length, tested = out.filter((h) => h.reached !== null).length;
    const status = !tested ? 'unknown' : ok === out.length ? 'reachable' : ok ? 'partial' : 'blocked';
    return { hosts: out, status, failed: out.filter((h) => h.reached !== true).map((h) => h.host) };
  }

  return { band, worst, classifyHosts };
});
