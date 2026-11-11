/* avd-ops portal engine v1.1.0: core.js. Personal project, not for production, as is; not affiliated with the author's employer or Microsoft. MIT.
   The portal engine (docs/portal-engine-spec.md): plain classic scripts the family's portals vendor at a pin. In a
   browser each file adds one member to window.AvdOpsEngine; in Node each is a module. Load this file first. */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else { root.AvdOpsEngine = root.AvdOpsEngine || {}; root.AvdOpsEngine.core = factory(); }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const VERSION = '1.1.0';

  // A pattern's test with no state: a g or y flag would carry lastIndex from one call to the next.
  function matches(value, pattern) {
    return typeof value === 'string' && pattern instanceof RegExp && new RegExp(pattern.source, pattern.flags.replace(/[gy]/g, '')).test(value);
  }
  // The one place a value is accepted: it is a string that fits the pattern, or this throws, naming it.
  function check(value, pattern, name) {
    if (!matches(value, pattern)) throw new Error(`${name || 'A value'} does not fit.`);
    return value;
  }
  // The same test without the throw, for values read from a paste: the value, or null.
  function fits(value, pattern) { return matches(value, pattern) ? value : null; }

  return { VERSION, check, fits };
});
