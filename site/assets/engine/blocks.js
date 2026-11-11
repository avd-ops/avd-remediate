/* avd-ops portal engine v1.1.0: blocks.js. Personal project, not for production, as is; not affiliated with the author's employer or Microsoft. MIT.
   Quoting and arguments for the self-contained Cloud Shell blocks a portal hands out. Pure: no DOM, no network. */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory(require('./core.js'));
  else root.AvdOpsEngine.blocks = factory(root.AvdOpsEngine.core);
})(typeof self !== 'undefined' ? self : this, function (core) {
  'use strict';

  const CONTROL = /[\u0000-\u001f\u007f]/;

  // A PowerShell single-quoted string. PowerShell also ends one at the typographic single quotes (U+2018 to
  // U+201B), so each quote of any kind is doubled, as its own EscapeSingleQuotedStringContent does. A line break
  // or control character is refused: a block is pasted line by line, and the Bash form writes it through a heredoc.
  function psQuote(s) {
    const v = String(s);
    if (CONTROL.test(v)) throw new Error('A value holds a line break or a control character.');
    return `'${v.replace(/['\u2018\u2019\u201a\u201b]/g, '$&$&')}'`;
  }
  // A Bash single-quoted string, with the same refusal.
  function bashQuote(s) {
    const v = String(s);
    if (CONTROL.test(v)) throw new Error('A value holds a line break or a control character.');
    return `'${v.replace(/'/g, "'\\''")}'`;
  }
  // ' -Name ''value''', after the value is checked against its pattern; a command takes values only this way.
  function arg(name, value, pattern) {
    if (!/^[A-Za-z][A-Za-z0-9]*$/.test(String(name))) throw new Error('A parameter name does not fit.');
    return ` -${name} ${psQuote(core.check(value, pattern, name))}`;
  }
  // A JSON document as a PowerShell here-string: the lines between @' and '@. Refused when a line would end the
  // here-string early or a character would not survive a paste.
  function hereString(name, obj) {
    const json = JSON.stringify(obj, null, 2);
    if (/^'@/m.test(json) || /[^\x20-\x7e\n]/.test(json)) throw new Error(`${name} holds a character the block cannot carry.`);
    return ["@'", json, "'@"];
  }
  // What a block may clone and check out (avd-landing-zone decision 0017): a plain GitHub repo URL and a ref.
  function isRepoUrl(u) { return typeof u === 'string' && /^https:\/\/github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\/?$/.test(u) && !/\.\./.test(u); }
  function isRef(r) { return typeof r === 'string' && /^[A-Za-z0-9][A-Za-z0-9._/-]{0,99}$/.test(r) && !/\.\.|\/\/|\/$|\.lock$/.test(r); }
  function isCommit(c) { return typeof c === 'string' && /^[0-9a-f]{7,40}$/i.test(c); }

  return { psQuote, bashQuote, arg, hereString, isRepoUrl, isRef, isCommit };
});
