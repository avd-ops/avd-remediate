/* avd-ops portal engine v1.1.0: runin.js. Personal project, not for production, as is; not affiliated with the author's employer or Microsoft. MIT.
   Run in (avd-ops docs/design-system.md, "Run in"): where the operator runs a portal's blocks, Cloud Shell, Windows
   or macOS, in PowerShell or Bash. A portal writes its blocks for Cloud Shell PowerShell, the default; these
   primitives tell it how well a block works elsewhere and rewrite it. Pure. */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory(require('./core.js'));
  else root.AvdOpsEngine.runin = factory(root.AvdOpsEngine.core);
})(typeof self !== 'undefined' ? self : this, function (core) {
  'use strict';

  const PLACES = { cloudshell: 'Cloud Shell', windows: 'Windows', macos: 'macOS' };
  const has = (o, k) => Object.prototype.hasOwnProperty.call(o, k);

  // Windows runs PowerShell 7 only; Bash there means WSL, which is its own Linux machine.
  function validRunIn(r) {
    const o = r || {};
    const where = has(PLACES, o.where) ? o.where : 'cloudshell';
    return { where, shell: o.shell === 'bash' && where !== 'windows' ? 'bash' : 'pwsh' };
  }
  function isDefaultRunIn(r) { const v = validRunIn(r); return v.where === 'cloudshell' && v.shell === 'pwsh'; }
  // The key a portal's platforms.json uses for a place: cloudshell-pwsh, cloudshell-bash, windows, macos.
  function platformKey(r) { const v = validRunIn(r); return v.where === 'cloudshell' ? `cloudshell-${v.shell}` : v.where; }

  // The scripts a block runs, in order, once each. pattern is the portal's: global, with the path in group 1.
  function scriptsIn(command, pattern) {
    if (!(pattern instanceof RegExp) || !pattern.global) throw new Error('scriptsIn needs a global pattern with the path in group 1.');
    const seen = new Set(), out = [], re = new RegExp(pattern.source, pattern.flags);
    let m;
    while ((m = re.exec(String(command || '')))) {
      if (m[1] && !seen.has(m[1])) { seen.add(m[1]); out.push(m[1]); }
      if (m[0] === '') re.lastIndex++;
    }
    return out;
  }

  // How well a block works where the operator runs it: the weakest of its scripts (tested, untested, no). A block
  // with no script is tested where it was written and untested elsewhere. Cloud Shell has every requirement.
  function support(command, runIn, platforms, pattern) {
    const r = validRunIn(runIn), key = platformKey(r), rank = { tested: 0, untested: 1, no: 2 };
    const scripts = scriptsIn(command, pattern), table = platforms || {};
    let status = !scripts.length && !isDefaultRunIn(r) ? 'untested' : 'tested';
    const requires = [], blockedBy = [];
    for (const s of scripts) {
      const p = has(table, s) ? table[s] : null;
      let v = p ? p[key] : 'untested';
      if (!has(rank, v)) v = 'untested';
      if (v === 'no') blockedBy.push(s);
      if (rank[v] > rank[status]) status = v;
      if (p && p.requires) for (const q of String(p.requires).split(/,\s*/)) if (q && !requires.includes(q)) requires.push(q);
    }
    return { status, requires: r.where === 'cloudshell' ? [] : requires, blockedBy, place: PLACES[r.where], shell: r.shell };
  }

  // PowerShell lines run from Bash: written word for word to a temp .ps1 through a quoted heredoc (bash expands
  // nothing in it), then run with pwsh. opts.declare false reuses the file a block already declared.
  function pwshFile(lines, opts) {
    const body = [].concat(lines || []).map(String);
    if (body.some((l) => /^AVD_PS$/m.test(l))) throw new Error('The block holds a line the Bash version cannot carry.');
    const head = opts && opts.declare === false ? [] : ['f="$(mktemp -d)/step.ps1"'];
    return head.concat([`cat > "$f" <<'AVD_PS'`], body, ['AVD_PS', 'pwsh -NoLogo -File "$f"']);
  }

  // The sign-in a block needs off Cloud Shell, which is signed in already: Az PowerShell, the az CLI, or both.
  const SIGN_IN = {
    azPowerShell: 'if (-not (Get-AzContext)) { Connect-AzAccount -UseDeviceAuthentication | Out-Null }',
    azCliPwsh: 'az account show -o none 2>$null; if ($LASTEXITCODE -ne 0) { az login --use-device-code -o none }',
    azCliBash: 'az account show -o none 2>/dev/null || az login --use-device-code -o none'
  };
  // In Bash only the az CLI line is returned: an Az PowerShell sign-in goes inside the pwsh file that needs it.
  function signInLines(where, shell, needs) {
    const r = validRunIn({ where, shell }), n = needs || {}, out = [];
    if (r.where === 'cloudshell') return out;
    if (r.shell === 'pwsh') {
      if (n.azPowerShell) out.push(SIGN_IN.azPowerShell);
      if (n.azCli) out.push(SIGN_IN.azCliPwsh);
    } else if (n.azCli) out.push(SIGN_IN.azCliBash);
    return out;
  }

  // The whole-block rewrite: PowerShell runs a block as it is anywhere (the portal's blocks sign in when they need
  // to); Bash runs the whole block in one pwsh. A portal that splits a block into stretches builds on pwshFile and
  // signInLines instead.
  function forRunIn(command, runIn) {
    const r = validRunIn(runIn);
    if (!command || r.shell === 'pwsh') return command || '';
    return pwshFile(String(command).split('\n')).join('\n');
  }

  return { PLACES, SIGN_IN, validRunIn, isDefaultRunIn, platformKey, scriptsIn, support, pwshFile, signInLines, forRunIn };
});
