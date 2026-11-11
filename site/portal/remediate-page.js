/* avd-remediate v0.1.0: remediate-page.js. Personal project, not for production, as is; not affiliated with the author's employer, Liquidware or Microsoft. MIT.
   Browser controller for the 5-step guided wizard and docked Chat Assistant drawer.
   Strictly no eval(), no innerHTML from untrusted data, no external network calls (connect-src 'self' only). */
(function () {
  'use strict';

  const Core = window.RemediateCore;
  const Engine = window.AvdOpsEngine;
  if (!Core || !Engine) return;

  const STEP_NAMES = [
    'Context & symptom',
    'Evidence & probes',
    'Root cause & citations',
    'Plan & approval',
    'Verify & capture'
  ];

  const SAMPLE_C11 = {
    schema: 'avd-current-state-facts/v1',
    contract: 'C11',
    planesCollected: {
      azure: { status: 'collected' },
      entra: { status: 'collected' },
      intune: { status: 'collected' },
      m365: { status: 'collected' },
      'power-platform': { status: 'collected' }
    },
    facts: {
      'c11.hostPool.sessionHosts.entraJoined': 4,
      'c11.hostPool.entraSso': 'enabled',
      'c11.hostPool.directUserAssignments': 0,
      'c11.entra.kerberosStoragePrincipalsReady': 0,
      'c11.entra.caAvdRequiresMfa': 'enforced',
      'c11.entra.caAvdBreakGlassExcluded': true,
      'c11.intune.fslogixProfileConfigured': true,
      'c11.intune.rdpShortpathConfigured': false,
      'c11.intune.sessionTimeLimitsConfigured': false,
      'c11.hostPool.sessionHosts.intuneNoncompliant': 0,
      'c11.hostPool.sessionHosts.intuneConfigErrors': 0,
      'c11.m365.m365AppsSharedComputerActivation': true,
      'c11.m365.oneDriveKfmState': 'enforced',
      'c11.m365.teamsMediaOptimizationState': 'enabled',
      'c11.m365.outlookCachedModeConfigured': true,
      'c11.powerPlatform.dedicatedEnvironments': 1,
      'c11.powerPlatform.dlpPoliciesCoveringAvdEnv': 1,
      'c11.powerPlatform.enterprisePoliciesCount': 1
    }
  };

  const SAMPLE_C21 = {
    schema: 'avd-assessment-report/v1',
    contract: 'C21',
    checks: [
      { id: 'asm-entra-files-kerberos-ready', plane: 'entra', outcome: 'gap' },
      { id: 'asm-intune-rdp-shortpath', plane: 'intune', outcome: 'warn' },
      { id: 'asm-intune-session-limits', plane: 'intune', outcome: 'warn' },
      { id: 'asm-entra-sso-enabled', plane: 'entra', outcome: 'pass' }
    ]
  };

  const SAMPLE_VAULT_NOTES = [
    {
      path: 'lessons/2026-10-18-fslogix-entra-kerberos-needs-aes-128-gcm.md',
      category: 'lesson',
      title: 'Entra Kerberos on Azure Files is refused when SMB channel encryption is AES-256-GCM only',
      date: '2026-10-18',
      tags: ['fslogix', 'azure-files', 'entra-kerberos', 'smb'],
      summary: 'Every SMB SESSION_SETUP to the profile share answered 0xC0000022 until AES-128-GCM plus AES-256-GCM (CCM off) was enabled on the storage account.'
    },
    {
      path: 'decisions/ADR-0001-spend-needs-an-estimate-and-approval.md',
      category: 'decision',
      title: 'ADR-0001: Every billable run starts from a priced estimate and explicit approval',
      date: '2026-10-20',
      tags: ['cost', 'governance'],
      summary: 'No billable change starts without a written estimate priced from the retail prices API and explicit go batch approval.'
    },
    {
      path: 'decisions/ADR-0002-durable-run-store-and-companion-vault.md',
      category: 'decision',
      title: 'ADR-0002: Durable run store and private companion vault keep the records',
      date: '2026-10-20',
      tags: ['operations', 'companion-vault'],
      summary: 'Run records and incident bundles persist in the private companion vault so teardowns never delete the last copy.'
    },
    {
      path: 'runbooks/fslogix-entra-kerberos-smb-channel-encryption.md',
      category: 'runbook',
      title: 'Enable AES-128-GCM + AES-256-GCM SMB channel encryption for FSLogix Entra Kerberos',
      date: '2026-10-21',
      tags: ['fslogix', 'entra-kerberos', 'azure-files', 'smb'],
      resolvesChecks: ['asm-entra-files-kerberos-ready'],
      summary: 'Step-by-step runbook to enable AES-128-GCM;AES-256-GCM on the Azure Files profile storage account and consent Graph User.Read.'
    },
    {
      path: 'environments/contoso-avd-prod/findings.md',
      category: 'finding',
      title: 'Findings — contoso-avd-prod',
      date: '2026-10-21',
      tags: ['findings', 'validator'],
      summary: 'Generated from validator runs. Open advisories for FSLogix Entra Kerberos channel encryption and RDP Shortpath UDP 3390.'
    },
    {
      path: 'environments/contoso-avd-prod/evidence/2026-10-fslogix-entra-kerberos/fslogix-block-e.md',
      category: 'evidence',
      title: 'FSLogix Block E — AES-128-GCM + AES-256-GCM verification',
      date: '2026-10-18',
      tags: ['fslogix', 'evidence', 'smb'],
      summary: 'Confirmed AES-128-GCM plus AES-256-GCM (CCM off) permits cloud-only Entra Kerberos SMB mount cleanly.'
    }
  ];

  const state = {
    step: 0,
    domain: 'fslogix',
    query: '',
    playbookId: 'pb-fsx-kerberos-smb-auth',
    c11: null,
    c21: null,
    c25: null,
    measuredUsage: null,
    familyGraph: null,
    probeStates: [],
    verifyState: null,
    telemetryMode: 'OfflineVault',
    telemetryWorkload: 'medium',
    telemetryVmSku: 'Standard_D8s_v5',
    remediationMode: 'DryRunPreflight',
    activePath: 'day2',
    vaultPath: '../avd-vault',
    sandboxPath: '../avd-vault',
    envName: 'contoso-avd-prod',
    vaultNotes: SAMPLE_VAULT_NOTES.slice(),
    vaultCategory: 'all',
    vaultSearch: '',
    snapshotDate: '2026-10-21',
    snapshotStale: false,
    snapshotRelPath: 'environments/contoso-avd-prod/snapshots/20261021T032412-inventory.json',
    latestBrief: null,
    llmModeLabel: 'Offline deterministic ($0, zero network)',
    serverOnline: false,
    csrfToken: '',
    runIn: loadRunIn()
  };

  function loadRunIn() {
    try {
      const raw = localStorage.getItem('avd-ops-runin');
      if (raw) return Engine.runin.validRunIn(JSON.parse(raw));
    } catch (_) {}
    return { where: 'cloudshell', shell: 'pwsh' };
  }

  function saveRunIn(r) {
    state.runIn = Engine.runin.validRunIn(r);
    try {
      localStorage.setItem('avd-ops-runin', JSON.stringify(state.runIn));
    } catch (_) {}
  }

  function $(id) { return document.getElementById(id); }

  function el(tag, attrs, children) {
    const node = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) {
        if (k === 'text') node.textContent = attrs[k];
        else if (k === 'className') node.className = attrs[k];
        else node.setAttribute(k, attrs[k]);
      });
    }
    if (Array.isArray(children)) {
      children.forEach(function (c) {
        if (typeof c === 'string') node.appendChild(document.createTextNode(c));
        else if (c) node.appendChild(c);
      });
    }
    return node;
  }

  function clearNode(node) {
    while (node && node.firstChild) node.removeChild(node.firstChild);
  }

  function setDevText(node, pubText, devText) {
    if (!node) return;
    node.setAttribute('data-pub-text', pubText);
    node.setAttribute('data-dev-text', devText);
    const devOn = Boolean(window.AvdOpsDev && typeof window.AvdOpsDev.isOn === 'function' && window.AvdOpsDev.isOn());
    node.textContent = devOn ? devText : pubText;
  }

  function copyText(text, btn) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () {
        if (btn) {
          const prev = btn.textContent;
          btn.textContent = 'Copied';
          setTimeout(function () { btn.textContent = prev; }, 1400);
        }
      }).catch(function () {});
    }
  }

  function downloadBlob(filename, content, mime) {
    const blob = new Blob([content], { type: mime || 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = el('a', { href: url, download: filename });
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }

  function renderDomains() {
    const grid = $('domain-grid');
    clearNode(grid);
    Core.DOMAINS.forEach(function (d) {
      const btn = el('button', {
        type: 'button',
        className: 'domain-card',
        'aria-pressed': state.domain === d.id ? 'true' : 'false',
        'data-domain': d.id
      }, [
        el('span', { className: 'd-title', text: d.label }),
        el('span', { className: 'd-desc', text: d.summary })
      ]);
      btn.addEventListener('click', function () {
        state.domain = d.id;
        const firstInDomain = Core.PLAYBOOKS.find(function (p) { return p.domain === d.id; });
        if (firstInDomain) state.playbookId = firstInDomain.id;
        renderDomains();
        renderPlaybookSelect();
        refreshAll();
      });
      grid.appendChild(btn);
    });
  }

  function renderPlaybookSelect() {
    const sel = $('playbook-select');
    clearNode(sel);
    Core.PLAYBOOKS.forEach(function (pb) {
      const opt = el('option', {
        value: pb.id,
        text: '[' + pb.plane + '] ' + pb.title
      });
      if (pb.id === state.playbookId) opt.selected = true;
      sel.appendChild(opt);
    });
  }

  function getDiagnosis() {
    return Core.diagnose({
      domain: state.domain,
      query: state.query,
      c11: state.c11,
      c21: state.c21,
      c25: state.c25,
      measuredUsage: state.measuredUsage,
      familyGraph: state.familyGraph,
      probeStates: state.probeStates,
      playbookId: state.playbookId
    });
  }

  function renderStep2(diag) {
    const top = diag.primary;
    const pb = top.playbook;
    const r = state.runIn;
    const runInText = Engine.runin.PLACES[r.where] + ', ' + (r.shell === 'bash' ? 'Bash' : 'PowerShell');
    $('runin-Summary-2').textContent = runInText;

    const built = Core.probeCommand({
      probeId: pb.probeId,
      vaultPath: state.vaultPath
    }, r);

    const term = $('probe-term');
    term.setAttribute('data-shell', r.shell === 'bash' ? 'bash' : 'pwsh');
    $('probe-term-label').textContent = pb.probeId + ' (' + pb.plane + ' plane, read-only)';
    $('probe-cmd-code').textContent = built.command;

    const telemTerm = $('telemetry-term');
    if (telemTerm && typeof Core.hostTelemetryCommand === 'function') {
      const profileId = pb.domain === 'fslogix' ? 'storage-fslogix-io' : 'multisession-density';
      const telemBuilt = Core.hostTelemetryCommand({
        mode: state.telemetryMode || 'OfflineVault',
        profileId: profileId,
        workloadClass: state.telemetryWorkload || 'medium',
        vmSku: state.telemetryVmSku || 'Standard_D8s_v5',
        vaultPath: state.vaultPath,
        envName: state.envName
      }, r);
      telemTerm.setAttribute('data-shell', r.shell === 'bash' ? 'bash' : 'pwsh');
      $('telemetry-term-label').textContent = 'Export-AvdHostTelemetry.ps1 (' + (state.telemetryMode || 'OfflineVault') + ' · C25 + avd-measured-usage/v1)';
      $('telemetry-cmd-code').textContent = telemBuilt.command;
    }

    const latestProbe = state.probeStates.length ? state.probeStates[state.probeStates.length - 1] : null;
    const bl = $('step2-verdict-bl');
    const detail = $('step2-verdict-detail');
    const stop1 = $('probe-stop-1');

    if (latestProbe) {
      const isGap = latestProbe.status === 'gap' || latestProbe.status === 'poor' || latestProbe.status === 'fail';
      bl.className = 'bl ' + (isGap ? 'poor' : 'good');
      bl.textContent = (isGap ? 'GAP CONFIRMED · ' : 'PASS · ') + (latestProbe.summary || latestProbe.probeId);
      detail.textContent = 'Evidence captured from ' + latestProbe.probeId + ' on plane ' + (latestProbe.plane || pb.plane) + '. Proceed to Step 3 for full root cause and citations.';
      stop1.className = 'stop ' + (isGap ? 'poor' : 'good');
    } else {
      bl.className = 'bl ok';
      bl.textContent = 'Ready to run read-only probe: ' + pb.probeId;
      detail.textContent = 'Target playbook: ' + pb.title + '. No write scopes are requested.';
      stop1.className = 'stop';
    }

    const tbody = $('step2-facts-tbody');
    clearNode(tbody);
    const factsObj = (state.c11 && state.c11.facts) || {};
    const keys = Object.keys(factsObj);
    if (!keys.length) {
      const td1 = el('td');
      const td2 = el('td');
      setDevText(td1, 'No Estate Facts snapshot loaded yet', 'No Estate Facts (C11) snapshot loaded yet');
      setDevText(td2, 'Click "Load sample estate" or drop an Estate Facts JSON file in Step 1', 'Click "Load sample estate" or drop an Estate Facts (C11) JSON file in Step 1');
      tbody.appendChild(el('tr', null, [td1, td2]));
    } else {
      keys.forEach(function (k) {
        tbody.appendChild(el('tr', null, [
          el('td', null, [el('code', { text: k })]),
          el('td', { className: 'num', text: JSON.stringify(factsObj[k]) })
        ]));
      });
    }
  }

  function renderStep3(diag) {
    const top = diag.primary;
    const pb = top.playbook;

    const bl = $('step3-bl');
    bl.className = 'bl ' + (pb.severity === 'high' ? 'poor' : 'ok');
    bl.textContent = pb.severity.toUpperCase() + ' · ' + pb.title;
    $('step3-summary').textContent = pb.bottomLine;

    const chips = $('step3-chips');
    clearNode(chips);
    chips.appendChild(el('span', { className: 'outcome o-gap', text: 'PLANE: ' + pb.remediation.plane.toUpperCase() }));
    chips.appendChild(el('span', { className: 'chip', text: 'Pillar: ' + pb.pillar }));
    chips.appendChild(el('span', { className: 'chip', text: 'Confidence: ' + top.confidence.toUpperCase() }));
    pb.c21Checks.forEach(function (c) {
      chips.appendChild(el('span', { className: 'chip', text: c }));
    });

    const sigBody = $('step3-signals-tbody');
    clearNode(sigBody);
    const signals = top.signals.length ? top.signals : ['Matched domain (' + pb.domain + ') and playbook baseline'];
    signals.forEach(function (sig) {
      sigBody.appendChild(el('tr', null, [
        el('td', { text: sig }),
        el('td', null, [el('span', { className: 'outcome o-warn', text: 'EVIDENCE' })])
      ]));
    });

    const citBody = $('step3-citations-tbody');
    clearNode(citBody);
    pb.citations.forEach(function (cit) {
      citBody.appendChild(el('tr', null, [
        el('td', null, [el('code', { text: cit.id })]),
        el('td', null, [el('code', { text: cit.source })]),
        el('td', { text: cit.claim })
      ]));
    });

    const candBody = $('step3-candidates-tbody');
    clearNode(candBody);
    diag.all.slice(0, 6).forEach(function (cand) {
      const selectBtn = el('button', {
        type: 'button',
        className: cand.playbook.id === pb.id ? '' : 'secondary',
        text: cand.playbook.id === pb.id ? 'Selected' : 'Select'
      });
      selectBtn.addEventListener('click', function () {
        state.playbookId = cand.playbook.id;
        state.domain = cand.playbook.domain;
        renderDomains();
        renderPlaybookSelect();
        refreshAll();
      });
      candBody.appendChild(el('tr', null, [
        el('td', { text: cand.playbook.title }),
        el('td', null, [el('code', { text: cand.playbook.remediation.plane })]),
        el('td', { text: cand.confidence.toUpperCase() + ' (' + cand.score + ')' }),
        el('td', null, [selectBtn])
      ]));
    });
  }

  function renderStep4(diag) {
    const top = diag.primary;
    const pb = top.playbook;
    const rem = pb.remediation;
    const r = state.runIn;
    const runInText = Engine.runin.PLACES[r.where] + ', ' + (r.shell === 'bash' ? 'Bash' : 'PowerShell');
    $('runin-Summary-4').textContent = runInText;

    $('step4-action-summary').textContent = rem.actionSummary;
    $('step4-blast-radius').textContent = 'Blast radius: ' + rem.blastRadius;
    $('step4-plane-chip').textContent = 'Plane: ' + rem.plane;
    $('step4-cost-chip').textContent = 'Cost: ' + rem.costEstimate;
    $('step4-rollback-text').textContent = 'Rollback: ' + rem.rollbackSummary;

    const cmdBuilt = Core.remediationCommand({
      playbookId: pb.id,
      vaultPath: state.vaultPath,
      mode: state.remediationMode
    }, r);

    const term = $('remediate-term');
    term.setAttribute('data-shell', r.shell === 'bash' ? 'bash' : 'pwsh');
    $('remediate-term-label').textContent = pb.id + ' (' + state.remediationMode + ')';
    $('remediate-cmd-code').textContent = cmdBuilt.command;

    const c24 = Core.buildC24Plan([top]);
    $('c24-json-code').textContent = JSON.stringify(c24, null, 2);

    const swarm = Core.buildSwarmHandoff(pb, top.signals);
    $('swarm-json-code').textContent = JSON.stringify(swarm, null, 2);

    ['day2', 'c24', 'swarm'].forEach(function (k) {
      const panel = $('panel-path-' + k);
      const tab = $('tab-path-' + k);
      if (state.activePath === k) {
        panel.classList.remove('hidden');
        tab.classList.remove('secondary');
      } else {
        panel.classList.add('hidden');
        tab.classList.add('secondary');
      }
    });
  }

  function renderStep5(diag) {
    const top = diag.primary;
    const pb = top.playbook;
    const bl = $('step5-verify-bl');
    const detail = $('step5-verify-detail');

    if (state.verifyState && state.verifyState.status === 'pass') {
      bl.className = 'bl good';
      bl.textContent = 'VERIFIED PASS · ' + (state.verifyState.summary || pb.title + ' remediated');
      detail.textContent = 'Post-fix state line confirmed the remediation landed cleanly. Save the incident bundle to your companion vault below.';
    } else {
      bl.className = 'bl ok';
      bl.textContent = 'Waiting for post-fix verification';
      detail.textContent = 'Paste the output of Invoke-AvdRemediationPlan.ps1 or click "Simulate verification pass" to verify.';
    }

    const kbDraft = Core.buildRedactedKbDraft({
      playbookId: pb.id,
      symptom: state.query || pb.title,
      cause: pb.bottomLine,
      fix: pb.remediation.actionSummary
    });
    $('kb-yaml-code').textContent = kbDraft.yaml;
    $('kb-redaction-summary').textContent = kbDraft.redactionSummary + ' Safe for public avd-second-brain / avd-assess PRs.';
  }

  function renderStepNav() {
    const step = state.step;
    for (let i = 0; i < 5; i++) {
      const sec = $('stage-' + i);
      if (i === step) sec.classList.remove('hidden');
      else sec.classList.add('hidden');
    }

    const stepBtns = document.querySelectorAll('#step-list button.step');
    stepBtns.forEach(function (btn) {
      const idx = Number(btn.getAttribute('data-step'));
      if (idx === step) btn.setAttribute('aria-current', 'step');
      else btn.removeAttribute('aria-current');
      if (idx < step) btn.classList.add('done');
      else btn.classList.remove('done');
    });

    const segBtns = document.querySelectorAll('#step-progress button.seg');
    segBtns.forEach(function (btn) {
      const idx = Number(btn.getAttribute('data-step'));
      btn.classList.toggle('current', idx === step);
      btn.classList.toggle('done', idx < step);
    });

    $('prev-step-btn').disabled = step === 0;
    $('next-step-btn').disabled = step === 4;
    $('step-where-label').textContent = 'Step ' + (step + 1) + ' of 5 · ' + STEP_NAMES[step];
  }

  function renderVaultExplorer() {
    const tbody = $('vault-notes-tbody');
    const countSpan = $('vault-notes-count');
    if (!tbody) return;
    clearNode(tbody);

    const allNotes = Array.isArray(state.vaultNotes) ? state.vaultNotes : [];
    if (countSpan) countSpan.textContent = String(allNotes.length);

    const catFilter = state.vaultCategory || 'all';
    const q = String(state.vaultSearch || '').trim().toLowerCase();

    const filtered = allNotes.filter(function (n) {
      const cat = n.category || (
        /^lessons\//i.test(n.path) ? 'lesson' :
        /^decisions\//i.test(n.path) ? 'decision' :
        /^runbooks\//i.test(n.path) ? 'runbook' :
        /findings\.md$/i.test(n.path) ? 'finding' :
        /\/evidence\//i.test(n.path) ? 'evidence' : 'environment'
      );
      if (catFilter !== 'all' && cat !== catFilter) return false;
      if (!q) return true;
      const hay = ((n.title || '') + ' ' + (n.path || '') + ' ' + (n.tags || []).join(' ') + ' ' + (n.summary || '')).toLowerCase();
      return hay.includes(q);
    });

    if (!filtered.length) {
      tbody.appendChild(el('tr', null, [
        el('th', { scope: 'row', text: 'No matching vault notes' }),
        el('td', { text: catFilter }),
        el('td', { text: '—' }),
        el('td', { text: 'Clear filter to view all notes' })
      ]));
      return;
    }

    filtered.forEach(function (note) {
      const cat = note.category || (
        /^lessons\//i.test(note.path) ? 'lesson' :
        /^decisions\//i.test(note.path) ? 'decision' :
        /^runbooks\//i.test(note.path) ? 'runbook' :
        /findings\.md$/i.test(note.path) ? 'finding' :
        /\/evidence\//i.test(note.path) ? 'evidence' : 'environment'
      );
      const tagRow = el('span', { className: 'vault-note-tags' }, (note.tags || []).map(function (t) {
        return el('span', { className: 'chip', text: t });
      }));
      const rowHead = el('th', { scope: 'row' }, [
        el('span', { text: note.title || note.path }),
        el('span', { className: 'vault-note-summary', text: note.summary || '' }),
        tagRow
      ]);

      const citeBtn = el('button', {
        type: 'button',
        className: 'secondary',
        text: 'Ask in Assistant'
      });
      citeBtn.addEventListener('click', function () {
        submitChatQuestion('How does vault note ' + note.path + ' (' + (note.title || '') + ') apply to our current AVD estate?');
      });

      const outcomeClass = cat === 'lesson' || cat === 'finding' ? 'o-warn' : cat === 'runbook' ? 'o-pass' : 'o-unknown';
      tbody.appendChild(el('tr', null, [
        rowHead,
        el('td', null, [el('span', { className: 'outcome ' + outcomeClass, text: cat.toUpperCase() })]),
        el('td', null, [
          el('code', { text: note.path }),
          note.date ? el('span', { className: 'vault-note-summary', text: note.date }) : null
        ]),
        el('td', null, [citeBtn])
      ]));
    });
  }

  function updateReasoningBadges(modeLabel, redactSummary) {
    if (modeLabel) {
      state.llmModeLabel = modeLabel;
      $('chat-mode-badge').textContent = modeLabel;
      const settingsMode = $('settings-llm-mode');
      if (settingsMode) settingsMode.textContent = modeLabel;
    }
    if (redactSummary) {
      $('chat-redact-badge').textContent = redactSummary;
      const settingsRedact = $('settings-redact-summary');
      if (settingsRedact) {
        settingsRedact.textContent = redactSummary + ' All prompts, C11/C21 facts, and companion vault notes are scrubbed via AvdOpsEngine.redact before leaving server.mjs.';
      }
    }
  }

  function generateBriefAction() {
    const detailsEl = $('vault-explorer-details');
    if (detailsEl) detailsEl.open = true;
    const panel = $('brief-output-panel');
    const bl = $('brief-status-bl');
    const detail = $('brief-status-detail');
    const label = $('brief-term-label');
    const code = $('brief-markdown-code');

    const localBrief = Core.generateEstateBrief({
      envName: state.envName || 'contoso-avd-prod',
      notes: state.vaultNotes || [],
      c11: state.c11,
      c21: state.c21,
      snapshotDate: state.snapshotDate || '2026-10-21',
      snapshotStale: Boolean(state.snapshotStale),
      snapshotRelPath: state.snapshotRelPath || ('environments/' + (state.envName || 'contoso-avd-prod') + '/snapshots/20261021T032412-inventory.json')
    });

    if (!state.serverOnline) {
      state.latestBrief = localBrief;
      panel.classList.remove('hidden');
      bl.className = 'bl good';
      bl.textContent = 'ESTATE BRIEF READY · ' + localBrief.relativePath;
      detail.textContent = 'Generated offline from loaded estate evidence. Start scripts/server.mjs to save directly into ' + localBrief.relativePath + ', or download below.';
      label.textContent = localBrief.relativePath;
      code.textContent = localBrief.markdown;
      return;
    }

    fetch('/api/brief', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-AVD-CSRF': state.csrfToken },
      body: JSON.stringify({
        vaultPath: state.vaultPath,
        envName: state.envName,
        c11: state.c11,
        c21: state.c21,
        vaultNotes: state.vaultNotes
      })
    }).then(function (r) { return r.json(); }).then(function (res) {
      if (res && res.ok && res.markdown) {
        state.latestBrief = res;
        panel.classList.remove('hidden');
        bl.className = 'bl good';
        bl.textContent = 'SAVED TO VAULT · ' + (res.relativePath || ('inbox/brief-' + state.envName + '.md'));
        detail.textContent = 'Verified PRIVATE visibility and wrote brief to ' + res.savedTo + '.';
        label.textContent = res.relativePath || ('inbox/brief-' + state.envName + '.md');
        code.textContent = res.markdown;
      } else {
        state.latestBrief = localBrief;
        panel.classList.remove('hidden');
        label.textContent = localBrief.relativePath;
        code.textContent = localBrief.markdown;
      }
    }).catch(function () {
      state.latestBrief = localBrief;
      panel.classList.remove('hidden');
      label.textContent = localBrief.relativePath;
      code.textContent = localBrief.markdown;
    });
  }

  function fileInboxAction() {
    const detailsEl = $('vault-explorer-details');
    if (detailsEl) detailsEl.open = true;
    const panel = $('brief-output-panel');
    const bl = $('brief-status-bl');
    const detail = $('brief-status-detail');
    const label = $('brief-term-label');
    const code = $('brief-markdown-code');

    if (!state.serverOnline) {
      const diag = getDiagnosis();
      const pb = diag.primary.playbook;
      const sampleFiled = Core.fileInboxNote({
        fileName: 'incident-' + pb.id + '.md',
        envName: state.envName,
        raw: '# Remediated ' + pb.id + ' (' + pb.remediation.plane + ' plane)\n\n## What happened\n\n- ' + pb.bottomLine + '\n\n## What we changed\n\n- ' + pb.remediation.actionSummary
      }, state.vaultNotes || []);
      panel.classList.remove('hidden');
      bl.className = 'bl good';
      bl.textContent = 'INBOX PREVIEW (' + sampleFiled.action.toUpperCase() + ') · ' + sampleFiled.targetRelPath;
      detail.textContent = 'Classified as ' + sampleFiled.category + '. Connect scripts/server.mjs to file inbox/*.md directly into your companion vault.';
      label.textContent = sampleFiled.targetRelPath;
      code.textContent = sampleFiled.markdown;
      return;
    }

    fetch('/api/inbox/file', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-AVD-CSRF': state.csrfToken },
      body: JSON.stringify({ vaultPath: state.vaultPath, envName: state.envName })
    }).then(function (r) { return r.json(); }).then(function (res) {
      if (res && res.ok) {
        if (res.vault && Array.isArray(res.vault.notes)) {
          state.vaultNotes = res.vault.notes;
          $('chip-vault').textContent = 'Vault (' + state.envName + '): ' + res.vault.notesCount + ' notes' + (state.snapshotDate ? ' · ' + state.snapshotDate : '');
        }
        panel.classList.remove('hidden');
        bl.className = 'bl good';
        if (res.filedCount > 0) {
          const summaryPaths = res.filed.map(function (f) { return f.sourceRelPath + ' -> ' + f.targetRelPath + ' (' + f.action + ')'; }).join('\n');
          bl.textContent = 'FILED ' + res.filedCount + ' INBOX NOTE(S) TO VAULT';
          detail.textContent = 'Classified and filed raw inbox notes into companion vault (' + state.envName + ').';
          label.textContent = res.filed[0].targetRelPath;
          code.textContent = summaryPaths + '\n\n' + res.filed[0].markdown;
        } else {
          bl.textContent = 'INBOX CLEAN · 0 RAW NOTES PENDING';
          detail.textContent = 'All non-brief raw notes in inbox/ are already filed into lessons/, decisions/, or runbooks/.';
          label.textContent = 'inbox/';
          code.textContent = '# No unfiled raw notes in inbox/';
        }
        refreshAll();
      }
    }).catch(function () {});
  }

  function refreshAll() {
    const diag = getDiagnosis();
    renderStepNav();
    renderVaultExplorer();
    renderStep2(diag);
    renderStep3(diag);
    renderStep4(diag);
    renderStep5(diag);
  }

  function setStep(idx) {
    state.step = Math.max(0, Math.min(4, idx));
    refreshAll();
    const activeHeading = document.querySelector('#stage-' + state.step + ' h2');
    if (activeHeading) {
      activeHeading.setAttribute('tabindex', '-1');
      activeHeading.focus();
    }
  }

  function appendChatMessage(role, contentObj) {
    const log = $('chat-messages');
    if (role === 'user') {
      const msg = el('div', { className: 'chat-msg user', text: contentObj.text });
      log.appendChild(msg);
      log.scrollTop = log.scrollHeight;
      return;
    }

    const jumpProbeBtn = el('button', { type: 'button', className: 'secondary', text: 'Step 2: Run ' + contentObj.probeId });
    jumpProbeBtn.addEventListener('click', function () {
      state.playbookId = contentObj.playbookId;
      renderPlaybookSelect();
      setStep(1);
    });

    const jumpFixBtn = el('button', { type: 'button', text: 'Step 4: ' + contentObj.plane + ' fix' });
    jumpFixBtn.addEventListener('click', function () {
      state.playbookId = contentObj.playbookId;
      renderPlaybookSelect();
      setStep(3);
    });

    const citList = el('ul', null, (contentObj.citations || []).map(function (c) {
      return el('li', { text: c });
    }));

    const details = el('details', { className: 'more' }, [
      el('summary', { text: 'Citations & matched signals (' + (contentObj.confidence || 'medium') + ')' }),
      citList
    ]);

    const bodyNodes = [
      el('p', { className: 'msg-bl', text: contentObj.bottomLine }),
      el('p', { text: contentObj.nextStep })
    ];
    if (contentObj.llmSynthesis && contentObj.llmSynthesis !== contentObj.bottomLine) {
      bodyNodes.push(el('p', { className: 'muted', text: contentObj.llmSynthesis }));
    }
    bodyNodes.push(el('div', { className: 'msg-actions' }, [jumpProbeBtn, jumpFixBtn]));
    bodyNodes.push(details);

    const msg = el('div', { className: 'chat-msg assistant' }, bodyNodes);
    log.appendChild(msg);
    log.scrollTop = log.scrollHeight;

    const modeLabel = contentObj.mode === 'byo-llm-redacted'
      ? ('BYO-LLM (Redacted' + (contentObj.llmProvider ? ' · ' + contentObj.llmProvider : '') + ')')
      : state.llmModeLabel;
    const redactSummary = (contentObj.redaction && contentObj.redaction.summary) || '';
    updateReasoningBadges(modeLabel, redactSummary);
  }

  function submitChatQuestion(rawQuestion) {
    const q = String(rawQuestion || '').trim();
    if (!q) return;
    appendChatMessage('user', { text: q });
    state.query = q;
    $('symptom-input').value = q;

    const reply = Core.answerChat(q, {
      domain: state.domain,
      c11: state.c11,
      c21: state.c21,
      probeStates: state.probeStates,
      vaultNotes: state.vaultNotes || [],
      snapshotDate: state.snapshotDate || '',
      snapshotStale: Boolean(state.snapshotStale),
      playbookId: ''
    });

    state.playbookId = reply.playbookId;
    const pb = Core.PLAYBOOKS.find(function (p) { return p.id === reply.playbookId; });
    if (pb) state.domain = pb.domain;
    renderDomains();
    renderPlaybookSelect();
    refreshAll();

    if (state.serverOnline) {
      fetch('/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-AVD-CSRF': state.csrfToken },
        body: JSON.stringify({
          question: q,
          domain: state.domain,
          playbookId: state.playbookId,
          c11: state.c11,
          c21: state.c21,
          probeStates: state.probeStates
        })
      }).then(function (r) { return r.ok ? r.json() : null; }).then(function (srvReply) {
        if (srvReply && srvReply.bottomLine) {
          const modeLabel = srvReply.mode === 'byo-llm-redacted'
            ? ('BYO-LLM (Redacted' + (srvReply.llmProvider ? ' · ' + srvReply.llmProvider : '') + ')')
            : 'Offline deterministic ($0, zero network)';
          updateReasoningBadges(modeLabel, srvReply.redaction && srvReply.redaction.summary);
          appendChatMessage('assistant', srvReply);
        } else {
          appendChatMessage('assistant', reply);
        }
      }).catch(function () {
        appendChatMessage('assistant', reply);
      });
    } else {
      appendChatMessage('assistant', reply);
    }
  }

  function loadSampleEstate() {
    state.c11 = SAMPLE_C11;
    state.c21 = SAMPLE_C21;
    if (!state.vaultNotes || !state.vaultNotes.length) {
      state.vaultNotes = SAMPLE_VAULT_NOTES.slice();
    }
    state.domain = 'fslogix';
    state.playbookId = 'pb-fsx-kerberos-smb-auth';
    setDevText($('chip-c11'), 'Estate Facts: 5 planes loaded', 'Estate Facts (C11): 5 planes loaded');
    setDevText($('chip-c21'), 'Assessment Report: 1 gap, 2 warn', 'Assessment Report (C21): 1 gap, 2 warn');
    $('chip-vault').textContent = 'Vault (' + state.envName + '): ' + state.vaultNotes.length + ' notes · ' + (state.snapshotDate || '2026-10-21');
    $('sandbox-status-text').textContent = 'Loaded sample estate snapshot (' + state.envName + ' — Entra Kerberos & RDP Shortpath findings detected).';
    renderDomains();
    renderPlaybookSelect();
    refreshAll();
  }

  function checkLocalServer() {
    if (location.protocol !== 'http:' && location.protocol !== 'https:') return;
    fetch('/api/status').then(function (r) { return r.ok ? r.json() : null; }).then(function (info) {
      if (!info || !info.ok) return;
      state.serverOnline = true;
      state.csrfToken = info.csrfToken || '';
      const vPath = info.vaultPath || info.sandboxPath;
      if (vPath) {
        state.vaultPath = vPath;
        state.sandboxPath = vPath;
        $('settings-sandbox-path').value = vPath;
      }
      if (info.envName) {
        state.envName = info.envName;
      }
      if (info.llm && info.llm.modeLabel) {
        updateReasoningBadges(info.llm.modeLabel, null);
      }
      const pill = $('sandbox-mode-pill');
      const vaultExists = Boolean(info.vaultExists ?? info.sandboxExists);
      if (vaultExists) {
        pill.className = 'outcome o-pass';
        pill.textContent = 'VAULT CONNECTED (' + state.envName.toUpperCase() + ')';
        const snapLabel = (info.vault && info.vault.snapshotRelPath) ? ' · ' + info.vault.snapshotRelPath : '';
        $('sandbox-status-text').textContent = 'Connected to ' + state.vaultPath + ' (env: ' + state.envName + ', visibility: ' + (info.visibility || 'PRIVATE') + ')' + snapLabel + '.';
      } else {
        pill.className = 'outcome o-warn';
        pill.textContent = 'SERVER ONLINE · NO VAULT DIR';
        $('sandbox-status-text').textContent = 'Local server active, but ' + state.vaultPath + ' was not found. Showing built-in sample snapshot until a companion vault or C11/C21 file is loaded.';
      }
      if (info.vault) {
        state.vaultNotes = (info.vault.notes && info.vault.notes.length) ? info.vault.notes : SAMPLE_VAULT_NOTES.slice();
        state.snapshotDate = info.vault.snapshotDate || '2026-10-21';
        state.snapshotStale = Boolean(info.vault.snapshotStale);
        state.snapshotRelPath = info.vault.snapshotRelPath || state.snapshotRelPath;
        $('chip-vault').textContent = 'Vault (' + state.envName + '): ' + (info.vault.notesCount || state.vaultNotes.length) + ' notes' + (info.vault.snapshotDate ? ' · ' + info.vault.snapshotDate : '');
      }
      if (info.c11) {
        state.c11 = info.c11;
        const armCount = info.c11.facts && info.c11.facts['c11.azure.armResources'];
        if (armCount) {
          setDevText($('chip-c11'), 'Estate Facts: ' + armCount + ' resources', 'Estate Facts (C11): ' + armCount + ' resources');
        } else {
          setDevText($('chip-c11'), 'Estate Facts: loaded (' + state.envName + ')', 'Estate Facts (C11): loaded (' + state.envName + ')');
        }
      }
      if (info.c21) {
        state.c21 = info.c21;
        setDevText($('chip-c21'), 'Assessment Report: loaded (' + state.envName + ')', 'Assessment Report (C21): loaded (' + state.envName + ')');
      }
      if (info.c25) {
        state.c25 = info.c25;
      }
      if (info.measuredUsage) {
        state.measuredUsage = info.measuredUsage;
      }
      if (info.familyGraph) {
        state.familyGraph = info.familyGraph;
      }
      refreshAll();
    }).catch(function () {});
  }

  function wireEvents() {
    document.querySelectorAll('#step-list button.step, #step-progress button.seg').forEach(function (btn) {
      btn.addEventListener('click', function () {
        setStep(Number(btn.getAttribute('data-step')));
      });
    });

    $('prev-step-btn').addEventListener('click', function () { setStep(state.step - 1); });
    $('next-step-btn').addEventListener('click', function () { setStep(state.step + 1); });

    $('symptom-input').addEventListener('input', function (e) {
      state.query = e.target.value;
      const diag = Core.diagnose({
        domain: state.domain,
        query: state.query,
        c11: state.c11,
        c21: state.c21,
        c25: state.c25,
        familyGraph: state.familyGraph,
        probeStates: state.probeStates
      });
      if (diag.primary && diag.primary.score > 10) {
        state.playbookId = diag.primary.playbook.id;
        state.domain = diag.primary.playbook.domain;
        renderDomains();
        renderPlaybookSelect();
      }
      refreshAll();
    });

    $('playbook-select').addEventListener('change', function (e) {
      state.playbookId = e.target.value;
      const pb = Core.PLAYBOOKS.find(function (p) { return p.id === state.playbookId; });
      if (pb) state.domain = pb.domain;
      renderDomains();
      refreshAll();
    });

    $('step1-diagnose-btn').addEventListener('click', function () { setStep(1); });
    $('step1-sample-btn').addEventListener('click', loadSampleEstate);
    $('load-demo-btn').addEventListener('click', loadSampleEstate);
    $('generate-brief-btn').addEventListener('click', generateBriefAction);
    $('file-inbox-btn').addEventListener('click', fileInboxAction);

    document.querySelectorAll('.vault-cat-btn').forEach(function (btn) {
      btn.addEventListener('click', function () {
        state.vaultCategory = btn.getAttribute('data-category') || 'all';
        document.querySelectorAll('.vault-cat-btn').forEach(function (b) {
          const active = b.getAttribute('data-category') === state.vaultCategory;
          b.setAttribute('aria-pressed', active ? 'true' : 'false');
          b.classList.toggle('secondary', !active);
        });
        renderVaultExplorer();
      });
    });

    $('vault-search-input').addEventListener('input', function (e) {
      state.vaultSearch = e.target.value;
      renderVaultExplorer();
    });

    $('copy-brief-btn').addEventListener('click', function () {
      copyText($('brief-markdown-code').textContent, $('copy-brief-btn'));
    });

    $('download-brief-btn').addEventListener('click', function () {
      const envSlug = (state.latestBrief && state.latestBrief.envName) || state.envName || 'default-estate';
      const filename = (state.latestBrief && state.latestBrief.date)
        ? ('brief-' + envSlug + '-' + state.latestBrief.date + '.md')
        : ('brief-' + envSlug + '.md');
      downloadBlob(filename, $('brief-markdown-code').textContent, 'text/markdown');
    });

    $('artifact-file-input').addEventListener('change', function (e) {
      const files = Array.prototype.slice.call(e.target.files || []);
      $('artifact-file-error').textContent = '';
      files.forEach(function (file) {
        const reader = new FileReader();
        reader.onload = function () {
          try {
            const text = String(reader.result || '');
            const parsed = JSON.parse(text);
            if (parsed.contract === 'C11' || parsed.schema === 'avd-current-state-facts/v1' || parsed.planesCollected || parsed.facts) {
              state.c11 = parsed;
              setDevText($('chip-c11'), 'Estate Facts: ' + file.name, 'Estate Facts (C11): ' + file.name);
            } else if (parsed.contract === 'C21' || parsed.schema === 'avd-assessment/v1' || parsed.schema === 'avd-assessment-report/v1' || Array.isArray(parsed.checks) || Array.isArray(parsed.results)) {
              state.c21 = parsed;
              setDevText($('chip-c21'), 'Assessment Report: ' + file.name, 'Assessment Report (C21): ' + file.name);
            } else if (parsed.contract === 'C25' || parsed.schema === 'avd-benchmark-result/v1' || (parsed.verdict && parsed.metrics && parsed.environment)) {
              state.c25 = parsed;
            } else if (parsed.schema === 'avd-measured-usage/v1' || (parsed.measurementGate && Array.isArray(parsed.groups))) {
              state.measuredUsage = parsed;
            } else if (parsed.schema === 'family-graph-report/v1' || (parsed.graph && parsed.graph.schema === 'family-graph/v1')) {
              state.familyGraph = parsed;
            }
            $('artifact-file-status').textContent = 'Loaded ' + file.name;
            refreshAll();
          } catch (err) {
            const sl = Core.parseStateLines(String(reader.result || ''));
            if (sl.valid.length) {
              state.probeStates = state.probeStates.concat(sl.valid);
              $('artifact-file-status').textContent = 'Parsed ' + sl.valid.length + ' state line(s) from ' + file.name;
              refreshAll();
            } else {
              setDevText($('artifact-file-error'), 'Could not parse ' + file.name + ' as Estate Facts / Assessment Report JSON or state line.', 'Could not parse ' + file.name + ' as Estate Facts (C11) / Assessment Report (C21) JSON or state line.');
            }
          }
        };
        reader.readAsText(file);
      });
    });

    $('copy-probe-btn').addEventListener('click', function () {
      copyText($('probe-cmd-code').textContent, $('copy-probe-btn'));
    });

    if ($('telemetry-mode-select')) {
      $('telemetry-mode-select').addEventListener('change', function (e) {
        state.telemetryMode = e.target.value;
        refreshAll();
      });
    }
    if ($('telemetry-workload-select')) {
      $('telemetry-workload-select').addEventListener('change', function (e) {
        state.telemetryWorkload = e.target.value;
        refreshAll();
      });
    }
    if ($('telemetry-sku-input')) {
      $('telemetry-sku-input').addEventListener('change', function (e) {
        try {
          state.telemetryVmSku = Engine.core.check(e.target.value.trim(), /^Standard_[A-Za-z0-9_]{1,40}$/, 'VmSku');
          refreshAll();
        } catch (_) {}
      });
    }
    if ($('copy-telemetry-cmd-btn')) {
      $('copy-telemetry-cmd-btn').addEventListener('click', function () {
        copyText($('telemetry-cmd-code').textContent, $('copy-telemetry-cmd-btn'));
      });
    }
    if ($('download-c25-btn')) {
      $('download-c25-btn').addEventListener('click', function () {
        const diag = getDiagnosis();
        const pb = diag.primary.playbook;
        const c25 = state.c25 || Core.buildC25BenchmarkResult({
          profileId: pb.domain === 'fslogix' ? 'storage-fslogix-io' : 'multisession-density',
          workloadClass: state.telemetryWorkload,
          vmSku: state.telemetryVmSku,
          c11: state.c11
        });
        state.c25 = c25;
        downloadBlob('benchmark-c25.json', JSON.stringify(c25, null, 2), 'application/json');
        refreshAll();
      });
    }
    if ($('download-measured-usage-btn')) {
      $('download-measured-usage-btn').addEventListener('click', function () {
        const diag = getDiagnosis();
        const pb = diag.primary.playbook;
        const c25 = state.c25 || Core.buildC25BenchmarkResult({
          profileId: pb.domain === 'fslogix' ? 'storage-fslogix-io' : 'multisession-density',
          workloadClass: state.telemetryWorkload,
          vmSku: state.telemetryVmSku,
          c11: state.c11
        });
        const measured = Core.buildMeasuredUsage({
          workloadClass: state.telemetryWorkload,
          vmSku: state.telemetryVmSku,
          c11: state.c11,
          c25: c25
        });
        state.c25 = c25;
        state.measuredUsage = measured;
        downloadBlob('measured-usage.json', JSON.stringify(measured, null, 2), 'application/json');
        refreshAll();
      });
    }
    if ($('export-telemetry-vault-btn')) {
      $('export-telemetry-vault-btn').addEventListener('click', function () {
        const diag = getDiagnosis();
        const pb = diag.primary.playbook;
        const profileId = pb.domain === 'fslogix' ? 'storage-fslogix-io' : 'multisession-density';
        if (!state.serverOnline) {
          const c25 = Core.buildC25BenchmarkResult({
            profileId: profileId,
            workloadClass: state.telemetryWorkload,
            vmSku: state.telemetryVmSku,
            c11: state.c11
          });
          const measured = Core.buildMeasuredUsage({
            workloadClass: state.telemetryWorkload,
            vmSku: state.telemetryVmSku,
            c11: state.c11,
            c25: c25
          });
          state.c25 = c25;
          state.measuredUsage = measured;
          if ($('telemetry-status-detail')) {
            $('telemetry-status-detail').textContent = 'Built schema-valid Contract C25 (' + c25.verdict + ') and avd-measured-usage/v1 (' + measured.measurementGate.daysObserved + 'd window) in browser. Use the Download buttons or connect scripts/server.mjs to write to your vault.';
          }
          refreshAll();
          return;
        }
        fetch('/api/telemetry/export', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-AVD-CSRF': state.csrfToken },
          body: JSON.stringify({
            vaultPath: state.vaultPath,
            envName: state.envName,
            mode: state.telemetryMode,
            profileId: profileId,
            workloadClass: state.telemetryWorkload,
            vmSku: state.telemetryVmSku,
            c11: state.c11
          })
        }).then(function (r) { return r.json(); }).then(function (res) {
          if (res && res.ok) {
            state.c25 = res.c25;
            state.measuredUsage = res.measuredUsage;
            if ($('telemetry-status-detail')) {
              $('telemetry-status-detail').textContent = 'Saved benchmark-c25.json and measured-usage.json to ' + res.c25Path + ' (visibility verified PRIVATE).';
            }
            refreshAll();
          }
        }).catch(function () {});
      });
    }

    $('simulate-probe-btn').addEventListener('click', function () {
      const diag = getDiagnosis();
      const pb = diag.primary.playbook;
      const sampleLine = '<<<AVDREM-STATE ' + JSON.stringify({
        v: 1,
        stage: 'probe',
        probeId: pb.probeId,
        playbookId: pb.id,
        plane: pb.remediation.plane,
        status: 'gap',
        summary: pb.bottomLine
      }) + ' AVDREM-STATE>>>';
      $('probe-paste-box').value = sampleLine;
      const parsed = Core.parseStateLines(sampleLine);
      state.probeStates = parsed.valid;
      refreshAll();
    });

    $('run-live-probe-btn').addEventListener('click', function () {
      const diag = getDiagnosis();
      const pb = diag.primary.playbook;
      if (!state.serverOnline) {
        $('simulate-probe-btn').click();
        return;
      }
      fetch('/api/probe', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-AVD-CSRF': state.csrfToken },
        body: JSON.stringify({ probeId: pb.probeId, playbookId: pb.id, vaultPath: state.vaultPath, envName: state.envName })
      }).then(function (r) { return r.json(); }).then(function (res) {
        if (res && res.output) {
          $('probe-paste-box').value = res.output;
          const parsed = Core.parseStateLines(res.output);
          if (parsed.valid.length) state.probeStates = parsed.valid;
          refreshAll();
        }
      }).catch(function () {});
    });

    $('probe-paste-box').addEventListener('input', function (e) {
      const masked = Engine.redact.maskSecrets(e.target.value);
      const parsed = Core.parseStateLines(masked.text);
      state.probeStates = parsed.valid;
      refreshAll();
    });

    $('step3-to-remediate-btn').addEventListener('click', function () { setStep(3); });
    $('step3-ask-chat-btn').addEventListener('click', function () {
      const diag = getDiagnosis();
      submitChatQuestion('Explain why ' + diag.primary.playbook.id + ' triggered and how to remediate it safely.');
    });

    document.querySelectorAll('.path-tab').forEach(function (btn) {
      btn.addEventListener('click', function () {
        state.activePath = btn.getAttribute('data-path');
        refreshAll();
      });
    });

    $('copy-remediate-btn').addEventListener('click', function () {
      copyText($('remediate-cmd-code').textContent, $('copy-remediate-btn'));
    });
    $('copy-c24-btn').addEventListener('click', function () {
      copyText($('c24-json-code').textContent, $('copy-c24-btn'));
    });
    $('copy-swarm-btn').addEventListener('click', function () {
      copyText($('swarm-json-code').textContent, $('copy-swarm-btn'));
    });

    $('download-c24-btn').addEventListener('click', function () {
      downloadBlob('remediation-c24.json', $('c24-json-code').textContent, 'application/json');
    });
    $('download-swarm-btn').addEventListener('click', function () {
      downloadBlob('avd-swarm-plan-proposal.json', $('swarm-json-code').textContent, 'application/json');
    });
    $('download-ps1-btn').addEventListener('click', function () {
      downloadBlob('Invoke-AvdApprovedFix.ps1', $('remediate-cmd-code').textContent, 'text/plain');
    });

    const dialog = $('approval-dialog');
    $('open-approval-modal-btn').addEventListener('click', function () {
      if (dialog && typeof dialog.showModal === 'function') {
        dialog.showModal();
      } else {
        state.remediationMode = 'ApplyApprovedFix';
        refreshAll();
      }
    });
    if (dialog) {
      dialog.addEventListener('close', function () {
        if (dialog.returnValue === 'approve') {
          state.remediationMode = 'ApplyApprovedFix';
          refreshAll();
        }
      });
    }

    $('verify-paste-box').addEventListener('input', function (e) {
      const parsed = Core.parseStateLines(Engine.redact.maskSecrets(e.target.value).text);
      state.verifyState = parsed.latest;
      refreshAll();
    });

    $('simulate-verify-btn').addEventListener('click', function () {
      const diag = getDiagnosis();
      const pb = diag.primary.playbook;
      const line = '<<<AVDREM-STATE ' + JSON.stringify({
        v: 1,
        stage: 'verify',
        playbookId: pb.id,
        plane: pb.remediation.plane,
        status: 'pass',
        summary: 'Verified ' + pb.remediation.name + ' on plane ' + pb.remediation.plane
      }) + ' AVDREM-STATE>>>';
      $('verify-paste-box').value = line;
      state.verifyState = Core.parseStateLines(line).latest;
      refreshAll();
    });

    $('copy-kb-yaml-btn').addEventListener('click', function () {
      copyText($('kb-yaml-code').textContent, $('copy-kb-yaml-btn'));
    });

    $('download-incident-btn').addEventListener('click', function () {
      const diag = getDiagnosis();
      const bundle = {
        schema: 'avd-remediate-incident/v1',
        capturedAt: new Date().toISOString(),
        playbookId: diag.primary.playbook.id,
        plane: diag.primary.playbook.remediation.plane,
        confidence: diag.primary.confidence,
        signals: diag.primary.signals,
        probeStates: state.probeStates,
        verifyState: state.verifyState,
        c24Plan: Core.buildC24Plan([diag.primary])
      };
      downloadBlob('incident-' + diag.primary.playbook.id + '.json', JSON.stringify(bundle, null, 2), 'application/json');
    });

    $('save-sandbox-btn').addEventListener('click', function () {
      const diag = getDiagnosis();
      const bundle = {
        schema: 'avd-remediate-incident/v1',
        capturedAt: new Date().toISOString(),
        playbookId: diag.primary.playbook.id,
        plane: diag.primary.playbook.remediation.plane,
        confidence: diag.primary.confidence,
        signals: diag.primary.signals,
        probeStates: state.probeStates,
        verifyState: state.verifyState,
        c24Plan: Core.buildC24Plan([diag.primary])
      };
      if (!state.serverOnline) {
        downloadBlob('incident-' + diag.primary.playbook.id + '.json', JSON.stringify(bundle, null, 2), 'application/json');
        return;
      }
      fetch('/api/capture', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-AVD-CSRF': state.csrfToken },
        body: JSON.stringify({ vaultPath: state.vaultPath, envName: state.envName, incident: bundle })
      }).then(function (r) { return r.json(); }).then(function (res) {
        if (res && res.savedTo) {
          $('step5-verify-detail').textContent = 'Saved incident bundle to ' + res.savedTo + ' (visibility verified PRIVATE).';
        }
      }).catch(function () {});
    });

    // Chat drawer toggle
    function setChatOpen(open) {
      document.body.classList.toggle('chat-open', open);
      $('chat-drawer').classList.toggle('hidden', !open);
      $('chat-open-btn').setAttribute('aria-expanded', open ? 'true' : 'false');
      const isNarrow = window.matchMedia('(max-width: 81.99rem)').matches;
      $('chat-backdrop').classList.toggle('hidden', !(open && isNarrow));
    }

    $('chat-open-btn').addEventListener('click', function () {
      const currentlyOpen = $('chat-open-btn').getAttribute('aria-expanded') === 'true';
      setChatOpen(!currentlyOpen);
    });
    $('chat-close-btn').addEventListener('click', function () { setChatOpen(false); });
    $('chat-backdrop').addEventListener('click', function () { setChatOpen(false); });

    document.querySelectorAll('.prompt-chip').forEach(function (chip) {
      chip.addEventListener('click', function () {
        submitChatQuestion(chip.getAttribute('data-prompt'));
      });
    });

    $('chat-form').addEventListener('submit', function (e) {
      e.preventDefault();
      const input = $('chat-input');
      const q = input.value;
      input.value = '';
      submitChatQuestion(q);
    });

    // Settings sheet
    function setSettingsOpen(open) {
      $('settings-sheet').classList.toggle('hidden', !open);
      $('settings-backdrop').classList.toggle('hidden', !open);
      $('settings-open-btn').setAttribute('aria-expanded', open ? 'true' : 'false');
    }
    $('settings-open-btn').addEventListener('click', function () { setSettingsOpen(true); });
    $('settings-close-btn').addEventListener('click', function () { setSettingsOpen(false); });
    $('settings-backdrop').addEventListener('click', function () { setSettingsOpen(false); });
    document.querySelectorAll('.runin-change-btn').forEach(function (btn) {
      btn.addEventListener('click', function () { setSettingsOpen(true); });
    });

    document.querySelectorAll('input[name="runin-where"], input[name="runin-shell"]').forEach(function (radio) {
      radio.addEventListener('change', function () {
        const whereEl = document.querySelector('input[name="runin-where"]:checked');
        const shellEl = document.querySelector('input[name="runin-shell"]:checked');
        saveRunIn({
          where: whereEl ? whereEl.value : 'cloudshell',
          shell: shellEl ? shellEl.value : 'pwsh'
        });
        refreshAll();
      });
    });

    $('settings-sandbox-path').addEventListener('change', function (e) {
      try {
        const checked = Engine.core.check(e.target.value.trim(), /^[A-Za-z0-9_./:\\~-]{1,240}$/, 'VaultPath');
        state.vaultPath = checked;
        state.sandboxPath = checked;
        refreshAll();
      } catch (_) {}
    });

    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape') {
        setSettingsOpen(false);
        if (window.matchMedia('(max-width: 81.99rem)').matches) {
          setChatOpen(false);
        }
      }
    });
  }

  // Initialize
  renderDomains();
  renderPlaybookSelect();
  wireEvents();
  loadSampleEstate();
  appendChatMessage('assistant', Core.answerChat('FSLogix profile mount fails with 0x0000052e Access Denied on Entra-joined host', {
    domain: state.domain,
    c11: state.c11,
    c21: state.c21
  }));
  checkLocalServer();
})();
