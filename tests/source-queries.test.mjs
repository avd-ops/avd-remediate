import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  queryAvdAssess,
  queryAvdSecondBrain,
  queryMicrosoftLearn
} from '../scripts/source-queries.mjs';
import { createRemediationServer } from '../scripts/server.mjs';

const ROOT = fileURLToPath(new URL('../', import.meta.url));

function makeMockSources() {
  const tmpBase = fs.mkdtempSync(path.join(ROOT, 'tmp-sources-'));
  const assessDir = path.join(tmpBase, 'avd-assess');
  const brainDir = path.join(tmpBase, 'avd-second-brain');

  fs.mkdirSync(path.join(assessDir, 'methods'), { recursive: true });
  fs.writeFileSync(
    path.join(assessDir, 'index.json'),
    JSON.stringify({
      schema: 'avd-assess-index/v1',
      references: [
        {
          id: 'fslogix-kerberos',
          title: 'FSLogix Cloud Kerberos with Azure Files',
          url: 'https://learn.microsoft.com/azure/virtual-desktop/fslogix-containers-azure-files',
          notes: 'Requires Entra Kerberos service principal and Share SMB Contributor RBAC.',
          claims: [
            { id: 'aes-128-gcm', says: 'Enable AES-128-GCM or RC4/AES-256 Kerberos ticket alignment.' }
          ]
        }
      ]
    }),
    'utf8'
  );
  fs.writeFileSync(
    path.join(assessDir, 'methods', 'entra.md'),
    '# Entra ID and Kerberos\n\nCheck Cloud Kerberos and Conditional Access for AVD.\n',
    'utf8'
  );

  fs.mkdirSync(path.join(brainDir, 'docs', 'knowledge', 'troubleshooting'), { recursive: true });
  fs.writeFileSync(
    path.join(brainDir, 'docs', 'knowledge', 'troubleshooting', 'known-errors.yaml'),
    [
      'errors:',
      '- id: fslogix-kerberos-0x52e',
      '  symptom: FSLogix profile mount fails with Status 0x0000052e',
      '  cause: Missing Cloud Kerberos ticket or SMB RBAC role on Azure Files',
      '  fix: Grant Storage File Data SMB Share Contributor and enable CloudKerberosTicketRetrievalEnabled',
      '  source: docs/knowledge/fslogix/README.md',
      '  status: verified',
      "  added: '2026-11-10'"
    ].join('\n'),
    'utf8'
  );
  fs.writeFileSync(
    path.join(brainDir, 'docs', 'knowledge', 'fslogix-notes.md'),
    '---\ntitle: FSLogix Entra Kerberos\nsummary: Cloud Kerberos profile mount checklist\ntopic: fslogix\nstatus: verified\n---\n\n# FSLogix\n',
    'utf8'
  );

  return { tmpBase, assessDir, brainDir };
}

test('mechanical queries search avd-assess and avd-second-brain without an LLM', () => {
  const { tmpBase, assessDir, brainDir } = makeMockSources();
  try {
    const assessRes = queryAvdAssess('FSLogix Kerberos 0x0000052e', assessDir);
    assert.equal(assessRes.available, true);
    assert.ok(assessRes.hits.length >= 1);
    assert.equal(assessRes.hits[0].id, 'ref:fslogix-kerberos');

    const brainRes = queryAvdSecondBrain('FSLogix Kerberos 0x0000052e', brainDir);
    assert.equal(brainRes.available, true);
    assert.ok(brainRes.hits.length >= 1);
    assert.equal(brainRes.hits[0].id, 'known-error:fslogix-kerberos-0x52e');
  } finally {
    fs.rmSync(tmpBase, { recursive: true, force: true });
  }
});

test('queryMicrosoftLearn strips redaction placeholders, queries Learn Search API, and degrades gracefully on error', async () => {
  let requestedUrl = '';
  const mockLearnFetch = async (url) => {
    requestedUrl = url;
    return {
      ok: true,
      status: 200,
      async json() {
        return {
          results: [
            {
              title: 'Store FSLogix profile containers on Azure Files',
              url: 'https://learn.microsoft.com/en-us/azure/virtual-desktop/store-logic-profile-containers',
              description: 'Configure Microsoft Entra Kerberos for FSLogix.'
            }
          ]
        };
      }
    };
  };

  const okRes = await queryMicrosoftLearn(
    'FSLogix <domain-1> 0x0000052e <id-1>',
    { fetchImpl: mockLearnFetch, limit: 3 }
  );
  assert.equal(okRes.available, true);
  assert.equal(okRes.hits.length, 1);
  assert.match(requestedUrl, /^https:\/\/learn\.microsoft\.com\/api\/search\?/);
  assert.doesNotMatch(requestedUrl, /domain-1|id-1/);

  const failRes = await queryMicrosoftLearn('FSLogix Kerberos', {
    fetchImpl: async () => { throw new Error('offline'); }
  });
  assert.equal(failRes.available, false);
  assert.deepEqual(failRes.hits, []);
});

test('/api/chat enriches deterministic-offline replies with avd-assess, avd-second-brain, and Microsoft Learn hits', async () => {
  const { tmpBase, assessDir, brainDir } = makeMockSources();
  const vaultDir = path.join(tmpBase, 'private-vault');
  fs.mkdirSync(vaultDir, { recursive: true });

  const srv = createRemediationServer({
    vaultPath: vaultDir,
    assessPath: assessDir,
    secondBrainPath: brainDir,
    learnSearch: true,
    learnFetch: async () => ({
      ok: true,
      status: 200,
      async json() {
        return {
          results: [
            {
              title: 'Troubleshoot FSLogix profiles',
              url: 'https://learn.microsoft.com/en-us/fslogix/troubleshooting',
              description: 'Resolve 0x0000052e errors.'
            }
          ]
        };
      }
    })
  });

  await new Promise((resolve) => srv.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${srv.address().port}`;
  try {
    const status = await (await fetch(`${base}/api/status`)).json();
    assert.equal(status.sources.assess.available, true);
    assert.equal(status.sources.secondBrain.available, true);
    assert.equal(status.sources.microsoftLearn.enabled, true);

    const chatRes = await fetch(`${base}/api/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-AVD-CSRF': status.csrfToken },
      body: JSON.stringify({ question: 'FSLogix Kerberos 0x0000052e' })
    });
    assert.equal(chatRes.status, 200);
    const chat = await chatRes.json();
    assert.equal(chat.mode, 'deterministic-offline');
    assert.ok(chat.sourceHits.assess.length >= 1);
    assert.ok(chat.sourceHits.secondBrain.length >= 1);
    assert.ok(chat.sourceHits.microsoftLearn.length >= 1);
    assert.ok(chat.citations.some((c) => c.startsWith('avd-assess:ref:fslogix-kerberos')));
    assert.ok(chat.citations.some((c) => c.startsWith('avd-second-brain:known-error:fslogix-kerberos-0x52e')));
    assert.ok(chat.citations.some((c) => c.startsWith('learn:Troubleshoot FSLogix profiles')));
  } finally {
    await new Promise((resolve) => srv.close(resolve));
    fs.rmSync(tmpBase, { recursive: true, force: true });
  }
});
