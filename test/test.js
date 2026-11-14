'use strict';

/**
 * Gatekeep smoke tests (node --test).
 *
 * Starts the real server on an ephemeral port and asserts end-to-end:
 * /health, landing page, /guard clean case -> APPROVE, unlimited-approval
 * case -> REVIEW or REJECT, malformed input -> 400, demo cases return their
 * expected verdicts (live or clearly-labelled cached snapshot).
 *
 * Notes:
 * - Tests hit live public RPCs / DexScreener. If the network is down, the
 *   demo endpoints fall back to build-time snapshots; the /guard assertions
 *   accept REVIEW|REJECT where the verdict depends on live data.
 * - Run: npm test
 */

const { test } = require('node:test');
const assert = require('node:assert');

const app = require('../server');
const { approveCalldata, VITALIK, USDC_ETH, UNISWAP_V2_ROUTER, DEMO_CASES } = require('../src/demo');
const { getDemoCase } = require('../src/demo');

let base;
let server;

test.before(async () => {
  await new Promise((resolve) => { server = app.listen(0, '127.0.0.1', resolve); });
  base = `http://127.0.0.1:${server.address().port}`;
});

test.after(async () => {
  await new Promise((resolve) => server.close(resolve));
});

async function post(path, body) {
  const res = await fetch(base + path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  return { status: res.status, json: await res.json() };
}

test('GET /health returns ok with version and chains', async () => {
  const res = await fetch(base + '/health');
  assert.equal(res.status, 200);
  const j = await res.json();
  assert.equal(j.status, 'ok');
  assert.equal(j.agent, 'gatekeep');
  assert.ok(j.version);
  assert.deepEqual(j.chains, ['ethereum', 'base', 'sepolia', 'base-sepolia']);
});

test('GET / serves the landing page', async () => {
  const res = await fetch(base + '/');
  assert.equal(res.status, 200);
  const html = await res.text();
  assert.ok(html.includes('Gatekeep'));
  assert.ok(html.includes('/guard'));
});

test('POST /guard clean transfer returns APPROVE', async () => {
  const { status, json } = await post('/guard', {
    chain: 'ethereum',
    tx: { to: VITALIK, value: '100000000000000000', data: '0x' },
  });
  assert.equal(status, 200, JSON.stringify(json));
  assert.equal(json.verdict, 'APPROVE');
  assert.ok(json.risk_score <= 29, `score ${json.risk_score}`);
  assert.ok(Array.isArray(json.checks) && json.checks.length > 0);
  assert.ok(json.signature && json.public_key && json.signature_payload);
  assert.equal(json.evidence.evidence_hash_algo, 'sha3-256');
});

test('POST /guard unlimited approval returns REVIEW or REJECT', async () => {
  const { status, json } = await post('/guard', {
    chain: 'ethereum',
    tx: { to: USDC_ETH, value: '0', data: approveCalldata(UNISWAP_V2_ROUTER) },
  });
  assert.equal(status, 200, JSON.stringify(json));
  assert.ok(['REVIEW', 'REJECT'].includes(json.verdict), `verdict ${json.verdict}`);
  assert.ok(json.risk_score >= 30, `score ${json.risk_score}`);
  const approval = json.checks.find((c) => c.name === 'approval-amount');
  assert.ok(approval && approval.status === 'fail');
});

test('POST /guard malformed input returns 400 with a clear error', async () => {
  const bad1 = await post('/guard', { chain: 'ethereum', token: 'not-an-address' });
  assert.equal(bad1.status, 400);
  assert.ok(bad1.json.error.includes('token'));

  const bad2 = await post('/guard', { chain: 'solana' });
  assert.equal(bad2.status, 400);
  assert.ok(bad2.json.error.includes('chain'));

  const bad3 = await post('/guard', { chain: 'ethereum' });
  assert.equal(bad3.status, 400);
  assert.ok(bad3.json.error.includes('at least one'));
});

test('POST /verify accepts a real verdict signature', async () => {
  const g = await post('/guard', { chain: 'ethereum', token: USDC_ETH });
  assert.equal(g.status, 200);
  const v = await post('/verify', {
    public_key: g.json.public_key,
    signature: g.json.signature,
    signature_payload: g.json.signature_payload,
  });
  assert.equal(v.status, 200);
  assert.equal(v.json.valid, true);

  const tampered = await post('/verify', {
    public_key: g.json.public_key,
    signature: g.json.signature,
    signature_payload: g.json.signature_payload + 'x',
  });
  assert.equal(tampered.json.valid, false);
});

test('GET /demo/:case returns the expected verdicts', async () => {
  for (const id of Object.keys(DEMO_CASES)) {
    const res = await fetch(base + '/demo/' + id);
    assert.equal(res.status, 200, id);
    const j = await res.json();
    assert.equal(j.demo, id);
    assert.equal(j.verdict, getDemoCase(id).expectedVerdict, `${id}: got ${j.verdict} score=${j.risk_score} live=${j.live}`);
    assert.equal(typeof j.live, 'boolean');
    if (j.live === false) assert.ok(typeof j.source === 'string' && j.source.includes('snapshot'));
  }
});

test('GET /demo/unknown returns 404', async () => {
  const res = await fetch(base + '/demo/nope');
  assert.equal(res.status, 404);
});
