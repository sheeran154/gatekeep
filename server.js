'use strict';

/**
 * Gatekeep — Wallet & Transaction Guard Agent.
 *
 * Read-only security agent: screens a wallet address, a pending transaction
 * or a token BEFORE you sign, and returns a deterministic, signed verdict
 * (APPROVE / REVIEW / REJECT + risk score + reasons).
 *
 * It never moves funds, never sends transactions, and never asks for or
 * signs anything on your behalf.
 *
 * Endpoints:
 *   GET  /              landing page + interactive demo
 *   GET  /health        { status, version, uptime, chains, lastKnownBlocks }
 *   GET  /demo/:case    canned demo verdict (clean | approval | honeypot)
 *   POST /guard         { chain, wallet?, tx?, token? } -> full verdict
 *   POST /verify        { public_key, signature, signature_payload } -> { valid }
 */

const express = require('express');
const path = require('node:path');

const { CHAINS } = require('./src/chains');
const { guard, validateGuardInput } = require('./src/checks');
const { getDemoCase, getSnapshot } = require('./src/demo');
const { verifyString, loadOrCreateKeypair } = require('./src/sign');
const { getBlockNumber } = require('./src/rpc');

const VERSION = '1.0.0';
const PORT = parseInt(process.env.PORT || '3000', 10);

const app = express();
app.use(express.json({ limit: '64kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Last-known block numbers per chain (populated opportunistically by /guard runs).
const lastKnownBlocks = {};

async function refreshBlock(chainName) {
  const n = await getBlockNumber(chainName);
  if (n !== null) lastKnownBlocks[chainName] = n;
  return n;
}

app.get('/health', async (req, res) => {
  res.json({
    status: 'ok',
    agent: 'gatekeep',
    version: VERSION,
    uptime_seconds: Math.floor(process.uptime()),
    chains: Object.keys(CHAINS),
    last_known_blocks: lastKnownBlocks,
    note: 'last_known_blocks is populated by /guard runs; empty until the first check on that chain.',
  });
});

app.get('/demo/:case', async (req, res) => {
  const demo = getDemoCase(req.params.case);
  if (!demo) {
    return res.status(404).json({
      error: `Unknown demo case "${req.params.case}". Available: ${Object.keys(require('./src/demo').DEMO_CASES).join(', ')}.`,
    });
  }
  try {
    const result = await guard(demo.input);
    const live = result.evidence.block_number !== null;
    if (live) {
      if (result.evidence.block_number !== null) lastKnownBlocks[demo.input.chain] = result.evidence.block_number;
      return res.json({
        demo: demo.id,
        title: demo.title,
        description: demo.description,
        live: true,
        ...result,
      });
    }
    // RPC unreachable — fall back to the build-time snapshot, labelled as such.
    const snapshot = getSnapshot(demo.id);
    if (!snapshot) {
      return res.status(503).json({
        error: 'Chain RPC is unreachable and no cached snapshot exists for this demo.',
        demo: demo.id,
      });
    }
    return res.json({
      demo: demo.id,
      title: demo.title,
      description: demo.description,
      live: false,
      source: `cached snapshot captured ${snapshot.captured_at} at block ${snapshot.verdict.evidence.block_number} (live RPC unreachable)`,
      ...snapshot.verdict,
    });
  } catch (err) {
    const snapshot = getSnapshot(demo.id);
    if (snapshot) {
      return res.json({
        demo: demo.id,
        title: demo.title,
        description: demo.description,
        live: false,
        source: `cached snapshot captured ${snapshot.captured_at} (live run failed: ${err.message})`,
        ...snapshot.verdict,
      });
    }
    return res.status(500).json({ error: `Demo failed: ${err.message}` });
  }
});

app.post('/guard', async (req, res) => {
  const v = validateGuardInput(req.body || {});
  if (!v.ok) return res.status(400).json({ error: v.error });
  try {
    const result = await guard(v.input);
    if (result.evidence.block_number !== null) lastKnownBlocks[v.input.chain] = result.evidence.block_number;
    return res.json(result);
  } catch (err) {
    return res.status(500).json({ error: `Guard failed: ${err.message}` });
  }
});

app.post('/verify', (req, res) => {
  const { public_key, signature, signature_payload } = req.body || {};
  if (typeof public_key !== 'string' || typeof signature !== 'string' || typeof signature_payload !== 'string') {
    return res.status(400).json({ error: 'Provide public_key, signature and signature_payload (all strings).' });
  }
  return res.json({ valid: verifyString(signature_payload, signature, public_key) });
});

// JSON 404 + error handler
app.use((req, res) => res.status(404).json({ error: `Unknown route: ${req.method} ${req.path}` }));
app.use((err, req, res, next) => {
  if (err && err.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'Body must be valid JSON.' });
  }
  return res.status(500).json({ error: err && err.message ? err.message : 'Internal error.' });
});

async function main() {
  // Generate (or load) the per-deployment ed25519 signing key at startup.
  loadOrCreateKeypair();
  // Warm the block cache for the chains in the background; failures are fine.
  for (const chainName of Object.keys(CHAINS)) {
    refreshBlock(chainName).catch(() => {});
  }
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Gatekeep v${VERSION} listening on :${PORT}`);
    console.log('Chains: ' + Object.keys(CHAINS).join(', '));
  });
}

if (require.main === module) main();

module.exports = app;
