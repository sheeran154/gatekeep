'use strict';

/**
 * Capture build-time snapshots for the demo cases.
 *
 * Runs the live guard pipeline for each demo input and writes
 * src/demo-snapshots.json with the verdict + capture metadata. The server
 * serves a snapshot only when the live RPC is unreachable, clearly labelled.
 *
 * Usage: node scripts/capture-snapshots.js
 * (needs the same live connectivity as the server — run on this VM.)
 */

const fs = require('node:fs');
const path = require('node:path');
const { DEMO_CASES } = require('../src/demo');
const { guard } = require('../src/checks');

async function main() {
  const out = {};
  for (const [id, demo] of Object.entries(DEMO_CASES)) {
    console.log(`capturing ${id} ...`);
    const verdict = await guard(demo.input);
    out[id] = {
      captured_at: new Date().toISOString(),
      input: demo.input,
      expected_verdict: demo.expectedVerdict,
      verdict,
    };
    console.log(`  ${id}: ${verdict.verdict} score=${verdict.risk_score} block=${verdict.evidence.block_number}`);
  }
  const file = path.join(__dirname, '..', 'src', 'demo-snapshots.json');
  fs.writeFileSync(file, JSON.stringify(out, null, 2) + '\n');
  console.log('wrote ' + file);
}

main().catch((err) => { console.error(err); process.exit(1); });
