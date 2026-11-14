'use strict';

/**
 * Demo cases for Gatekeep.
 *
 * Each case is a fixed, honest input with an expected verdict. The live
 * pipeline runs first; if the chain RPC is unreachable (block number comes
 * back null) the endpoint falls back to a snapshot captured at build time
 * from live data — clearly marked `live: false` with its capture block.
 *
 * The cases are deliberately labelled: the "honeypot" case is a synthetic
 * scam pattern (a fake token + an unlimited approval to a fresh wallet),
 * NOT a claim that a specific real token is a scam. Real-token honeypot
 * signals come from the live /guard token-market check instead.
 */

const VITALIK = '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045'; // vitalik.eth — a well-known EOA
const USDC_ETH = '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48';
const USDC_BASE = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
const UNISWAP_V2_ROUTER = '0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D';
const FRESH_EOA = '0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF'; // vanity address, no code, nonce 0
const FAKE_TOKEN = '0x1111111111111111111111111111111111111111'; // no contract code on Base

const MAX_UINT256_HEX = 'f'.repeat(64);

function approveCalldata(spender, amountHex = MAX_UINT256_HEX) {
  return '0x095ea7b3' + spender.toLowerCase().replace(/^0x/, '').padStart(64, '0') + amountHex;
}
function decimalToHex(dec) {
  return BigInt(dec).toString(16).padStart(64, '0');
}

const DEMO_CASES = {
  clean: {
    id: 'clean',
    title: 'Clean transfer',
    description: 'Plain 0.1 ETH transfer to a well-known wallet (vitalik.eth). No approval, no contract — the boring, safe case.',
    input: {
      chain: 'ethereum',
      tx: { to: VITALIK, value: '100000000000000000', data: '0x' },
    },
    expectedVerdict: 'APPROVE',
  },
  approval: {
    id: 'approval',
    title: 'Unlimited approval to a known protocol',
    description: 'Unlimited (max uint256) USDC approval to the Uniswap V2 Router. The spender is legitimate — but an unlimited allowance is still a risk if the protocol is ever exploited, so Gatekeep asks you to review it.',
    input: {
      chain: 'ethereum',
      tx: { to: USDC_ETH, value: '0', data: approveCalldata(UNISWAP_V2_ROUTER) },
    },
    expectedVerdict: 'REVIEW',
  },
  honeypot: {
    id: 'honeypot',
    title: 'Fake token + unlimited approval (scam pattern)',
    description: 'A "token" that is not a contract at all, plus an unlimited USDC approval to a fresh, unknown wallet. This is the classic approval-drain setup — Gatekeep rejects it outright.',
    input: {
      chain: 'base',
      token: FAKE_TOKEN,
      tx: { to: USDC_BASE, value: '0', data: approveCalldata(FRESH_EOA) },
    },
    expectedVerdict: 'REJECT',
  },
};

let snapshots = null;
try {
  // Snapshots are captured at build time from live runs (see scripts/capture-snapshots.js).
  snapshots = require('./demo-snapshots.json');
} catch {
  snapshots = {};
}

function getDemoCase(id) {
  return DEMO_CASES[id] || null;
}

function getSnapshot(id) {
  return snapshots && snapshots[id] ? snapshots[id] : null;
}

module.exports = {
  DEMO_CASES,
  getDemoCase,
  getSnapshot,
  approveCalldata,
  decimalToHex,
  MAX_UINT256_HEX,
  VITALIK,
  USDC_ETH,
  USDC_BASE,
  UNISWAP_V2_ROUTER,
  FRESH_EOA,
  FAKE_TOKEN,
};
