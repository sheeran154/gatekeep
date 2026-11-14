'use strict';

/**
 * Minimal JSON-RPC client over public, keyless endpoints.
 * Read-only calls only (eth_blockNumber, eth_getCode, eth_call) — this agent
 * NEVER sends transactions and NEVER asks a node to sign anything.
 *
 * Behaviour on failure: returns { ok: false, error } and the caller turns
 * that into an "unknown" check with an honest detail. No fake data, ever.
 * Per-call timeout: 5s. Endpoints are tried in order until one answers.
 * GET-style reads are cached 60s (block numbers 15s).
 */

const { fetchJson, TtlCache } = require('./util');
const { CHAINS } = require('./chains');

const cache = new TtlCache(60000);
const blockCache = new TtlCache(15000);
let rpcCallCount = 0;

function nextId() { return Math.floor(Math.random() * 1e9); }

/** Raw JSON-RPC call against one chain. Tries each endpoint in order. */
async function rpcCall(chainName, method, params) {
  const chain = CHAINS[chainName];
  rpcCallCount += 1;
  const errors = [];
  for (const url of chain.rpc) {
    const res = await fetchJson(url, {
      method: 'POST',
      body: { jsonrpc: '2.0', id: nextId(), method, params },
      timeoutMs: 5000,
    });
    if (res.ok && res.json && !res.json.error && res.json.result !== undefined) {
      return { ok: true, result: res.json.result, endpoint: url };
    }
    errors.push(`${url}: ${res.json && res.json.error ? res.json.error.message : (res.error || 'HTTP ' + res.status)}`);
  }
  return { ok: false, error: errors.join(' | ') };
}

/** Latest block number (decimal), or null when every endpoint fails. */
async function getBlockNumber(chainName) {
  const cached = blockCache.get('block:' + chainName);
  if (cached !== null) return cached;
  const r = await rpcCall(chainName, 'eth_blockNumber', []);
  if (!r.ok) return null;
  const n = parseInt(r.result, 16);
  blockCache.set('block:' + chainName, n);
  return n;
}

/** Bytecode at an address ('0x' = EOA / no contract), or null on failure. */
async function getCode(chainName, address) {
  const key = `code:${chainName}:${address.toLowerCase()}`;
  const cached = cache.get(key);
  if (cached !== null) return cached;
  const r = await rpcCall(chainName, 'eth_getCode', [address, 'latest']);
  if (!r.ok) return null;
  cache.set(key, r.result);
  return r.result;
}

/** Read-only eth_call. Returns the raw hex result, or null on failure. */
async function ethCall(chainName, to, data) {
  const key = `call:${chainName}:${to.toLowerCase()}:${data.toLowerCase()}`;
  const cached = cache.get(key);
  if (cached !== null) return cached;
  const r = await rpcCall(chainName, 'eth_call', [{ to, data }, 'latest']);
  if (!r.ok) return null;
  cache.set(key, r.result);
  return r.result;
}

/** Transaction count (nonce) for an address, or null on failure. */
async function getTransactionCount(chainName, address) {
  const r = await rpcCall(chainName, 'eth_getTransactionCount', [address, 'latest']);
  if (!r.ok) return null;
  return parseInt(r.result, 16);
}

/** Number of JSON-RPC calls made since process start (for evidence). */
function getRpcCallCount() { return rpcCallCount; }

module.exports = { rpcCall, getBlockNumber, getCode, ethCall, getTransactionCount, getRpcCallCount };
