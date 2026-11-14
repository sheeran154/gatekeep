'use strict';

/**
 * Small shared helpers: deterministic JSON, hashing, fetch with timeout,
 * and a tiny in-memory TTL cache. Zero dependencies.
 */

const crypto = require('node:crypto');

/** JSON.stringify with object keys sorted recursively — deterministic output. */
function stableStringify(value) {
  if (value === undefined) return 'null'; // keep payloads valid JSON (never bare `undefined`)
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(stableStringify).join(',') + ']';
  const keys = Object.keys(value).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + stableStringify(value[k])).join(',') + '}';
}

/**
 * Hash of the canonical (stable-sorted) JSON of `value`.
 *
 * NOTE (honesty label): Node's crypto does not ship keccak-256, so Gatekeep
 * uses NIST SHA3-256 and says so everywhere. The field is named
 * `evidence_hash_algo: "sha3-256"` in API responses — it is NOT keccak256.
 */
function evidenceHash(value) {
  return crypto.createHash('sha3-256').update(stableStringify(value), 'utf8').digest('hex');
}

/** Fetch JSON with a hard timeout. Returns { ok, status, json, error }. */
async function fetchJson(url, { method = 'GET', body = null, timeoutMs = 5000, headers = {} } = {}) {
  try {
    const res = await fetch(url, {
      method,
      body: body ? JSON.stringify(body) : null,
      headers: { 'content-type': 'application/json', ...headers },
      signal: AbortSignal.timeout(timeoutMs),
    });
    const text = await res.text();
    let json = null;
    try { json = JSON.parse(text); } catch { /* non-JSON body */ }
    return { ok: res.ok, status: res.status, json, text };
  } catch (err) {
    return { ok: false, status: 0, json: null, error: String(err && err.message || err) };
  }
}

/** Tiny TTL cache: get/set with per-key expiry (ms). */
class TtlCache {
  constructor(defaultTtlMs = 60000) {
    this.map = new Map();
    this.defaultTtlMs = defaultTtlMs;
  }
  get(key) {
    const entry = this.map.get(key);
    if (!entry) return null;
    if (Date.now() > entry.expiresAt) { this.map.delete(key); return null; }
    return entry.value;
  }
  set(key, value, ttlMs = this.defaultTtlMs) {
    this.map.set(key, { value, expiresAt: Date.now() + ttlMs });
  }
}

module.exports = { stableStringify, evidenceHash, fetchJson, TtlCache };
