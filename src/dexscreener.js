'use strict';

/**
 * DexScreener (free, no API key): https://api.dexscreener.com
 * Only used for public market data about a token — pair liquidity, 24h
 * price change, 24h buy/sell counts, pool creation time.
 *
 * What DexScreener does NOT tell us (stated honestly in check details):
 * - whether the contract source is verified
 * - whether sells are blocked on-chain (honeypot) — we only infer a SIGNAL
 *   when a pair has buys but zero sells over 24h, and label it as such
 * - who holds the supply (no holder data in this endpoint)
 */

const { fetchJson, TtlCache } = require('./util');

const cache = new TtlCache(60000);
const DEX_API = 'https://api.dexscreener.com/latest/dex/tokens';

/** Fetch all pairs for a token, filtered to one chain. Returns { ok, pairs, source, error }. */
async function getTokenPairs(tokenAddress, dexscreenerChain) {
  if (!dexscreenerChain) {
    return { ok: true, pairs: [], source: 'not-indexed', note: 'DexScreener does not index this chain' };
  }
  const key = `dex:${dexscreenerChain}:${tokenAddress.toLowerCase()}`;
  const cached = cache.get(key);
  if (cached) return { ok: true, ...cached, source: 'cache' };

  const res = await fetchJson(`${DEX_API}/${tokenAddress}`, { timeoutMs: 5000 });
  if (!res.ok || !res.json || !Array.isArray(res.json.pairs)) {
    return { ok: false, pairs: [], source: 'live', error: res.error || `HTTP ${res.status}` };
  }
  const pairs = res.json.pairs.filter((p) => p.chainId === dexscreenerChain);
  const out = { pairs };
  cache.set(key, out);
  return { ok: true, ...out, source: 'live' };
}

/** Pick the most-liquid pair and normalise the fields the guard scores on. */
function summarizePair(pairs) {
  if (!pairs || pairs.length === 0) return null;
  const best = pairs.reduce((a, b) => ((b.liquidity && b.liquidity.usd || 0) > (a.liquidity && a.liquidity.usd || 0) ? b : a));
  return {
    dexId: best.dexId || null,
    pairAddress: best.pairAddress || null,
    liquidityUsd: best.liquidity ? (best.liquidity.usd || 0) : 0,
    priceUsd: best.priceUsd ? parseFloat(best.priceUsd) : null,
    priceChangeH24: best.priceChange && best.priceChange.h24 !== undefined ? best.priceChange.h24 : null,
    buysH24: best.txns && best.txns.h24 ? (best.txns.h24.buys || 0) : 0,
    sellsH24: best.txns && best.txns.h24 ? (best.txns.h24.sells || 0) : 0,
    pairCreatedAt: best.pairCreatedAt || null,
    url: best.url || null,
  };
}

module.exports = { getTokenPairs, summarizePair };
