'use strict';

/**
 * Gatekeep guard pipeline — the agent itself.
 *
 * Input:  { chain, wallet?, tx?: { to, value, data }, token? }
 * Output: { verdict, risk_score, chain, checks, explanation, evidence,
 *           signature, signature_algo, public_key, signature_payload }
 *
 * All checks are deterministic and read-only (eth_call / eth_getCode /
 * eth_blockNumber / DexScreener GET). A check that cannot fetch its data
 * returns status "unknown" and contributes 0 points — never a guess.
 * No transactions are ever sent, no user transaction is ever signed.
 */

const { CHAINS, KNOWN_SPENDERS, ZERO_ADDRESS, DEAD_ADDRESS } = require('./chains');
const { getBlockNumber, getCode, ethCall, getRpcCallCount, getTransactionCount } = require('./rpc');
const { getTokenPairs, summarizePair } = require('./dexscreener');
const { RULES, MAX_UINT256, verdictFor } = require('./scoring');
const { evidenceHash, stableStringify } = require('./util');
const { signString, getPublicKeyB64 } = require('./sign');

const APPROVE_SELECTOR = '0x095ea7b3'; // approve(address,uint256)
const TRANSFER_SELECTOR = '0xa9059cbb'; // transfer(address,uint256)

function isAddress(v) {
  return typeof v === 'string' && /^0x[0-9a-fA-F]{40}$/.test(v);
}

/**
 * EIP-7702 delegation designator: code starting 0xef01 + 20-byte address.
 * Such an account is a delegated EOA — it behaves like a normal wallet for
 * plain transfers, but it is NOT a regular smart contract. Seen on
 * well-known wallets (e.g. vitalik.eth) since the Pectra upgrade.
 */
function isDelegatedEoaCode(code) {
  return typeof code === 'string' && code.toLowerCase().startsWith('0xef01');
}
function isEoaCode(code) {
  return code === '0x' || isDelegatedEoaCode(code);
}

/** Validate + normalise a /guard body. Returns { ok, input, error }. */
function validateGuardInput(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return { ok: false, error: 'Body must be a JSON object.' };
  }
  const { chain, wallet, tx, token } = body;
  if (!chain || typeof chain !== 'string' || !CHAINS[chain]) {
    return { ok: false, error: `Unknown chain "${chain}". Use one of: ${Object.keys(CHAINS).join(', ')}.` };
  }
  if (wallet !== undefined && wallet !== null && !isAddress(wallet)) {
    return { ok: false, error: `"wallet" must be a 0x Ethereum address (40 hex chars), got: ${wallet}` };
  }
  if (token !== undefined && token !== null && !isAddress(token)) {
    return { ok: false, error: `"token" must be a 0x Ethereum address (40 hex chars), got: ${token}` };
  }
  let normTx = null;
  if (tx !== undefined && tx !== null) {
    if (typeof tx !== 'object' || Array.isArray(tx)) {
      return { ok: false, error: '"tx" must be an object { to, value?, data? }.' };
    }
    if (!isAddress(tx.to)) {
      return { ok: false, error: `"tx.to" must be a 0x Ethereum address (40 hex chars), got: ${tx.to}` };
    }
    if (tx.value !== undefined && tx.value !== null) {
      const v = tx.value;
      const okNum = (typeof v === 'number' && Number.isSafeInteger(v) && v >= 0)
        || (typeof v === 'string' && /^[0-9]+$/.test(v));
      if (!okNum) {
        return { ok: false, error: '"tx.value" must be a non-negative integer (decimal string or number).' };
      }
    }
    if (tx.data !== undefined && tx.data !== null && !/^0x([0-9a-fA-F]{2})*$/.test(tx.data)) {
      return { ok: false, error: '"tx.data" must be 0x-prefixed hex (even length).' };
    }
    normTx = { to: tx.to, value: tx.value !== undefined && tx.value !== null ? String(tx.value) : '0', data: tx.data || '0x' };
  }
  if (!wallet && !normTx && !token) {
    return { ok: false, error: 'Provide at least one of: wallet, tx, token.' };
  }
  return { ok: true, input: { chain, wallet: wallet || null, tx: normTx, token: token || null } };
}

/* ---------- ABI decoding helpers (minimal, no deps) ---------- */

function decodeAddressWord(hex) {
  if (!hex || hex.length < 66) return null;
  return '0x' + hex.slice(-40);
}

function decodeUint256(hex) {
  if (!hex || hex.length < 66) return null;
  try { return BigInt(hex); } catch { return null; }
}

/** Decode an ABI-encoded dynamic string return (name()/symbol()). */
function decodeString(hex) {
  try {
    if (!hex || hex.length < 130 || !hex.startsWith('0x')) return null;
    const len = parseInt(hex.slice(66, 130), 16);
    const dataHex = hex.slice(130, 130 + len * 2);
    return Buffer.from(dataHex, 'hex').toString('utf8').replace(/\u0000/g, '');
  } catch { return null; }
}

function encodeAddressParam(addr) {
  return addr.toLowerCase().replace(/^0x/, '').padStart(64, '0');
}

function allowanceCalldata(owner, spender) {
  return '0xdd62ed3e' + encodeAddressParam(owner) + encodeAddressParam(spender);
}

/* ---------- the guard ---------- */

async function guard(input) {
  const chain = CHAINS[input.chain];
  const checks = [];
  let score = 0;
  const rpcBefore = getRpcCallCount();

  function add(name, status, detail, delta, sentence) {
    checks.push({ name, status, detail, score_delta: delta });
    score += delta;
    if (sentence) add._sentences.push({ delta, sentence });
  }
  add._sentences = [];

  const blockNumber = await getBlockNumber(input.chain);

  /* ----- 1. Transaction analysis ----- */
  if (input.tx) {
    const { to, value, data } = input.tx;
    const dataLower = (data || '0x').toLowerCase();
    const valueIsZero = !value || value === '0';
    const txCode = await getCode(input.chain, to);
    const toLower = to.toLowerCase();

    // Recipient: burn / zero / self
    if (toLower === ZERO_ADDRESS) {
      add('recipient-address', 'fail', 'Recipient is the zero address — any funds sent would be unrecoverable.', RULES.recipientIsBurn,
        'the recipient is the zero address');
    } else if (toLower === DEAD_ADDRESS) {
      add('recipient-address', 'fail', 'Recipient is the 0x000...dEaD burn address — any funds sent would be destroyed.', RULES.recipientIsBurn,
        'the recipient is a burn address');
    } else if (input.wallet && toLower === input.wallet.toLowerCase()) {
      add('recipient-address', 'pass', 'Recipient is your own wallet.', 0);
    } else {
      add('recipient-address', 'pass', 'Recipient is not a known burn address.', 0);
    }

    // Value sanity: native currency to a token contract
    const knownTokenAddrs = Object.values(chain.tokens).map((a) => a.toLowerCase());
    if (!valueIsZero && knownTokenAddrs.includes(toLower)) {
      add('value-shape', 'warn', 'Native currency is being sent to a token contract address — usually a mistake; funds sent there are often stuck.', RULES.ethToTokenContract,
        'native currency is being sent to a token contract');
    }

    // Plain transfer vs contract call
    if (!valueIsZero && dataLower === '0x') {
      if (txCode === '0x') {
        add('tx-shape', 'pass', 'Plain native-currency transfer to a wallet address (EOA).', RULES.plainTransferToEoa);
      } else if (isDelegatedEoaCode(txCode)) {
        add('tx-shape', 'pass', 'Plain native-currency transfer to a wallet address with an EIP-7702 delegation (delegated EOA) — plain transfers still behave like a normal wallet.', RULES.plainTransferToEoa);
      } else if (txCode) {
        add('tx-shape', 'warn', 'Native currency sent to a contract with no calldata — the contract may not expect plain transfers.', RULES.sendToContractNoData,
          'native currency is sent to a contract with no calldata');
      } else {
        add('tx-shape', 'unknown', 'Could not check whether the recipient is a contract (RPC unavailable).', 0);
      }
    }

    // ERC-20 approve() decoding
    if (dataLower.startsWith(APPROVE_SELECTOR) && dataLower.length >= 138) {
      const spender = '0x' + dataLower.slice(34, 74);
      const amount = decodeUint256('0x' + dataLower.slice(74, 138));
      const spenderLower = spender.toLowerCase();
      const tokenName = Object.entries(chain.tokens).find(([, a]) => a.toLowerCase() === toLower)?.[0] || null;

      if (amount === MAX_UINT256) {
        add('approval-amount', 'fail',
          `Unlimited approval (2^256-1)${tokenName ? ` for ${tokenName}` : ''} — the spender can move your entire balance of this token at any time until you revoke it.`,
          RULES.unlimitedApproval, 'the approval is unlimited (max uint256)');
      } else if (amount === 0n) {
        add('approval-amount', 'pass', 'Zero approval — this revokes a previous allowance.', 0);
      } else {
        add('approval-amount', 'warn', `Bounded approval of ${amount.toString()} base units — finite, but still review the spender.`, RULES.boundedApproval,
          'the approval amount is finite but non-zero');
      }

      const knownName = KNOWN_SPENDERS[spenderLower];
      if (knownName) {
        add('spender-known', 'pass', `Spender is ${knownName} — a well-known protocol contract.`, RULES.spenderKnownProtocol);
      } else {
        const spenderCode = await getCode(input.chain, spender);
        if (spenderCode === null) {
          add('spender-known', 'unknown', 'Could not check the spender contract code (RPC unavailable).', 0);
        } else if (isEoaCode(spenderCode)) {
          add('spender-known', 'fail',
            isDelegatedEoaCode(spenderCode)
              ? 'Spender is a wallet account with an EIP-7702 delegation, not a smart contract — token approvals to wallet accounts are almost never legitimate.'
              : 'Spender is a plain wallet (EOA), not a smart contract — token approvals to EOAs are almost never legitimate.',
            RULES.spenderIsEoa, 'the spender is an externally-owned account, not a contract');
          const nonce = await getTransactionCount(input.chain, spender);
          if (nonce === 0) {
            add('spender-history', 'fail', 'This spender address has never sent a transaction — it is a fresh address with no on-chain history.', RULES.spenderFreshAddress,
              'the spender address has no on-chain history');
          } else if (nonce === null) {
            add('spender-history', 'unknown', 'Could not read the spender transaction count (RPC unavailable).', 0);
          } else {
            add('spender-history', 'pass', `Spender has sent ${nonce} transaction(s) before.`, 0);
          }
        } else {
          add('spender-known', 'warn',
            'Spender is a contract that is NOT in the known-protocol list — it could be legitimate or malicious; verify it before signing.',
            RULES.spenderUnknownContract, 'the spender is an unknown contract');
        }
      }
    } else if (dataLower.startsWith(TRANSFER_SELECTOR) && dataLower.length >= 138) {
      const dest = '0x' + dataLower.slice(34, 74);
      add('transfer-destination', 'pass', `Token transfer to ${dest}. No approval is granted by this call.`, 0);
    } else if (dataLower !== '0x') {
      add('calldata', 'pass', 'Calldata is not an approve() call — no token allowance is granted by this transaction.', 0);
    }
  }

  /* ----- 2. Token rug-check ----- */
  if (input.token) {
    const token = input.token;
    const tokenLower = token.toLowerCase();

    const code = await getCode(input.chain, token);
    let isContract = null;
    if (code === null) {
      add('token-is-contract', 'unknown', 'Could not check contract code (RPC unavailable).', 0);
    } else if (code === '0x' || isDelegatedEoaCode(code)) {
      isContract = false;
      add('token-is-contract', 'fail',
        isDelegatedEoaCode(code)
          ? 'This address is a wallet account with an EIP-7702 delegation — it is not a token contract.'
          : 'This address has no contract code — it is not a token contract.',
        RULES.tokenNotContract,
        'the address is not a token contract at all');
    } else {
      isContract = true;
      const nameHex = await ethCall(input.chain, token, '0x06fdde03');
      const symbolHex = await ethCall(input.chain, token, '0x95d89b41');
      const name = decodeString(nameHex);
      const symbol = decodeString(symbolHex);
      add('token-is-contract', 'pass',
        `Contract code present${name || symbol ? ` — ${name || ''}${symbol ? ` (${symbol})` : ''}` : ''}.`, 0);
    }

    if (isContract !== false) {
      // owner() — privileged-owner detection
      const ownerHex = await ethCall(input.chain, token, '0x8da5cb5b');
      const owner = ownerHex ? decodeAddressWord(ownerHex) : null;
      if (ownerHex === null) {
        add('token-owner', 'unknown', 'owner() call failed (RPC unavailable) — ownership status could not be checked.', 0);
      } else if (!owner) {
        add('token-owner', 'pass', 'No owner() function detected — no privileged owner found via this call (source is not verified here).', RULES.tokenNoOwner);
      } else if (owner.toLowerCase() === ZERO_ADDRESS) {
        add('token-owner', 'pass', 'owner() returns the zero address — ownership appears renounced.', RULES.tokenNoOwner);
      } else {
        add('token-owner', 'warn',
          `owner() is set to ${owner} — the owner may retain mint, pause or blacklist powers. Ownership alone is not proof of a rug, but it is a privilege that can be abused.`,
          RULES.tokenOwnerSet, `the token owner is still set (${owner.slice(0, 10)}…)`);
      }

      // DexScreener market data
      const dex = await getTokenPairs(token, chain.dexscreenerChain);
      if (!chain.dexscreenerChain) {
        add('token-market', 'unknown', 'DexScreener does not index this chain — no market data available.', 0);
      } else if (!dex.ok) {
        add('token-market', 'unknown', `DexScreener unreachable (${dex.error || 'no response'}) — market checks skipped, no score added.`, 0);
      } else {
        const summary = summarizePair(dex.pairs);
        if (!summary) {
          add('token-market', 'unknown', 'No DEX pair found for this token on DexScreener — it may be unlisted, brand new, or not traded on a tracked DEX.', 0);
        } else {
          let delta = 0;
          const notes = [];
          notes.push(`Top pair: ${summary.dexId || 'unknown DEX'} — liquidity $${summary.liquidityUsd.toLocaleString('en-US')} — 24h buys ${summary.buysH24} / sells ${summary.sellsH24}`);
          if (summary.priceChangeH24 !== null) notes.push(`24h price change ${summary.priceChangeH24}%`);
          if (summary.liquidityUsd < 5000) { delta += RULES.liquidityUnder5k; notes.push('liquidity under $5,000 — a small sell can crash the price'); }
          else if (summary.liquidityUsd < 50000) { delta += RULES.liquidityUnder50k; notes.push('liquidity under $50,000 — thin market'); }
          if (summary.pairCreatedAt) {
            const ageMs = Date.now() - summary.pairCreatedAt;
            if (ageMs < 3600_000) { delta += RULES.poolUnder1h; notes.push('pair created less than 1 hour ago'); }
            else if (ageMs < 86400_000) { delta += RULES.poolUnder24h; notes.push('pair created less than 24 hours ago'); }
          }
          if (summary.buysH24 >= 10 && summary.sellsH24 === 0) {
            delta += RULES.buysNoSells;
            notes.push('buys but ZERO sells in 24h — a possible sell-restriction (honeypot) SIGNAL, not proof');
          }
          if (summary.priceChangeH24 !== null && summary.priceChangeH24 <= -50) {
            delta += RULES.priceCrash24h; notes.push('price down 50%+ in 24h');
          }
          if (summary.buysH24 > 0 && summary.sellsH24 > 3 * summary.buysH24) {
            delta += RULES.sellsDominate; notes.push('sells outnumber buys 3:1 in 24h');
          }
          const status = delta >= 25 ? 'fail' : delta > 0 ? 'warn' : 'pass';
          add('token-market', status, notes.join('. ') + '.', delta,
            delta >= 25 ? 'the token market looks very thin or one-sided' : delta > 0 ? 'the token market shows some weak spots' : null);
        }
      }
    }
    // Honest coverage note (always appended, no score)
    checks.push({
      name: 'coverage-note',
      status: 'pass',
      detail: 'NOT checked here (no keyless source): contract source verification, LP lock/burn status, holder concentration, sell simulation. A low score means "no red flags found in the checks above", not "this token is safe".',
      score_delta: 0,
    });
  }

  /* ----- 3. Wallet hygiene ----- */
  if (input.wallet) {
    const tokenEntries = Object.entries(chain.tokens);
    if (tokenEntries.length === 0) {
      add('wallet-hygiene', 'unknown', 'No verified reference token list for this chain — hygiene scan skipped rather than guessing testnet addresses.', 0);
    } else {
      const spenders = Object.keys(KNOWN_SPENDERS).slice(0, 4); // bounded: 4 tokens x 4 spenders max
      const found = [];
      let rpcFailed = 0;
      for (const [symbol, tokenAddr] of tokenEntries) {
        for (const spender of spenders) {
          const res = await ethCall(input.chain, tokenAddr, allowanceCalldata(input.wallet, spender));
          if (res === null) { rpcFailed += 1; continue; }
          const allowance = decodeUint256(res);
          if (allowance === MAX_UINT256) found.push(`${symbol} → ${KNOWN_SPENDERS[spender]}`);
        }
      }
      if (found.length === 0 && rpcFailed >= tokenEntries.length * spenders.length) {
        add('wallet-hygiene', 'unknown', 'RPC unavailable — allowances could not be read.', 0);
      } else if (found.length === 0) {
        add('wallet-hygiene', 'pass', `No unlimited approvals found among the checked tokens/spenders${rpcFailed ? ` (${rpcFailed} allowance reads failed, see note)` : ''}.`, 0);
      } else {
        const delta = Math.min(found.length * RULES.hygieneUnlimitedApproval, 15);
        add('wallet-hygiene', 'warn',
          `Unlimited approvals still open: ${found.join('; ')}. Unlimited allowances stay dangerous if the spender contract is ever exploited — consider revoking ones you no longer use.`,
          delta, `${found.length} unlimited approval(s) still open on this wallet`);
      }
      checks.push({
        name: 'hygiene-scope',
        status: 'pass',
        detail: 'Scope: allowances of this wallet to 4 well-known protocol spenders for the chain reference tokens only. Approvals to unknown spenders are invisible without an indexer — this scan cannot prove you have no risky approvals.',
        score_delta: 0,
      });
    }
  }

  /* ----- score, verdict, explanation, evidence, signature ----- */
  const riskScore = Math.max(0, Math.min(100, score));
  const verdict = verdictFor(riskScore);

  const topReasons = add._sentences
    .filter((s) => s.delta > 0)
    .sort((a, b) => b.delta - a.delta)
    .slice(0, 3)
    .map((s) => s.sentence);
  let explanation;
  if (verdict === 'APPROVE') {
    explanation = topReasons.length
      ? `Looks safe to sign — no blocking issues found${topReasons.length ? ', though note: ' + topReasons.join('; ') + '.' : '.'}`
      : 'Looks safe to sign — no red flags found in the checks above.';
  } else if (verdict === 'REVIEW') {
    explanation = `Review before signing — ${topReasons.join('; ') || 'some checks raised cautions'}.`;
  } else {
    explanation = `Do NOT sign — ${topReasons.join('; ') || 'multiple high-risk signals'}.`;
  }

  const evidenceCore = {
    chain: input.chain,
    wallet: input.wallet || null,
    tx: input.tx || null,
    token: input.token || null,
    block_number: blockNumber,
  };
  const evidenceHashValue = evidenceHash(evidenceCore);
  const payload = stableStringify({ ...evidenceCore, verdict, risk_score: riskScore, checks });
  const signature = signString(payload);

  return {
    verdict,
    risk_score: riskScore,
    chain: input.chain,
    checks,
    explanation,
    evidence: {
      block_number: blockNumber,
      rpc_calls: getRpcCallCount() - rpcBefore,
      evidence_hash: evidenceHashValue,
      evidence_hash_algo: 'sha3-256',
      evidence_hash_note: 'SHA3-256 (NIST) of the canonical inputs + block number. Labelled honestly — this is NOT keccak256 (Node crypto does not ship keccak).',
    },
    signature,
    signature_algo: 'ed25519',
    public_key: getPublicKeyB64(),
    signature_payload: payload,
  };
}

module.exports = { guard, validateGuardInput, isAddress };
