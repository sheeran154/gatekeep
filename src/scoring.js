'use strict';

/**
 * Deterministic scoring rubric.
 *
 * Every point comes from a named check (see src/checks.js). Nothing scores
 * on "unknown" — a check that could not fetch its data contributes 0 and
 * says so in its detail. The full rubric is documented in README.md.
 *
 * Verdict thresholds: 0–29 APPROVE, 30–69 REVIEW, 70–100 REJECT.
 * Score is clamped to 0–100.
 */

const RULES = {
  // Approval checks
  unlimitedApproval: 40,      // approve() amount == 2^256 - 1
  boundedApproval: 5,         // approve() with a finite, non-zero amount
  spenderIsEoa: 25,           // spender has no contract code
  spenderFreshAddress: 10,    // spender has never sent a transaction (nonce 0)
  spenderUnknownContract: 10, // spender is a contract, not in the known list
  spenderKnownProtocol: -10,  // spender is a well-known protocol contract

  // Token checks
  tokenNotContract: 50,       // token address has no code
  tokenOwnerSet: 15,          // owner() returns a non-zero address
  tokenNoOwner: -5,           // owner() reverts or returns zero address
  liquidityUnder5k: 25,       // top DEX pair liquidity < $5,000
  liquidityUnder50k: 10,      // top DEX pair liquidity $5,000–$50,000
  poolUnder1h: 15,            // top pair created < 1 hour ago
  poolUnder24h: 5,            // top pair created < 24 hours ago
  buysNoSells: 25,            // >=10 buys and 0 sells in 24h (sell-restriction SIGNAL, not proof)
  priceCrash24h: 10,          // price -50% or worse in 24h
  sellsDominate: 10,          // sells > 3x buys in 24h

  // Wallet hygiene (per unlimited approval found, cap +15 per scan)
  hygieneUnlimitedApproval: 5,

  // Transaction shape
  plainTransferToEoa: -5,     // plain native transfer to a wallet address
  ethToTokenContract: 5,      // native currency sent to a token contract
  recipientIsBurn: 30,        // to-address is 0x0 or the dead address
  sendToContractNoData: 5,    // native currency to a contract with no calldata
};

const MAX_UINT256 = (2n ** 256n) - 1n;

function verdictFor(score) {
  const clamped = Math.max(0, Math.min(100, score));
  if (clamped <= 29) return 'APPROVE';
  if (clamped <= 69) return 'REVIEW';
  return 'REJECT';
}

module.exports = { RULES, MAX_UINT256, verdictFor };
