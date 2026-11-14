# Gatekeep 🛡️ — Wallet & Transaction Guard Agent

![status](https://img.shields.io/badge/status-working-brightgreen)
![license](https://img.shields.io/badge/license-MIT-blue)

**Screens approvals, transactions and tokens BEFORE you sign — and tells you, in plain language, whether it's safe.**

Built for [Agent Games by zkVerify](https://agentgames.zkverify.io/events/wildcard) — Wildcard track, Season 01 (Nov 2026).

Live demo: *TBD — endpoint URL goes here after deploy* · `GET /` is an interactive page with demo cases.

## The problem

Most wallet drains don't start with a hack — they start with a signature. A user approves
"unlimited" spending to a contract they never checked, or interacts with a token that was
created an hour ago with $400 of liquidity. By the time the drain happens, the signature
has already been given.

Existing tools either need an API key, hide their logic, or only check one thing. Gatekeep
does one job, openly: **give a deterministic verdict (APPROVE / REVIEW / REJECT) with the
reasons attached, before you sign.**

## Who it helps

- **Everyday wallet users** about to sign an approval or a token interaction they don't fully understand.
- **Airdrop/testnet farmers** who connect to a new dApp every day — the highest-exposure users.
- **Anyone reviewing a new token** before buying: liquidity, pool age, owner privileges, buy/sell balance.

## How it works

```
POST /guard  { chain, wallet?, tx?, token? }
        │
        ├─ decode approve() calldata → spender + amount (unlimited? known protocol? EOA? fresh?)
        ├─ token checks (RPC) → contract code, owner(), name/symbol
        ├─ market checks (DexScreener, free, no key) → liquidity, pool age, 24h buys/sells, price move
        └─ wallet hygiene (RPC) → open unlimited allowances to known protocol spenders
        │
        ▼
{ verdict, risk_score 0–100, checks[], explanation, evidence{block_number, rpc_calls, evidence_hash}, signature }
```

- **Deterministic, no LLM.** The same input at the same block height always gives the same verdict. No hallucinated risk.
- **Read-only.** Only `eth_call` / `eth_getCode` / `eth_blockNumber` and public GETs. It never sends a transaction and never signs anything on your behalf.
- **Signed verdicts.** Every verdict is signed with the deployment's ed25519 key and carries an `evidence_hash` (SHA3-256 of the canonical inputs + block number) plus the exact `signature_payload` that was signed, so anyone can re-run the checks at that block and verify the verdict — via `POST /verify` or any ed25519 verifier.
- **Honest about unknowns.** A check that can't fetch its data returns `status: "unknown"` and adds **0** points. No invented coverage.

### Scoring rubric (all rules, no hidden weights)

| Signal | Points |
|---|---|
| Unlimited approval (`2^256-1`) | +40 |
| Spender is a plain wallet / delegated EOA (not a contract) | +25 |
| Token address is not a contract at all | +50 |
| Token owner still set (`owner()` non-zero) | +15 |
| Spender is an unknown contract | +10 |
| Spender is a fresh address (nonce 0) | +10 |
| Top DEX pair liquidity < $5,000 | +25 |
| Top DEX pair liquidity $5,000–$50,000 | +10 |
| Pair created < 1 hour ago | +15 |
| Pair created < 24 hours ago | +5 |
| ≥10 buys and 0 sells in 24h (sell-restriction *signal*, not proof) | +25 |
| Price −50% or worse in 24h | +10 |
| Sells > 3× buys in 24h | +10 |
| Each open unlimited approval found in wallet hygiene (cap +15) | +5 |
| ETH sent to a token contract / contract with no calldata | +5 |
| Recipient is the zero / burn address | +30 |
| Bounded (finite) approval | +5 |
| Spender is a well-known protocol (Uniswap, 1inch, Seaport, Permit2) | −10 |
| No `owner()` / ownership renounced | −5 |
| Plain transfer to a wallet address | −5 |
| Any check that could not fetch data | 0 |

Verdict: **0–29 APPROVE · 30–69 REVIEW · 70–100 REJECT**. Score is clamped to 0–100.

## Endpoints

| Method | Route | Description |
|---|---|---|
| `GET` | `/` | Landing page + interactive demo (form calls `/guard`) |
| `GET` | `/health` | `{ status, version, uptime, chains, last_known_blocks }` |
| `GET` | `/demo/:case` | Canned demo verdict: `clean` / `approval` / `honeypot` |
| `POST` | `/guard` | Guard a wallet / transaction / token (JSON in, verdict out) |
| `POST` | `/verify` | `{ public_key, signature, signature_payload }` → `{ valid }` |

### `POST /guard` — request

```jsonc
{
  "chain": "ethereum | base | sepolia | base-sepolia",   // required
  "wallet": "0x…",            // optional — wallet-hygiene scan
  "token": "0x…",             // optional — rug-check this token
  "tx": {                     // optional — the pending transaction
    "to": "0x…", "value": "0", "data": "0x095ea7b3…" // value = wei as a decimal string
  }
}
```

At least one of `wallet`, `tx`, `token` is required. Malformed input → `400` with a clear error.

### `POST /guard` — response

```jsonc
{
  "verdict": "APPROVE | REVIEW | REJECT",
  "risk_score": 15,
  "chain": "ethereum",
  "checks": [
    { "name": "token-owner", "status": "warn",
      "detail": "owner() is set to 0xfcb1… — the owner may retain mint, pause or blacklist powers.",
      "score_delta": 15 }
  ],
  "explanation": "Looks safe to sign — no blocking issues found, though note: the token owner is still set (0xfcb19e6a…).",
  "evidence": {
    "block_number": 26414409,
    "rpc_calls": 7,
    "evidence_hash": "…",
    "evidence_hash_algo": "sha3-256",
    "evidence_hash_note": "SHA3-256 (NIST) … this is NOT keccak256 (Node crypto does not ship keccak)."
  },
  "signature": "…",                 // base64 ed25519 signature of signature_payload
  "signature_algo": "ed25519",
  "public_key": "…",                // base64 DER/SPKI public key
  "signature_payload": "{…}"       // exact canonical string that was signed
}
```

## Demo cases (`GET /demo/:case`)

| Case | Input | Live result (verified 2026-11-14) |
|---|---|---|
| `clean` | Plain 0.1 ETH transfer to vitalik.eth | **APPROVE**, score 0 |
| `approval` | Unlimited USDC approval to Uniswap V2 Router | **REVIEW**, score 30 (40 − 10 known protocol) |
| `honeypot` | Fake token (not a contract) + unlimited USDC approval to a fresh wallet | **REJECT**, score 100 (40 + 25 + 10 + 50, clamped) |

Demo runs live first. If the chain RPC is unreachable, it falls back to a snapshot captured
at build time (`src/demo-snapshots.json`) and the response is clearly marked `live: false`
with the capture time and block. The "honeypot" case is a deliberately labelled synthetic scam
pattern — it is **not** a claim that a specific real token is a scam; real-token honeypot
signals come from the live `/guard` token-market check.

## Run it locally

```bash
npm install
npm start            # listens on :3000 (PORT env var overrides)
npm test             # node --test, starts the server on an ephemeral port
```

No API keys, no database, no config. On first start it generates an ed25519 signing key at
`.keys/gatekeep-ed25519.json` (mode 0600, git-ignored). Delete that file and restart to rotate
the deployment key — the key identifies *this deployment*, not a person.

## Deploy

Stateless Node service, `npm install && npm start`. Needs outbound HTTPS to the public RPCs
and DexScreener (see `src/chains.js` for the endpoint list). Any free host with a public
HTTPS URL works (Render free tier, Vercel, Railway). Keep it live through judging
(22–30 Nov 2026). Free tiers that sleep are fine — the agent is request/response only,
no live dispatch.

## What Gatekeep does NOT do (honest limits)

- **No contract-source verification** — no keyless source; the README and every verdict say so.
- **No LP lock/burn or holder-concentration data** — same reason.
- **No sell simulation** — a real honeypot test needs a simulation API; the buys-with-zero-sells signal is labelled as a *signal*, not proof.
- **No external blacklist / scam-list coverage** — only a local burn-address list; the agent never claims otherwise.
- **DexScreener is rate-limited when hammered** — reads are cached 60s and a failed fetch degrades to `unknown`, never to a fake verdict.
- **Wallet hygiene is scoped**: it checks allowances to 4 well-known protocol spenders for the chain's reference tokens only. It cannot see approvals to unknown spenders without an indexer, and says so in the verdict.
- **Scores are heuristics, not a safety guarantee.** A low score means "no red flags found in the checks above", not "this token is safe".

## Project layout

```
server.js                  Express app (routes, JSON errors)
src/
  chains.js                chain + RPC + known-protocol config (with notes on dead endpoints)
  rpc.js                   keyless JSON-RPC client (5s timeout, endpoint fallback, 60s cache)
  dexscreener.js           DexScreener market data (free, no key)
  checks.js                the guard pipeline (decode, checks, scoring, explanation)
  scoring.js               the rubric (single source of truth)
  sign.js                  per-deployment ed25519 key + sign/verify
  demo.js                  3 canned demo cases
  demo-snapshots.json      build-time snapshots (offline fallback, labelled)
  util.js                  stable JSON, SHA3-256, fetch-with-timeout, TTL cache
public/index.html          landing page + demo UI (no external assets)
test/test.js               8 end-to-end tests (node --test)
scripts/capture-snapshots.js  re-capture demo snapshots from live data
```

## Credits / context

Built by the Garapan Agent Team (sheeran) for Agent Games by zkVerify, Wildcard track.
Check taxonomy reuses the team's `security-audit` and `meme-coin-audit` skills
(rug-pull kill signals: retained owner privileges, thin/honeypot liquidity, unlimited approvals).
License: MIT.
