'use strict';

/**
 * Verdict signing (cheap verifiability layer).
 *
 * On first start the agent generates an ed25519 keypair and stores it in
 * `.keys/gatekeep-ed25519.json` (mode 0600, git-ignored). The key is
 * PER-DEPLOYMENT: it proves "this deployment produced this verdict", it is
 * NOT an identity claim about a person or organisation, and rotating it
 * (delete the file, restart) just creates a new deployment key.
 *
 * The verifier needs three fields from the /guard response:
 *   signature_payload — the exact canonical string that was signed
 *   signature         — base64 ed25519 signature of that string
 *   public_key        — base64 DER/SPKI public key
 * plus POST /verify, which checks a (payload, signature, public_key) triple.
 */

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const KEY_DIR = process.env.GATEKEEP_KEY_DIR || path.join(__dirname, '..', '.keys');
const KEY_FILE = path.join(KEY_DIR, 'gatekeep-ed25519.json');

let keypair = null;

function loadOrCreateKeypair() {
  if (keypair) return keypair;
  try {
    const raw = fs.readFileSync(KEY_FILE, 'utf8');
    const saved = JSON.parse(raw);
    keypair = {
      publicKey: crypto.createPublicKey(saved.publicKeyPem),
      privateKey: crypto.createPrivateKey(saved.privateKeyPem),
      publicKeyPem: saved.publicKeyPem,
    };
    return keypair;
  } catch {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });
    const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
    fs.mkdirSync(KEY_DIR, { recursive: true });
    fs.writeFileSync(KEY_FILE, JSON.stringify({ publicKeyPem, privateKeyPem }, null, 2), { mode: 0o600 });
    keypair = { publicKey, privateKey, publicKeyPem };
    return keypair;
  }
}

/** Base64 DER/SPKI public key (the value published in every verdict). */
function getPublicKeyB64() {
  const kp = loadOrCreateKeypair();
  return kp.publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
}

/** Sign a string; returns base64 signature. */
function signString(text) {
  const kp = loadOrCreateKeypair();
  return crypto.sign(null, Buffer.from(text, 'utf8'), kp.privateKey).toString('base64');
}

/** Verify (payload, signatureB64, publicKeyB64) — true/false, never throws. */
function verifyString(text, signatureB64, publicKeyB64) {
  try {
    const publicKey = crypto.createPublicKey({ key: Buffer.from(publicKeyB64, 'base64'), format: 'der', type: 'spki' });
    return crypto.verify(null, Buffer.from(text, 'utf8'), publicKey, Buffer.from(signatureB64, 'base64'));
  } catch {
    return false;
  }
}

module.exports = { loadOrCreateKeypair, getPublicKeyB64, signString, verifyString };
