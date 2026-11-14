'use strict';

/**
 * Vercel serverless entry point.
 *
 * Vercel's filesystem is read-only except /tmp, so the per-deployment
 * ed25519 signing key lives in /tmp (see src/sign.js GATEKEEP_KEY_DIR).
 * The key is per-deployment anyway: a cold start just generates a new one,
 * and every verdict publishes its own public_key, so signatures stay
 * verifiable via POST /verify.
 *
 * server.js already exports the Express app and only listens when run as
 * `node server.js`, so requiring it here is safe — no port is opened.
 */

process.env.GATEKEEP_KEY_DIR = process.env.GATEKEEP_KEY_DIR || '/tmp/.keys';

module.exports = require('../server.js');
