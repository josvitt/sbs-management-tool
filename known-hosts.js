'use strict';

/**
 * SSH host keys the app has seen, so a switch is recognised the next time it
 * is connected to and an impostor is not. The ONE place host keys are
 * checked and stored (like OpenSSH's known_hosts, trust on first use):
 *
 * - first connection to host:port   the key is remembered and accepted;
 * - same key as remembered          accepted;
 * - a DIFFERENT key                 refused. The page says so and offers
 *   "Trust the new key", which replaces the remembered one (a replaced or
 *   re-keyed switch). Nothing is replaced without that explicit step.
 *
 * Keys are public, so the file (known-hosts.json, beside the app) is not a
 * secret; it is written atomically through rotate.writeFileAtomic.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const rotate = require('./rotate');

const FILE = process.env.SBS_KNOWN_HOSTS_FILE || path.join(__dirname, 'known-hosts.json');

let hosts = null;   // "host:port" -> { fingerprint, firstSeen, trustedAt }

const keyOf = (host, port) => String(host || '').trim().toLowerCase() + ':' + (Number(port) || 22);

/** OpenSSH-style fingerprint of a raw host key: "SHA256:<base64, no padding>". */
function fingerprint(keyBuffer) {
  return 'SHA256:' + crypto.createHash('sha256').update(keyBuffer).digest('base64').replace(/=+$/, '');
}

function load() {
  if (hosts) return hosts;
  hosts = new Map();
  try {
    const parsed = JSON.parse(fs.readFileSync(FILE, 'utf8'));
    for (const [k, v] of Object.entries(parsed || {})) if (v && v.fingerprint) hosts.set(k, v);
  } catch (e) { /* none yet, or unreadable: start empty */ }
  return hosts;
}

function save() {
  rotate.writeFileAtomic(FILE, JSON.stringify(Object.fromEntries(load()), null, 2));
}

/**
 * Check a presented key. Returns { result: 'new' | 'match' | 'changed',
 * fingerprint, expected? }. A 'new' key is remembered as it is checked.
 */
function check(host, port, keyBuffer) {
  const fp = fingerprint(keyBuffer);
  const k = keyOf(host, port);
  const known = load().get(k);
  if (!known) {
    load().set(k, { fingerprint: fp, firstSeen: new Date().toISOString() });
    try { save(); } catch (e) { /* still accepted; remembered in memory */ }
    return { result: 'new', fingerprint: fp };
  }
  if (known.fingerprint === fp) return { result: 'match', fingerprint: fp };
  return { result: 'changed', fingerprint: fp, expected: known.fingerprint };
}

/** The user's explicit "trust the new key": replace what is remembered. */
function trust(host, port, fp) {
  if (!/^SHA256:[A-Za-z0-9+/]{43}$/.test(String(fp || ''))) throw new Error('Not a SHA256 host-key fingerprint.');
  const k = keyOf(host, port);
  const prior = load().get(k);
  load().set(k, { fingerprint: fp, firstSeen: (prior && prior.firstSeen) || new Date().toISOString(), trustedAt: new Date().toISOString() });
  save();
}

module.exports = { check, trust, fingerprint, FILE };
