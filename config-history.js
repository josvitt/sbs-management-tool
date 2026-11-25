'use strict';

/**
 * Config history: an encrypted copy of each switch's running-config every
 * time its content changes, so an operator can see what a switch looked like
 * before a change and compare it with what it runs now.
 *
 * Copies are made when the collector's change detection pulls the config
 * (collector.maybeConfigDiff, which takes a baseline on first sight) and when
 * the operator fetches the running-config by hand. A copy whose text matches
 * the newest stored one is not stored again.
 *
 * Storage is one file per version under config-history/<host>/, named
 * <time>-<hash>.enc, written atomically through rotate.writeFileAtomic and
 * encrypted with the vault's key (a running-config holds community strings
 * and password hashes). Only the newest SBS_CONFIG_HISTORY_KEEP versions per
 * switch are kept (default 50). SBS_CONFIG_HISTORY_DIR moves the folder.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const vault = require('./vault');
const rotate = require('./rotate');
const log = require('./logger');

// SBS_CONFIG_HISTORY_DIR moves it (as SBS_KNOWN_HOSTS_FILE does for known-hosts).
const DIR = process.env.SBS_CONFIG_HISTORY_DIR || path.join(__dirname, 'config-history');
const ID_RE = /^\d{8}T\d{9}Z-[0-9a-f]{12}$/;

function keep() {
  const n = Number(process.env.SBS_CONFIG_HISTORY_KEEP);
  return Number.isInteger(n) && n > 0 ? n : 50;
}

// Same rule as events.js: the host as the operator knows it, made file-safe.
function dirFor(host) {
  return path.join(DIR, String(host || 'unknown').replace(/[^A-Za-z0-9._-]/g, '_'));
}

function stamp(d) {
  return d.toISOString().replace(/[-:]/g, '').replace('.', '');   // 20261125T104512123Z
}

function ids(host) {
  let names;
  try { names = fs.readdirSync(dirFor(host)); } catch (e) { return []; }
  return names.filter((f) => f.endsWith('.enc')).map((f) => f.slice(0, -4))
    .filter((id) => ID_RE.test(id)).sort().reverse();   // newest first
}

function describeId(id) {
  const t = id.slice(0, 18);
  const at = `${t.slice(0, 4)}-${t.slice(4, 6)}-${t.slice(6, 8)}T${t.slice(9, 11)}:${t.slice(11, 13)}:${t.slice(13, 15)}.${t.slice(15, 18)}Z`;
  return { id, at, hash: id.slice(20) };
}

/** Versions for a host, newest first: [{ id, at, hash }]. */
function list(host) {
  return ids(host).map(describeId);
}

/** One version's text, or null when the id is not one of this host's versions. */
function get(host, id) {
  if (!ID_RE.test(String(id)) || !ids(host).includes(id)) return null;
  try {
    const text = vault.decrypt(fs.readFileSync(path.join(dirFor(host), id + '.enc')));
    return Object.assign(describeId(id), { text });
  } catch (e) {
    log.error('config-history', 'Could not read a stored config version', { host, id, message: e.message });
    return null;
  }
}

/**
 * Store `text` as the host's newest version unless it matches the current
 * newest. Returns the stored { id, at, hash }, or null when nothing changed.
 */
function record(host, text) {
  if (text == null) return null;
  const body = String(text);
  const hash = crypto.createHash('sha256').update(body).digest('hex').slice(0, 12);
  const existing = ids(host);
  if (existing.length && existing[0].endsWith('-' + hash)) return null;

  const id = stamp(new Date()) + '-' + hash;
  const dir = dirFor(host);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  rotate.writeFileAtomic(path.join(dir, id + '.enc'), vault.encrypt(body), { mode: 0o600 });

  for (const old of [id, ...existing].sort().reverse().slice(keep())) {
    try { fs.unlinkSync(path.join(dir, old + '.enc')); } catch (e) { /* already gone */ }
  }
  log.info('config-history', 'Stored a running-config version', { host, id, bytes: body.length });
  return describeId(id);
}

module.exports = { record, list, get };
