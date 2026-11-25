'use strict';

/**
 * The half of self-update that runs at start-up, before anything else.
 *
 * Why at start-up: while the app runs, the native add-ons under node_modules
 * (serialport, ssh2's helpers) are loaded, and Windows will not rename a
 * folder holding a loaded file. Before server.js requires anything, nothing
 * is loaded, so the swap is a handful of renames inside one folder. server.js
 * calls run() on its first line; when run() changed the files it returns
 * RESTART and server.js exits with that code, so the service (or
 * scripts/run.js) starts the new version cleanly.
 *
 * What it does, all under updates/ (see updater.js for how a release is
 * downloaded and prepared into updates/staging/<version>/):
 *
 *   pending.json {action:'install'} - move the current app files to
 *     updates/backup/, move the staged release in. Every rename is written to
 *     updates/journal.json first, so a power cut mid-swap is undone on the
 *     next start, and any error undoes the renames made so far.
 *   pending.json {action:'rollback'} - the same swap back to the backup.
 *   applied.json, not yet confirmed - the new version has not yet stayed up
 *     for a minute (updater.confirmWhenHealthy). Each start counts; after
 *     MAX_UNCONFIRMED_BOOTS starts it is rolled back automatically.
 *
 * What it never touches: PROTECTED below - the vault (state.enc, .state-key),
 * logs, metric and config history, layouts, known SSH host keys, the Windows
 * service wrapper (daemon/) and updates/ itself. Only names that a release
 * ships (plus node_modules) are ever moved.
 *
 * Only fs/path here, and nothing that could fail to load: a broken release
 * must not be able to stop the rollback that undoes it.
 */

const fs = require('fs');
const path = require('path');

const RESTART = 75;              // exit code: "restart me" (EX_TEMPFAIL)
const MAX_UNCONFIRMED_BOOTS = 3;

// Machine-local data and things outside the app's own files. Matched against
// top-level names in the install folder and in a release alike.
const PROTECTED = new Set([
  'state.enc', '.state-key', 'logs', 'history.json', 'layouts.json',
  'known-hosts.json', 'config-history', 'updates', 'daemon', '.npm', '.git'
]);
function isProtected(name) {
  return PROTECTED.has(name) || /^state\.enc\./.test(name) || /\.tmp-/.test(name);
}

function paths(appDir) {
  const u = path.join(appDir, 'updates');
  return {
    app: appDir,
    dir: u,
    staging: path.join(u, 'staging'),
    backup: path.join(u, 'backup'),
    failed: path.join(u, 'failed'),
    pending: path.join(u, 'pending.json'),
    journal: path.join(u, 'journal.json'),
    applied: path.join(u, 'applied.json'),
    manifest: path.join(u, 'manifest.json'),
    status: path.join(u, 'status.json')
  };
}

function readJson(file) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch (e) { return null; }
}
// Same temp-fsync-rename as rotate.writeFileAtomic, inlined so this file
// depends on nothing a release can replace or break.
function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = file + '.tmp-' + process.pid;
  const fd = fs.openSync(tmp, 'w');
  try { fs.writeFileSync(fd, JSON.stringify(value, null, 2)); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  fs.renameSync(tmp, file);
}
function remove(file) { try { fs.rmSync(file, { recursive: true, force: true }); } catch (e) { /* best effort */ } }
const exists = (p) => { try { fs.lstatSync(p); return true; } catch (e) { return false; } };

// Antivirus and the search indexer briefly hold files on Windows; a rename
// that meets EPERM/EBUSY is worth a few short retries before giving up.
function sleepSync(ms) { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms); }
function renameRetry(from, to) {
  for (let i = 0; ; i++) {
    try { fs.renameSync(from, to); return; } catch (e) {
      if (i >= 9 || !/^(EPERM|EBUSY|EACCES)$/.test(e.code)) throw e;
      sleepSync(200);
    }
  }
}

/**
 * Do a list of renames as one step: journal each before it happens, undo
 * them all (newest first) if one fails. Throws the original error after the
 * undo.
 */
function moveAll(p, moves) {
  const done = [];
  const save = () => writeJson(p.journal, { at: new Date().toISOString(), done });
  try {
    for (const m of moves) {
      if (!exists(m.from)) continue;
      fs.mkdirSync(path.dirname(m.to), { recursive: true });
      done.push(m); save();
      renameRetry(m.from, m.to);
    }
  } catch (e) {
    undo(p, done);
    throw e;
  }
  remove(p.journal);
}
function undo(p, done) {
  for (const m of done.slice().reverse()) {
    if (exists(m.to) && !exists(m.from)) {
      try { renameRetry(m.to, m.from); } catch (e) { /* leave the journal for a manual look */ return; }
    }
  }
  remove(p.journal);
}

function topNames(dir) {
  try { return fs.readdirSync(dir).filter((n) => !isProtected(n)); } catch (e) { return []; }
}

// The swap itself: the names leaving go to `parkDir`, the names arriving come
// from `fromDir`. Returns what moved.
function swap(p, { fromDir, parkDir, leaving, arriving }) {
  const moves = [];
  for (const n of leaving) moves.push({ from: path.join(p.app, n), to: path.join(parkDir, n) });
  for (const n of arriving) moves.push({ from: path.join(fromDir, n), to: path.join(p.app, n) });
  moveAll(p, moves);
}

function install(p, pending, log) {
  const fromDir = path.join(p.dir, pending.staged || '');
  if (!pending.staged || !exists(path.join(fromDir, 'package.json'))) {
    throw new Error('the prepared copy of ' + pending.version + ' is missing');
  }
  const arriving = topNames(fromDir);
  const previous = readJson(p.manifest);
  // Leaving: what this release replaces, plus what the last installed release
  // shipped (so a file a release dropped goes too). Never anything else.
  const leaving = [...new Set([...arriving, ...((previous && previous.names) || [])])]
    .filter((n) => !isProtected(n) && exists(path.join(p.app, n)));
  // Only the version just before this one is kept to roll back to.
  remove(p.backup); remove(p.failed);
  const parkDir = path.join(p.backup, String(pending.from || 'previous'));
  swap(p, { fromDir, parkDir, leaving, arriving });
  writeJson(p.applied, {
    version: pending.version, from: pending.from, at: new Date().toISOString(),
    backup: path.relative(p.dir, parkDir), leaving, arriving,
    previousManifest: previous, boots: 0, confirmed: false
  });
  writeJson(p.manifest, { version: pending.version, names: arriving });
  remove(p.staging);
  log('Installed ' + pending.version + ' (was ' + pending.from + ')');
  return { kind: 'installed', version: pending.version, from: pending.from };
}

function rollback(p, applied, reason, log) {
  const parkFrom = path.join(p.dir, applied.backup || '');
  if (!applied.backup || !exists(parkFrom)) throw new Error('the backup of ' + applied.from + ' is missing');
  const failedDir = path.join(p.failed, String(applied.version));
  // Back out what the update brought in; restore what it moved aside.
  swap(p, {
    fromDir: parkFrom, parkDir: failedDir,
    leaving: (applied.arriving || []).filter((n) => !isProtected(n) && exists(path.join(p.app, n))),
    arriving: topNames(parkFrom)
  });
  remove(p.applied);
  if (applied.previousManifest) writeJson(p.manifest, applied.previousManifest); else remove(p.manifest);
  remove(p.backup);
  log('Rolled back from ' + applied.version + ' to ' + applied.from + ': ' + reason);
  return { kind: 'rolled-back', version: applied.from, from: applied.version, message: reason };
}

/**
 * Called first thing by server.js. Returns RESTART when it changed the app's
 * files (the caller exits with it), otherwise 0. Never throws: a failure is
 * written to updates/status.json for the Updates window and the current
 * version carries on.
 */
function run(opts) {
  opts = opts || {};
  const p = paths(opts.appDir || __dirname);
  const log = opts.log || ((m) => console.log('[update] ' + m));
  if (!exists(p.dir)) return 0;
  const status = (s) => { try { writeJson(p.status, Object.assign({ at: new Date().toISOString() }, s)); } catch (e) { /* best effort */ } };

  // A swap the last run did not finish (power cut, killed process): undo it.
  const journal = readJson(p.journal);
  if (journal && Array.isArray(journal.done)) {
    undo(p, journal.done);
    remove(p.pending);
    if (exists(p.journal)) {
      // A rename back failed too. Restarting would only meet it again.
      status({ kind: 'install-failed', message: 'An update was interrupted part-way and could not be fully undone; see updates/journal.json.' });
      return 0;
    }
    status({ kind: 'install-failed', message: 'An update was interrupted part-way and was undone.' });
    log('Undid an interrupted update');
    return RESTART;
  }

  const pending = readJson(p.pending);
  if (pending) {
    remove(p.pending);
    try {
      if (pending.action === 'install') {
        status(install(p, pending, log));
      } else if (pending.action === 'rollback') {
        const applied = readJson(p.applied);
        if (!applied) throw new Error('there is no earlier version to go back to');
        status(rollback(p, applied, 'you asked to go back', log));
      } else {
        return 0;
      }
    } catch (e) {
      status({ kind: pending.action === 'rollback' ? 'rollback-failed' : 'install-failed',
        version: pending.version, message: e.message });
      log('Update step failed: ' + e.message);
      remove(p.staging);
      return 0;
    }
    return RESTART;
  }

  const applied = readJson(p.applied);
  if (applied && !applied.confirmed) {
    applied.boots = (applied.boots || 0) + 1;
    if (applied.boots > MAX_UNCONFIRMED_BOOTS) {
      try {
        status(rollback(p, applied, 'version ' + applied.version + ' did not stay running', log));
      } catch (e) {
        status({ kind: 'rollback-failed', version: applied.version, message: e.message });
        return 0;
      }
      return RESTART;
    }
    writeJson(p.applied, applied);
  }
  return 0;
}

module.exports = { run, paths, readJson, writeJson, remove, isProtected, PROTECTED, RESTART, MAX_UNCONFIRMED_BOOTS };
