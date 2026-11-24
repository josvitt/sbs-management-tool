/**
 * Local, encrypted storage for the things the app has to remember between
 * runs: which switches you had open, and the credentials to reach them.
 *
 * What this protects against, and what it does not
 * -----------------------------------------------
 * The realistic risks for a file sitting in an app directory are the
 * boring ones: it gets copied into a backup, synced to cloud storage,
 * committed to a repository, or read over someone's shoulder. Plain text
 * loses to all of those. AES-256-GCM with a key held in a separate
 * 0600 file does not.
 *
 * It does *not* protect against someone who already has your OS account
 * and can read both files - nothing stored unattended can, because the app
 * has to start without you there to type anything. That is the trade being
 * made, and it is stated plainly rather than dressed up.
 *
 * If you want the stronger version, set SBS_PASSPHRASE. The key
 * is then derived from it with scrypt and never written to disk, so the
 * stored file is worthless without the passphrase - at the cost of having
 * to supply it whenever the app starts.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const log = require('./logger');
const rotate = require('./rotate');

const DIR = __dirname;
const STATE_FILE = path.join(DIR, 'state.enc');
const KEY_FILE = path.join(DIR, '.state-key');

const ALGORITHM = 'aes-256-gcm';
const SCRYPT_PARAMS = { N: 16384, r: 8, p: 1 };

let cachedKey = null;
let keySource = null;
// Set when the last load found a state file it could not decrypt. The UI then
// starts fresh, and its next save would otherwise overwrite the only copy:
// a service started without the right key, or a restored key file, must not
// cost every saved switch. save() moves such a file aside first.
let unreadableOnDisk = false;

/**
 * The key: derived from a passphrase when one is set, otherwise a random
 * key generated once and kept beside the data with owner-only permissions.
 */
function getKey() {
  if (cachedKey) return cachedKey;

  // SBS_PASSPHRASE is the current name; SWITCH_CONSOLE_PASSPHRASE is still
  // accepted so an existing install keeps working after the rename.
  const passphrase = process.env.SBS_PASSPHRASE || process.env.SWITCH_CONSOLE_PASSPHRASE;
  if (passphrase) {
    // A fixed salt keeps the derivation reproducible across restarts. It
    // is not secret, and does not need to be: it exists to stop the same
    // passphrase producing the same key in two different applications. The
    // literal is a key-derivation constant, NOT branding - it must never
    // change, or state encrypted under the old key can no longer be read.
    const salt = crypto.createHash('sha256').update('switch-console-v1').digest().slice(0, 16);
    cachedKey = crypto.scryptSync(passphrase, salt, 32, SCRYPT_PARAMS);
    keySource = 'passphrase';
    return cachedKey;
  }

  try {
    if (fs.existsSync(KEY_FILE)) {
      const raw = fs.readFileSync(KEY_FILE);
      if (raw.length >= 32) {
        cachedKey = raw.slice(0, 32);
        keySource = 'key file';
        return cachedKey;
      }
    }
  } catch (e) {
    log.warn('vault', 'Could not read the key file', { message: e.message });
  }

  cachedKey = crypto.randomBytes(32);
  keySource = 'key file (new)';
  try {
    // Written before anything else so a crash cannot leave data encrypted
    // under a key that was never saved.
    fs.writeFileSync(KEY_FILE, cachedKey, { mode: 0o600 });
    try { fs.chmodSync(KEY_FILE, 0o600); } catch (e) { /* Windows has no mode */ }
    log.info('vault', 'Created a new encryption key', { file: KEY_FILE });
  } catch (e) {
    log.error('vault', 'Could not write the key file; state will not persist', {
      message: e.message
    });
  }
  return cachedKey;
}

function encrypt(plainText) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGORITHM, getKey(), iv);
  const body = Buffer.concat([cipher.update(plainText, 'utf8'), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), body]);
}

function decrypt(buffer) {
  const iv = buffer.slice(0, 12);
  const tag = buffer.slice(12, 28);
  const body = buffer.slice(28);
  const decipher = crypto.createDecipheriv(ALGORITHM, getKey(), iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(body), decipher.final()]).toString('utf8');
}

function load() {
  try {
    if (!fs.existsSync(STATE_FILE)) { unreadableOnDisk = false; return null; }
    const parsed = JSON.parse(decrypt(fs.readFileSync(STATE_FILE)));
    unreadableOnDisk = false;
    log.info('vault', 'Restored saved state', {
      switches: (parsed.switches || []).length, key: keySource
    });
    return parsed;
  } catch (e) {
    // A wrong key, a truncated file, or a passphrase that has changed all
    // land here. Saying which is impossible and guessing would be worse
    // than admitting the file cannot be read.
    unreadableOnDisk = true;
    log.error('vault', 'Could not read the saved state', {
      message: e.message,
      hint: (process.env.SBS_PASSPHRASE || process.env.SWITCH_CONSOLE_PASSPHRASE)
        ? 'the passphrase may differ from the one used when it was written'
        : 'the key file may be missing or from another installation'
    });
    return { unreadable: true };
  }
}

function save(state) {
  try {
    const payload = JSON.stringify(state);
    if (unreadableOnDisk && fs.existsSync(STATE_FILE)) {
      const kept = STATE_FILE + '.unreadable-' + new Date().toISOString().replace(/[:.]/g, '-');
      fs.renameSync(STATE_FILE, kept);
      unreadableOnDisk = false;
      log.warn('vault', 'Kept the unreadable state file instead of overwriting it', { file: kept });
    }
    rotate.writeFileAtomic(STATE_FILE, encrypt(payload), { mode: 0o600 });
    return true;
  } catch (e) {
    log.error('vault', 'Could not save state', { message: e.message });
    return false;
  }
}

function clear() {
  for (const file of [STATE_FILE]) {
    try { if (fs.existsSync(file)) fs.unlinkSync(file); } catch (e) { /* nothing to do */ }
  }
  log.info('vault', 'Saved state cleared');
}

/** What the UI needs to explain how credentials are being held. */
function describe() {
  getKey();
  return {
    file: STATE_FILE,
    key: keySource,
    passphrase: !!(process.env.SBS_PASSPHRASE || process.env.SWITCH_CONSOLE_PASSPHRASE),
    stored: fs.existsSync(STATE_FILE)
  };
}

module.exports = { load, save, clear, describe };
