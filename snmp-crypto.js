/**
 * SNMPv3 authentication and privacy protocol support.
 *
 * net-snmp ships every SHA variant we need, but only AES-128 and two
 * AES-256 flavours -- there is no AES-192, which Catalyst 1200/1300
 * firmware does offer. Its algorithm table is data-driven, so AES-192 is
 * registered here rather than left as a gap in the UI.
 *
 * The wrinkle with AES-192 and AES-256 is key localisation. A localised
 * key derived from SHA-1 is 20 bytes, which is short of the 24 and 32
 * bytes those ciphers need, so the key has to be extended. Two
 * incompatible extensions are in the wild:
 *
 *   - Reeder      (used by Cisco, and so the default here)
 *   - Blumenthal  (used by several other vendors)
 *
 * They are not interoperable, and a mismatch looks exactly like a wrong
 * password, so both are offered explicitly instead of guessing.
 */

const crypto = require('crypto');
const snmp = require('net-snmp');

// Identifiers for the protocols we add. The numbers only have to be
// unique within this process; they are never sent on the wire. They are
// deliberately clear of the values net-snmp already uses (1-8) so a
// library upgrade cannot silently collide with them.
const AES192_REEDER = 192;
const AES192_BLUMENTHAL = 193;

let registered = false;

function registerExtraProtocols() {
  if (registered) return;

  // net-snmp exposes its internals through the module's exported classes;
  // if a future version reshapes them, fail loudly at startup rather than
  // producing packets the switch silently rejects.
  const Encryption = snmp.Encryption;
  if (!Encryption || !Encryption.algorithms) {
    throw new Error('This version of net-snmp does not expose Encryption.algorithms; cannot add AES-192 support.');
  }

  const base = Encryption.algorithms[snmp.PrivProtocols.aes256r];
  if (!base) throw new Error('net-snmp is missing AES support; cannot add AES-192.');

  const make = (localizationAlgorithm) => ({
    CRYPTO_ALGORITHM: 'aes-192-cfb',
    KEY_LENGTH: 24,
    BLOCK_LENGTH: 16,
    encryptPdu: Encryption.encryptPduAes,
    decryptPdu: Encryption.decryptPduAes,
    localizationAlgorithm
  });

  Encryption.algorithms[AES192_REEDER] = make(Encryption.generateLocalizedKeyReeder);
  Encryption.algorithms[AES192_BLUMENTHAL] = make(Encryption.generateLocalizedKeyBlumenthal);

  snmp.PrivProtocols[AES192_REEDER] = 'aes192r';
  snmp.PrivProtocols[AES192_BLUMENTHAL] = 'aes192b';
  snmp.PrivProtocols.aes192r = AES192_REEDER;
  snmp.PrivProtocols.aes192b = AES192_BLUMENTHAL;

  registered = true;
}

registerExtraProtocols();

// What the user picks -> what the library wants.
const AUTH = {
  none: snmp.AuthProtocols.none,
  md5: snmp.AuthProtocols.md5,
  sha: snmp.AuthProtocols.sha,
  sha1: snmp.AuthProtocols.sha,
  sha224: snmp.AuthProtocols.sha224,
  sha256: snmp.AuthProtocols.sha256,
  sha384: snmp.AuthProtocols.sha384,
  sha512: snmp.AuthProtocols.sha512
};

const PRIV = {
  none: snmp.PrivProtocols.none,
  des: snmp.PrivProtocols.des,
  aes: snmp.PrivProtocols.aes,          // AES-128
  aes128: snmp.PrivProtocols.aes,
  aes192: AES192_REEDER,                // Cisco's key extension
  aes192r: AES192_REEDER,
  aes192b: AES192_BLUMENTHAL,
  aes256: snmp.PrivProtocols.aes256r,   // Cisco's key extension
  aes256r: snmp.PrivProtocols.aes256r,
  aes256b: snmp.PrivProtocols.aes256b
};

/**
 * Is a cipher actually usable on this Node build? OpenSSL 3 drops DES
 * unless the legacy provider is loaded, and offering a method that cannot
 * possibly work is worse than not offering it -- the failure surfaces as
 * an opaque "digital envelope routines::unsupported" mid-request.
 */
function cipherAvailable(algorithm, keyLength, ivLength) {
  try {
    crypto.createCipheriv(algorithm, Buffer.alloc(keyLength), Buffer.alloc(ivLength));
    return true;
  } catch (e) {
    return false;
  }
}

const DES_AVAILABLE = cipherAvailable('des-cbc', 8, 8);

/** Menu the UI renders, so the two can never drift apart. */
const AUTH_CHOICES = [
  { value: 'none', label: 'None' },
  { value: 'md5', label: 'MD5' },
  { value: 'sha', label: 'SHA (SHA-1)' },
  { value: 'sha224', label: 'SHA-224' },
  { value: 'sha256', label: 'SHA-256' },
  { value: 'sha384', label: 'SHA-384' },
  { value: 'sha512', label: 'SHA-512' }
];

const PRIV_CHOICES = [
  { value: 'none', label: 'None' },
  { value: 'aes128', label: 'AES-128' },
  { value: 'aes192', label: 'AES-192' },
  { value: 'aes256', label: 'AES-256' },
  // Same ciphers, the other key-extension scheme. Offered separately
  // because a mismatch is indistinguishable from a wrong password.
  { value: 'aes192b', label: 'AES-192 (Blumenthal key extension)' },
  { value: 'aes256b', label: 'AES-256 (Blumenthal key extension)' }
].concat(DES_AVAILABLE ? [{ value: 'des', label: 'DES (legacy)' }] : []);

const normalise = (v, fallback) => String(v === undefined || v === null || v === '' ? fallback : v)
  .toLowerCase().replace(/[\s_-]/g, '');

function resolveAuth(name) {
  const key = normalise(name, 'none');
  const p = AUTH[key];
  if (p === undefined) {
    throw new Error('Unsupported authentication method: ' + name +
      '. Supported: ' + AUTH_CHOICES.map((c) => c.label).join(', ') + '.');
  }
  return p;
}

function resolvePriv(name) {
  const key = normalise(name, 'none');
  if (key === 'des' && !DES_AVAILABLE) {
    throw new Error('DES is not available in this Node build (OpenSSL 3 removed it from the default provider). Use AES-128 or stronger.');
  }
  const p = PRIV[key];
  if (p === undefined) {
    throw new Error('Unsupported privacy method: ' + name +
      '. Supported: ' + PRIV_CHOICES.map((c) => c.label).join(', ') + '.');
  }
  return p;
}

/**
 * The security level follows from the two choices, so it is derived rather
 * than asked for separately: picking authPriv and leaving privacy at None
 * is a contradiction the user should never have to resolve.
 */
function securityLevelFor(authName, privName) {
  const auth = normalise(authName, 'none') !== 'none';
  const priv = normalise(privName, 'none') !== 'none';
  if (!auth && priv) {
    throw new Error('Privacy requires authentication: choose an authentication method, or set privacy to None.');
  }
  if (auth && priv) return 'authPriv';
  if (auth) return 'authNoPriv';
  return 'noAuthNoPriv';
}

module.exports = {
  resolveAuth, resolvePriv, securityLevelFor,
  AUTH_CHOICES, PRIV_CHOICES, DES_AVAILABLE,
  AES192_REEDER, AES192_BLUMENTHAL
};
