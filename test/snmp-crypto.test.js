'use strict';

// snmp-crypto.js adds AES-192 by reaching into net-snmp's internals, which is
// why net-snmp is pinned. These pin that the additions still work against the
// installed net-snmp, so a dependency update that reshapes them fails here
// instead of on a switch.
const test = require('node:test');
const assert = require('node:assert/strict');
const snmp = require('net-snmp');
const sc = require('../snmp-crypto');

const engine = { engineID: Buffer.from('80000009030000aabbccddee', 'hex'), engineBoots: 3, engineTime: 12345 };
const pdu = Buffer.from('a0 1c 02 04 12 34 56 78 02 01 00 02 01 00 30 0e 30 0c 06 08 2b 06 01 02 01 01 01 00 05 00'.replace(/ /g, ''), 'hex');

for (const name of ['aes192r', 'aes192b', 'aes256r', 'aes128']) {
  test('privacy ' + name + ' round-trips a PDU through net-snmp', () => {
    const priv = sc.resolvePriv(name);
    const auth = sc.resolveAuth('sha');
    const enc = snmp.Encryption.encryptPdu(priv, pdu, 'privpass123', auth, engine);
    assert.notDeepEqual(enc.encryptedPdu, pdu);
    const dec = snmp.Encryption.decryptPdu(priv, enc.encryptedPdu, enc.msgPrivacyParameters, 'privpass123', auth, engine);
    assert.deepEqual(dec, pdu);
    // The wrong password does not give the PDU back.
    const bad = snmp.Encryption.decryptPdu(priv, enc.encryptedPdu, enc.msgPrivacyParameters, 'wrongpass12', auth, engine);
    assert.notDeepEqual(bad, pdu);
  });
}

test('AES-192 keys are 24 bytes, and the two key extensions differ', () => {
  const auth = sc.resolveAuth('sha');
  const key = (name) => {
    const alg = snmp.Encryption.algorithms[sc.resolvePriv(name)];
    assert.equal(alg.CRYPTO_ALGORITHM, 'aes-192-cfb');
    return alg.localizationAlgorithm(alg, auth, 'privpass123', engine.engineID);
  };
  const r = key('aes192r'), b = key('aes192b');
  assert.equal(r.length, 24);
  assert.equal(b.length, 24);
  assert.notDeepEqual(r, b);
  // Both extend the same SHA-1 localised key, so the first 20 bytes agree.
  assert.deepEqual(r.subarray(0, 20), b.subarray(0, 20));
});
