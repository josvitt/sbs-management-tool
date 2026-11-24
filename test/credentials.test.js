'use strict';
// credentials.js at its interface: what leaves the server, what is kept on
// save, and how a request without secrets gets them back.
const test = require('node:test');
const assert = require('node:assert/strict');
const c = require('../credentials');

const stored = {
  switches: [
    { id: 'aa11', host: '10.0.0.1', target: { host: '10.0.0.1', port: 161, version: '2c', community: 'c-one' },
      ssh: { host: '10.0.0.1', port: 22, username: 'admin', password: 'pw-one' } },
    { id: 'bb22', host: '10.0.0.2', target: { host: '10.0.0.2', version: '3',
      v3: { username: 'u', authProtocol: 'sha', authKey: 'ak', privProtocol: 'aes128', privKey: 'pk' } } }
  ]
};

test('publicState removes every secret and says which ones are saved', () => {
  const out = c.publicState(stored);
  const text = JSON.stringify(out);
  for (const secret of ['c-one', 'pw-one', '"ak"', '"pk"']) assert.ok(!text.includes(secret), secret + ' leaked');
  assert.deepEqual(out.switches[0].saved, { community: true, sshPassword: true });
  assert.deepEqual(out.switches[1].saved, { authKey: true, privKey: true });
  assert.equal(out.switches[0].ssh.username, 'admin');
  assert.equal(out.switches[1].target.v3.authProtocol, 'sha');
  assert.equal(stored.switches[0].target.community, 'c-one');   // input untouched
});

test('mergeForSave keeps a stored secret the browser sent back empty', () => {
  const pub = c.publicState(stored).switches;
  const merged = c.mergeForSave(pub, stored);
  assert.equal(merged[0].target.community, 'c-one');
  assert.equal(merged[0].ssh.password, 'pw-one');
  assert.equal(merged[1].target.v3.authKey, 'ak');
  assert.equal(merged[1].target.v3.privKey, 'pk');
  assert.equal(merged[0].saved, undefined);
});

test('mergeForSave lets a newly typed secret replace the stored one', () => {
  const incoming = [{ id: 'aa11', target: { host: '10.0.0.1', version: '2c', community: 'c-new' },
    ssh: { host: '10.0.0.1', username: 'admin', password: 'pw-new' } }];
  const merged = c.mergeForSave(incoming, stored);
  assert.equal(merged[0].target.community, 'c-new');
  assert.equal(merged[0].ssh.password, 'pw-new');
});

test('mergeForSave does not carry an SSH password over to a different username', () => {
  const incoming = [{ id: 'aa11', target: { host: '10.0.0.1' }, ssh: { host: '10.0.0.1', username: 'other' } }];
  assert.equal(c.mergeForSave(incoming, stored)[0].ssh.password, undefined);
});

test('mergeForSave gives a new switch an id and an existing one keeps its id', () => {
  const merged = c.mergeForSave([{ target: { host: '10.0.0.9', community: 'x' } }, { target: { host: '10.0.0.1' } }], stored);
  assert.match(merged[0].id, /^[0-9a-f]{16}$/);
  assert.equal(merged[1].id, 'aa11');
});

test('resolveTarget fills a missing secret by ref, then by host:port; a sent one wins', () => {
  assert.equal(c.resolveTarget({ host: '10.0.0.1', version: '2c', ref: 'aa11' }, stored).community, 'c-one');
  assert.equal(c.resolveTarget({ host: '10.0.0.1', port: 161, version: '2c' }, stored).community, 'c-one');
  assert.equal(c.resolveTarget({ host: '10.0.0.1', version: '2c', community: 'typed' }, stored).community, 'typed');
  assert.equal(c.resolveTarget({ host: '10.0.0.7', version: '2c' }, stored).community, undefined);
  assert.equal(c.resolveTarget({ host: '10.0.0.1', ref: 'aa11' }, stored).ref, undefined);
  const v3 = c.resolveTarget({ host: '10.0.0.2', version: '3', v3: { username: 'u', authProtocol: 'sha', privProtocol: 'aes128' } }, stored);
  assert.equal(v3.v3.authKey, 'ak');
  assert.equal(v3.v3.privKey, 'pk');
});

test('resolveTarget with nothing saved changes nothing but the ref', () => {
  assert.deepEqual(c.resolveTarget({ host: 'h', community: 'x', ref: 'zz' }, null), { host: 'h', community: 'x' });
});

test('resolveSsh fills the password only for a matching host, port and username', () => {
  assert.equal(c.resolveSsh({ type: 'connect', host: '10.0.0.1', port: 22, username: 'admin' }, stored).password, 'pw-one');
  assert.equal(c.resolveSsh({ type: 'connect', host: '10.0.0.1', port: 22, username: 'root' }, stored).password, undefined);
  assert.equal(c.resolveSsh({ type: 'connect', host: '10.0.0.1', port: 2222, username: 'admin' }, stored).password, undefined);
  assert.equal(c.resolveSsh({ type: 'connect', host: '10.0.0.1', username: 'admin', password: 'typed' }, stored).password, 'typed');
});
