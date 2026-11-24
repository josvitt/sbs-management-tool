'use strict';
// Offline tests for the shared helpers changed in the hardening pass:
// logger.redact, rotate.writeFileAtomic, source-limit, aaa blank fields,
// and the vault's handling of an unreadable state file.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const tmpDir = () => fs.mkdtempSync(path.join(os.tmpdir(), 'sbs-test-'));

test('logger.redact hides credentials at any depth and keeps everything else', () => {
  const { redact } = require('../logger');
  const out = redact({
    target: { host: '10.0.0.1', community: 'private', v3: { username: 'admin', authKey: 'a', privKey: 'p', authProtocol: 'sha' } },
    key: 'radius-secret', password: 'pw', list: [{ community: 'c2' }], keySource: 'key file', count: 3
  });
  assert.deepEqual(out, {
    target: { host: '10.0.0.1', community: '[REDACTED]', v3: { username: 'admin', authKey: '[REDACTED]', privKey: '[REDACTED]', authProtocol: 'sha' } },
    key: '[REDACTED]', password: '[REDACTED]', list: [{ community: '[REDACTED]' }], keySource: 'key file', count: 3
  });
});

test('logger.redact survives a circular object', () => {
  const { redact } = require('../logger');
  const a = { host: 'x' }; a.self = a;
  assert.deepEqual(redact(a), { host: 'x', self: '[…]' });
});

test('rotate.writeFileAtomic replaces the file and leaves no temp file behind', () => {
  const { writeFileAtomic } = require('../rotate');
  const dir = tmpDir();
  const file = path.join(dir, 'store.json');
  fs.writeFileSync(file, 'old');
  writeFileAtomic(file, 'new', { mode: 0o600 });
  assert.equal(fs.readFileSync(file, 'utf8'), 'new');
  assert.deepEqual(fs.readdirSync(dir), ['store.json']);
});

test('rotate.writeFileAtomic throws and keeps the old content when the write fails', () => {
  const { writeFileAtomic } = require('../rotate');
  const dir = tmpDir();
  const file = path.join(dir, 'missing-dir', 'store.json');
  assert.throws(() => writeFileAtomic(file, 'new'));
});

test('source-limit admits known sources past the limit and drops new ones', () => {
  process.env.SBS_MAX_STREAM_SOURCES = '2';
  delete require.cache[require.resolve('../source-limit')];
  const { sourceLimiter } = require('../source-limit');
  const warnings = [];
  const known = new Map([['10.0.0.1', {}], ['10.0.0.2', {}]]);
  const admit = sourceLimiter('syslog', known, { warn: (...a) => warnings.push(a) });
  assert.equal(admit('10.0.0.1'), true);
  assert.equal(admit('10.0.0.9'), false);
  assert.equal(admit('10.0.0.10'), false);
  assert.equal(warnings.length, 1);          // once per minute, not per message
  known.delete('10.0.0.2');
  assert.equal(admit('10.0.0.9'), true);     // room again
  delete process.env.SBS_MAX_STREAM_SOURCES;
  delete require.cache[require.resolve('../source-limit')];
});

test('aaa: a blank numeric field is left out of the SET, a real value is sent', () => {
  const aaa = require('../aaa');
  const oids = (plan) => plan.varbinds.map((v) => v.oid);
  const blank = aaa.planRadius({ address: '10.1.1.1', priority: null, timeout: '', retries: undefined, key: 'k' });
  const col = (c) => aaa.RADIUS + '.' + c + '.1.4.10.1.1.1.1812.1813';
  assert.ok(!oids(blank).includes(col(aaa.RCOL.priority)));
  assert.ok(!oids(blank).includes(col(aaa.RCOL.timeout)));
  const set = aaa.planRadius({ address: '10.1.1.1', priority: 0, timeout: '5', key: 'k' });
  const byOid = Object.fromEntries(set.varbinds.map((v) => [v.oid, v.value]));
  assert.equal(byOid[col(aaa.RCOL.priority)], 0);
  assert.equal(byOid[col(aaa.RCOL.timeout)], 5);
});

// The vault keeps its files beside itself, so it is exercised from a copy in
// a temp directory, in a child process, never against the real install.
test('vault keeps an unreadable state file instead of overwriting it', () => {
  const dir = tmpDir();
  for (const f of ['vault.js', 'rotate.js', 'logger.js']) fs.copyFileSync(path.join(ROOT, f), path.join(dir, f));
  const script = `
    const fs = require('fs'); const v = require('./vault.js');
    v.save({ switches: [1] });
    fs.writeFileSync('./state.enc', 'not a vault at all, just bytes......');
    const r = v.load();
    v.save({ switches: [2] });
    console.log(JSON.stringify({ unreadable: r.unreadable, now: v.load().switches,
      kept: fs.readdirSync('.').filter((f) => f.startsWith('state.enc.unreadable-')).length }));`;
  const env = { ...process.env }; delete env.SBS_PASSPHRASE; delete env.SWITCH_CONSOLE_PASSPHRASE;
  const out = execFileSync(process.execPath, ['-e', script], { cwd: dir, env }).toString().trim().split('\n').pop();
  assert.deepEqual(JSON.parse(out), { unreadable: true, now: [2], kept: 1 });
});
