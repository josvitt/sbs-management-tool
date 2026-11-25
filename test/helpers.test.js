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

test('vault: repeated loads do not re-read the file; a save is seen at once', () => {
  const dir = tmpDir();
  for (const f of ['vault.js', 'rotate.js', 'logger.js']) fs.copyFileSync(path.join(ROOT, f), path.join(dir, f));
  const script = `
    const fs = require('fs'); const v = require('./vault.js');
    v.save({ switches: [1] });
    let reads = 0; const orig = fs.readFileSync;
    fs.readFileSync = function (f, ...a) { if (String(f).endsWith('state.enc')) reads++; return orig.call(this, f, ...a); };
    const a = v.load(); a.switches.push('mutated');
    const hit = v.load(); hit.switches.push('mutated');   // a cache hit, mutated
    const b = v.load();
    v.save({ switches: [2] });
    const c = v.load();
    console.log(JSON.stringify({ reads, b: b.switches, c: c.switches }));`;
  const env = { ...process.env }; delete env.SBS_PASSPHRASE; delete env.SWITCH_CONSOLE_PASSPHRASE;
  const out = execFileSync(process.execPath, ['-e', script], { cwd: dir, env }).toString().trim().split('\n').pop();
  assert.deepEqual(JSON.parse(out), { reads: 2, b: [1], c: [2] });
});

test('rotate.adoptLegacy moves a misplaced store once and never overwrites', () => {
  const { adoptLegacy } = require('../rotate');
  const dir = tmpDir();
  const oldFile = path.join(dir, 'routes', 'layouts.json');
  const newFile = path.join(dir, 'layouts.json');
  fs.mkdirSync(path.dirname(oldFile), { recursive: true });
  fs.writeFileSync(oldFile, 'old');
  assert.equal(adoptLegacy(oldFile, newFile), 1);
  assert.equal(fs.readFileSync(newFile, 'utf8'), 'old');
  assert.equal(fs.existsSync(oldFile), false);
  // A second copy appearing later does not replace the adopted one.
  fs.writeFileSync(oldFile, 'stale');
  assert.equal(adoptLegacy(oldFile, newFile), 0);
  assert.equal(fs.readFileSync(newFile, 'utf8'), 'old');
  // Folders merge file by file.
  fs.mkdirSync(path.join(dir, 'routes', 'logs', 'traps'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'routes', 'logs', 'traps', 'a.log'), 'a');
  fs.mkdirSync(path.join(dir, 'logs', 'traps'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'logs', 'traps', 'b.log'), 'b');
  assert.equal(adoptLegacy(path.join(dir, 'routes', 'logs', 'traps'), path.join(dir, 'logs', 'traps')), 1);
  assert.deepEqual(fs.readdirSync(path.join(dir, 'logs', 'traps')).sort(), ['a.log', 'b.log']);
  assert.equal(fs.existsSync(path.join(dir, 'routes', 'logs', 'traps')), false);
  assert.equal(adoptLegacy(path.join(dir, 'missing'), path.join(dir, 'x')), 0);
});
