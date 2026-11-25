'use strict';

// The config history keeps encrypted copies of each switch's running-config.
// Like the vault it keeps its files beside itself, so it runs from a copy in
// a temp directory, in a child process, never against the real install.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const ROOT = path.join(__dirname, '..');

function run(script, extraEnv) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sbs-cfghist-'));
  for (const f of ['config-history.js', 'vault.js', 'rotate.js', 'logger.js']) {
    fs.copyFileSync(path.join(ROOT, f), path.join(dir, f));
  }
  const env = { ...process.env, ...(extraEnv || {}) };
  delete env.SBS_PASSPHRASE; delete env.SWITCH_CONSOLE_PASSPHRASE;
  const out = execFileSync(process.execPath, ['-e', script], { cwd: dir, env }).toString().trim().split('\n').pop();
  return { dir, result: JSON.parse(out) };
}

test('config history stores a new version only when the text changes', () => {
  const { dir, result } = run(`
    const h = require('./config-history.js');
    const a = h.record('10.0.0.1', 'hostname a\\n');
    const same = h.record('10.0.0.1', 'hostname a\\n');
    const b = h.record('10.0.0.1', 'hostname b\\n');
    const list = h.list('10.0.0.1');
    console.log(JSON.stringify({
      a: !!a, same, b: !!b, count: list.length,
      newestFirst: list[0].id === b.id,
      textA: h.get('10.0.0.1', a.id).text,
      textB: h.get('10.0.0.1', b.id).text
    }));`);
  assert.deepEqual(result, { a: true, same: null, b: true, count: 2, newestFirst: true,
    textA: 'hostname a\n', textB: 'hostname b\n' });
  // On disk the text is not readable.
  const files = fs.readdirSync(path.join(dir, 'config-history', '10.0.0.1'));
  assert.equal(files.length, 2);
  for (const f of files) {
    const raw = fs.readFileSync(path.join(dir, 'config-history', '10.0.0.1', f));
    assert.equal(raw.includes('hostname'), false);
  }
});

test('config history keeps only the newest N versions per switch', () => {
  const { result } = run(`
    const h = require('./config-history.js');
    for (let i = 0; i < 5; i++) h.record('sw', 'v' + i);
    console.log(JSON.stringify(h.list('sw').map((v) => h.get('sw', v.id).text)));`,
    { SBS_CONFIG_HISTORY_KEEP: '3' });
  assert.deepEqual(result, ['v4', 'v3', 'v2']);
});

test('config history refuses ids that are not its own file names', () => {
  const { result } = run(`
    const h = require('./config-history.js');
    const v = h.record('sw', 'x');
    console.log(JSON.stringify({
      own: !!h.get('sw', v.id),
      traversal: h.get('sw', '../../vault.js'),
      other: h.get('sw', 'nope'),
      unknownHost: h.list('never-seen').length
    }));`);
  assert.deepEqual(result, { own: true, traversal: null, other: null, unknownHost: 0 });
});

test('history routes list versions and return one; unknown ids are 404', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sbs-cfghist-routes-'));
  const { result } = (() => {
    const script = `
      const express = require(${JSON.stringify(require.resolve('express'))});
      const h = require(${JSON.stringify(path.join(ROOT, 'config-history.js'))});
      const app = express(); app.use(express.json());
      require(${JSON.stringify(path.join(ROOT, 'routes', 'config.js'))})(app);
      const v = h.record('10.1.1.1', 'hostname r\\n');
      const srv = app.listen(0, '127.0.0.1', async () => {
        const base = 'http://127.0.0.1:' + srv.address().port;
        const list = await (await fetch(base + '/api/config/history?host=10.1.1.1')).json();
        const one = await (await fetch(base + '/api/config/history/version?host=10.1.1.1&id=' + v.id)).json();
        const miss = (await fetch(base + '/api/config/history/version?host=10.1.1.1&id=..%2F..%2Fvault.js')).status;
        const noHost = (await fetch(base + '/api/config/history')).status;
        console.log(JSON.stringify({ n: list.versions.length, text: one.text, miss, noHost }));
        srv.close(); process.exit(0);
      });`;
    const env = { ...process.env, SBS_CONFIG_HISTORY_DIR: dir, SBS_PASSPHRASE: 'test-only passphrase' };
    const out = execFileSync(process.execPath, ['-e', script], { env }).toString().trim().split('\n').pop();
    return { result: JSON.parse(out) };
  })();
  assert.deepEqual(result, { n: 1, text: 'hostname r\n', miss: 404, noHost: 400 });
});
