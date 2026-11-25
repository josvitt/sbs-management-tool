'use strict';
// Offline tests for self-update: the archive reader (targz.js), the swap and
// rollback at start-up (update-boot.js), and the check/prepare half
// (updater.js) with GitHub, npm and the vault replaced by stand-ins.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const zlib = require('zlib');
const http = require('http');

const boot = require('../update-boot');
const { extractTarGz } = require('../targz');
const updaterMod = require('../updater');

const tmpDir = () => fs.mkdtempSync(path.join(os.tmpdir(), 'sbs-update-'));
const write = (file, text) => { fs.mkdirSync(path.dirname(file), { recursive: true }); fs.writeFileSync(file, text); };
const read = (file) => fs.readFileSync(file, 'utf8');
const quiet = () => {};

// ---- a minimal tar writer, so the tests need no tar program ----
function tarHeader(name, size, type, extra) {
  const h = Buffer.alloc(512);
  h.write(name.slice(0, 100), 0);
  h.write('0000644\0', 100); h.write('0000000\0', 108); h.write('0000000\0', 116);
  h.write(size.toString(8).padStart(11, '0') + '\0', 124);
  h.write('00000000000\0', 136);
  h.write('        ', 148);
  h.write(type, 156);
  if (extra && extra.link) h.write(extra.link, 157);
  h.write('ustar\0', 257); h.write('00', 263);
  if (extra && extra.prefix) h.write(extra.prefix, 345);
  let sum = 0; for (const b of h) sum += b;
  h.write(sum.toString(8).padStart(6, '0') + '\0 ', 148);
  return h;
}
const pad = (buf) => Buffer.concat([buf, Buffer.alloc((512 - (buf.length % 512)) % 512)]);
function makeTarGz(entries) {
  const parts = [];
  for (const e of entries) {
    if (e.pax) {
      const rec = ' path=' + e.pax + '\n';
      let len = rec.length + 3; len = String(len).length + rec.length;
      const body = Buffer.from(len + rec);
      parts.push(tarHeader('PaxHeader', body.length, 'x'), pad(body));
    }
    const data = Buffer.from(e.data || '');
    parts.push(tarHeader(e.name, e.type === '5' || e.type === '2' ? 0 : data.length, e.type || '0', e));
    if (e.type !== '5' && e.type !== '2') parts.push(pad(data));
  }
  parts.push(Buffer.alloc(1024));
  return zlib.gzipSync(Buffer.concat(parts));
}

// A release archive the way GitHub serves it: everything under one folder.
function releaseArchive(version, extra) {
  const top = 'josvitt-sbs-management-tool-abc1234/';
  return makeTarGz([
    { name: top, type: '5' },
    { name: top + 'package.json', data: JSON.stringify({ name: 'sbs-management-tool', version }) },
    { name: top + 'package-lock.json', data: '{}' },
    { name: top + 'server.js', data: '// v' + version },
    { name: top + 'scripts/self-check.js', data: '' },
    ...(extra || [])
  ]);
}

// ---- targz ----

test('targz unpacks a GitHub-style archive, stripping its top folder', () => {
  const dir = tmpDir();
  const long = 'a/' + 'deep/'.repeat(30) + 'file.txt';
  const gz = makeTarGz([
    { name: 'top/', type: '5' },
    { name: 'top/readme.md', data: 'hello' },
    { name: 'ignored-name', pax: 'top/' + long, data: 'long path' },
    { name: 'mid/file.js', prefix: 'top/public', data: 'prefixed' },
    { name: 'top/link', type: '2', link: '/etc/passwd' }
  ]);
  const out = extractTarGz(gz, dir, { strip: 1 });
  assert.equal(read(path.join(dir, 'readme.md')), 'hello');
  assert.equal(read(path.join(dir, long)), 'long path');
  assert.equal(read(path.join(dir, 'public', 'mid', 'file.js')), 'prefixed');
  assert.equal(fs.existsSync(path.join(dir, 'link')), false);
  assert.equal(out.skipped, 1);
});

test('targz refuses an entry that climbs out of the folder', () => {
  const dir = tmpDir();
  for (const bad of ['top/../../escape.txt', '/abs/file', 'top/..\\x', 'C:/x']) {
    assert.throws(() => extractTarGz(makeTarGz([{ name: bad, data: 'x' }]), path.join(dir, 'out'), { strip: 1 }), /unsafe path/);
  }
  assert.equal(fs.existsSync(path.join(dir, 'escape.txt')), false);
});

// ---- update-boot: the swap ----

// An installed app at version 1.0.0 with every kind of data an update must keep.
function installedApp() {
  const app = tmpDir();
  write(path.join(app, 'package.json'), JSON.stringify({ version: '1.0.0' }));
  write(path.join(app, 'server.js'), '// v1.0.0');
  write(path.join(app, 'old-only.js'), 'dropped in 2.0.0');
  write(path.join(app, 'node_modules', 'dep', 'index.js'), 'dep v1');
  const keep = {
    'state.enc': 'vault', '.state-key': 'key', 'history.json': '{}', 'layouts.json': '{}',
    'known-hosts.json': '{}', 'logs/app.log': 'log', 'logs/events/10.0.0.1.log': 'event',
    'config-history/10.0.0.1/x.enc': 'cfg', 'daemon/sbsmanagementtool.exe': 'winsw',
    'state.enc.unreadable-123': 'old vault'
  };
  for (const [f, t] of Object.entries(keep)) write(path.join(app, f), t);
  return { app, keep };
}
function stage(app, version, files) {
  const dir = path.join(app, 'updates', 'staging', version);
  write(path.join(dir, 'package.json'), JSON.stringify({ version }));
  write(path.join(dir, 'server.js'), '// v' + version);
  write(path.join(dir, 'node_modules', 'dep', 'index.js'), 'dep v' + version);
  for (const [f, t] of Object.entries(files || {})) write(path.join(dir, f), t);
  boot.writeJson(path.join(app, 'updates', 'pending.json'),
    { action: 'install', version, from: '1.0.0', staged: 'staging/' + version });
}
function assertKept(app, keep) {
  for (const [f, t] of Object.entries(keep)) assert.equal(read(path.join(app, f)), t, f + ' must be untouched');
}

test('with no updates folder, start-up does nothing', () => {
  const { app } = installedApp();
  assert.equal(boot.run({ appDir: app, log: quiet }), 0);
});

test('a prepared update is swapped in at start-up and every data file is kept', () => {
  const { app, keep } = installedApp();
  stage(app, '2.0.0', { 'state.enc': 'a release must never bring this' });
  assert.equal(boot.run({ appDir: app, log: quiet }), boot.RESTART);
  assert.equal(read(path.join(app, 'server.js')), '// v2.0.0');
  assert.equal(read(path.join(app, 'node_modules', 'dep', 'index.js')), 'dep v2.0.0');
  assertKept(app, keep);
  // The old version is parked whole, to go back to.
  assert.equal(read(path.join(app, 'updates', 'backup', '1.0.0', 'server.js')), '// v1.0.0');
  assert.equal(read(path.join(app, 'updates', 'backup', '1.0.0', 'node_modules', 'dep', 'index.js')), 'dep v1');
  const applied = boot.readJson(path.join(app, 'updates', 'applied.json'));
  assert.equal(applied.version, '2.0.0'); assert.equal(applied.confirmed, false);
  assert.equal(boot.readJson(path.join(app, 'updates', 'status.json')).kind, 'installed');
  assert.equal(fs.existsSync(path.join(app, 'updates', 'pending.json')), false);
  assert.equal(fs.existsSync(path.join(app, 'updates', 'staging')), false);
  // The next start (the new version) just counts the boot.
  assert.equal(boot.run({ appDir: app, log: quiet }), 0);
});

test('a version that keeps failing to start is rolled back by itself', () => {
  const { app, keep } = installedApp();
  stage(app, '2.0.0');
  boot.run({ appDir: app, log: quiet });
  for (let i = 0; i < boot.MAX_UNCONFIRMED_BOOTS; i++) assert.equal(boot.run({ appDir: app, log: quiet }), 0);
  assert.equal(boot.run({ appDir: app, log: quiet }), boot.RESTART);
  assert.equal(read(path.join(app, 'server.js')), '// v1.0.0');
  assert.equal(read(path.join(app, 'old-only.js')), 'dropped in 2.0.0');
  assert.equal(read(path.join(app, 'node_modules', 'dep', 'index.js')), 'dep v1');
  assertKept(app, keep);
  const st = boot.readJson(path.join(app, 'updates', 'status.json'));
  assert.equal(st.kind, 'rolled-back'); assert.equal(st.version, '1.0.0');
  assert.equal(fs.existsSync(path.join(app, 'updates', 'applied.json')), false);
  assert.equal(boot.run({ appDir: app, log: quiet }), 0);
});

test('a confirmed version stays, and going back on request restores the old one', () => {
  const { app, keep } = installedApp();
  stage(app, '2.0.0');
  boot.run({ appDir: app, log: quiet });
  const appliedFile = path.join(app, 'updates', 'applied.json');
  const a = boot.readJson(appliedFile); a.confirmed = true; boot.writeJson(appliedFile, a);
  for (let i = 0; i < 6; i++) assert.equal(boot.run({ appDir: app, log: quiet }), 0);
  assert.equal(read(path.join(app, 'server.js')), '// v2.0.0');
  boot.writeJson(path.join(app, 'updates', 'pending.json'), { action: 'rollback' });
  assert.equal(boot.run({ appDir: app, log: quiet }), boot.RESTART);
  assert.equal(read(path.join(app, 'server.js')), '// v1.0.0');
  assertKept(app, keep);
});

test('a file a release dropped is removed by the next update', () => {
  const { app } = installedApp();
  stage(app, '2.0.0', { 'extra.js': 'only in 2' });
  boot.run({ appDir: app, log: quiet });
  stage(app, '3.0.0');
  boot.readJson(path.join(app, 'updates', 'pending.json'));
  boot.writeJson(path.join(app, 'updates', 'pending.json'), { action: 'install', version: '3.0.0', from: '2.0.0', staged: 'staging/3.0.0' });
  assert.equal(boot.run({ appDir: app, log: quiet }), boot.RESTART);
  assert.equal(fs.existsSync(path.join(app, 'extra.js')), false);
  assert.equal(read(path.join(app, 'updates', 'backup', '2.0.0', 'extra.js')), 'only in 2');
});

test('a missing prepared copy leaves the app as it was and says why', () => {
  const { app, keep } = installedApp();
  boot.writeJson(path.join(app, 'updates', 'pending.json'), { action: 'install', version: '2.0.0', from: '1.0.0', staged: 'staging/2.0.0' });
  assert.equal(boot.run({ appDir: app, log: quiet }), 0);
  assert.equal(read(path.join(app, 'server.js')), '// v1.0.0');
  assertKept(app, keep);
  const st = boot.readJson(path.join(app, 'updates', 'status.json'));
  assert.equal(st.kind, 'install-failed'); assert.match(st.message, /missing/);
});

test('a swap cut off part-way (power cut) is undone at the next start', () => {
  const { app, keep } = installedApp();
  // As if the process died after moving server.js aside and before the rest.
  const parked = path.join(app, 'updates', 'backup', '1.0.0', 'server.js');
  fs.mkdirSync(path.dirname(parked), { recursive: true });
  fs.renameSync(path.join(app, 'server.js'), parked);
  boot.writeJson(path.join(app, 'updates', 'journal.json'), { done: [{ from: path.join(app, 'server.js'), to: parked }] });
  assert.equal(boot.run({ appDir: app, log: quiet }), boot.RESTART);
  assert.equal(read(path.join(app, 'server.js')), '// v1.0.0');
  assert.equal(fs.existsSync(path.join(app, 'updates', 'journal.json')), false);
  assert.equal(boot.readJson(path.join(app, 'updates', 'status.json')).kind, 'install-failed');
  assertKept(app, keep);
});

// ---- updater: check and prepare ----

function fakeResponse(status, body, headers) {
  const buf = Buffer.isBuffer(body) ? body : Buffer.from(typeof body === 'string' ? body : JSON.stringify(body || {}));
  const h = new Map(Object.entries(headers || {}));
  return {
    ok: status >= 200 && status < 300, status,
    headers: { get: (k) => h.get(k.toLowerCase()) || null },
    json: async () => JSON.parse(buf.toString()),
    arrayBuffer: async () => buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.length)
  };
}
// Reversible stand-in for the vault, so no real key file is created.
const fakeVault = {
  encrypt: (t) => Buffer.from(t, 'utf8').reverse(),
  decrypt: (b) => Buffer.from(b).reverse().toString('utf8')
};

function makeUpdater(app, routes, extra) {
  const calls = [];
  const u = updaterMod.create(Object.assign({
    appDir: app, vault: fakeVault, log: { info() {}, warn() {}, error() {} },
    fetch: async (url, opts) => {
      calls.push({ url, auth: opts && opts.headers && opts.headers.Authorization });
      for (const [re, fn] of routes) if (re.test(url)) return fn(url, opts);
      return fakeResponse(404, {});
    },
    run: async (cmd, args) => (args.join(' ').includes('self-check') ? 'self-check ok (40 modules)' : ''),
    restart: () => calls.push({ restart: true })
  }, extra || {}));
  return { u, calls };
}
const releaseRoute = (version) => [/\/releases\/latest$/, () => fakeResponse(200, {
  tag_name: 'v' + version, name: 'v' + version, body: 'Notes for ' + version,
  published_at: '2026-11-24T10:00:00Z', html_url: 'https://github.com/x/y/releases/tag/v' + version
})];

test('a private repository with no token gets a plain explanation', async () => {
  const { app } = installedApp();
  const { u } = makeUpdater(app, []);
  const st = await u.check();
  assert.equal(st.available, false);
  assert.match(st.checkError, /private: add a read-only token/);
});

test('a newer release is offered; the token is used for GitHub but never shown', async () => {
  const { app } = installedApp();
  const { u, calls } = makeUpdater(app, [releaseRoute('1.2.0')]);
  u.saveToken('github_pat_' + 'A'.repeat(40));
  const raw = fs.readFileSync(path.join(app, 'updates', 'token.enc'));
  assert.equal(raw.includes(Buffer.from('github_pat_')), false, 'the token is stored encrypted');
  const st = await u.check();
  assert.equal(st.available, true);
  assert.equal(st.latest.version, '1.2.0');
  assert.equal(st.latest.notes, 'Notes for 1.2.0');
  assert.deepEqual(st.token, { set: true, source: 'saved' });
  assert.doesNotMatch(JSON.stringify(st), /github_pat_/);
  assert.equal(calls[0].auth, 'Bearer github_pat_' + 'A'.repeat(40));
  // A later failed check keeps showing the release it already found.
  const offline = makeUpdater(app, [[/releases\/latest$/, () => fakeResponse(500, {})]]).u;
  const again = await offline.check();
  assert.match(again.checkError, /HTTP 500/);
  assert.equal(again.available, true);
  assert.throws(() => u.saveToken('not a token!'), /does not look like/);
});

test('the same or an older release is not offered', async () => {
  const { app } = installedApp();
  for (const v of ['1.0.0', '0.9.9']) {
    const { u } = makeUpdater(app, [releaseRoute(v)]);
    assert.equal((await u.check()).available, false);
  }
  const { u } = makeUpdater(app, []);
  assert.equal(u.isNewer('1.10.0', '1.9.9'), true);
  assert.equal(u.isNewer('2.0.0', 'garbage'), false);
});

test('install downloads, prepares and checks the release, then asks for a restart', async () => {
  const { app, keep } = installedApp();
  const archive = releaseArchive('1.2.0');
  const { u, calls } = makeUpdater(app, [
    releaseRoute('1.2.0'),
    [/\/tarball\/v1\.2\.0$/, () => fakeResponse(302, '', { location: 'https://codeload.github.com/x/y/legacy.tar.gz/v1.2.0?token=t' })],
    [/^https:\/\/codeload\.github\.com\//, () => fakeResponse(200, archive)]
  ]);
  u.saveToken('github_pat_' + 'B'.repeat(40));
  await u.check();
  await u.install();
  await new Promise((r) => setTimeout(r, 400));
  assert.ok(calls.some((c) => c.restart), 'restart requested');
  // The token goes to the API, never to the download host.
  assert.equal(calls.find((c) => /codeload/.test(c.url)).auth, undefined);
  const pending = boot.readJson(path.join(app, 'updates', 'pending.json'));
  assert.equal(pending.version, '1.2.0'); assert.equal(pending.from, '1.0.0');
  assert.equal(read(path.join(app, 'updates', pending.staged, 'server.js')), '// v1.2.0');
  // Nothing in the running app has changed yet.
  assert.equal(read(path.join(app, 'server.js')), '// v1.0.0');
  assertKept(app, keep);
  // And the start-up half finishes it.
  assert.equal(boot.run({ appDir: app, log: quiet }), boot.RESTART);
  assert.equal(read(path.join(app, 'server.js')), '// v1.2.0');
  assertKept(app, keep);
});

test('a failed preparation leaves nothing behind and nothing pending', async () => {
  const { app } = installedApp();
  const wrongVersion = releaseArchive('9.9.9');
  const routes = [
    releaseRoute('1.2.0'),
    [/\/tarball\//, () => fakeResponse(302, '', { location: 'https://codeload.github.com/x' })],
    [/^https:\/\/codeload/, () => fakeResponse(200, wrongVersion)]
  ];
  const { u } = makeUpdater(app, routes);
  await u.check();
  await assert.rejects(u.install(), /says version 9\.9\.9/);
  assert.equal(fs.existsSync(path.join(app, 'updates', 'pending.json')), false);
  assert.equal(fs.existsSync(path.join(app, 'updates', 'staging')), false);
  assert.equal(u.status().phase, 'idle');
  assert.match(u.status().phaseError, /9\.9\.9/);

  // npm failing, or the new version failing its start-up check, also stops it.
  const good = releaseArchive('1.2.0');
  routes[2] = [/^https:\/\/codeload/, () => fakeResponse(200, good)];
  const failing = makeUpdater(app, routes, { run: async () => { throw new Error('self-check failed: web.js: boom'); } }).u;
  await failing.check();
  await assert.rejects(failing.install(), /boom/);
  assert.equal(fs.existsSync(path.join(app, 'updates', 'pending.json')), false);
});

test('a download redirected off GitHub is refused', async () => {
  const { app } = installedApp();
  const { u } = makeUpdater(app, [
    releaseRoute('1.2.0'),
    [/\/tarball\//, () => fakeResponse(302, '', { location: 'https://evil.example/x.tar.gz' })]
  ]);
  await u.check();
  await assert.rejects(u.install(), /somewhere unexpected/);
});

test('install with nothing newer is refused', async () => {
  const { app } = installedApp();
  const { u } = makeUpdater(app, [releaseRoute('1.0.0')]);
  await u.check();
  await assert.rejects(u.install(), /no newer version/);
});

test('the new version is marked good only after it has stayed up', async () => {
  const { app } = installedApp();
  stage(app, '2.0.0');
  boot.run({ appDir: app, log: quiet });
  const { u } = makeUpdater(app, [], { confirmAfterMs: 20 });
  assert.equal(u.status().previous.confirmed, false);
  u.confirmWhenHealthy();
  await new Promise((r) => setTimeout(r, 60));
  // package.json in the app is still 1.0.0 in this fixture (the stand-in
  // release has its own), so make it the installed version first.
  write(path.join(app, 'package.json'), JSON.stringify({ version: '2.0.0' }));
  u.confirmWhenHealthy();
  await new Promise((r) => setTimeout(r, 60));
  assert.equal(u.status().previous.confirmed, true);
  assert.equal(u.status().previous.version, '1.0.0');
});

// ---- routes ----

test('the update routes are behind the request guard and never return the token', async () => {
  const app = require('../web');
  const stub = {
    status: () => ({ token: { set: true, source: 'saved' } }),
    install: async () => { throw new Error('must not be reached'); },
    check: async () => ({}), requestRollback: () => ({}), saveToken: () => {}, saveSettings: () => {}
  };
  require('../routes/update')(app, stub);
  const server = app.listen(0, '127.0.0.1');
  await new Promise((r) => server.once('listening', r));
  const base = 'http://127.0.0.1:' + server.address().port;
  const call = (p, method, headers) => new Promise((resolve, reject) => {
    const req = http.request(base + p, { method, headers: Object.assign({ 'Content-Type': 'application/json' }, headers), agent: false }, (res) => {
      let body = ''; res.on('data', (d) => { body += d; }); res.on('end', () => resolve({ status: res.statusCode, body }));
    });
    req.on('error', reject); req.end(method === 'POST' ? '{}' : undefined);
  });
  try {
    assert.equal((await call('/api/update/install', 'POST', { Origin: 'http://evil.example' })).status, 403);
    const st = await call('/api/update/status', 'GET', {});
    assert.equal(st.status, 200);
    assert.deepEqual(JSON.parse(st.body).token, { set: true, source: 'saved' });
  } finally {
    server.closeAllConnections();
    await new Promise((r) => server.close(r));
  }
});
