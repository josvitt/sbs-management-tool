'use strict';

/**
 * Self-update from the repository's GitHub releases: the running half.
 *
 * It checks GitHub's newest release (once a day, and when asked), and on the
 * user's click prepares that release beside the running app, under
 * updates/staging/<version>/:
 *
 *   1. download the release's source archive (the repository is private, so
 *      with a read-only token kept encrypted with the vault key);
 *   2. unpack it (targz.js) and check its package.json says that version;
 *   3. `npm ci --omit=dev` in it, so its own dependencies are ready;
 *   4. `node scripts/self-check.js` in it: every module of the new version
 *      must load before anything is swapped.
 *
 * Only then does it write updates/pending.json and ask server.js to restart.
 * The swap itself, the rollback, and the list of files an update never
 * touches are in update-boot.js, which runs before anything else loads. A
 * failure at any step above leaves the running app exactly as it was.
 *
 * Nothing here installs without a click: autoCheck only checks.
 */

const fs = require('fs');
const path = require('path');
const { execFile } = require('child_process');
const boot = require('./update-boot');
const { extractTarGz } = require('./targz');

const REPO = process.env.SBS_UPDATE_REPO || 'josvitt/sbs-management-tool';
const API = 'https://api.github.com';
const CHECK_EVERY_MS = 24 * 60 * 60 * 1000;
const FIRST_CHECK_MS = 2 * 60 * 1000;
const CONFIRM_AFTER_MS = 60 * 1000;
const MAX_DOWNLOAD = 100 * 1024 * 1024;
const NPM_TIMEOUT_MS = 15 * 60 * 1000;

/**
 * deps: { appDir, fetch, log, vault, run (child-process runner), restart }.
 * Everything that touches the network, the vault or a child process is
 * injected so the tests can run it offline.
 */
function create(deps) {
  deps = deps || {};
  const appDir = deps.appDir || __dirname;
  const p = boot.paths(appDir);
  const files = {
    settings: path.join(p.dir, 'settings.json'),
    latest: path.join(p.dir, 'latest.json'),
    token: path.join(p.dir, 'token.enc')
  };
  const doFetch = deps.fetch || ((...a) => fetch(...a));
  const log = deps.log || { info() {}, warn() {}, error() {} };
  const vault = deps.vault || require('./vault');
  const run = deps.run || runChild;
  const restart = deps.restart || (() => process.exit(boot.RESTART));

  let phase = 'idle';       // idle | checking | downloading | preparing | restarting
  let phaseError = null;
  let timer = null;

  // ---- versions ----
  function currentVersion() {
    const pkg = boot.readJson(path.join(appDir, 'package.json'));
    return (pkg && pkg.version) || '0.0.0';
  }
  function parseVersion(v) {
    const m = String(v || '').trim().replace(/^v/, '').match(/^(\d+)\.(\d+)\.(\d+)$/);
    return m ? m.slice(1).map(Number) : null;
  }
  function isNewer(a, b) {   // is a newer than b?
    const x = parseVersion(a); const y = parseVersion(b);
    if (!x || !y) return false;
    for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i] > y[i];
    return false;
  }

  // ---- settings and token ----
  function settings() {
    return Object.assign({ autoCheck: true }, boot.readJson(files.settings) || {});
  }
  function saveSettings(patch) {
    const next = settings();
    if (patch && typeof patch.autoCheck === 'boolean') next.autoCheck = patch.autoCheck;
    boot.writeJson(files.settings, next);
    schedule();
    return next;
  }
  function token() {
    if (process.env.SBS_UPDATE_TOKEN) return { value: process.env.SBS_UPDATE_TOKEN, source: 'environment' };
    try {
      if (fs.existsSync(files.token)) return { value: vault.decrypt(fs.readFileSync(files.token)), source: 'saved' };
    } catch (e) {
      log.warn('update', 'The saved GitHub token could not be read', { message: e.message });
    }
    return { value: null, source: null };
  }
  function saveToken(value) {
    value = String(value || '').trim();
    if (!value) { boot.remove(files.token); return; }
    if (!/^[A-Za-z0-9_]{20,255}$/.test(value)) throw new Error('That does not look like a GitHub token.');
    fs.mkdirSync(p.dir, { recursive: true });
    require('./rotate').writeFileAtomic(files.token, vault.encrypt(value), { mode: 0o600 });
  }

  // ---- GitHub ----
  function headers() {
    const h = { 'Accept': 'application/vnd.github+json', 'User-Agent': 'sbs-management-tool-updater', 'X-GitHub-Api-Version': '2022-11-28' };
    const t = token().value;
    if (t) h.Authorization = 'Bearer ' + t;
    return h;
  }
  function explain(status, hasToken) {
    if (status === 401) return 'GitHub refused the token (it may have expired or been revoked).';
    if (status === 403) return 'GitHub refused the request (rate limit, or the token lacks read access to Contents).';
    if (status === 404) return hasToken
      ? 'GitHub could not find ' + REPO + ' or a release in it with this token. Check the token has read access to this repository.'
      : 'GitHub could not find ' + REPO + '. The repository is private: add a read-only token.';
    return 'GitHub answered HTTP ' + status + '.';
  }

  async function check() {
    if (phase !== 'idle') throw new Error('An update is already in progress.');
    phase = 'checking'; phaseError = null;
    // A failed check keeps the release the last good one found, so a passing
    // network problem does not hide an update that is waiting.
    const prior = (boot.readJson(files.latest) || {}).latest || null;
    const record = { checkedAt: new Date().toISOString(), latest: prior, error: null };
    try {
      const r = await doFetch(API + '/repos/' + REPO + '/releases/latest', { headers: headers(), signal: AbortSignal.timeout(30000) });
      if (!r.ok) throw new Error(explain(r.status, !!token().value));
      const b = await r.json();
      const version = String(b.tag_name || '').replace(/^v/, '');
      if (!parseVersion(version)) throw new Error('The newest release is tagged "' + b.tag_name + '", not vX.Y.Z.');
      record.latest = {
        version, tag: b.tag_name, name: b.name || b.tag_name,
        notes: String(b.body || '').slice(0, 20000),
        publishedAt: b.published_at || null, url: b.html_url || null
      };
      log.info('update', 'Checked for updates', { current: currentVersion(), latest: version });
    } catch (e) {
      record.error = e.name === 'TimeoutError' ? 'GitHub did not answer within 30 seconds.' : e.message;
      log.warn('update', 'Update check failed', { message: record.error });
    } finally {
      phase = 'idle';
    }
    try { boot.writeJson(files.latest, record); } catch (e) { /* the answer is still returned */ }
    return status();
  }

  async function download(tag) {
    // The API answers with a redirect to a short-lived signed link on
    // codeload.github.com; the token goes to api.github.com only.
    const r = await doFetch(API + '/repos/' + REPO + '/tarball/' + encodeURIComponent(tag),
      { headers: headers(), redirect: 'manual', signal: AbortSignal.timeout(60000) });
    let res = r;
    if (r.status >= 300 && r.status < 400) {
      const loc = r.headers.get('location');
      if (!loc || !/^https:\/\/([a-z0-9-]+\.)*github(usercontent)?\.com\//i.test(loc)) {
        throw new Error('GitHub sent the download somewhere unexpected.');
      }
      res = await doFetch(loc, { headers: { 'User-Agent': 'sbs-management-tool-updater' }, signal: AbortSignal.timeout(5 * 60000) });
    }
    if (!res.ok) throw new Error('Download failed: ' + explain(res.status, !!token().value));
    const len = Number(res.headers.get('content-length') || 0);
    if (len > MAX_DOWNLOAD) throw new Error('The release archive is larger than expected.');
    const buf = Buffer.from(await res.arrayBuffer());
    if (buf.length > MAX_DOWNLOAD) throw new Error('The release archive is larger than expected.');
    return buf;
  }

  /**
   * Prepare the newest release and restart into it. Resolves once the
   * restart is requested; any failure rejects and leaves the app as it was.
   */
  async function install() {
    if (phase !== 'idle') throw new Error('An update is already in progress.');
    const latest = (boot.readJson(files.latest) || {}).latest;
    const from = currentVersion();
    if (!latest || !isNewer(latest.version, from)) throw new Error('There is no newer version to install. Check for updates first.');
    const dir = path.join(p.staging, latest.version);
    phaseError = null;
    try {
      phase = 'downloading';
      log.info('update', 'Downloading update', { version: latest.version });
      const gz = await download(latest.tag);

      phase = 'preparing';
      boot.remove(p.staging);
      extractTarGz(gz, dir, { strip: 1 });
      const pkg = boot.readJson(path.join(dir, 'package.json'));
      if (!pkg || pkg.version !== latest.version) {
        throw new Error('The downloaded release says version ' + (pkg && pkg.version) + ', not ' + latest.version + '.');
      }
      for (const n of fs.readdirSync(dir)) if (boot.isProtected(n)) boot.remove(path.join(dir, n));
      // Its own cache under updates/: the service account may have no usable
      // home folder, and ProtectSystem=strict allows writes only to the app.
      const npmEnv = Object.assign({}, process.env, { npm_config_cache: path.join(p.dir, 'npm-cache'), npm_config_update_notifier: 'false' });
      await run(process.execPath, [npmCli(), 'ci', '--omit=dev', '--no-audit', '--no-fund'], {
        cwd: dir, timeout: NPM_TIMEOUT_MS,
        env: npmEnv
      }, 'Installing the new version\'s dependencies failed');
      // The Windows service starts node_modules/node-windows/lib/wrapper.js,
      // which install-service.bat added outside package.json. Without it in
      // the new node_modules the service could not start again.
      const nw = boot.readJson(path.join(appDir, 'node_modules', 'node-windows', 'package.json'));
      if (nw && nw.version) {
        await run(process.execPath, [npmCli(), 'install', '--no-save', '--no-audit', '--no-fund', 'node-windows@' + nw.version], {
          cwd: dir, timeout: NPM_TIMEOUT_MS,
          env: npmEnv
        }, 'Carrying the Windows service helper (node-windows) over failed');
      }
      const out = await run(process.execPath, [path.join('scripts', 'self-check.js')], { cwd: dir, timeout: 60000 },
        'The new version failed its start-up check');
      if (!/self-check ok/.test(out)) throw new Error('The new version failed its start-up check.');

      boot.writeJson(p.pending, { action: 'install', version: latest.version, from, staged: path.relative(p.dir, dir), at: new Date().toISOString() });
      log.info('update', 'Update prepared; restarting into it', { version: latest.version, from });
      phase = 'restarting';
      setTimeout(restart, 300);
      return status();
    } catch (e) {
      phase = 'idle';
      phaseError = e.message;
      boot.remove(p.staging);
      log.error('update', 'Update failed; nothing was changed', { version: latest.version, message: e.message });
      throw e;
    }
  }

  function requestRollback() {
    if (phase !== 'idle') throw new Error('An update is already in progress.');
    const applied = boot.readJson(p.applied);
    if (!applied || !applied.backup || !fs.existsSync(path.join(p.dir, applied.backup))) {
      throw new Error('There is no earlier version to go back to.');
    }
    boot.writeJson(p.pending, { action: 'rollback', at: new Date().toISOString() });
    log.info('update', 'Going back to the previous version; restarting', { from: applied.version, to: applied.from });
    phase = 'restarting';
    setTimeout(restart, 300);
    return status();
  }

  /** Mark a just-installed version good once it has served for a minute. */
  function confirmWhenHealthy() {
    const applied = boot.readJson(p.applied);
    if (!applied || applied.confirmed) return;
    const t = setTimeout(() => {
      const a = boot.readJson(p.applied);
      if (!a || a.confirmed || a.version !== currentVersion()) return;
      a.confirmed = true; a.confirmedAt = new Date().toISOString();
      boot.writeJson(p.applied, a);
      log.info('update', 'Updated version is running normally', { version: a.version, from: a.from });
    }, deps.confirmAfterMs != null ? deps.confirmAfterMs : CONFIRM_AFTER_MS);
    if (t.unref) t.unref();
  }

  function schedule() {
    if (timer) { clearTimeout(timer); timer = null; }
    if (!settings().autoCheck) return;
    const last = Date.parse((boot.readJson(files.latest) || {}).checkedAt || '') || 0;
    const wait = Math.max(FIRST_CHECK_MS, last + CHECK_EVERY_MS - Date.now());
    timer = setTimeout(() => { check().catch(() => {}).finally(schedule); }, wait);
    if (timer.unref) timer.unref();
  }
  function start() { confirmWhenHealthy(); schedule(); }
  function stop() { if (timer) clearTimeout(timer); timer = null; }

  function status() {
    const rec = boot.readJson(files.latest) || {};
    const applied = boot.readJson(p.applied);
    const current = currentVersion();
    const t = token();
    return {
      current, repo: REPO,
      token: { set: !!t.value, source: t.source },
      settings: settings(),
      checkedAt: rec.checkedAt || null,
      checkError: rec.error || null,
      latest: rec.latest || null,
      available: !!(rec.latest && isNewer(rec.latest.version, current)),
      phase, phaseError,
      lastOutcome: boot.readJson(p.status),
      previous: applied && applied.backup && fs.existsSync(path.join(p.dir, applied.backup))
        ? { version: applied.from, confirmed: !!applied.confirmed } : null
    };
  }

  return { check, install, requestRollback, status, saveSettings, saveToken, start, stop, confirmWhenHealthy, isNewer, currentVersion };
}

// npm ships beside node: <node dir>/node_modules/npm on Windows,
// <prefix>/lib/node_modules/npm on Linux. SBS_NPM_CLI overrides.
function npmCli() {
  const dir = path.dirname(process.execPath);
  const candidates = [process.env.SBS_NPM_CLI,
    path.join(dir, 'node_modules', 'npm', 'bin', 'npm-cli.js'),
    path.join(dir, '..', 'lib', 'node_modules', 'npm', 'bin', 'npm-cli.js')].filter(Boolean);
  const found = candidates.find((c) => fs.existsSync(c));
  if (!found) throw new Error('npm was not found next to node (' + process.execPath + '). Set SBS_NPM_CLI to npm-cli.js.');
  return found;
}

function runChild(cmd, args, opts, failMessage) {
  return new Promise((resolve, reject) => {
    execFile(cmd, args, Object.assign({ maxBuffer: 16 * 1024 * 1024, windowsHide: true }, opts), (err, stdout, stderr) => {
      if (err) {
        const tail = String(stderr || stdout || err.message).trim().split(/\r?\n/).slice(-3).join(' ');
        return reject(new Error(failMessage + ': ' + tail));
      }
      resolve(String(stdout || ''));
    });
  });
}

module.exports = { create, REPO };
