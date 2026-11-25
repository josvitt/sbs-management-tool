/**
 * SBS Management Tool - backend
 *
 * A browser can't open a raw SSH/TCP socket, so this small local server
 * does the actual SSH connection (via ssh2) and streams the terminal
 * session to the browser over a WebSocket. It also proxies SNMP
 * requests (via net-snmp), since browsers can't send raw UDP either.
 * The HTML page in /public is the entire user-facing frontend, and
 * supports multiple concurrent sessions as browser tabs -- SSH tabs
 * each get their own WebSocket here (independent SSH client, stream,
 * and state per connection); SNMP "tabs" are stateless request/response
 * calls to the REST endpoint below, so no per-tab backend state is
 * needed for those at all.
 *
 * All errors -- backend and frontend -- are logged with timestamps to
 * both the console and logs/app.log. See logger.js. This is metadata
 * only (host, username, error text) for troubleshooting the tool
 * itself -- never the actual content of an SSH session or SNMP query.
 *
 * Session output is NEVER written to disk automatically. The only way
 * to save it is the "Save Output" button in the browser, which
 * downloads what's currently on screen on demand -- there is no
 * separate always-on recording path to keep in sync with it.
 *
 * Run with:  start.bat  (Windows)  or  npm install && npm start
 * Then open: http://localhost:3000
 */

// First, before anything else loads: finish (or undo) a self-update. When it
// changed the app's files this process is the old version, so it exits and
// the service, or scripts/run.js, starts the new one (update-boot.js).
const updateBoot = require('./update-boot');
const bootResult = updateBoot.run();
if (bootResult === updateBoot.RESTART) process.exit(bootResult);

const http = require('http');
const { WebSocketServer } = require('ws');
const log = require('./logger');
const configFetch = require('./config-fetch');
const syslog = require('./syslog');
const vault = require('./vault');
const history = require('./history');
const events = require('./events');
const configHistory = require('./config-history');
const collector = require('./collector');
const guard = require('./request-guard');
const { buildSnmpSession, onSwitchWrite } = require('./snmp-core');
const { SETTINGS_TABLES } = require('./health');
const { collectModulesFor } = require('./module-collection');
const { probeSwitch, collectHealthFor } = require('./collection');

// Catch anything that would otherwise silently kill the process.
process.on('uncaughtException', (err) => {
  log.error('process', 'Uncaught exception', { message: err.message, stack: err.stack });
});
process.on('unhandledRejection', (reason) => {
  log.error('process', 'Unhandled promise rejection', {
    message: reason && reason.message ? reason.message : String(reason)
  });
});


const app = require('./web');

require('./routes/snmp')(app);
require('./routes/snmp-config')(app);
require('./routes/config')(app);
require('./routes/opc')(app);
require('./routes/aaa')(app);
require('./routes/flash')(app);
require('./routes/maint')(app);
require('./routes/system')(app);
require('./routes/port-features')(app);
require('./routes/monitoring')(app);
require('./routes/state')(app);
require('./routes/streams')(app);
require('./routes/ports')(app);
require('./routes/layouts')(app);
require('./routes/health')(app);

const updater = require('./updater').create({ log, restart: () => shutdown('update', updateBoot.RESTART) });
require('./routes/update')(app, updater);

const server = http.createServer(app);
const wss = new WebSocketServer({ server, verifyClient: guard.verifyClient(log) });
require('./routes/terminal')(app, wss);

const PORT = process.env.PORT || 3000;
// Start the syslog receiver alongside the web server. A failure to bind
// is logged and surfaced in the UI rather than being fatal: everything
// else in the app still works without it.
syslog.start(Number(process.env.SYSLOG_PORT) || undefined).then((r) => {
  if (!r.listening) {
    log.warn('syslog', 'Syslog receiver did not start', { port: r.port, error: r.error });
  }
});

// A build marker so the running build can be confirmed (the last captures were
// taken against a stale process/cache). Bumped when polling behaviour changes.
const BUILD_MARKER = 'sbs-12 (reopen = display the server\'s last poll, no SNMP: restore/connect now read the cached snapshot instead of forcing a fresh poll. A fresh SNMP poll happens only on the server\'s own schedule, on a manual Refresh, or the one-off auto-poll when a switch has no snapshot yet. Plus sbs-11 C1300X counter fallback.)';

// The collector runs collection THROUGH collectHealthFor (the one path) for
// every saved switch, on a wall-clock cadence, whether or not a browser is
// open. SNMP/vault/TFTP wiring is injected so collector.js stays free of it.
function startCollector() {
  collector.start({
    probe: (target) => probeSwitch(target),
    collect: (target, opts) => collectHealthFor(target, opts),
    loadSwitches: () => {
      const st = vault.load();
      return (st && !st.unreadable && Array.isArray(st.switches)) ? st.switches : [];
    },
    // Gated config content-diff: pull the running-config over the built-in
    // TFTP path (same mechanism as /api/config/fetch) and return its text.
    fetchConfig: async (target) => {
      const r = await configFetch.fetchConfig(() => buildSnmpSession(target), {
        host: target.host, kind: 'running',
        tftpPort: Number(process.env.TFTP_PORT) || undefined
      });
      return r && r.text;
    },
    // Tables the collector carries between full reads (health.js `settings`).
    settingsTables: SETTINGS_TABLES,
    // The server-side panels (module-collection.js): the capture list is read
    // with every full collection; SNMP configuration, Flash files and Reboot
    // and firmware follow the settings rule (after a change, a reboot, a
    // Refresh, or hourly).
    modules: { everyCycle: ['captures'], onSettings: ['snmpConfig', 'flash', 'maint', 'system', 'ports'] },
    collectModules: (target, keys) => collectModulesFor(target, keys),
    history, events, log, configHistory
  });
  // Any successful SNMP write from the app marks that switch's settings for a
  // fresh read on its next full collection.
  onSwitchWrite((host) => collector.flagSettingsChange(host));
}

// Only this PC can open the dashboard: the web server listens on the
// loopback address unless SBS_BIND says otherwise (SBS_BIND=0.0.0.0 opens it
// to the LAN again; there is no sign-in, see README "Security"). The
// receivers the switches send to (TFTP, syslog, traps) are UDP sockets of
// their own and still listen on every interface.
const BIND = process.env.SBS_BIND || '127.0.0.1';
server.listen(PORT, BIND, () => {
  log.info('server', `SBS Management Tool running at http://localhost:${PORT}`, { bind: BIND, logFile: log.LOG_FILE, build: BUILD_MARKER });
  if (BIND !== '127.0.0.1' && BIND !== '::1' && BIND !== 'localhost') {
    log.warn('server', 'The dashboard is reachable from the network, with no sign-in', { bind: BIND });
  }
  // Also print plainly so it's obvious in the console which build is live.
  console.log('BUILD:', BUILD_MARKER);
  startCollector();
  // Daily update check (it never installs on its own), and, after an update,
  // marking the new version good once it has stayed up for a minute.
  updater.start();
});

// Persist any pending metric history before the process exits, so a restart
// (or Ctrl-C) never loses the last batch of samples. flush() is synchronous and
// safe to call more than once.
let shuttingDown = false;
function shutdown(signal, exitCode) {
  if (shuttingDown) return;
  shuttingDown = true;
  try { collector.stop(); } catch (e) { /* best effort */ }
  try { updater.stop(); } catch (e) { /* best effort */ }
  try { history.flush(); } catch (e) { /* best effort */ }
  log.info('server', 'Shutting down, metric history flushed', { signal });
  // Give the log a tick to write, then exit.
  setTimeout(() => process.exit(exitCode || 0), 50);
}
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
// A last-chance synchronous flush if the process exits some other way.
process.on('exit', () => { try { history.flush(); } catch (e) {} });
