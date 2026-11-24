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

const http = require('http');
const { WebSocketServer } = require('ws');
const log = require('./logger');
const configFetch = require('./config-fetch');
const syslog = require('./syslog');
const vault = require('./vault');
const history = require('./history');
const events = require('./events');
const collector = require('./collector');
const guard = require('./request-guard');
const { buildSnmpSession } = require('./snmp-core');
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
require('./routes/monitoring')(app);
require('./routes/state')(app);
require('./routes/streams')(app);
require('./routes/ports')(app);
require('./routes/layouts')(app);
require('./routes/health')(app);

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
    history, events, log
  });
}

server.listen(PORT, () => {
  log.info('server', `SBS Management Tool running at http://localhost:${PORT}`, { logFile: log.LOG_FILE, build: BUILD_MARKER });
  // Also print plainly so it's obvious in the console which build is live.
  console.log('BUILD:', BUILD_MARKER);
  startCollector();
});

// Persist any pending metric history before the process exits, so a restart
// (or Ctrl-C) never loses the last batch of samples. flush() is synchronous and
// safe to call more than once.
let shuttingDown = false;
function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  try { collector.stop(); } catch (e) { /* best effort */ }
  try { history.flush(); } catch (e) { /* best effort */ }
  log.info('server', 'Shutting down, metric history flushed', { signal });
  // Give the log a tick to write, then exit.
  setTimeout(() => process.exit(0), 50);
}
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
// A last-chance synchronous flush if the process exits some other way.
process.on('exit', () => { try { history.flush(); } catch (e) {} });
