'use strict';

/**
 * SSH and serial-console terminals over the WebSocket, the live-session
 * list, and the serial port list.
 */

const log = require('../logger');
const vault = require('../vault');
const credentials = require('../credentials');
const knownHosts = require('../known-hosts');
const serial = require('../serial');
const { Client } = require('ssh2');

module.exports = function register(app, wss) {
  // "Trust the new key": the explicit step that replaces a remembered SSH host
  // key after the page showed the user the old and new fingerprints.
  app.post('/api/ssh/trust-key', (req, res) => {
    const { host, port, fingerprint } = req.body || {};
    if (!host) return res.status(400).json({ error: 'host is required.' });
    try {
      knownHosts.trust(host, port, fingerprint);
      log.warn('ssh', 'New SSH host key trusted by the user', { host, port: Number(port) || 22, fingerprint });
      res.json({ ok: true });
    } catch (e) {
      res.status(400).json({ error: e.message });
    }
  });

  // -----------------------------------------------------------------
  // Console (serial)
  // -----------------------------------------------------------------
  app.get('/api/serial/ports', async (req, res) => {
    const info = await serial.listPorts();
    res.json(Object.assign({ baudRates: serial.BAUD_RATES }, info));
  });

  // Strongest first; every algorithm the list offered before is still offered.
  // SSH picks the client's FIRST choice the switch also supports, so a switch
  // that only speaks the old suites still connects, and one that speaks modern
  // suites is no longer talked down to SHA-1 / CBC / ssh-rsa. The
  // legacy entries stay because older Cisco firmware may offer nothing else
  // (modern ssh2 drops them by default).
  const LEGACY_ALGORITHMS = {
    kex: [
      'curve25519-sha256', 'curve25519-sha256@libssh.org',
      'ecdh-sha2-nistp256', 'ecdh-sha2-nistp384', 'ecdh-sha2-nistp521',
      'diffie-hellman-group-exchange-sha256',
      'diffie-hellman-group14-sha256',
      // legacy
      'diffie-hellman-group14-sha1',
      'diffie-hellman-group-exchange-sha1',
      'diffie-hellman-group1-sha1'
    ],
    cipher: [
      'aes128-gcm@openssh.com', 'aes256-gcm@openssh.com', 'chacha20-poly1305@openssh.com',
      'aes128-ctr', 'aes192-ctr', 'aes256-ctr',
      // legacy
      'aes128-cbc', 'aes192-cbc', 'aes256-cbc',
      '3des-cbc'
    ],
    serverHostKey: [
      'ssh-ed25519', 'ecdsa-sha2-nistp256', 'rsa-sha2-512', 'rsa-sha2-256',
      // legacy
      'ssh-rsa', 'ssh-dss'
    ],
    hmac: [
      'hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com',
      'hmac-sha2-256', 'hmac-sha2-512',
      // legacy
      'hmac-sha1', 'hmac-md5'
    ]
  };

  // Terminal output is full of ANSI/VT100 control sequences -- erase-line,
  // cursor movement, colour. The live terminal needs them raw, but captured
  // text has to be cleaned before it is parsed or saved, otherwise section
  // headers and table columns are polluted with escape codes.
  function stripAnsiAndControls(str) {
    if (!str) return str;
    let out = str;
    out = out.replace(/\x1b\[[0-?]*[ -\/]*[@-~]/g, '');
    out = out.replace(/\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)/g, '');
    out = out.replace(/\x1b./g, '').replace(/\x1b/g, '').replace(/\x07/g, '');
    let result = '';
    for (const ch of out) {
      if (ch === '\b') result = result.slice(0, -1);
      else result += ch;
    }
    return result;
  }

  let connectionCounter = 0;

  /**
   * Every live session this app holds, so the switch's own view of who is
   * connected can be shown next to ours. A console session in particular is
   * worth knowing about: it is a physical port, and "why can I not open the
   * console" is usually answered by "because this tab already has it".
   */
  const liveSessions = new Map();

  app.get('/api/sessions', (req, res) => {
    const now = Date.now();
    res.json({
      sessions: Array.from(liveSessions.values()).map((x) => ({
        id: x.id, kind: x.kind, target: x.target, since: x.since,
        seconds: Math.round((now - x.started) / 1000), capturing: !!x.capturing
      }))
    });
  });

  wss.on('connection', (ws, req) => {
    const connId = ++connectionCounter;
    const clientIp = req.socket.remoteAddress;
    log.info('ws', `Browser tab connected [#${connId}]`, { ip: clientIp });

    let conn = null;
    let stream = null;
    let console_ = null;   // an attached serial port, when this is a console session
    let targetHost = null;
    let endedNotified = false;
    let capture = null;   // active `show tech-support` collection, if any

    const send = (obj) => {
      if (ws.readyState === ws.OPEN) ws.send(JSON.stringify(obj));
    };

    // Sends the "session is over" signal exactly once per SSH attempt,
    // regardless of which event (stream close, conn error, conn end)
    // triggers it first. The frontend uses this to reset the
    // Connect/Disconnect state no matter how the session ended.
    function notifyEnded(message) {
      liveSessions.delete(connId);
      if (endedNotified) return;
      endedNotified = true;
      send({ type: 'ended', message });
      // The browser opens a fresh WebSocket for each new connect
      // attempt in a given tab, so it's safe -- and tidier -- to close
      // this one now.
      setImmediate(() => {
        try { ws.close(); } catch (e) { /* already closed */ }
      });
    }

    // A device prompt at the very end of the output, e.g. "core-350#" or
    // "core-350(config)#". Seeing it is the signal the command has finished,
    // but only once the stream has also gone quiet -- show tech-support
    // prints intermediate prompts inside its own output.
    const PROMPT_AT_END = /(?:^|\n)\s*\S[\w.\-]*(?:\([^)]*\))?\s*[#>]\s*$/;

    /**
     * Write to whichever transport this tab is using. A console session runs
     * the same commands as an SSH one -- the switch does not care which
     * cable the characters arrive on -- so everything above this stays
     * transport-agnostic.
     */
    /**
     * A terminal sends DEL (0x7f) for Backspace. An SSH shell has a line
     * discipline that understands that; a raw console line does not, and
     * the Catalyst CLI erases on BS (0x08, Ctrl-H) instead -- so on a
     * console the key appeared to do nothing. Cisco accepts both, so
     * translating one way is safe and fixes the case that was broken.
     */
    function forConsole(data) {
      return String(data).replace(/\x7f/g, '\b');
    }

    function writeToSession(text) {
      if (console_) { console_.write(text); return true; }
      if (stream && stream.writable) { stream.write(text); return true; }
      return false;
    }

    const sessionOpen = () => !!(console_ || stream);

    function feedCapture(text) {
      if (!capture) return;
      capture.buffer += text;
      capture.lastData = Date.now();
      clearTimeout(capture.idleTimer);
      capture.idleTimer = setTimeout(() => {
        if (!capture) return;
        const tail = stripAnsiAndControls(capture.buffer).slice(-400);
        // Quiet plus a prompt means done. Quiet without a prompt is treated
        // as done too, but flagged, so a stalled capture still returns data
        // instead of hanging until the hard limit.
        capture.finish(PROMPT_AT_END.test(tail) ? 'prompt returned' : 'output went idle');
      }, capture.idleMs);
    }

    /**
     * End the session the way a person would: send "exit" so the switch
     * closes its own side and logs a clean logout, then give it a moment
     * before dropping the transport. Killing the socket outright leaves the
     * switch with a dangling VTY line until its timeout expires.
     */
    /**
     * A session left untouched is a VTY line held open on the switch for no
     * reason, and on a console it is a serial port nobody else can use. Five
     * minutes of no input closes it the same way a person would.
     *
     * A running capture counts as activity: show tech-support prints for
     * minutes with nobody typing, and killing that would be perverse.
     */
    const IDLE_MS = Number(process.env.SESSION_IDLE_MS) || 5 * 60 * 1000;
    let idleTimer = null;
    function resetIdle() {
      if (idleTimer) clearTimeout(idleTimer);
      if (!conn && !console_) return;
      idleTimer = setTimeout(() => {
        if (capture) { resetIdle(); return; }        // still working
        log.info('ws', `Session idle, closing [#${connId}]`, {
          host: targetHost,
          idle: IDLE_MS >= 60000 ? Math.round(IDLE_MS / 60000) + ' min' : Math.round(IDLE_MS / 1000) + ' s'
        });
        send({ type: 'status', message: 'closing after 5 minutes with no activity' });
        if (console_) {
          console_.close();
          console_ = null;
          send({ type: 'ended', message: 'Console closed after 5 minutes idle.' });
        } else {
          closeGracefully('Session closed after 5 minutes idle.');
        }
      }, IDLE_MS);
    }
    function stopIdle() { if (idleTimer) { clearTimeout(idleTimer); idleTimer = null; } }

    let closing = false;
    function closeGracefully(reason) {
      if (closing) { return; }
      closing = true;
      if (!conn) { notifyEnded(reason || 'Disconnected.'); return; }
      try {
        if (stream && stream.writable) stream.write('exit\n');
      } catch (e) { /* stream already gone */ }
      setTimeout(() => {
        try { if (stream) stream.end(); } catch (e) {}
        try { conn.end(); } catch (e) {}
        // Belt and braces: if the switch does not close, drop it.
        setTimeout(() => { try { conn.destroy(); } catch (e) {} }, 2000);
      }, 400);
    }

    ws.on('message', async (raw) => {
      let msg;
      try {
        msg = JSON.parse(raw);
      } catch (err) {
        log.error('ws', `Malformed message from browser [#${connId}]`, { error: err.message });
        return;
      }

      switch (msg.type) {
        case 'connect': {
          // Same guard serial-connect has: a second connect on this socket
          // would replace `conn` and leave the first SSH session running with
          // nothing able to close it.
          if (console_ || conn) {
            send({ type: 'error', message: 'This tab already has a session open.' });
            break;
          }
          // A saved switch's SSH password stays on the server; the browser
        // sends the connect without it (credentials.resolveSsh).
        const saved = vault.load();
        const resolved = credentials.resolveSsh(msg, saved && !saved.unreadable ? saved : null);
        const { host, port, username, password, cols, rows } = resolved;
          targetHost = host;
          endedNotified = false;

          if (!host || !username || !password) {
            const errMsg = 'Host, username, and password are required.';
            log.warn('ssh', `Rejected connect attempt [#${connId}]: missing fields`, { host, username });
            send({ type: 'error', message: errMsg });
            notifyEnded('Connection rejected: missing fields.');
            return;
          }

          log.info('ssh', `Connect attempt [#${connId}]`, { host, port: port || 22, username });

          conn = new Client();

          conn.on('ready', () => {
            log.info('ssh', `SSH session established [#${connId}]`, { host });
            send({ type: 'status', message: `Connected to ${host}. Starting shell...` });

            conn.shell({ term: 'xterm-256color', cols: cols || 100, rows: rows || 30 }, (err, s) => {
              if (err) {
                log.error('ssh', `Shell open failed [#${connId}]`, { host, error: err.message });
                send({ type: 'error', message: 'Shell error: ' + err.message });
                notifyEnded('Shell could not be opened.');
                return;
              }
              stream = s;
              send({ type: 'ready', message: 'Shell ready.' });
              liveSessions.set(connId, {
                id: connId, kind: 'ssh', target: targetHost,
                since: new Date().toISOString(), started: Date.now()
              });
              resetIdle();

              stream.on('data', (chunk) => {
                const text = chunk.toString('utf8');
                send({ type: 'data', data: text });
                feedCapture(text);
              });
              stream.stderr.on('data', (chunk) => {
                const text = chunk.toString('utf8');
                send({ type: 'data', data: text });
                feedCapture(text);
              });
              stream.on('close', () => {
                // This fires when the remote side closes the channel --
                // e.g. the user typed "exit" at the switch prompt.
                log.info('ssh', `Shell closed by remote host [#${connId}]`, { host });
                notifyEnded('Session closed by remote host.');
                conn.end();
              });
            });
          });

          // Set when the switch presented a different host key than the one
          // remembered; the connection is refused and the page is told why.
          let hostKeyChanged = null;

          conn.on('error', (err) => {
            if (hostKeyChanged) {
              send({ type: 'hostkey-changed', host, port: port || 22, ...hostKeyChanged });
              notifyEnded('Connection refused: the switch\'s SSH host key has changed. Open Settings to review it.');
              return;
            }
            log.error('ssh', `SSH error [#${connId}]`, { host, error: err.message, level: err.level });
            send({ type: 'error', message: 'SSH error: ' + err.message });
            notifyEnded('Session ended due to an error.');
          });

          conn.on('end', () => {
            log.info('ssh', `SSH connection ended [#${connId}]`, { host });
            notifyEnded('Connection ended.');
          });

          conn.connect({
            host,
            port: port || 22,
            username,
            password,
            readyTimeout: 15000,
            algorithms: LEGACY_ALGORITHMS,
            // Trust on first use (known-hosts.js): remember a new switch's
            // key, accept it again, refuse a different one.
            hostVerifier: (key) => {
              const v = knownHosts.check(host, port || 22, key);
              if (v.result === 'new') {
                log.info('ssh', `Remembered a new SSH host key [#${connId}]`, { host, port: port || 22, fingerprint: v.fingerprint });
                send({ type: 'status', message: 'First connection: remembered host key ' + v.fingerprint });
              }
              if (v.result !== 'changed') return true;
              hostKeyChanged = { fingerprint: v.fingerprint, expected: v.expected };
              log.warn('ssh', `SSH host key CHANGED; connection refused [#${connId}]`, {
                host, port: port || 22, expected: v.expected, presented: v.fingerprint
              });
              return false;
            }
          });
          break;
        }

        case 'input': {
          resetIdle();
          if (console_) { console_.write(forConsole(msg.data || '')); break; }
          if (stream) stream.write(msg.data);
          break;
        }

        case 'exec': {
          // Run a long command (show tech-support) in the live shell and
          // capture everything it prints. Output still goes to the terminal
          // so the operator can watch it happen.
          if (!sessionOpen()) {
            send({ type: 'exec-error', message: 'No active session.' });
            break;
          }
          if (capture) {
            send({ type: 'exec-error', message: 'A collection is already running.' });
            break;
          }

          const command = String(msg.command || '').trim();
          if (!command) {
            send({ type: 'exec-error', message: 'No command given.' });
            break;
          }

          const idleMs = Math.max(1000, Number(msg.idleMs) || 4000);
          const maxMs = Math.max(10000, Number(msg.maxMs) || 600000);

          log.info('exec', `Starting capture [#${connId}]`, { host: targetHost, command, idleMs, maxMs });
          if (liveSessions.has(connId)) liveSessions.get(connId).capturing = true;
          resetIdle();

          capture = {
            command,
            // The browser says whether it is watching the terminal. If it is
            // not, the session existed only for this command and should be
            // closed once it finishes rather than left idle on the switch.
            keepOpen: msg.keepOpen === true,
            buffer: '',
            started: Date.now(),
            idleMs,
            lastData: Date.now(),
            idleTimer: null,
            hardTimer: null,
            progressTimer: null,
            // Cisco small-business CLI pages output with "More:" prompts,
            // which would stall a scripted capture. `terminal datadump`
            // turns paging off for the session; if a model doesn't know the
            // command it just prints an error and continues harmlessly.
            finish(reason) {
              if (!capture) return;
              clearTimeout(capture.idleTimer);
              clearTimeout(capture.hardTimer);
              clearInterval(capture.progressTimer);
              const text = stripAnsiAndControls(capture.buffer);
              log.info('exec', `Capture finished [#${connId}]`, {
                host: targetHost, reason, bytes: text.length,
                seconds: Math.round((Date.now() - capture.started) / 1000)
              });
              send({
                type: 'exec-done',
                command: capture.command,
                reason,
                text,
                bytes: text.length,
                seconds: Math.round((Date.now() - capture.started) / 1000)
              });
              const keepOpen = capture.keepOpen;
              capture = null;
              if (liveSessions.has(connId)) liveSessions.get(connId).capturing = false;
              if (keepOpen) return;
              if (console_) {
                // A console is a physical port someone else may want; hand
                // it back rather than sitting on it. There is no session to
                // log out of, so it just closes.
                log.info('serial', `Closing console after capture [#${connId}]`, { port: console_.describe() });
                console_.close();
                console_ = null;
                send({ type: 'ended', message: 'Console closed after the capture finished.' });
                return;
              }
              log.info('ssh', `Closing session after capture [#${connId}]`, { host: targetHost });
              closeGracefully('Session closed after the capture finished.');
            }
          };

          capture.hardTimer = setTimeout(() => {
            if (capture) capture.finish('time limit reached');
          }, maxMs);

          capture.progressTimer = setInterval(() => {
            if (!capture) return;
            send({
              type: 'exec-progress',
              bytes: capture.buffer.length,
              seconds: Math.round((Date.now() - capture.started) / 1000)
            });
          }, 1000);

          send({ type: 'exec-started', command });
          // Paging off first, or the capture stalls on a "More:" prompt.
          // A console needs this at least as much as an SSH session does.
          writeToSession('terminal datadump\n');
          setTimeout(() => {
            if (capture) writeToSession(command + '\n');
          }, 400);
          break;
        }

        /**
         * Push configuration lines into the live session, whether that is
         * SSH or a console. Paced rather than dumped: a switch echoing every
         * character will drop input if it arrives faster than it can parse,
         * and a half-applied configuration is worse than none.
         */
        case 'exec-cancel': {
          if (capture) capture.finish('cancelled');
          break;
        }

        case 'resize': {
          if (stream) stream.setWindow(msg.rows, msg.cols, 0, 0);
          break;
        }

        case 'disconnect': {
          if (console_) {
            log.info('serial', `Console disconnect requested [#${connId}]`, { port: console_.describe() });
            console_.close();
            console_ = null;
            break;
          }
          log.info('ssh', `Disconnect requested by browser [#${connId}]`, { host: targetHost });
          closeGracefully('Disconnected.');
          break;
        }

        // ---- console ----
        case 'serial-connect': {
          resetIdle();
          if (console_ || conn) {
            send({ type: 'ssh-error', message: 'This tab already has a session open.' });
            break;
          }
          try {
            targetHost = 'console ' + (msg.path || '');
            console_ = await serial.attach(ws, msg, {
              onOpen: (info) => {
                send({ type: 'ready', host: info.path + ' @ ' + info.baudRate });
                liveSessions.set(connId, {
                  id: connId, kind: 'console', target: info.path + ' @ ' + info.baudRate,
                  since: new Date().toISOString(), started: Date.now()
                });
                resetIdle();
              },
              onData: (text) => {
                send({ type: 'data', data: text });
                feedCapture(text);
              },
              onError: (message) => {
                send({ type: 'ssh-error', message });
                if (console_) { console_.close(); console_ = null; }
                // Same reasoning: a console that cannot be opened is not a
                // session, and saying so now saves a confusing reconnect.
                setTimeout(() => { try { ws.close(); } catch (e) {} }, 50);
              },
              /**
               * The port going away ends the session, so the socket goes
               * with it. Leaving the socket open left the browser believing
               * it still had a console: the transport switch showed it as
               * live, and reconnecting did nothing because there appeared to
               * be nothing to reconnect. A closed socket is unambiguous.
               */
              onClose: () => {
                console_ = null;
                send({ type: 'ended', message: 'Console closed.' });
                log.info('serial', `Console ended; closing the session [#${connId}]`, {
                  host: targetHost
                });
                setTimeout(() => { try { ws.close(); } catch (e) { /* already gone */ } }, 50);
              }
            });
          } catch (e) {
            log.error('serial', `Console attach failed [#${connId}]`, { message: e.message });
            send({ type: 'ssh-error', message: e.message });
            console_ = null;
          }
          break;
        }

        case 'client-error': {
          // Frontend JS errors reported over the already-open socket.
          log.error('client', msg.message || 'Unspecified client error', msg.meta);
          break;
        }
      }
    });

    ws.on('error', (err) => {
      log.error('ws', `WebSocket error [#${connId}]`, { error: err.message });
    });

    ws.on('close', () => {
      liveSessions.delete(connId);
      log.info('ws', `Browser tab disconnected [#${connId}]`, { host: targetHost });
      if (capture) {
        clearTimeout(capture.idleTimer);
        clearTimeout(capture.hardTimer);
        clearInterval(capture.progressTimer);
        capture = null;
      }
      // A serial port stays open until it is told otherwise, so a closed tab
      // must release it or the next attempt finds the port busy.
      stopIdle();
      if (console_) { console_.close(); console_ = null; }
      if (conn) conn.end();
    });
  });
};
