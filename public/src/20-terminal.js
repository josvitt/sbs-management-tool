  // =================================================================
  // 20-terminal.js: CLI access: console, SSH, the terminal and host-key handling.
  // =================================================================

  const hasConsole = (s) => !!(s.consoleTarget && s.consoleTarget.path);
  const hasSsh = (s) => !!(s.sshEverConnected || (s.sshUser.value && (s.sshPass.value || (s.savedSecrets && s.savedSecrets.sshPassword))));

  function cliTooltip(s) {
    if (hasConsole(s)) return 'Console  \u2014  ' + s.consoleTarget.path + ' @ ' + s.consoleTarget.baudRate;
    if (hasSsh(s)) return 'SSH  \u2014  ' + (s.sshHost.value || s.host);
    return 'Set up SSH or console access in Settings';
  }

  /**
   * Open the command line by whichever route exists, preferring the
   * console: it is the one that still works when the network path is the
   * problem. With neither set up, go to Settings and show both as the
   * options they are rather than failing silently.
   */
  function openCli(s) {
    if (hasConsole(s)) { openConsole(s, s.consoleTarget.path, s.consoleTarget.baudRate); return; }
    if (hasSsh(s)) { openTerminal(s); return; }
    /**
     * Nothing is set up yet, so credentials come first -- but the request
     * was for a terminal and it should survive the detour. Without this
     * the operator asks for the CLI, fills in a serial port, is returned
     * to the dashboard, and has to ask for the CLI all over again.
     */
    s.pendingCli = true;
    showView(s, 'creds');
    for (const card of [s.sshCard, s.consoleCard]) {
      card.classList.add('needs-setup');
      setTimeout(() => card.classList.remove('needs-setup'), 4000);
    }
    s.sshCard.scrollIntoView({ block: 'nearest' });
    appLog('info', 'CLI access needs SSH or console credentials first', { host: s.host });
  }

  /** Open the terminal, or the credentials that it needs first. */
  /**
   * Which transports this switch can offer, and which one is live. Kept
   * on the terminal itself so the answer is where the question is asked.
   */
  function paintTransport(s) {
    if (!s.trConsole) return;
    // An open socket is not the same as a working session: the far end can
    // report the console gone while the socket is still up. Both have to
    // be true.
    const live = s.ws && s.ws.readyState === WebSocket.OPEN && s.sessionLive !== false;
    const onConsole = live && s.lastTransport === 'serial';
    const onSsh = live && s.lastTransport !== 'serial';

    s.trConsole.disabled = !hasConsole(s);
    s.trSsh.disabled = !hasSsh(s);
    s.trConsole.classList.toggle('active', !!onConsole);
    s.trSsh.classList.toggle('active', !!onSsh);
    s.trConsole.title = hasConsole(s)
      ? (onConsole ? 'Connected on ' + s.consoleTarget.path
        : 'Switch to the console on ' + s.consoleTarget.path)
      : 'No serial port chosen for this switch';
    s.trSsh.title = hasSsh(s)
      ? (onSsh ? 'Connected over SSH' : 'Switch to SSH')
      : 'No SSH credentials for this switch';
  }

  function openTerminal(s) {
    s.wantTerminal = true;
    paintTransport(s);
    if (s.ws && s.ws.readyState === WebSocket.OPEN) { openOverlay(s, 'termOverlay'); return; }
    if (s.subMode !== 'ready') selectCredCard(s, 'ssh');
    showView(s, 'creds');
    if (!s.sshHost.value) s.sshHost.value = s.host || '';
    (s.sshUser.value ? s.sshPass : s.sshUser).focus();
  }

  // =================================================================
  // SSH
  // =================================================================
  /**
   * Populate the console form from what the machine can actually see. A
   * dropdown of ports the operator has to guess at is worse than none, so
   * when serial support is missing the form says why instead.
   */
  function initConsole(s) {
    for (const rate of [115200, 9600, 19200, 38400, 57600, 230400]) {
      const o = document.createElement('option');
      o.value = String(rate); o.textContent = String(rate);
      s.baud.appendChild(o);
    }
    s.baud.value = '115200';

    const loadPorts = () => {
      fetch('/api/serial/ports').then((r) => r.json()).then((info) => {
        clear(s.comPort);
        if (!info.available) {
          s.serialStatus.textContent = 'Serial support is not installed on this machine' +
            (info.error ? ': ' + info.error : '') + '.';
          s.comPort.appendChild(new Option('unavailable', ''));
          s.consoleForm.querySelector('button').disabled = true;
          return;
        }
        if (info.error) {
          s.serialStatus.textContent = 'Could not list ports: ' + info.error;
        } else if (!info.ports.length) {
          s.serialStatus.textContent = 'No serial ports found. Plug in the console cable and reload.';
        } else {
          s.serialStatus.textContent = info.ports.length + ' port(s) found.';
        }
        s.comPort.appendChild(new Option(info.ports.length ? 'select a port\u2026' : 'none found', ''));
        for (const port of info.ports) {
          s.comPort.appendChild(new Option(
            port.path + (port.label && port.label !== port.path ? '  \u2014  ' + port.label : ''),
            port.path));
        }
        applyConsoleChoice(s);
      }).catch((e) => { s.serialStatus.textContent = 'Could not read the port list: ' + e.message; });
    };
    loadPorts();

    // Ports come and go with the cable, so refresh the list on each visit.
    s.consoleCard.addEventListener('mouseenter', () => {
      if (!s.serialLoadedAt || Date.now() - s.serialLoadedAt > 5000) {
        s.serialLoadedAt = Date.now();
        loadPorts();
      }
    });

    s.consoleForm.addEventListener('submit', (e) => {
      e.preventDefault();
      const path = s.comPort.value;
      if (!path) { s.consoleError.textContent = 'Choose a serial port first.'; return; }
      s.consoleError.textContent = '';
      /**
       * Connecting from the credentials form is usually setting the switch
       * up, so what happens next is decided once the session is live. But
       * if the operator got here by asking for the CLI, that is still what
       * they asked for -- sending them back to the dashboard to click CLI
       * a second time makes the first click a waste of their time.
       */
      const wanted = s.cliPending === true;
      s.cliPending = false;
      openConsole(s, path, Number(s.baud.value), wanted);
    });
  }

  /**
   * Put this switch's remembered port back on the form. The port list and
   * the saved layout arrive independently, so whichever lands second has
   * to do this -- and a port that is not currently present is still shown,
   * labelled, rather than silently reverting to nothing.
   */
  function applyConsoleChoice(s) {
    const want = s.consoleTarget;
    if (!want || !want.path || !s.comPort) return;
    if (![...s.comPort.options].some((o) => o.value === want.path)) {
      s.comPort.appendChild(new Option(want.path + '  (not connected)', want.path));
    }
    s.comPort.value = want.path;
    if (want.baudRate) s.baud.value = String(want.baudRate);
  }

  /**
   * Open a console session. `showTerminal` is false when something else
   * asked for the session -- a tech-support collection, say -- which
   * should not take over the screen.
   */
  function openConsole(s, path, baudRate, showTerminal) {
    /**
     * A session may already be open. Doing nothing in that case -- which
     * is what this used to do when the caller did not want the terminal --
     * looks exactly like a broken button: no terminal, no reconnection, no
     * message. So the two cases are handled separately.
     *
     * Already on this port: show it, because asking to open a console you
     * already have can only mean "let me see it".
     *
     * On something else: close that first and open this. A serial port is
     * exclusive, and two sessions from one tab is not a thing anyone wants.
     */
    const live = s.ws && s.ws.readyState === WebSocket.OPEN && s.sessionLive !== false;
    const samePort = live && s.lastTransport === 'serial' && s.consoleTarget &&
      s.consoleTarget.path === path && Number(s.consoleTarget.baudRate) === Number(baudRate);

    if (samePort) {
      appLog('info', 'Console already open; showing it', { host: s.host, port: path });
      paintTransport(s);
      openOverlay(s, 'termOverlay');
      return;
    }

    if (live) {
      appLog('info', 'Closing the current session before opening the console', {
        host: s.host, port: path
      });
      const previous = s.ws;
      let opened = false;
      const openWhenClosed = () => {
        if (opened) return;
        opened = true;
        // Give the port a moment to be released before claiming it.
        setTimeout(() => openConsole(s, path, baudRate, showTerminal), 400);
      };
      previous.addEventListener('close', openWhenClosed, { once: true });
      try { previous.send(JSON.stringify({ type: 'disconnect' })); } catch (e) { /* already gone */ }
      // A socket that will not close must not strand the request.
      setTimeout(() => { try { previous.close(); } catch (e) {} openWhenClosed(); }, 2000);
      return;
    }

    s.wantTerminal = showTerminal !== false;
    s.consoleTarget = { path, baudRate };
    saveLayout(s);
    saveState();
    // Quick Actions gains a Console button the moment there is a port to
    // reopen; without this it only appeared at the next unrelated repaint,
    // which is why a second switch looked like it had none.
    repaintPanel(s, 'summary');
    sshConnect(s, { path, baudRate });
  }

  function initSsh(s) {
    s.sshForm.addEventListener('submit', (e) => {
      e.preventDefault();
      // Same as the console form: a CLI request made before the
      // credentials existed is still a CLI request.
      if (s.cliPending) { s.wantTerminal = true; s.cliPending = false; }
      /**
       * Filling in SSH credentials while a session is already open is a
       * request to move to SSH, not to set something up for later -- so it
       * lands in the terminal rather than back on the dashboard, which is
       * what the transport switch would have done from the same intent.
       */
      if (s.ws && s.ws.readyState === WebSocket.OPEN && s.sessionLive !== false) {
        s.wantTerminal = true;
      }
      sshConnect(s);
    });
    s.disconnectBtn.addEventListener('click', () => {
      if (s.ws) { try { s.ws.send(JSON.stringify({ type: 'disconnect' })); s.ws.close(); } catch (err) {} }
      s.disconnectBtn.style.display = 'none';
      s.reconnectBtn.style.display = 'inline-block';
      paintTransport(s);
    });
    /**
     * Come back on the transport you were using. Sending a console
     * session to the SSH credentials form is how "reconnect" turned into
     * "the console is broken": nothing was wrong with it, the button just
     * went somewhere else.
     */
    s.reconnectBtn.addEventListener('click', () => {
      if (s.lastTransport === 'serial' && hasConsole(s)) {
        openConsole(s, s.consoleTarget.path, s.consoleTarget.baudRate);
        return;
      }
      if (hasSsh(s)) {
        s.wantTerminal = true;
        sshConnect(s);
        return;
      }
      if (hasConsole(s)) {
        openConsole(s, s.consoleTarget.path, s.consoleTarget.baudRate);
        return;
      }
      closeOverlays(s);
      if (s.subMode !== 'ready') selectCredCard(s, 'ssh');
      showView(s, 'creds');
      s.sshUser.focus();
    });

    /**
     * Move the CLI between the console and SSH without leaving it. The
     * two are different routes to the same switch, and which one is
     * usable changes -- a switch being rebooted answers on the console
     * long before it answers on the network.
     */
    const switchTransport = (want) => {
      if (want === 'serial') {
        if (!hasConsole(s)) return;
        s.wantTerminal = true;
        openConsole(s, s.consoleTarget.path, s.consoleTarget.baudRate);
      } else {
        if (!hasSsh(s)) return;
        s.wantTerminal = true;
        // sshConnect replaces whatever is open, so a console session is
        // closed and its port released before the SSH one starts.
        sshConnect(s);
      }
      paintTransport(s);
    };
    s.trConsole.addEventListener('click', () => switchTransport('serial'));
    s.trSsh.addEventListener('click', () => switchTransport('ssh'));
    s.sshSave.addEventListener('click', () => download('ssh-' + safeHost(s.host) + '-' + stamp() + '.log', s.sshBuffer));
    // Any long output leaves the screen unusable, whether it came from
    // Quick Actions or was typed by hand. The saved log keeps everything,
    // so clearing costs nothing.
    s.termClear.addEventListener('click', () => clearTerminal(s, true));
    // Paint once at the start, so the switch reads correctly before
    // anything has been connected rather than defaulting to both enabled.
    paintTransport(s);
  }

  // xterm sizes itself from its container, so fitting while the pane is
  // hidden yields a tiny terminal. Fit after two frames and tell the
  // switch the real size, or it wraps output to the wrong width.
  function fitTerm(s) {
    if (!s.fit || !s.term) return;
    requestAnimationFrame(() => requestAnimationFrame(() => {
      try {
        s.fit.fit();
        if (s.ws && s.ws.readyState === WebSocket.OPEN) {
          s.ws.send(JSON.stringify({ type: 'resize', cols: s.term.cols, rows: s.term.rows }));
        }
      } catch (e) { /* not measurable yet */ }
    }));
  }

  /** Wipe the screen and ask the switch to redraw its prompt. */
  function clearTerminal(s, prompt) {
    if (!s.term) return;
    s.term.reset();
    if (prompt && s.ws && s.ws.readyState === WebSocket.OPEN) {
      s.ws.send(JSON.stringify({ type: 'input', data: '\r' }));
    }
  }

  function initTerm(s) {
    if (s.term) return true;
    if (!librariesLoaded()) { showErr(s.sshError, 'Terminal library did not load.'); return false; }
    try {
      s.term = new Terminal({
        // 500,000 lines was chosen when the terminal was where captures
        // landed. They go to the viewer now, and are saved from there, so
        // this only has to hold a session's worth of scrollback: a full
        // show tech-support is under 8,000 lines and still fits five times
        // over, for a fraction of the memory.
        cursorBlink: true, scrollback: 40000,
        fontFamily: '"IBM Plex Mono", Consolas, monospace', fontSize: 13,
        theme: { background: '#0a0f0d', foreground: '#d7e5dd', cursor: '#e8a33d' }
      });
      s.fit = new FitAddon.FitAddon();
      s.term.loadAddon(s.fit);
      s.term.open(s.termEl);
      s.fit.fit();
      s.term.onData((d) => {
        if (s.ws && s.ws.readyState === WebSocket.OPEN) s.ws.send(JSON.stringify({ type: 'input', data: d }));
      });
      return true;
    } catch (e) {
      appLog('error', 'Failed to init terminal', { message: e.message });
      showErr(s.sshError, 'Failed to initialise the terminal: ' + e.message);
      return false;
    }
  }

  /**
   * One session path for both transports. A console session differs only
   * in the opening message and in there being no credentials to send, so
   * the terminal, the capture machinery and the teardown are shared rather
   * than duplicated.
   */
  /**
   * Close whatever session this switch has and run `then` once it is gone.
   * A tab holds one session: opening a second leaves the first running,
   * holding a serial port or a VTY line that nobody can see any more.
   */
  /** Whichever form was used, both buttons become usable again. */
  function enableConnectButtons(s) {
    if (s.sshConnect) s.sshConnect.disabled = false;
    if (s.consoleConnect) s.consoleConnect.disabled = false;
  }

  function replaceSession(s, then) {
    if (!s.ws || s.ws.readyState !== WebSocket.OPEN) { then(); return; }
    const previous = s.ws;
    let done = false;
    const go = () => { if (!done) { done = true; setTimeout(then, 400); } };
    previous.addEventListener('close', go, { once: true });
    try { previous.send(JSON.stringify({ type: 'disconnect' })); } catch (e) { /* gone */ }
    setTimeout(() => { try { previous.close(); } catch (e) {} go(); }, 2000);
  }

  /**
   * The switch answered with a different SSH host key than the one the app
   * remembered (known-hosts.js), and the server refused the connection. Say
   * so plainly with both fingerprints, and offer the one explicit way on:
   * trusting the new key, behind the two-tap confirm, then connecting again.
   * A replaced or re-keyed switch needs that click once; an impostor is
   * never let through silently.
   */
  function showHostKeyChanged(s, msg) {
    appLog('warn', 'SSH host key changed; connection refused', { host: msg.host, expected: msg.expected, presented: msg.fingerprint });
    subDot(s, 'ssh', 'err');
    s.sshStatus.textContent = 'refused: the SSH host key changed';
    const box = s.sshError;
    clear(box);
    box.style.display = 'block';
    box.appendChild(el('div', '', 'The SSH host key of ' + msg.host + ':' + msg.port + ' has changed, so the connection was refused. ' +
      'This is expected after replacing the switch or regenerating its key; otherwise someone may be impersonating it.'));
    box.appendChild(el('div', 'card-sub', 'Remembered: ' + msg.expected));
    box.appendChild(el('div', 'card-sub', 'Presented:  ' + msg.fingerprint));
    const btn = el('button', 'btn', 'Trust the new key');
    btn.type = 'button';
    withConfirm(btn, (e) => runButtonAction(e.currentTarget, {
      failLabel: 'Trust the new key',
      run: () => apiPost('/api/ssh/trust-key', { host: msg.host, port: msg.port, fingerprint: msg.fingerprint }),
      settle: () => { showErr(s.sshError, ''); sshConnect(s); return Promise.resolve(); }
    }), { label: 'Trust the new key', danger: true });
    box.appendChild(btn);
    enableConnectButtons(s);
  }

  function sshConnect(s, serialOpts) {
    const host = serialOpts ? serialOpts.path : (s.sshHost.value.trim() || s.host);
    const port = serialOpts ? serialOpts.baudRate : (parseInt(s.sshPort.value, 10) || 22);
    const username = serialOpts ? '' : s.sshUser.value;
    const password = serialOpts ? '' : s.sshPass.value;
    const errBox = serialOpts ? s.consoleError : s.sshError;
    const button = serialOpts ? s.consoleConnect : s.sshConnect;
    if (!host) { showErr(errBox, serialOpts ? 'Choose a serial port.' : 'Host is required.'); return; }
    showErr(errBox, '');

    // Connecting while something is already open replaces it rather than
    // stacking a second session behind the first.
    if (s.ws && s.ws.readyState === WebSocket.OPEN && s.sessionLive !== false && !s.replacing) {
      s.replacing = true;
      appLog('info', 'Replacing the open session', { host: s.host });
      replaceSession(s, () => { s.replacing = false; sshConnect(s, serialOpts); });
      return;
    }
    if (button) button.disabled = true;
    s.lastTransport = serialOpts ? 'serial' : 'ssh';
    s.sessionLive = true;
    paintTransport(s);
    appLog('info', serialOpts ? 'Opening console' : 'Connecting (SSH)',
      serialOpts ? { port: host, baudRate: port } : { host, port, username });

    let sock;
    try {
      const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      sock = new WebSocket(proto + '//' + window.location.host);
      s.ws = sock;
    } catch (e) {
      showErr(errBox, 'Could not open a connection to the local backend: ' + e.message);
      if (button) button.disabled = false;
      return;
    }

    sock.onopen = () => {
      if (!initTerm(s)) { sock.close(); enableConnectButtons(s); return; }
      // Only take over the screen when the user asked for a terminal; a
      // collection triggered from Quick Actions runs in the background,
      // and either way the credentials form has served its purpose.
      /**
       * What to show now the session is up.
       *
       * A terminal is opened when somebody asked for one -- the CLI
       * button, or reconnecting an existing session. Otherwise the useful
       * question is whether this switch can be polled: if not, offer to
       * set it up, because that is usually why the session was opened at
       * all. This is decided from intent rather than from transport; the
       * console form used to imply "terminal" and so skipped the offer
       * that the SSH form gave.
       */
      paintTransport(s);
      // Either an explicit request now, or one made before the
      // credentials it needed existed.
      if (s.wantTerminal || s.pendingCli) {
        s.pendingCli = false;
        openOverlay(s, 'termOverlay');
      } else if (!s.target) offerSetup(s);
      else if (s.subMode === 'ready') showView(s, 'overview');
      s.wantTerminal = false;
      fitTerm(s);
      s.sshStatus.textContent = serialOpts
        ? 'opening ' + host + ' at ' + port + ' baud'
        : 'connecting to ' + host;
      sock.send(JSON.stringify(serialOpts
        ? { type: 'serial-connect', path: host, baudRate: port }
        : { type: 'connect', host, port, username, password, ref: s.savedId || undefined, cols: s.term.cols, rows: s.term.rows }));
    };

    sock.onmessage = (ev) => {
      let msg;
      try { msg = JSON.parse(ev.data); } catch (e) { return; }
      switch (msg.type) {
        case 'status': s.sshStatus.textContent = msg.message; break;
        case 'ready':
          appLog('info', 'SSH ready', { host });
          subDot(s, 'ssh', 'on');
          s.sshStatus.textContent = 'connected \u2014 ' + host;
          s.disconnectBtn.style.display = 'inline-block';
          s.reconnectBtn.style.display = 'none';
          enableConnectButtons(s);
          s.canCapture = true;
          if (s.lastTransport !== 'serial') { s.sshEverConnected = true; saveState(); }
          // xterm outlives the session it belonged to, so without this a
          // reconnect opens onto the last session's output -- including a
          // tech-support capture, which fills the screen entirely.
          s.term.reset();
          fitTerm(s);
          s.sshBuffer += '\n===== SSH session ' + new Date().toISOString() + ' \u2014 ' + host + ' =====\n';
          if (s.techPending) {
            // Credentials were the only thing missing; run it now.
            s.techPending = false;
            appLog('info', 'SSH ready \u2014 running the queued tech-support collection', { host });
            runTechCommand(s);
          }
          break;
        case 'data':
          s.term.write(msg.data);
          s.sshBuffer += stripAnsi(msg.data);
          s.sshSave.disabled = false;
          break;
        case 'ended':
          appLog('info', msg.message, { host });
          // The far end is gone whatever the socket thinks.
          s.sessionLive = false;
          paintTransport(s);
          cancelTechPending(s);
          s.term.write('\r\n\x1b[33m*** ' + msg.message + ' ***\x1b[0m\r\n');
          subDot(s, 'ssh', '');
          s.sshStatus.textContent = 'disconnected \u2014 ' + msg.message;
          s.canCapture = false; s.capturing = false;
          s.disconnectBtn.style.display = 'none';
          s.reconnectBtn.style.display = 'inline-block';
          enableConnectButtons(s);
          break;
        case 'error':
          appLog('error', msg.message, { host });
          cancelTechPending(s);
          subDot(s, 'ssh', 'err');
          s.sshStatus.textContent = 'error: ' + msg.message;
          showErr(s.sshError, msg.message);
          enableConnectButtons(s);
          s.disconnectBtn.style.display = 'none';
          s.reconnectBtn.style.display = 'inline-block';
          break;
        case 'hostkey-changed':
          showHostKeyChanged(s, msg);
          break;
        case 'exec-started':
          s.capturing = true;
          s.sshStatus.textContent = 'collecting ' + msg.command + '\u2026';
          setTechCollecting(s, 'Collecting show tech-support over SSH\u2026');
          appLog('info', 'tech-support collection started', { host });
          break;
        case 'exec-progress':
          s.sshStatus.textContent = 'collecting\u2026 ' + msg.bytes.toLocaleString() + ' bytes, ' + msg.seconds + 's';
          setTechCollecting(s, 'Collecting\u2026 ' + msg.bytes.toLocaleString() + ' bytes, ' + msg.seconds + 's');
          break;
        case 'exec-error':
          s.capturing = false;
          setTechCollecting(s, null);
          s.techStatus.textContent = 'collection failed: ' + msg.message;
          appLog('error', 'tech-support failed', { host, message: msg.message });
          s.sshStatus.textContent = 'collection failed: ' + msg.message;
          break;
        case 'exec-done':
          s.capturing = false;
          s.sshStatus.textContent = 'connected \u2014 ' + host;
          setTechCollecting(s, null);
          // A tech-support capture leaves several hundred kilobytes on the
          // screen and the cursor somewhere in the middle of it. The
          // output is safe in the viewer, so the terminal is cleared and
          // the switch nudged for a fresh prompt -- otherwise the session
          // is technically usable and practically not.
          if (s.term && s.ws && s.ws.readyState === WebSocket.OPEN) {
            clearTerminal(s, true);
            s.term.write('\u2014 capture finished, ' + msg.bytes.toLocaleString() +
              ' bytes; screen cleared \u2014\r\n');
          }
          appLog('info', 'tech-support collected', { host, bytes: msg.bytes, seconds: msg.seconds, reason: msg.reason });
          if (!msg.text || msg.bytes < 200) {
            s.techStatus.textContent = 'the switch returned almost no output';
            appLog('warn', 'tech-support output looked empty', { host, bytes: msg.bytes });
            break;
          }
          loadTech(s, msg.text, 'collected ' + msg.seconds + 's ago from ' + host);
          break;
      }
    };

    sock.onclose = () => {
      s.sessionLive = false;
      // The request does not outlive the attempt: a session that ends must
      // not reopen a terminal the next time one is made for another reason.
      s.pendingCli = false;
      enableConnectButtons(s);
      s.disconnectBtn.style.display = 'none';
      s.reconnectBtn.style.display = 'inline-block';
      // The switch of transports has to stop claiming something is live
      // when it is not, or the next click looks like it did nothing.
      paintTransport(s);
      loadSessions(s);
    };
    sock.onerror = () => {
      appLog('error', 'WebSocket error reaching the backend', { host });
      cancelTechPending(s);
      subDot(s, 'ssh', 'err');
      showErr(s.sshError, 'Could not reach the local backend server.');
      enableConnectButtons(s);
    };
  }
