  // =================================================================
  // 21-tech-support.js: show tech-support collection and viewer.
  // =================================================================

  // =================================================================
  // Tech-support
  // =================================================================
  // Collection is triggered from the Configuration panel, alongside the
  // running and startup configs -- one place to pull files off the switch.
  // The capture then gets its own tab for section-by-section browsing.

  function initTech(s) {
    s.techSave.addEventListener('click', () =>
      download('tech-' + safeHost(s.host) + '-' + stamp() + '.log', s.techRaw));
    let deb = null;
    s.techSearch.addEventListener('input', () => {
      clearTimeout(deb);
      deb = setTimeout(() => { renderTechNav(s); renderTechPane(s); }, 180);
    });
  }

  /**
   * Collect a capture. If a shell is already open the command runs
   * immediately; otherwise the request is remembered, the user is sent to
   * the SSH tab to enter credentials, and the command fires by itself as
   * soon as the shell is ready. Asking for credentials should be the only
   * manual step -- having to come back and press the button again is just
   * a second thing to remember.
   */
  function startTechCollect(s) {
    if (s.capturing) return;
    if (s.ws && s.ws.readyState === WebSocket.OPEN && s.canCapture) {
      runTechCommand(s);
      setTechCollecting(s, 'Collecting show tech-support over SSH\u2026');
      return;
    }
    // No session yet. The command runs the same over either transport, so
    // take whichever route is set up -- console first, for the same reason
    // the CLI button prefers it.
    s.techPending = true;
    if (hasConsole(s)) {
      setTechCollecting(s, 'Opening the console\u2026');
      appLog('info', 'tech-support queued; opening the console first', { host: s.host });
      openConsole(s, s.consoleTarget.path, s.consoleTarget.baudRate, false);
      return;
    }
    setTechCollecting(s, 'Waiting for SSH credentials\u2026');
    appLog('info', 'tech-support queued; SSH credentials needed first', { host: s.host });
    if (s.subMode !== 'ready') selectCredCard(s, 'ssh');
    showView(s, 'creds');
    if (!s.sshHost.value) s.sshHost.value = s.host || '';
    (s.sshUser.value ? s.sshPass : s.sshUser).focus();
  }

  function runTechCommand(s) {
    s.ws.send(JSON.stringify({
      type: 'exec', command: 'show tech-support', idleMs: 8000, maxMs: 900000,
      // Keep the session only if the terminal is on screen; a collection
      // from Quick Actions has no other use for it.
      keepOpen: s.termOverlay.classList.contains('open')
    }));
  }

  function cancelTechPending(s) {
    if (!s.techPending) return;
    s.techPending = false;
    setTechCollecting(s, null);
  }

  /** Drive the Tech-Support page's own busy state. */
  function setTechCollecting(s, message) {
    s.techBusy = message || null;
    if (s.techStatus) s.techStatus.textContent = message || (s.tech ? s.techStatus.textContent : 'no capture');
    // The button lives in Quick Actions, which is part of the Overview
    // panel, so the panel is what needs repainting.
    repaintPanel(s, 'summary');
  }

  /** Repaint one built-in panel in place. */
  // The dashboard does NOT scroll the window - the panel grid lives inside a
  // .scroll-body element with overflow-y:auto, so that element is what scrolls.
  // window.scrollY/scrollTo therefore do nothing here. scrollKeeper captures the
  // real container's scrollTop and returns a restore fn to call after a rebuild,
  // so clearing a panel (which momentarily collapses the page) never jumps the
  // view. Returns a no-op restore if the container can't be found.
  function scrollKeeper(s) {
    const box = (s && s.grid && (s.grid.closest ? s.grid.closest('.scroll-body') : null)) ||
      document.querySelector('.subview.active .scroll-body') || null;
    if (!box) return function () {};
    const top = box.scrollTop, left = box.scrollLeft;
    return function () { if (box.scrollTop !== top) box.scrollTop = top; if (box.scrollLeft !== left) box.scrollLeft = left; };
  }

  function repaintPanel(s, key) {
    const panel = s.panels && s.panels.find((p) => p.kind === 'builtin' && p.key === key);
    if (panel && panel._body) {
      // Preserve the panel's own inner scroll AND the dashboard scroll container,
      // so a single-panel repaint (e.g. the config badge flip) never jumps the
      // whole view - clearing a panel briefly collapses the page height.
      const keep = panel._body.scrollTop;
      const restore = scrollKeeper(s);
      paintPanelBody(s, panel);
      panel._body.scrollTop = keep;
      restore();
    }
  }

  function loadTech(s, text, note) {
    s.techRaw = text;
    s.techNote = note || '';
    try {
      s.tech = TechParse.parse(text);
    } catch (e) {
      appLog('error', 'Could not parse tech-support capture', { message: e.message });
      return;
    }
    // Open on the whole capture, not on whichever section happens to be
    // first -- that is the command echo, which tells you nothing.
    s.techSection = FULL_OUTPUT;
    s.techSave.disabled = false;
    subDot(s, 'tech', 'on');
    enableSubtab(s, 'tech', true);
    s.techStatus.textContent = (s.techNote ? s.techNote + '  \u00b7  ' : '') +
      s.tech.order.length + ' sections  \u00b7  ' + text.split('\n').length.toLocaleString() + ' lines';

    // The capture feeds the viewer and the Configuration panel's document
    // list. The dashboard stays a live SNMP view, so collecting one must
    // not change what it shows.
    renderTechNav(s);
    renderTechPane(s);
    // Show the capture the moment it lands: it is what was asked for.
    // Quick Actions gains a "view" button now that there is one to view.
    repaintPanel(s, 'summary');
    openOverlay(s, 'techOverlay');
    appLog('info', 'tech-support parsed', {
      sections: s.tech.order.length, host: s.host, note: s.techNote
    });
  }

  function techTable(parsed, opts) {
    opts = opts || {};
    const wrap = el('div', 'table-scroll');
    const t = el('table', 'data-table wide');
    const hr = document.createElement('tr');
    for (const h of parsed.headers) hr.appendChild(el('th', '', h));
    t.appendChild(hr);
    for (const r of parsed.rows) {
      const tr = document.createElement('tr');
      parsed.headers.forEach((h, i) => {
        const v = r[h] !== undefined ? r[h] : (r._cells ? r._cells[i] : '');
        if (opts.stateCols && opts.stateCols.test(h) && v) {
          const td = document.createElement('td');
          td.appendChild(el('span', 'pill ' + stateClass(String(v)), v));
          tr.appendChild(td);
        } else tr.appendChild(el('td', 'col-value', v));
      });
      t.appendChild(tr);
    }
    wrap.appendChild(t);
    return wrap;
  }

  function logTable(logging) {
    const wrap = el('div', 'table-scroll');
    const t = el('table', 'data-table');
    const hr = document.createElement('tr');
    for (const h of ['Severity', 'When', 'Facility', 'Message']) hr.appendChild(el('th', '', h));
    t.appendChild(hr);
    for (const e of logging.entries.slice().sort((a, b) => a.rank - b.rank)) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.appendChild(el('span', 'sev-tag sev-' + e.sevName, e.sevName));
      tr.appendChild(td);
      tr.appendChild(el('td', 'col-value', e.when));
      tr.appendChild(el('td', 'col-name', e.facility + '-' + e.mnemonic));
      tr.appendChild(el('td', 'col-value', e.message));
      t.appendChild(tr);
    }
    wrap.appendChild(t);
    return wrap;
  }

  // ---------- section rail ----------
  function renderTechNav(s) {
    if (!s.tech) { clear(s.techNav); return; }
    const q = s.techSearch.value.trim().toLowerCase();
    clear(s.techNav);

    const addItem = (name, label, count) => {
      const item = el('div', 'tech-item' + (name === s.techSection ? ' active' : ''));
      if (count != null) item.appendChild(el('span', 'lines', count));
      item.appendChild(document.createTextNode(label));
      item.title = label;
      item.addEventListener('click', () => {
        s.techSection = name;
        renderTechNav(s);
        renderTechPane(s);
      });
      s.techNav.appendChild(item);
      return item;
    };

    // Whole capture first, and selected by default.
    let wholeHits = 0;
    if (q) for (const ln of s.techRaw.split('\n')) if (ln.toLowerCase().includes(q)) wholeHits++;
    s.techNav.appendChild(el('div', 'tech-nav-group', 'Everything'));
    const whole = addItem(FULL_OUTPUT, 'Full output', s.techRaw.split('\n').length);
    if (wholeHits) whole.appendChild(el('span', 'hits', wholeHits + ' hit' + (wholeHits === 1 ? '' : 's')));

    const key = s.tech.order.filter((n) => KEY_SECTIONS.some((k) => n.toLowerCase() === k));
    const rest = s.tech.order.filter((n) => key.indexOf(n) < 0);

    const group = (title, names) => {
      if (!names.length) return;
      const g = el('div', 'tech-nav-group', title);
      s.techNav.appendChild(g);
      let any = false;
      for (const n of names) {
        const lines = s.tech.secs[n] || [];
        let hits = 0;
        if (q) {
          for (const ln of lines) if (ln.toLowerCase().includes(q)) hits++;
          if (!hits && n.toLowerCase().indexOf(q) < 0) continue;
        }
        const it = addItem(n, n, lines.length);
        if (hits) it.appendChild(el('span', 'hits', hits + ' hit' + (hits === 1 ? '' : 's')));
        any = true;
      }
      if (!any) g.remove();
    };
    group('Key sections', key);
    group('All output', rest);
  }

  // Sections worth promoting: an operator looks at these first.
  const KEY_SECTIONS = [
    'show system', 'show version', 'show inventory', 'show stack',
    'show interfaces status', 'show interfaces counters', 'show power inline',
    'show power inline all interfaces', 'show vlan', 'show cdp neighbors',
    'show lldp neighbors', 'spanning tree info', 'show mac address-table',
    'show errdisable interfaces', 'show logging', 'show logging file',
    'show running-config'
  ];

  function highlightInto(pre, lines, q) {
    if (!q) { pre.textContent = lines.join('\n'); return; }
    const rx = new RegExp('(' + q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + ')', 'ig');
    for (const ln of lines) {
      let last = 0, m; rx.lastIndex = 0;
      while ((m = rx.exec(ln)) !== null) {
        pre.appendChild(document.createTextNode(ln.slice(last, m.index)));
        pre.appendChild(el('mark', '', m[0]));
        last = m.index + m[0].length;
      }
      pre.appendChild(document.createTextNode(ln.slice(last) + '\n'));
    }
  }

  function renderTechPane(s) {
    if (!s.tech) {
      clear(s.techPane);
      s.techPane.appendChild(el('div', 'empty-state',
        'No capture yet. Use Collect tech-support above \u2014 it runs the command over SSH, ' +
        'asking for credentials first if no session is open.'));
      return;
    }
    const pane = s.techPane;
    const q = s.techSearch.value.trim();
    clear(pane);

    if (s.techSection === FULL_OUTPUT) {
      const st = el('div', 'section-title', 'Full output');
      st.appendChild(el('span', 'st-note',
        s.tech.order.length + ' sections \u00b7 ' + s.techRaw.split('\n').length.toLocaleString() + ' lines'));
      pane.appendChild(st);
      const pre = document.createElement('pre');
      highlightInto(pre, s.techRaw.replace(/\r/g, '').split('\n'), q);
      pane.appendChild(pre);
      pane.scrollTop = 0;
      return;
    }

    const lines = s.tech.secs[s.techSection] || [];
    pane.appendChild(el('div', 'section-title', s.techSection));

    // Render every table the section contains, then the raw text: the
    // fixed-width parsing is a heuristic and the original is the truth.
    for (const t of TechParse.parseAllTables(lines)) {
      pane.appendChild(techTable({ headers: t.headers, rows: t.rows },
        { stateCols: /state|status|oper|admin/i }));
      pane.appendChild(el('div', 'card-sub', t.rows.length + ' rows parsed'));
    }
    pane.appendChild(el('div', 'section-title', 'Raw output'));
    const pre = document.createElement('pre');
    highlightInto(pre, lines, q);
    pane.appendChild(pre);
    pane.scrollTop = 0;
  }
