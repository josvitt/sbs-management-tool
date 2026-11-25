  // =================================================================
  // 12-syslog-events.js: Syslog and Events panels.
  // =================================================================

  // ---------- syslog panel ----------
  // Two things at once: what has arrived from this switch, and whether the
  // switch is actually configured to send it. A log view that is silently
  // empty because nobody pointed the switch at it is worse than useless,
  // so the state of the plumbing is shown alongside the messages.
  const SEV_CLASS = {
    Emergency: 'crit', Alert: 'crit', Critical: 'crit', Error: 'crit',
    Warning: 'warn', Notice: 'good', Info: 'good', Debug: 'idle', Unknown: 'idle'
  };

  /**
   * Live tail. Server-sent events rather than polling: messages arrive as
   * the switch emits them, and the browser reconnects on its own if the
   * link drops. New rows are inserted into the existing table rather than
   * repainting the panel, so a busy switch does not make the page flicker
   * or fight whatever the user is reading.
   */
  function startSyslogStream(s) {
    if (!s.host || s.syslogStream) return;
    try {
      const es = new EventSource('/api/syslog/stream?host=' + encodeURIComponent(s.host));
      s.syslogStream = es;
      es.onopen = () => { s.syslogLive = true; paintSyslogLiveState(s); };
      es.onerror = () => { s.syslogLive = false; paintSyslogLiveState(s); };
      es.onmessage = (ev) => {
        let payload;
        try { payload = JSON.parse(ev.data); } catch (e) { return; }
        onSyslogMessage(s, payload);
      };
      appLog('info', 'Syslog live stream opened', { host: s.host });
    } catch (e) {
      appLog('warn', 'Could not open the syslog stream', { message: e.message });
    }
  }

  function stopSyslogStream(s) {
    if (!s.syslogStream) return;
    try { s.syslogStream.close(); } catch (e) {}
    s.syslogStream = null;
    s.syslogLive = false;
  }

  /** Does an incoming message survive the filters currently on screen? */
  function syslogMatches(s, m) {
    if (s.syslogSeverity !== undefined && s.syslogSeverity !== null && s.syslogSeverity !== '') {
      if (m.severity !== null && m.severity > Number(s.syslogSeverity)) return false;
    }
    if (s.syslogSearch) {
      if (String(m.raw || '').toLowerCase().indexOf(String(s.syslogSearch).toLowerCase()) < 0) return false;
    }
    return true;
  }

  function onSyslogMessage(s, payload) {
    const m = payload.message;
    if (!s.syslog) s.syslog = { messages: [], total: 0, held: 0, matched: 0 };
    s.syslog.total = payload.total !== undefined ? payload.total : (s.syslog.total + 1);
    s.syslog.lastAt = m.at;

    if (!syslogMatches(s, m)) { paintSyslogLiveState(s); return; }

    s.syslog.messages.unshift(m);
    s.syslog.matched = (s.syslog.matched || 0) + 1;
    if (s.syslog.messages.length > 300) s.syslog.messages.pop();

    // Insert into the live table when one is on screen; otherwise the next
    // paint will pick it up from s.syslog.
    const tbody = s.syslogTable;
    if (tbody && tbody.isConnected) {
      const row = syslogRow(m);
      row.classList.add('syslog-new');
      const first = tbody.querySelector('tr:not(:first-child)');
      if (first) tbody.insertBefore(row, first);
      else tbody.appendChild(row);
      while (tbody.querySelectorAll('tr').length > 301) tbody.removeChild(tbody.lastChild);
      setTimeout(() => row.classList.remove('syslog-new'), 1500);
    } else {
      repaintSyslog(s);
    }
    paintSyslogLiveState(s);
  }

  function syslogRow(m) {
    const tr = document.createElement('tr');
    tr.appendChild(el('td', 'col-value', new Date(m.at).toLocaleTimeString()));
    const sc = document.createElement('td');
    sc.appendChild(el('span', 'pill ' + (SEV_CLASS[m.severityName] || 'idle'), m.severityName));
    tr.appendChild(sc);
    tr.appendChild(el('td', 'col-name', m.mnemonic || m.tag || m.facilityName || ''));
    tr.appendChild(el('td', 'col-value', m.message));
    return tr;
  }

  /** Update just the counter and the live badge, without a repaint. */
  function paintSyslogLiveState(s) {
    if (s.syslogCountEl && s.syslogCountEl.isConnected && s.syslog) {
      s.syslogCountEl.textContent = (s.syslog.total || 0).toLocaleString() +
        ' message(s) from ' + s.host +
        (s.syslog.lastAt ? '  \u00b7  last ' + new Date(s.syslog.lastAt).toLocaleTimeString() : '');
    }

  }

  /** Just the fetch, so the merged panel can await it without repainting. */
  function fetchSyslog(s) {
    const body = { host: s.host, limit: 300, maxSeverity: s.syslogSeverity, search: s.syslogSearch };
    return Promise.all([
      fetch('/api/syslog/messages', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
      }).then((r) => r.json()),
      s.target
        ? fetch('/api/syslog/collectors', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target: s.target })
          }).then((r) => r.json()).catch((e) => ({ error: e.message }))
        : Promise.resolve(null)
    ]).then(([messages, collectors]) => {
      s.syslog = messages;
      if (collectors) s.syslogCollectors = collectors;
    }).catch((e) => { s.syslogError = e.message; });
  }

  function loadSyslog(s, panel) {
    s.syslogBusy = true;
    repaintSyslog(s);
    const body = { host: s.host, limit: 300, maxSeverity: s.syslogSeverity, search: s.syslogSearch };
    Promise.all([
      fetch('/api/syslog/messages', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
      }).then((r) => r.json()),
      s.target
        ? fetch('/api/syslog/collectors', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target: s.target })
          }).then((r) => r.json()).catch((e) => ({ error: e.message }))
        : Promise.resolve(null)
    ]).then(([messages, collectors]) => {
      s.syslogBusy = false;
      s.syslog = messages;
      if (collectors) s.syslogCollectors = collectors;
      repaintSyslog(s);
    }).catch((e) => {
      s.syslogBusy = false;
      s.syslogError = e.message;
      repaintSyslog(s);
    });
  }

  function repaintSyslog(s) {
    const panel = s.panels.find((p) => p.kind === 'builtin' && p.key === 'events');
    if (panel && panel._body) {
      const keep = panel._body.scrollTop;
      paintPanelBody(s, panel);
      panel._body.scrollTop = keep;
    }
  }

  /**
   * Events: syslog and traps in one list.
   *
   * They answer the same question over two transports -- one is what the
   * switch wrote down, the other what it interrupted us about -- and
   * keeping them apart meant reading two panels to reconstruct one
   * sequence. Merged by time, with a column saying which arrived how.
   */
  function loadEvents(s, p) {
    // Both sources, then paint once they are both in: two half-populated
    // repaints in quick succession is worse than one complete one.
    Promise.all([
      fetchSyslog(s),
      fetch('/api/traps/messages', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ host: s.host, limit: 300 })
      }).then((r) => r.json()).catch(() => null)
    ]).then(([, trapData]) => {
      s.traps = trapData;
      if (p._body) paintPanelBody(s, p);
    });
  }

  /** One row shape for both, so the list reads as a single sequence. */
  function eventRows(s) {
    // Which sources to show. Default: syslog only — traps are off until the
    // user ticks them. Initialised once so the choice persists across repaints.
    if (!s.eventSources) s.eventSources = { syslog: true, trap: false };
    const rows = [];
    if (s.eventSources.syslog) {
      const sys = (s.syslog && s.syslog.messages) || [];
      for (const m of sys) {
        rows.push({
          at: m.at, kind: 'syslog', severity: m.severityName || 'info',
          what: m.mnemonic || m.severityName || 'message',
          detail: m.message
        });
      }
    }
    if (s.eventSources.trap) {
      const traps = (s.traps && s.traps.messages) || [];
      for (const m of traps) {
        rows.push({
          at: m.at, kind: 'trap', severity: m.severity,
          what: m.name,
          detail: m.varbinds.map((v) => v.name.replace(/\.\d+$/, '') + ' ' + v.value).join('  \u00b7  ')
        });
      }
    }
    rows.sort((a, b) => new Date(b.at) - new Date(a.at));
    return rows;
  }

  function paintEventsPanel(s, body) {
    startSyslogStream(s);
    startTrapStream(s);

    // Painting is not fetching. Expanding the panel calls straight in
    // here, so without this it draws an empty list from data nobody asked
    // for -- and then looks broken until the next refresh.
    // Either source missing is enough: a trap that arrived while this
    // panel was folded clears the held copy precisely so the next paint
    // goes and gets it.
    if ((!s.syslog || !s.traps) && !s.eventsLoading) {
      s.eventsLoading = true;
      const panel = s.panels.find((x) => x.key === 'events');
      if (panel) {
        loadEvents(s, panel);
        body.appendChild(el('div', 'empty-state', 'Reading events\u2026'));
        return;
      }
    }
    s.eventsLoading = false;

    const rows = eventRows(s);
    const receiver = (s.syslog && s.syslog.receiver) || null;

    const bar = el('div', 'syslog-bar');
    const counts = [];
    if (s.syslog && s.syslog.total) counts.push(s.syslog.total.toLocaleString() + ' syslog');
    if (s.traps && s.traps.total) counts.push(s.traps.total.toLocaleString() + ' trap(s)');
    bar.appendChild(el('span', 'card-sub', counts.length
      ? counts.join('  \u00b7  ') + '  from ' + s.host : ''));
    body.appendChild(bar);

    // The offer to point the switch at us belongs here, since this is
    // where its messages would appear.
    const cfg = s.syslogCollectors;
    if (cfg && !cfg.error && !cfg.configured && !(cfg.heard && cfg.heard.total)) {
      body.appendChild(buildSyslogOffer(s, cfg));
    }

    const tools = el('div', 'event-tools');

    // Source selector: syslog on by default, traps opt-in.
    if (!s.eventSources) s.eventSources = { syslog: true, trap: false };
    const srcWrap = el('span', 'event-sources');
    const srcBox = (key, labelText) => {
      const lab = el('label', 'check-label');
      const cb = el('input'); cb.type = 'checkbox'; cb.checked = !!s.eventSources[key];
      cb.addEventListener('change', () => {
        s.eventSources[key] = cb.checked;
        const p = s.panels.find((x) => x.key === 'events');
        if (p) paintPanelBody(s, p);   // re-render with the new source set
      });
      lab.appendChild(cb); lab.appendChild(el('span', '', labelText));
      return lab;
    };
    srcWrap.appendChild(srcBox('syslog', 'Syslog'));
    srcWrap.appendChild(srcBox('trap', 'Traps'));
    tools.appendChild(srcWrap);

    const sev = document.createElement('select');
    for (const [value, label] of [['', 'All severities'], ['3', 'Error and worse'],
      ['4', 'Warning and worse'], ['5', 'Notice and worse'], ['6', 'Info and worse']]) {
      const o = document.createElement('option');
      o.value = value; o.textContent = label;
      sev.appendChild(o);
    }
    sev.value = s.syslogSeverity || '';
    sev.addEventListener('change', () => {
      s.syslogSeverity = sev.value;
      const p = s.panels.find((x) => x.key === 'events');
      if (p) loadEvents(s, p);
    });
    tools.appendChild(sev);

    const search = document.createElement('input');
    search.type = 'search';
    search.className = 'search-input';
    search.placeholder = 'Search events\u2026';
    search.value = s.syslogSearch || '';
    search.addEventListener('input', () => {
      s.syslogSearch = search.value;
      clearTimeout(s.eventSearchTimer);
      s.eventSearchTimer = setTimeout(() => {
        const p = s.panels.find((x) => x.key === 'events');
        if (p) loadEvents(s, p);
      }, 250);
    });
    tools.appendChild(search);
    body.appendChild(tools);

    if (!rows.length) {
      body.appendChild(el('div', 'empty-state', receiver && receiver.listening
        ? 'Nothing from ' + s.host + ' yet \u2014 syslog and traps appear here as they arrive.'
        : 'Neither receiver is running, so nothing can arrive.'));
      return;
    }

    const table = document.createElement('table');
    table.className = 'data-table';
    const thead = document.createElement('thead');
    const hr = document.createElement('tr');
    for (const h of ['Time', 'Via', 'What', 'Detail']) {
      const th = document.createElement('th'); th.textContent = h; hr.appendChild(th);
    }
    thead.appendChild(hr); table.appendChild(thead);
    const tbody = document.createElement('tbody');
    for (const r of rows) tbody.appendChild(eventRow(r));
    table.appendChild(tbody);
    const scroll = el('div', 'table-scroll');
    scroll.appendChild(table);
    body.appendChild(scroll);
    s.eventTable = tbody;
  }

  function eventRow(r) {
    const tr = document.createElement('tr');
    const time = document.createElement('td');
    time.className = 'col-value';
    time.textContent = new Date(r.at).toLocaleTimeString();
    tr.appendChild(time);

    const via = document.createElement('td');
    via.appendChild(el('span', 'pill ' + (r.kind === 'trap' ? 'info' : 'idle'), r.kind));
    tr.appendChild(via);

    const what = document.createElement('td');
    what.appendChild(el('span', 'pill ' + severityClass(r.severity), r.what));
    tr.appendChild(what);

    const detail = document.createElement('td');
    detail.className = 'col-value';
    detail.textContent = r.detail;
    tr.appendChild(detail);
    return tr;
  }

  function severityClass(sev) {
    if (/emerg|alert|crit/i.test(sev)) return 'crit';
    if (/err|warn/i.test(sev)) return 'warn';
    return 'ok';
  }

  function paintSyslogPanel(s, body) {
    startSyslogStream(s);
    const data = s.syslog;
    const cfg = s.syslogCollectors;

    // --- receiver state ---
    // Only the count. Whether the receiver is bound and whether the
    // stream is connected are the app's problems, not the operator's --
    // and they are already visible in the messages arriving or not.
    const bar = el('div', 'syslog-bar');
    const receiver = (data && data.receiver) || (cfg && cfg.receiver);
    const count = el('span', 'card-sub', data && data.total !== undefined
      ? data.total.toLocaleString() + ' message(s) from ' + s.host +
        (data.lastAt ? '  \u00b7  last ' + new Date(data.lastAt).toLocaleTimeString() : '')
      : '');
    bar.appendChild(count);
    s.syslogCountEl = count;
    s.syslogLiveEl = null;
    body.appendChild(bar);

    if (receiver && !receiver.listening) {
      body.appendChild(el('div', 'panel-err',
        'The syslog receiver could not start: ' + (receiver.error || 'unknown reason') +
        ' Nothing can be collected until it is listening.'));
    }

    // --- is the switch pointed at us? ---
    // Only two states are worth saying anything about: it is not
    // configured (so offer to fix it), or it is configured but cannot
    // work. A switch that is set up correctly needs no commentary.
    if (cfg && !cfg.error) {
      const heard = cfg.heard && cfg.heard.total;
      if (!cfg.configured && !heard) {
        body.appendChild(buildSyslogOffer(s, cfg));
      } else if (cfg.configured) {
        const m = cfg.matching || {};
        const listenPort = receiver && receiver.port;
        if (listenPort && m.udpPort && Number(m.udpPort) !== Number(listenPort)) {
          body.appendChild(el('div', 'panel-err',
            'The switch is sending to port ' + m.udpPort + ', but this receiver is listening on ' +
            listenPort + ', so nothing will arrive.'));
        }
        if (cfg.globalEnabled === false) {
          body.appendChild(el('div', 'panel-err',
            'Logging is globally disabled on this switch, so the collector will receive nothing.'));
        }
      }
    } else if (cfg && cfg.error) {
      body.appendChild(el('div', 'panel-note',
        'Could not read the switch\u2019s syslog configuration: ' + cfg.error));
    }

    if (s.syslogError) {
      const err = el('div', 'panel-err', s.syslogError);
      err.style.whiteSpace = 'pre-wrap';   // the failure lists each table it tried
      body.appendChild(err);
    }
    if (s.syslogBusy && !data) { body.appendChild(el('div', 'card-sub', 'Loading\u2026')); return; }
    if (!data) {
      body.appendChild(el('div', 'card-sub', 'Press Reload to read collected messages.'));
      return;
    }

    // --- filters ---
    const filters = el('div', 'syslog-bar');
    const sev = document.createElement('select');
    sev.className = 'interval-input';
    sev.style.width = 'auto';
    for (const [value, label] of [['', 'All severities'], ['3', 'Error and worse'],
      ['4', 'Warning and worse'], ['5', 'Notice and worse'], ['6', 'Info and worse']]) {
      const o = document.createElement('option');
      o.value = value; o.textContent = label;
      sev.appendChild(o);
    }
    sev.value = s.syslogSeverity || '';
    sev.addEventListener('change', () => { s.syslogSeverity = sev.value; loadSyslog(s); });
    filters.appendChild(sev);

    const search = document.createElement('input');
    search.type = 'search';
    search.className = 'search-input';
    search.placeholder = 'Search messages\u2026';
    search.value = s.syslogSearch || '';
    let deb = null;
    search.addEventListener('input', () => {
      clearTimeout(deb);
      deb = setTimeout(() => { s.syslogSearch = search.value; loadSyslog(s); }, 300);
    });
    filters.appendChild(search);
    filters.appendChild(el('span', 'card-sub',
      data.matched !== undefined
        ? data.matched.toLocaleString() + ' matching, showing ' + data.messages.length
        : ''));
    body.appendChild(filters);

    if (!data.messages.length) {
      body.appendChild(el('div', 'empty-state', data.total
        ? 'No messages match the current filter.'
        : 'Waiting for messages from ' + s.host + ' \u2014 they appear here as they arrive.'));
      s.syslogTable = null;
      return;
    }

    const wrap = el('div', 'table-scroll');
    const t = el('table', 'data-table');
    const hr = document.createElement('tr');
    for (const h of ['Received', 'Severity', 'Facility', 'Message']) hr.appendChild(el('th', '', h));
    t.appendChild(hr);
    for (const m of data.messages) t.appendChild(syslogRow(m));
    wrap.appendChild(t);
    body.appendChild(wrap);
    // Held so arriving messages can be inserted without a repaint.
    s.syslogTable = t;
  }

  /** The offer to point the switch at us. Writes to the device, so it asks. */
  function buildSyslogOffer(s, cfg) {
    const box = el('div', 'cfg-sync');
    box.appendChild(el('div', 'card-sub',
      'This switch is not sending syslog here. ' + cfg.ourAddress +
      ' is not listed among its collectors' +
      (cfg.collectors && cfg.collectors.length
        ? ' (it has ' + cfg.collectors.length + ' other collector(s) configured).'
        : ' (it has none configured).')));

    const row = el('div', 'cfg-confirm');
    row.style.display = 'flex';
    const sev = document.createElement('select');
    sev.className = 'interval-input';
    sev.style.width = 'auto';
    for (const [value, label] of [['3', 'Error and worse'], ['4', 'Warning and worse'],
      ['5', 'Notice and worse'], ['6', 'Info and worse'], ['7', 'Everything, including debug']]) {
      const o = document.createElement('option');
      o.value = value; o.textContent = label;
      sev.appendChild(o);
    }
    sev.value = '6';
    row.appendChild(el('span', 'card-sub', 'Send'));
    row.appendChild(sev);

    const go = el('button', 'btn btn-amber', 'Configure this switch');
    go.type = 'button'; go.style.width = 'auto';
    const confirm = el('div', 'cfg-confirm');
    confirm.style.display = 'none';

    go.addEventListener('click', () => {
      clear(confirm);
      confirm.appendChild(el('span', 'card-sub',
        'Add ' + cfg.ourAddress + ':' + ((cfg.receiver && cfg.receiver.port) || 514) +
        ' to the syslog collectors on ' + s.host + '? This writes to the switch.'));
      const yes = el('button', 'btn btn-danger', 'Yes, configure it');
      yes.type = 'button'; yes.style.width = 'auto';
      const no = el('button', 'btn', 'Cancel');
      no.type = 'button'; no.style.width = 'auto';
      no.addEventListener('click', () => { confirm.style.display = 'none'; go.style.display = ''; });
      yes.addEventListener('click', () => configureSyslog(s, sev.value));
      confirm.appendChild(yes); confirm.appendChild(no);
      confirm.style.display = 'flex';
      go.style.display = 'none';
    });
    row.appendChild(go);
    box.appendChild(row);
    box.appendChild(confirm);
    return box;
  }

  function configureSyslog(s, severity) {
    s.syslogBusy = true; s.syslogError = null;
    repaintSyslog(s);
    appLog('info', 'Configuring switch to send syslog here', { host: s.host, severity });
    fetch('/api/syslog/configure', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: s.target, severity: Number(severity) })
    })
      .then((r) => r.json().then((b) => ({ ok: r.ok, body: b })))
      .then(({ ok, body }) => {
        s.syslogBusy = false;
        if (!ok || body.error) {
          s.syslogError = body.error || 'Could not configure the switch.';
          appLog('error', 'Syslog configuration failed', { host: s.host, message: s.syslogError });
          repaintSyslog(s);
          return;
        }
        appLog('info', 'Switch configured to send syslog here', {
          host: s.host, address: body.address, port: body.port, severity: body.severityName
        });
        // Re-read so the panel proves the change rather than asserting it.
        loadSyslog(s);
      })
      .catch((e) => { s.syslogBusy = false; s.syslogError = e.message; repaintSyslog(s); });
  }
