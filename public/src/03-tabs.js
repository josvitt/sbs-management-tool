  // =================================================================
  // 03-tabs.js: Switch tabs: create, select, close, reopen and reorder; sub-tabs and overlays.
  // =================================================================

  // =================================================================
  // Switch tabs
  // =================================================================
  const tabStrip = document.getElementById('tab-strip');
  const switchesEl = document.getElementById('switches');
  const switchTpl = document.getElementById('switch-template');
  const switches = new Map();
  let activeId = null;
  let counter = 0;
  let dragTab = null;

  const newSwitchBtn = document.getElementById('new-switch');

  /**
   * The topology is a tab, not a button in the corner.
   *
   * It is a view of the estate in the same way each other tab is a view of
   * one switch, so it belongs in the same row and is navigated the same
   * way. It has no close control: closing it would mean nothing, since
   * there is nothing behind it to close.
   *
   * It appears once there is a switch to draw and stays for as long as any
   * switch exists, open or merely put away.
   */
  const topoTab = el('div', 'tab topo-tab');
  topoTab.appendChild(el('span', 'tab-dot'));
  topoTab.appendChild(el('span', 'tab-label', 'Topology'));
  topoTab.title = 'Every switch you have added, and everything they can see';
  topoTab.style.display = 'none';
  tabStrip.insertBefore(topoTab, tabStrip.firstChild);
  topoTab.addEventListener('click', () => selectTopology());

  let topoTabActive = false;

  /** Show the topology, as a tab rather than as an overlay over a switch. */
  function selectTopology() {
    const prev = activeId && switches.get(activeId);
    if (prev) { prev.tab.classList.remove('active'); prev.pane.classList.remove('active'); }
    document.getElementById('mib-panel').classList.remove('open');
    topoTab.classList.add('active');
    topoTabActive = true;
    topoPanel.classList.add('open');
    paintTopoButton();
    topoRebuild(true);
  }

  /** Leaving the topology for a switch tab. */
  function leaveTopology() {
    if (!topoTabActive) return;
    topoTabActive = false;
    topoTab.classList.remove('active');
    topoPanel.classList.remove('open');
  }
  newSwitchBtn.addEventListener('click', () => createSwitch());

  /**
   * Drag a tab to reorder it. Uses the HTML drag API rather than pointer
   * maths: the browser handles the drag image and autoscroll, and a tab is
   * a small target that a hand-rolled version tends to get wrong.
   *
   * Only the tab strip's DOM order changes -- nothing else depends on it,
   * because each switch owns its own pane.
   */
  function initTabReorder(tab) {
    tab.draggable = true;

    tab.addEventListener('dragstart', (e) => {
      dragTab = tab;
      tab.classList.add('dragging');
      e.dataTransfer.effectAllowed = 'move';
      // Firefox will not start a drag without payload.
      try { e.dataTransfer.setData('text/plain', ''); } catch (err) {}
    });

    tab.addEventListener('dragend', () => {
      tab.classList.remove('dragging');
      for (const t of tabStrip.querySelectorAll('.tab')) {
        t.classList.remove('drop-before', 'drop-after');
      }
      dragTab = null;
    });

    tab.addEventListener('dragover', (e) => {
      if (!dragTab || dragTab === tab) return;
      e.preventDefault();
      e.dataTransfer.dropEffect = 'move';
      // Which half of the tab is the pointer over?
      const box = tab.getBoundingClientRect();
      const before = (e.clientX - box.left) < box.width / 2;
      tab.classList.toggle('drop-before', before);
      tab.classList.toggle('drop-after', !before);
    });

    tab.addEventListener('dragleave', () => {
      tab.classList.remove('drop-before', 'drop-after');
    });

    tab.addEventListener('drop', (e) => {
      if (!dragTab || dragTab === tab) return;
      e.preventDefault();
      const box = tab.getBoundingClientRect();
      const before = (e.clientX - box.left) < box.width / 2;
      tabStrip.insertBefore(dragTab, before ? tab : tab.nextSibling);
      tab.classList.remove('drop-before', 'drop-after');
      appLog('info', 'Switch tabs reordered', {
        order: Array.from(tabStrip.querySelectorAll('.tab-label')).map((l) => l.textContent)
      });
    });
  }

  /**
   * A tab, wired up. Built here rather than inline because a switch that
   * was closed and is being reopened needs exactly the same one back, and
   * two copies of this would drift apart.
   */
  function buildTab(id, text) {
    const tab = el('div', 'tab');
    tab.appendChild(el('span', 'tab-dot'));
    const label = el('span', 'tab-label', text || 'New switch');
    tab.appendChild(label);
    const close = el('span', 'tab-close', '\u00d7', 'Close');
    tab.appendChild(close);
    // The add button lives inside the strip, so tabs go before it.
    tabStrip.insertBefore(tab, newSwitchBtn);
    initTabReorder(tab);

    tab.addEventListener('click', (e) => {
      if (e.target === close) return;
      // A switch's tab is its front door: always land on the dashboard,
      // even if the last thing you did was stare at a terminal.
      const sw = switches.get(id);
      selectSwitch(id);
      if (sw) showView(sw, sw.subMode === 'ready' ? 'overview' : 'creds');
    });
    close.addEventListener('click', (e) => { e.stopPropagation(); closeSwitch(id); });
    return { tab, label, close };
  }

  function createSwitch() {
    counter += 1;
    const id = 'sw' + counter;

    const { tab, label } = buildTab(id, 'New switch');

    const pane = switchTpl.content.cloneNode(true).querySelector('.switch-pane');
    switchesEl.appendChild(pane);

    const q = (sel) => pane.querySelector(sel);
    const s = {
      id, tab, pane, label, dot: tab.querySelector('.tab-dot'),
      host: null, target: null, view: 'health',
      subtabs: Array.from(pane.querySelectorAll('.subtab')),
      views: {
        creds: pane.querySelector('.subview[data-view="creds"]'),
        setup: pane.querySelector('.subview[data-view="setup"]'),
        overview: pane.querySelector('.subview[data-view="overview"]')
      },
      setupIntro: q('.f-setup-intro'),
      // Overlays: opened by the action that produces them, not by a tab.
      techOverlay: q('.f-tech-overlay'), cfgOverlay: q('.f-cfg-overlay'), termOverlay: q('.f-term-overlay'),
      snmpCard: q('.f-snmp-card'), sshCard: q('.f-ssh-card'),
      // dashboard
      targetForm: q('.f-target-form'),
      healthStatus: q('.subview[data-view="overview"] .toolbar-status'),
      autoInput: q('.f-auto'), autoLabelEl: q('.f-auto-label'), autoLeft: null,
      intervalInput: q('.f-interval'), refreshBtn: q('.f-refresh-btn'),
      addPanelBtn: q('.f-add-panel'), resetLayoutBtn: q('.f-reset-layout'),
      grid: q('.f-grid'), panels: [], interval: 30,

      mibStatus: q('.f-mib-status'), targetError: q('.f-target-form .form-error'),
      hostInput: q('.f-host'), portInput: q('.f-port'), versionInput: q('.f-version'),
      communityField: q('.community-field'), communityInput: q('.f-community'),
      transportNote: q('.f-transport-note'),
      v3Fields: q('.v3-fields'), v3User: q('.f-v3-username'), v3Level: q('.f-v3-level'),
      v3Auth: q('.f-v3-auth'), v3AuthKey: q('.f-v3-authkey'), v3AuthKeyField: q('.f-v3-authkey-field'),
      v3Priv: q('.f-v3-priv'), v3PrivKey: q('.f-v3-privkey'), v3PrivKeyField: q('.f-v3-privkey-field'),
      collectBtn: q('.f-collect-btn'),
      health: null, autoTimer: null,
      // snmp
      // ssh
      sshForm: q('.f-ssh-form'),
      storageCard: q('.f-storage-card'), storageNote: q('.f-storage-note'),
      forgetBtn: q('.f-forget'),
      productCard: q('.f-product-card'), productNote: q('.f-product-note'),
      productSelect: q('.f-product-select'),
      consoleCard: q('.f-console-card'), consoleForm: q('.f-console-form'),
      consoleConnect: q('.f-console-connect'),
      comPort: q('.f-com-port'), baud: q('.f-baud'),
      serialStatus: q('.f-serial-status'), consoleError: q('.f-console-form .form-error'),
      sshHost: q('.f-ssh-host'), sshPort: q('.f-ssh-port'),
      sshUser: q('.f-ssh-user'), sshPass: q('.f-ssh-pass'),
      sshConnect: q('.f-ssh-connect'), sshError: q('.f-ssh-form .form-error'),
      sshStatus: q('.f-term-overlay .toolbar-status'), termClear: q('.f-term-clear'),
      sshSave: q('.f-ssh-save'), disconnectBtn: q('.f-disconnect'), reconnectBtn: q('.f-reconnect'),
      trConsole: q('.f-tr-console'), trSsh: q('.f-tr-ssh'),
      termEl: q('.f-term'), ws: null, term: null, fit: null, sshBuffer: '', capturing: false,
      // Configuration has its own page: fetching files is a task you go
      // and do, not a panel to scroll past on the dashboard.
      cfgBody: q('.f-cfg-body'),
      cfgStatus: q('.f-cfg-status'), cfgClose: q('.f-cfg-close'),
      // tech-support: the raw capture gets its own page too.
      techNav: q('.f-tech-nav'), techPane: q('.f-tech-pane'),
      techSearch: q('.f-tech-search'), techSave: q('.f-tech-save'),
      techStatus: q('.f-tech-status'),
      techSection: FULL_OUTPUT,
      techPending: false,
      tech: null, techRaw: '', techNote: ''
    };

    for (const st of s.subtabs) st.addEventListener('click', () => onSubtabClick(s, st));
    setSubtabMode(s, 'setup');

    for (const [btn, view] of [['.f-tech-close', null], ['.f-cfg-close', null],
      ['.f-term-close', null], ['.f-graph-close', null]]) {
      q(btn).addEventListener('click', () => closeOverlays(s));
    }

    switches.set(id, s);
    initHealth(s);
    initSsh(s);
    initConsole(s);
    initGraph(s);
    initSetup(s);
    initStorageCard(s);
    initProductCard(s);
    initTech(s);
    selectSwitch(id);
    tab.scrollIntoView({ inline: 'end', block: 'nearest' });
    // The MIB database is 2 MB of JSON, and nothing on the dashboard needs
    // it: names are resolved server-side. Only the MIB Explorer and the
    // add-panel autocomplete do, so it is fetched when one of those is
    // first opened rather than on the way to a page that will not use it.
    updateMibStatus(s);
    return s;
  }

  function selectSwitch(id) {
    if (id !== activeId) setTimeout(saveState, 0);
    leaveTopology();
    const prev = activeId && switches.get(activeId);
    if (prev) { prev.tab.classList.remove('active'); prev.pane.classList.remove('active'); }
    activeId = id;
    const s = switches.get(id);
    s.tab.classList.add('active');
    s.pane.classList.add('active');
    if (s.view === 'ssh' && s.fit) fitTerm(s);
  }

  /**
   * Closing a tab puts the switch away; it does not throw it out.
   *
   * A tab is a place to look at a switch, not the switch itself. Tearing
   * down the SSH session, the trap stream and everything collected -- and
   * then rebuilding all of it when the same switch is opened again a
   * minute later -- costs the operator time for nothing. So the pane is
   * detached and kept whole: the session stays up, the layout and the
   * history survive, and reopening is instant.
   *
   * The topology is where a put-away switch is found again, which is why
   * closing the last tab lands there.
   */
  const closedSwitches = new Map();

  function closeSwitch(id) {
    const s = switches.get(id);
    if (!s) return;
    appLog('info', 'Switch tab closed; session kept', { host: s.host, live: !!s.ws });

    // Auto-refresh stops -- nobody is watching, and a collection is not
    // free. The probe keeps going, because it is one small packet every
    // thirty seconds and it is what keeps the topology honest.
    if (s.autoTimer) { clearInterval(s.autoTimer); s.autoTimer = null; }

    s.tab.remove();
    // Detached rather than destroyed: putting this element back is what
    // makes reopening free.
    if (s.pane.parentNode) s.pane.parentNode.removeChild(s.pane);
    switches.delete(id);
    closedSwitches.set(id, s);

    saveState();
    paintTopoButton();
    if (activeId !== id) return;

    activeId = null;
    const rest = Array.from(switches.keys());
    if (rest.length) { selectSwitch(rest[rest.length - 1]); return; }

    /**
     * The last tab has gone. A blank credentials form is a strange place
     * to be left after deliberately closing everything, so the topology
     * takes over: it is the view that is about the network rather than
     * about one switch, and it is where the closed ones are waiting.
     */
    // Land on the topology: the closed switches are still there and this
    // is where they are found. No blank tab is created -- the "+" says
    // how to add one, and an empty credentials form pretending to be a
    // switch is just something else to close.
    paintTopoButton();
    selectTopology();
  }

  /** Put a closed switch back on screen, exactly as it was left. */
  function reopenSwitch(id) {
    const s = closedSwitches.get(id);
    if (!s) return false;
    closedSwitches.delete(id);
    switches.set(id, s);

    // The tab was removed, so it is built again; the pane is the original.
    const rebuilt = buildTab(id, s.host || 'switch');
    s.tab = rebuilt.tab;
    s.label = rebuilt.label;
    s.dot = rebuilt.tab.querySelector('.tab-dot');
    if (s.host) setTab(s, s.reachable === false ? 'err' : 'ok', s.host);
    switchesEl.appendChild(s.pane);
    selectSwitch(id);

    // Auto-refresh resumes if it was on, and the terminal needs a nudge:
    // xterm cannot size itself while detached.
    if (s.autoInput && s.autoInput.checked) startAuto(s);
    if (s.term && s.fit) setTimeout(() => fitTerm(s), 60);
    appLog('info', 'Switch tab reopened', { host: s.host, live: !!s.ws });
    saveState();
    paintTopoButton();
    return true;
  }

  /** Everything the topology should draw: on screen or merely put away. */
  function allSwitches() {
    return Array.from(switches.values()).concat(Array.from(closedSwitches.values()));
  }

  /** Really finish with a switch: the session goes too. */
  function forgetSwitch(id) {
    const s = switches.get(id) || closedSwitches.get(id);
    if (!s) return;
    if (s.autoTimer) clearInterval(s.autoTimer);
    stopProbe(s);
    stopSyslogStream(s);
    stopTrapStream(s);
    if (s.ws) { try { s.ws.send(JSON.stringify({ type: 'disconnect' })); s.ws.close(); } catch (e) {} }
    if (s.term) { try { s.term.dispose(); } catch (e) {} }
    switches.delete(id);
    closedSwitches.delete(id);
    if (s.tab.parentNode) s.tab.remove();
    if (s.pane.parentNode) s.pane.remove();
    saveState();
    paintTopoButton();
  }

  /**
   * The two sub-tabs mean different things before and after a switch
   * exists. Before: pick which credentials you are adding. After: the
   * dashboard, or the settings that produced it. Same two slots either
   * way, so nothing jumps around when a switch comes up.
   */
  function setSubtabMode(s, mode) {
    s.subMode = mode;
    const spec = mode === 'ready'
      ? [{ view: 'overview', label: 'Overview' },
         { view: 'overview', label: 'CLI', action: 'cli' },
         { view: 'creds', label: 'Settings' }]
      : [{ view: 'creds', label: 'SNMP', card: 'snmp' }, { view: 'creds', label: 'SSH', card: 'ssh' },
         { view: 'creds', label: 'Console', card: 'console' }];
    // The strip holds however many the mode needs: two once a switch is
    // up, three while choosing which credentials to add.
    const strip = s.subtabs[0].parentNode;
    while (s.subtabs.length < spec.length) {
      const extra = s.subtabs[0].cloneNode(true);
      strip.appendChild(extra);
      s.subtabs.push(extra);
      extra.addEventListener('click', () => onSubtabClick(s, extra));
    }
    s.subtabs.forEach((tab, i) => {
      const def = spec[i];
      tab.style.display = def ? '' : 'none';
      // A hidden tab must also stop being active, or it keeps matching
      // the current view and two tabs light up at once.
      if (!def) { tab.classList.remove('active'); return; }
      tab.dataset.view = def.view;
      tab.dataset.card = def.card || '';
      tab.dataset.action = def.action || '';
      tab.querySelector('.sub-label').textContent = def.label;
      tab.title = def.action === 'cli' ? cliTooltip(s) : '';
      tab.classList.remove('disabled');
    });
    // During setup each tab shows one credential card; in settings, both.
    if (mode === 'ready') {
      s.snmpCard.style.display = '';
      s.sshCard.style.display = '';
      s.consoleCard.style.display = '';
      // Only meaningful once there is a switch to have saved.
      if (s.storageCard) s.storageCard.style.display = '';
      if (s.productCard) s.productCard.style.display = '';
      showView(s, 'overview');
    } else {
      selectCredCard(s, 'snmp');
      showView(s, 'creds');
    }
  }

  function onSubtabClick(s, st) {
    if (st.classList.contains('disabled')) return;
    if (s.subMode !== 'ready') {
      s.credCard = st.dataset.card || 'snmp';
      selectCredCard(s, s.credCard);
      showView(s, 'creds');
      return;
    }
    // The CLI tab is an action, not a view: open the command line (console or
    // SSH, whichever is set up) and leave the current view in place.
    if (st.dataset.action === 'cli') { openCli(s); return; }
    showView(s, st.dataset.view);
  }

  function selectCredCard(s, which) {
    if (s.storageCard) s.storageCard.style.display = 'none';
    if (s.productCard) s.productCard.style.display = 'none';
    if (s.subMode === 'ready') return;
    s.snmpCard.style.display = which === 'snmp' ? '' : 'none';
    s.sshCard.style.display = which === 'ssh' ? '' : 'none';
    s.consoleCard.style.display = which === 'console' ? '' : 'none';
    s.subtabs.forEach((t) => t.classList.toggle('active', (t.dataset.card || 'snmp') === which));
  }

  function openOverlay(s, which) {
    // An overlay always sits over the dashboard. Entering credentials is a
    // detour on the way to one of these, and closing it should put you
    // back on the switch rather than on the form you passed through.
    if (s.subMode === 'ready' && s.view !== 'overview') showView(s, 'overview');
    for (const key of ['techOverlay', 'cfgOverlay', 'termOverlay', 'graphOverlay']) {
      if (s[key]) s[key].classList.toggle('open', key === which);
    }
    if (which === 'termOverlay' && s.fit) setTimeout(() => fitTerm(s), 30);
  }

  function closeOverlays(s) {
    for (const key of ['techOverlay', 'cfgOverlay', 'termOverlay', 'graphOverlay']) {
      if (s[key]) s[key].classList.remove('open');
    }
  }

  function showView(s, view) {
    s.view = view;
    closeOverlays(s);
    for (const st of s.subtabs) {
      const hidden = st.style.display === 'none';
      // An action tab (e.g. CLI) triggers something and owns no view, so it
      // never shows as the selected tab.
      st.classList.toggle('active', !hidden && !st.dataset.action && st.dataset.view === view &&
        (s.subMode === 'ready' || (st.dataset.card || 'snmp') === (s.credCard || 'snmp')));
    }
    for (const k in s.views) s.views[k].classList.toggle('active', k === view);
  }

  /** Sub-tabs that depend on data are disabled until that data exists. */
  function enableSubtab(s, view, on) {
    const st = s.subtabs.find((x) => x.dataset.view === view);
    if (st) st.classList.toggle('disabled', !on);
  }

  /** Colour the sub-tab's dot with the verdict, so the Overview tab carries
   *  the same colour as the Overview badge. Only the dot: the underline is
   *  the open tab's. */
  function subTint(s, view, sev) {
    const st = s.subtabs.find((x) => x.dataset.view === view);
    if (!st) return;
    st.classList.remove('sev-ok', 'sev-warning', 'sev-critical', 'sev-info');
    if (sev) st.classList.add('sev-' + sev);
  }

  /**
   * The dot, the sub-tab tint and the switch tab all say the same thing,
   * from the same value: the worst severity among the findings. Keeping
   * them in one function is what stops the dot claiming "fine" while the
   * badge says otherwise.
   */
  function applyHealthState(s, sev) {
    const dot = sev === 'critical' ? 'err' : (sev === 'warning' ? 'busy' : 'on');
    subDot(s, 'overview', dot);
    subTint(s, 'overview', sev === 'info' ? 'ok' : sev);
    setTab(s, sev === 'info' ? 'ok' : sev);
  }

  function subDot(s, view, cls) {
    const st = s.subtabs.find((x) => x.dataset.view === view);
    if (st) st.querySelector('.sdot').className = 'sdot' + (cls ? ' ' + cls : '');
  }

  function setTab(s, sev, label) {
    s.dot.className = 'tab-dot' + (sev ? ' ' + sev : '');
    if (!label) return;
    // The switch's own name wins over the address it was reached at, and
    // the address moves to the tooltip where it is still available.
    const name = s.sysName || label;
    s.label.textContent = name;
    s.label.title = s.sysName && s.sysName !== label ? s.sysName + '  \u00b7  ' + label : label;
  }

  function showErr(node, text) {
    node.textContent = text || '';
    node.style.display = text ? 'block' : 'none';
  }

  function updateMibStatus(s) {
    if (!s.mibStatus) return;
    // The MIB database is loaded lazily (only when the MIB Explorer or add-panel
    // autocomplete needs it), so "loading" must reflect an ACTUAL in-flight
    // load - MIB.loading being set - not merely "not loaded yet". Showing
    // "loading" before anything has been requested made the message appear to
    // hang forever.
    if (MIB.error) s.mibStatus.textContent = 'MIB database failed to load: ' + MIB.error;
    else if (MIB.loaded) s.mibStatus.textContent = '';
    else if (MIB.loading) s.mibStatus.textContent = 'loading MIB database\u2026';
    else s.mibStatus.textContent = '';   // not requested yet: nothing to report
  }

  window.addEventListener('resize', () => {
    const a = activeId && switches.get(activeId);
    if (a && a.fit) fitTerm(a);
  });
