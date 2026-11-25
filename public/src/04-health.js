  // =================================================================
  // 04-health.js: The Health page: target form, auto-refresh, saved state and layout, the reachability probe, trap-driven refreshes and the table refresh engine.
  // =================================================================

  // =================================================================
  // Health
  // =================================================================
  // =================================================================
  // Health dashboard
  // =================================================================
  // The page is a grid of panels. Some are built in (they render whatever
  // SNMP health and a tech-support capture provide); the rest are added by
  // the user and hold any OID they care about. Panels can be reordered,
  // resized, removed and individually excluded from auto-refresh, and the
  // arrangement is stored per host on the server so it survives a reload.

  const GRID_COLS = 12;
  // A full health walk is ~44 tables; at 30s it was a periodic spike every half
  // minute. 60s halves that while keeping the dashboard current - the user can
  // still choose a shorter interval if they want faster updates.
  const DEFAULT_INTERVAL = 300;

  // Built-in panels. `needs` decides whether a panel has anything to show:
  // a switch with no capture should not display an empty VLAN panel.
  const BUILTIN = [
    { key: 'summary', title: 'Details', span: 12, h: 0, needs: () => true },
    { key: 'metrics', title: 'Key metrics', span: 12, h: 0, needs: () => true },
    { key: 'events', title: 'Events', span: 12, h: 400, needs: () => true },
    { key: 'hardware', title: 'Hardware', span: 12, h: 0,
      needs: (s) => s.health && (s.health.psus.length || s.health.fans.length ||
        s.health.sensors.length || s.health.stack.length || s.health.inventory.length) },
    { key: 'interfaces', title: 'Interfaces', span: 12, h: 320,
      needs: (s) => s.health && (s.health.interfaces.length || s.health.poePorts.length) },
    { key: 'vlans', title: 'VLANs', span: 12, h: 0,
      needs: (s) => s.health && s.health.vlans.length },
    // Neighbours before spanning tree: what is attached is the more
    // common question, and it is the context for reading the topology.
    { key: 'auth', title: 'Sessions & authentication', span: 12, h: 300, needs: () => true },
    { key: 'connected', title: 'Connected devices', span: 12, h: 320,
      needs: (s) => s.health && (s.health.cdp.length || s.health.lldp.length || s.health.macTable.length) },
    { key: 'stp', title: 'Spanning tree', span: 12, h: 420,
      needs: (s) => s.health && (s.health.stpPorts.length || s.health.stpMode !== 'unknown') },
    // SNMP configuration: the write side. Unlike the others this is
    // interactive and does not come from the health poll, so it loads
    // lazily (on expand / its own refresh) and is always offered.
    { key: 'snmpcfg', title: 'SNMP configuration', span: 12, h: 0, needs: () => true },
    // IP access lists (the QoS ACL tables): a keyed write panel whose tables
    // are loaded on demand once per visit (14-acl.js).
    { key: 'acl', title: 'IP access lists', span: 12, h: 0, needs: () => true },
    // IPv4 Addressing: every interface address (VLAN SVIs and routed ports,
    // static or DHCP), global L3 status, the forwarding table, static routes,
    // DNS client status, nameservers and static host mappings. Interactive
    // (editable), always offered. The key stays 'routing' so saved dashboard
    // layouts keep their place for it.
    { key: 'routing', title: 'IPv4 Addressing', span: 12, h: 0, needs: () => true },
    // Packet capture: interactive like snmpcfg, driven by writes rather than
    // the health poll, so always offered and loaded on demand.
    { key: 'capture', title: 'Packet capture', span: 12, h: 0, needs: () => true },
    // Flash files: its own interactive module (list / download / delete).
    { key: 'flash', title: 'Flash files', span: 12, h: 0, needs: () => true }
  ];

  const builtinDef = (key) => BUILTIN.find((b) => b.key === key);

  // Which health tables each panel actually shows, so one panel can be
  // refreshed without re-walking the whole switch. Overview, metrics and
  // findings describe the box as a whole, so they need a full collection.
  const PANEL_TABLES = {
    hardware: ['psus', 'fans', 'sensors', 'stack', 'inventory'],
    interfaces: ['interfaces', 'poe', 'poePorts', 'vlans', 'vlansCurrent', 'portModes', 'portL2L3', 'dot1xPortCfg', 'dot1xHostMode', 'dot1xPortMethod',
      'lagCreation', 'lagAgg', 'lagMembers', 'lagPortKey'],
    // macTable is NOT listed here: it is large and fetched on demand (once per
    // visit, time-guarded) by the connected panel's own render, so a panel
    // refresh must not walk it again.
    connected: ['cdp', 'lldp', 'bridgePorts'],
    auth: ['mgmtSessions', 'sshSessions', 'telnetSessions', 'dot1xHosts', 'dot1xLocked',
      'radiusServers', 'radiusStats', 'tacacsServers',
      'dot1xHostStats', 'dot1xHostDiag', 'dot1xHostSession', 'vlans'],
    stp: ['stpPorts', 'stpExtPorts', 'mstpPorts', 'mstpInstances',
          'pvstPorts', 'pvstVlans', 'pvstInconsistencies', 'stpxInconsistencies'],
    // The panel's Refresh re-reads its own on-demand tables, not the whole switch.
    acl: ['aclNames', 'aclAces', 'aclTuples']
  };

  // Open on the two panels that answer "how is this switch", and leave the
  // rest folded. Everything is one click away, and a page that opens with
  // eight tables is a page nobody reads.
  const OPEN_BY_DEFAULT = new Set(['summary', 'metrics']);

  function defaultPanels() {
    return BUILTIN.map((b) => ({
      id: 'b:' + b.key, kind: 'builtin', key: b.key,
      title: b.title, span: b.span, h: b.h,
      collapsed: !OPEN_BY_DEFAULT.has(b.key)
    }));
  }

  function initHealth(s) {
    s.panels = defaultPanels();
    s.interval = DEFAULT_INTERVAL;

    fillV3Menus(s);
    s.versionInput.addEventListener('change', () => updateVersionFields(s));
    s.v3Auth.addEventListener('change', () => updateVersionFields(s));
    s.v3Priv.addEventListener('change', () => updateVersionFields(s));
    updateVersionFields(s);
    s.targetForm.addEventListener('submit', (e) => { e.preventDefault(); startHealth(s); });
    s.refreshBtn.addEventListener('click', () => refreshAll(s));
    s.addPanelBtn.addEventListener('click', () => openPanelDialog(s));
    s.resetLayoutBtn.addEventListener('click', () => {
      if (!s.host) return;
      s.panels = defaultPanels();
      s.renderedIds = null;
      s.interval = DEFAULT_INTERVAL;
      if (s.intervalInput) s.intervalInput.value = DEFAULT_INTERVAL;
      fetch('/api/layout/' + encodeURIComponent(s.host), { method: 'DELETE' }).catch(() => {});
      appLog('info', 'Dashboard layout reset', { host: s.host });
      renderSwitch(s);
    });

    // The auto-refresh checkbox and interval input were removed from the UI;
    // their listeners are wired only when the elements exist, so the dashboard
    // keeps working as a manual Refresh-now view.
    if (s.intervalInput) {
      s.intervalInput.addEventListener('change', () => {
        const v = Math.max(5, Math.min(3600, parseInt(s.intervalInput.value, 10) || DEFAULT_INTERVAL));
        s.interval = v;
        s.intervalInput.value = v;
        saveLayout(s);
        // This now sets the SERVER's poll rate for this switch, so persist it to
        // state (the collector reloads per-switch intervals on a state change).
        saveState();
        if (s.autoTimer) startAuto(s);
      });
    }
    if (s.autoInput) {
      s.autoInput.addEventListener('change', () => {
        if (s.autoInput.checked) startAuto(s); else stopAuto(s);
      });
    }
  }

  // ---------- auto-refresh ----------
  /**
   * A one-second tick rather than one long timer, so the label can count
   * down: a silent gap gives no clue whether the page is live or stale.
   */
  function startAuto(s) {
    stopAuto(s, true);
    s.autoLeft = s.interval;
    paintAuto(s);
    s.autoTimer = setInterval(() => {
      s.autoLeft -= 1;
      if (s.autoLeft <= 0) { s.autoLeft = s.interval; refreshAll(s, true); }
      paintAuto(s);
    }, 1000);
    appLog('info', 'Auto-refresh on', {
      host: s.host, everySeconds: s.interval, panels: s.panels.length
    });
  }
  function stopAuto(s, keepChecked) {
    if (s.autoTimer) { clearInterval(s.autoTimer); s.autoTimer = null; }
    if (s.autoInput && !keepChecked) s.autoInput.checked = false;
    s.autoLeft = null;
    paintAuto(s);
  }
  function paintAuto(s) {
    if (!s.autoLabelEl) return;
    s.autoLabelEl.textContent = s.autoLeft == null ? 'Auto-refresh' : 'Refreshing in ' + s.autoLeft + 's';
  }

  /**
   * Refresh only what the user has asked for. `auto` restricts the work to
   * panels still marked for refresh -- the point of the per-panel toggle is
   * that an expensive walk can be left out of the loop while still being
   * refreshable by hand.
   */
  /** Refresh everything. Individual panels have their own button. */
  function refreshAll(s, auto) {
    if (!s.target) return;
    if (s.autoTimer) startAuto(s);   // any refresh restarts the countdown
    if (s.panels.some((p) => p.kind === 'builtin')) {
      // The browser no longer walks the switch on a timer - the server-side
      // collector owns periodic collection (SERVER-STANDARD §0). A periodic
      // refresh (auto) re-reads the server's latest snapshot; a manual Refresh
      // (auto=false) nudges the server to poll now, then shows the result.
      // Writes and on-demand loads still read the switch live - that is
      // user-initiated and must reflect at once (MODULE-STANDARD §B6).
      syncView(s, { nudge: !auto });
    }
    for (const p of s.panels) if (p.kind === 'oid') loadPanelData(s, p);
  }

  // The v3 menus come from the server so the two cannot drift apart: the
  // list of protocols the UI offers is exactly the list it can build a
  // session for.
  const V3_MENUS = { loaded: null };
  function loadV3Menus() {
    if (!V3_MENUS.loaded) {
      V3_MENUS.loaded = fetch('/api/snmp/v3-options')
        .then((r) => r.json())
        .catch(() => ({
          auth: [{ value: 'none', label: 'None' }, { value: 'sha', label: 'SHA' }],
          priv: [{ value: 'none', label: 'None' }, { value: 'aes128', label: 'AES-128' }]
        }));
    }
    return V3_MENUS.loaded;
  }

  function fillV3Menus(s) {
    loadV3Menus().then((menus) => {
      const fill = (sel, items, preferred) => {
        clear(sel);
        for (const it of items) {
          const o = document.createElement('option');
          o.value = it.value; o.textContent = it.label;
          sel.appendChild(o);
        }
        if (items.some((i) => i.value === preferred)) sel.value = preferred;
      };
      fill(s.v3Auth, menus.auth, 'sha');
      fill(s.v3Priv, menus.priv, 'aes128');
      updateVersionFields(s);
    });
  }

  function updateVersionFields(s) {
    const v3 = s.versionInput.value === '3';
    s.communityField.classList.toggle('hidden', v3);
    s.v3Fields.classList.toggle('visible', v3);
    paintTransportNote(s);
    if (!v3) return;

    // Password fields only matter when the matching method is in use, and
    // the security level follows from the two choices rather than being a
    // third thing to get wrong.
    const auth = s.v3Auth.value !== 'none';
    const priv = s.v3Priv.value !== 'none';
    s.v3AuthKeyField.style.display = auth ? '' : 'none';
    s.v3PrivKeyField.style.display = priv ? '' : 'none';

    if (priv && !auth) {
      s.v3Level.textContent = 'Privacy requires authentication \u2014 choose an authentication method, or set privacy to None.';
      s.v3Level.style.color = 'var(--red)';
    } else {
      s.v3Level.textContent = 'Security level: ' +
        (auth && priv ? 'authPriv' : (auth ? 'authNoPriv' : 'noAuthNoPriv'));
      s.v3Level.style.color = '';
    }
  }
  /**
   * Say, where the credentials are chosen, what an SNMP write exposes. v1 and
   * v2c send the community string and every value written in the clear, and
   * so does v3 without privacy; anyone capturing the traffic between this PC
   * and the switch reads them. Stated once here rather than as a prompt on
   * every write, so it informs the choice without getting in the way of it.
   */
  function paintTransportNote(s) {
    if (!s.transportNote) return;
    const v3 = s.versionInput.value === '3';
    const priv = v3 && s.v3Priv && s.v3Priv.value !== 'none';
    s.transportNote.textContent = priv ? '' : (v3
      ? '\u26A0 Without privacy, values written to the switch travel unencrypted.'
      : '\u26A0 v' + s.versionInput.value + ' sends the community string and every value written unencrypted. SNMPv3 with privacy encrypts them.');
    s.transportNote.style.display = priv ? 'none' : '';
  }

  function buildTarget(s) {
    const t = {
      host: s.hostInput.value.trim(),
      port: parseInt(s.portInput.value, 10) || 161,
      version: s.versionInput.value
    };
    // A saved switch's secrets stay on the server (credentials.js): a field
    // left blank while it says "saved" is sent empty, and the server fills it
    // in from the switch named by `ref`.
    const saved = s.savedSecrets || {};
    if (s.savedId) t.ref = s.savedId;
    if (t.version === '3') {
      t.v3 = {
        username: s.v3User.value,
        authProtocol: s.v3Auth.value, authKey: s.v3AuthKey.value,
        privProtocol: s.v3Priv.value, privKey: s.v3PrivKey.value
      };
    } else if (s.communityInput.value || !saved.community) {
      t.community = s.communityInput.value || 'public';
    }
    return t;
  }

  function startHealth(s) {
    const t = buildTarget(s);
    if (!t.host) { showErr(s.targetError, 'Host is required.'); return; }
    showErr(s.targetError, '');
    // Verify the credentials are accepted before committing to the switch: one
    // SNMP GET of sysUpTime with the entered credentials. A bad community or
    // wrong v3 auth fails here, so the user gets an immediate, clear error
    // instead of an empty dashboard that silently never populates.
    const collectBtn = s.collectBtn;
    if (collectBtn) { collectBtn.disabled = true; collectBtn.dataset.label = collectBtn.textContent; collectBtn.textContent = 'Checking\u2026'; }
    fetch('/api/ping', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ target: t }) })
      .then((r) => r.json())
      .then((res) => {
        if (collectBtn) { collectBtn.disabled = false; if (collectBtn.dataset.label) collectBtn.textContent = collectBtn.dataset.label; }
        if (!res || !res.reachable) {
          showErr(s.targetError, 'The switch did not answer with these credentials' +
            (res && res.error ? ' (' + res.error + ')' : '') + '. Check the host, SNMP version, and community or v3 settings.');
          return;
        }
        proceedHealth(s, t);
      })
      .catch((e) => {
        if (collectBtn) { collectBtn.disabled = false; if (collectBtn.dataset.label) collectBtn.textContent = collectBtn.dataset.label; }
        showErr(s.targetError, 'Could not reach the local server to verify credentials: ' + e.message);
      });
  }

  // Commit to the switch once its credentials are verified.
  function proceedHealth(s, t) {
    s.target = t; s.host = t.host;
    s.sshHost.value = t.host;
    setTab(s, 'connecting', t.host);
    setSubtabMode(s, 'ready');
    startProbe(s);
    // The graphs start with whatever was recorded before, so a freshly
    // opened tab is not a blank hour.
    loadHistory(s);
    // Traps drive refreshes, so the stream opens with the switch rather
    // than with the panel: a linkDown while the Events panel is folded is
    // exactly the one that should still update the dashboard.
    startTrapStream(s);
    startSyslogStream(s);
    saveState();
    repaintConfig(s);
    startSyslogStream(s);
    loadSyslog(s);
    // First view: read the server's latest snapshot - no switch traffic. The
    // server owns the recurring collection, so opening a switch just displays
    // what it already has; syncView falls back to a one-off poll only if the
    // collector has no snapshot for this switch yet (e.g. just added). A manual
    // Refresh is the way to force a fresh poll.
    restoreLayout(s).then(() => syncView(s).then(() => { if (!s.autoTimer) startAuto(s); }).catch(() => { if (!s.autoTimer) startAuto(s); }));
  }

  // ---------- layout persistence ----------
  /**
   * Everything needed to put the app back as it was: which switches were
   * open and how to reach them. Saved whenever that set changes rather
   * than on a timer, so closing the browser mid-thought loses nothing.
   *
   * Credentials are part of it -- an app that restores your switches but
   * then asks for the community string has not restored anything. They are
   * encrypted at rest; see the note in Settings for what that means.
   */
  let stateSaveTimer = null;
  function saveState() {
    if (stateSaveTimer) clearTimeout(stateSaveTimer);
    // Adding a switch fires several of these in a row; one write will do.
    stateSaveTimer = setTimeout(() => {
      const list = [];
      for (const sw of allSwitches()) {
        if (sw.forgotten) continue;
        if (!sw.target && !sw.consoleTarget) continue;
        list.push({
          id: sw.savedId || undefined,
          host: sw.host || null,
          target: sw.target || null,
          // The per-switch poll interval drives the server's collector cadence
          // for this switch (SERVER-STANDARD §3), so it is saved with the switch.
          interval: Number(sw.interval) || null,
          // Manual product-line override (null = auto-detect). Decides the MIB
          // set and feature gating for this switch.
          productOverride: sw.productOverride || null,
          ssh: sw.sshUser && sw.sshUser.value ? {
            host: sw.sshHost.value || sw.host, port: Number(sw.sshPort.value) || 22,
            username: sw.sshUser.value, password: sw.sshPass.value
          } : null,
          console: sw.consoleTarget || null
        });
      }
      fetch('/api/state', {
        method: 'PUT', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ switches: list, activeId })
      }).catch((e) => appLog('warn', 'Could not save state', { message: e.message }));
    }, 400);
  }

  /**
   * Say plainly how credentials are kept. Somebody deciding whether to let
   * an app store a community string deserves the actual answer, not the
   * word "securely".
   */
  // The product card on the Settings page: shows the detected line and its
  // MIB-proven capabilities, and lets the user override the line (auto-detect
  // can be wrong or absent). The override is persisted and drives feature
  // gating and the MIB Explorer default. productPaint() is re-run whenever the
  // detected product changes (a health collection arrives).
  function initProductCard(s) {
    const paint = () => {
      if (!s.productSelect) return;
      if (PRODUCTS && !s.productSelect.options.length) {
        const auto = document.createElement('option');
        auto.value = ''; auto.textContent = 'Auto-detect';
        s.productSelect.appendChild(auto);
        for (const p of PRODUCTS.products) {
          const o = document.createElement('option');
          o.value = p.line; o.textContent = p.label; s.productSelect.appendChild(o);
        }
      }
      const detected = s.product && s.product.line;
      if (s.productSelect.options.length) {
        s.productSelect.options[0].textContent = 'Auto-detect' + (detected ? ' (' + detected + ')' : '');
      }
      s.productSelect.value = s.productOverride || '';
      const eff = effectiveProduct(s);
      const feats = (eff && eff.features) || {};
      const caps = Object.keys(feats).filter((k) => feats[k]);
      if (s.productNote) {
        s.productNote.textContent = eff
          ? (eff.label + (s.productOverride ? ' — set manually' : (detected ? ' — detected from the switch' : ' — default')) +
             '.  MIB features: ' + (caps.length ? caps.map((c) => c.toUpperCase()).join(', ') : 'base set only') + '.')
          : 'Product not detected yet — connect to the switch, or set it below.';
      }
    };
    s.productPaint = paint;
    if (s.productSelect) {
      s.productSelect.addEventListener('change', () => {
        s.productOverride = s.productSelect.value || null;
        appLog('info', 'Product line set', { host: s.host, product: effectiveProductLine(s), override: !!s.productOverride });
        saveState();
        paint();
        renderSwitch(s);   // re-evaluate panel visibility for the chosen product
      });
    }
    loadProducts().then(paint);
  }

  function initStorageCard(s) {
    const paint = () => {
      if (!s.storageNote) return;
      const info = storageInfo || {};
      s.storageNote.textContent = info.passphrase
        ? 'Switches and credentials are encrypted with a key derived from ' +
          'SBS_PASSPHRASE, which is never written to disk. Without that ' +
          'passphrase the saved file cannot be read.'
        : 'Switches and credentials are encrypted (AES-256-GCM) in state.enc, with the ' +
          'key in .state-key beside it, both readable only by your account. That protects ' +
          'them from backups, syncing and copied folders \u2014 not from someone already ' +
          'logged in as you. Set SBS_PASSPHRASE to require a passphrase instead.';
    };
    paint();
    s.storagePaint = paint;
    // Forget *this* switch: the card lives on a switch's settings page, so
    // clearing every saved switch from it would be a surprise.
    s.forgetBtn.addEventListener('click', () => {
      s.forgotten = true;
      saveState();
      appLog('info', 'Switch forgotten', { host: s.host });
      s.storageNote.textContent = s.host + ' will not be restored next time. It stays open ' +
        'now; using it again saves it again.';
      // A moment later the note goes back to describing the storage, so
      // the page does not sit on a stale confirmation.
      setTimeout(() => { s.forgotten = false; paint(); }, 8000);
    });
  }

  /** Put back what was open last time. */
  function restoreState() {
    return fetch('/api/state').then((r) => r.json()).then((body) => {
      storageInfo = body.storage || null;
      for (const sw of switches.values()) if (sw.storagePaint) sw.storagePaint();
      if (body.unreadable) {
        appLog('warn', 'Saved state could not be decrypted; starting fresh', {});
        return false;
      }
      const saved = body.state;
      if (!saved || !Array.isArray(saved.switches) || !saved.switches.length) return false;
      for (const entry of saved.switches) {
        const sw = createSwitch();
        if (entry.ssh) {
          sw.sshHost.value = entry.ssh.host || '';
          sw.sshPort.value = entry.ssh.port || 22;
          sw.sshUser.value = entry.ssh.username || '';
          sw.sshEverConnected = !!entry.ssh.username;
        }
        sw.savedId = entry.id || null;
        sw.savedSecrets = entry.saved || {};
        showSavedSecrets(sw);
        if (entry.console) sw.consoleTarget = entry.console;
        if (entry.target) {
          sw.target = entry.target;
          sw.host = entry.host || entry.target.host;
          applyTargetToForm(sw, entry.target);
          setTab(sw, '', sw.host);
          initHealth(sw);
          // The per-switch interval drives the server's poll rate for this
          // switch, so restore it from saved state (overriding the default
          // initHealth set) and reflect it in the control.
          if (Number.isFinite(entry.interval)) {
            sw.interval = entry.interval;
            if (sw.intervalInput) sw.intervalInput.value = entry.interval;
          }
          if (entry.productOverride) { sw.productOverride = entry.productOverride; if (sw.productPaint) sw.productPaint(); }
          setSubtabMode(sw, 'ready');
          startProbe(sw);
          // Reopen = display the server's last poll (no SNMP); syncView
          // auto-polls only if there is no snapshot for this switch yet.
          restoreLayout(sw).then(() => syncView(sw).then(() => { if (!sw.autoTimer) startAuto(sw); }).catch(() => { if (!sw.autoTimer) startAuto(sw); }));
        } else {
          applyConsoleChoice(sw);
        }
      }
      appLog('info', 'Restored the previous session', { switches: saved.switches.length });
      return true;
    }).catch((e) => {
      appLog('warn', 'Could not read saved state', { message: e.message });
      return false;
    });
  }

  /** Put a saved target back on the SNMP form, so Settings shows it. */
  function applyTargetToForm(s, target) {
    s.hostInput.value = target.host || '';
    s.portInput.value = target.port || 161;
    s.versionInput.value = target.version || '2c';
    if (target.community) s.communityInput.value = target.community;
    if (target.v3) {
      s.v3User.value = target.v3.username || '';
      if (target.v3.authProtocol) s.v3Auth.value = target.v3.authProtocol;
      if (target.v3.authKey) s.v3AuthKey.value = target.v3.authKey;
      if (target.v3.privProtocol) s.v3Priv.value = target.v3.privProtocol;
      if (target.v3.privKey) s.v3PrivKey.value = target.v3.privKey;
    }
    updateVersionFields(s);
  }

  /**
   * The server never sends a saved secret back (credentials.js), so each
   * secret field of a restored switch is left empty and says so. Typing in
   * it replaces the saved value; leaving it blank keeps it.
   */
  function showSavedSecrets(s) {
    const saved = s.savedSecrets || {};
    const mark = (input, has) => {
      if (!input || !has) return;
      input.value = '';
      input.placeholder = 'saved \u2014 leave blank to keep';
      input.required = false;
    };
    mark(s.communityInput, saved.community);
    mark(s.v3AuthKey, saved.authKey);
    mark(s.v3PrivKey, saved.privKey);
    mark(s.sshPass, saved.sshPassword);
  }

  let storageInfo = null;

  function saveLayout(s) {
    if (!s.host) return;
    const panels = s.panels.map((p) => ({
      id: p.id, kind: p.kind, key: p.key, title: p.title,
      oid: p.oid, op: p.op, span: p.span, h: p.h, collapsed: !!p.collapsed
    }));
    fetch('/api/layout/' + encodeURIComponent(s.host), {
      method: 'PUT', headers: { 'Content-Type': 'application/json' },
      // The console port belongs to the switch, not to the app: which
      // cable goes to which device is exactly the thing worth remembering
      // per switch rather than globally.
      body: JSON.stringify({
        panels,
        refresh: { interval: s.interval, on: !!s.autoTimer },
        console: s.consoleTarget || null
      })
    }).catch((e) => appLog('warn', 'Could not save layout', { message: e.message }));
  }

  function restoreLayout(s) {
    if (!s.host) return Promise.resolve();
    return fetch('/api/layout/' + encodeURIComponent(s.host))
      .then((r) => r.json())
      .then((body) => {
        const l = body && body.layout;
        if (!l) return;
        if (l.console && l.console.path) {
          s.consoleTarget = l.console;
          applyConsoleChoice(s);
        }
        if (!Array.isArray(l.panels) || !l.panels.length) return;
        // Drop panels this version no longer knows about, so a layout
        // saved before Configuration moved to its own page does not
        // resurrect an empty box.
        s.panels = l.panels.filter((pn) => pn.kind !== 'builtin' || builtinDef(pn.key));
        // A layout saved before a panel existed would otherwise hide it
        // forever. Anything missing is inserted where it belongs in the
        // default order rather than dumped at the end.
        const have = new Set(s.panels.filter((pn) => pn.kind === 'builtin').map((pn) => pn.key));
        BUILTIN.forEach((b, i) => {
          if (have.has(b.key)) return;
          const fresh = { id: 'b:' + b.key, kind: 'builtin', key: b.key, title: b.title,
            span: b.span, h: b.h, collapsed: !OPEN_BY_DEFAULT.has(b.key) };
          // Sit it after the last default-order panel that precedes it.
          let at = s.panels.length;
          for (let j = 0; j < s.panels.length; j++) {
            const idx = BUILTIN.findIndex((x) => x.key === s.panels[j].key);
            if (idx >= 0 && idx > i) { at = j; break; }
          }
          s.panels.splice(at, 0, fresh);
          appLog('info', 'Added a panel that postdates the saved layout',
            { host: s.host, panel: b.title });
        });
        if (l.refresh && l.refresh.interval) {
          s.interval = l.refresh.interval;
          if (s.intervalInput) s.intervalInput.value = l.refresh.interval;
        }
        appLog('info', 'Restored saved dashboard layout', { host: s.host, panels: s.panels.length });
      })
      .catch(() => { /* no saved layout is fine */ });
  }

  // ---------- data ----------
  /**
   * One spinner, in the middle of the page. It floats over whatever is
   * already there rather than replacing it, so a refresh does not blank
   * the dashboard you were reading, and there is nothing to read from it
   * beyond "working".
   */
  function showSpinner(s, on) {
    const host = s.views.overview;
    if (!host) return;
    let el_ = host.querySelector('.poll-spinner');
    if (on) {
      if (!el_) {
        el_ = el('div', 'poll-spinner');
        el_.appendChild(el('div', 'spinner'));
        host.appendChild(el_);
      }
    } else if (el_) {
      el_.remove();
    }
  }

  /**
   * A quiet reachability check, separate from the health poll. One GET of
   * sysUpTime every 30 seconds is about as small as SNMP gets, so it can
   * run regardless of whether auto-refresh is on -- the question "is this
   * switch still there" should not cost a full collection to answer.
   *
   * The uptime it returns doubles as a reboot detector: an uptime lower
   * than the last one means the switch restarted between probes.
   */
  const PROBE_MS = 30000;

  /**
   * Every reading the app takes becomes a point on the graphs, whether it
   * came from the 30-second probe or from a full collection. A refresh you
   * asked for is as real a sample as one taken on a timer, and dropping it
   * would leave visible gaps in the line.
   *
   * An hour is kept. At one point per probe that is 120 samples; manual
   * refreshes add more, so the cap is generous and the window is trimmed
   * by time rather than by count.
   */
  /**
   * How much history the browser holds. The graphs read from this, so it
   * has to be long enough for the longest range on offer -- trimming to an
   * hour would quietly discard the week that was just fetched, and the
   * graph would draw a day while its label claimed a week.
   *
   * Bounded by count as well as by age: a switch left open for a month
   * should not grow an array without limit.
   */
  const HISTORY_MS = 8 * 24 * 60 * 60 * 1000;
  const HISTORY_MAX = 25000;

  // History is persisted by the server-side collector now (SERVER-STANDARD §6),
  // so the browser no longer batches or POSTs samples - it reads history back
  // with loadHistory. recordSample keeps only an in-memory point for an instant
  // graph update after a live write-settle walk.

  /** Seed the graphs from what was recorded before this tab existed.
   *  windowMs semantics: a positive number is a lookback window; 0 means
   *  "all history" (no cutoff); undefined/null means "use the default 24h".
   *  These must stay distinct — collapsing 0 into the default is what made
   *  "All" quietly request only 24 hours, so it showed less than "7 days". */
  function loadHistory(s, windowMs) {
    if (!s.host) return Promise.resolve();
    const since = (windowMs === 0)
      ? 0
      : (Number.isFinite(windowMs) && windowMs > 0 ? windowMs : 24 * 60 * 60 * 1000);
    return fetch('/api/history?host=' + encodeURIComponent(s.host) + '&since=' + since)
      .then((r) => r.json())
      .then((body) => {
        const kept = (body.samples || []).filter((x) => Number.isFinite(x.t));
        if (!kept.length) return;
        // Anything already sampled in this tab wins: it is the same data
        // and merging duplicates would draw the same minute twice.
        const newest = kept[kept.length - 1].t;
        const mine = (s.history || []).filter((x) => x.t > newest);
        s.history = kept.concat(mine);
        repaintPanel(s, 'metrics');
      })
      .catch(() => { /* graphs simply start from now */ });
  }

  function recordSample(s, values) {
    const num = (v) => (v === null || v === undefined || v === '' ? null : Number(v));
    const sample = {
      t: Date.now(),
      cpu: num(values.cpu), poeW: num(values.poeW), cpuPps: num(values.cpuPps)
    };
    if (sample.cpu === null && sample.poeW === null && sample.cpuPps === null) return;
    s.history = s.history || [];
    // A collection and a probe can land within a moment of each other;
    // two points at the same instant say nothing the first did not.
    const last = s.history[s.history.length - 1];
    if (last && sample.t - last.t < 1000) s.history.pop();
    s.history.push(sample);
    // No POST: the server-side collector persists history now. This local push
    // only gives the graph an instant point after a live write-settle walk;
    // loadHistory reconciles it against the server's store.
    const cutoff = sample.t - HISTORY_MS;
    while (s.history.length && (s.history[0].t < cutoff || s.history.length > HISTORY_MAX)) {
      s.history.shift();
    }
    repaintPanel(s, 'metrics');
  }

  function startProbe(s) {
    stopProbe(s);
    if (!s.target) return;
    s.probeTimer = setInterval(() => probeOnce(s), PROBE_MS);
  }

  function stopProbe(s) {
    if (s.probeTimer) { clearInterval(s.probeTimer); s.probeTimer = null; }
  }

  function probeOnce(s) {
    if (!s.target || s.probing) return;
    // Hold the reachability probe too while a write is in flight, so nothing
    // adds frames while the switch is busy writing its configuration.
    if (s.writeBusy) return;
    s.probing = true;
    // Reachability comes from the SERVER's view - it polls the switch; the
    // browser no longer pings it. Reboot is detected and logged server-side
    // (an event), so the browser only reacts to the up/down transition here.
    fetch('/api/collector/status')
      .then((r) => r.json())
      .then((body) => {
        s.probing = false;
        const row = (body.switches || []).find((x) => x.host === s.host);
        if (!row) { paintReachability(s); return; }
        const was = s.reachable;
        s.reachable = !!row.reachable;
        if (was === false && s.reachable) {
          appLog('info', 'Switch is answering again', { host: s.host });
          syncView(s);   // repaint from the now-fresh snapshot
        } else if (was !== false && !s.reachable) {
          appLog('warn', 'Switch stopped answering SNMP', { host: s.host, error: row.error });
        }
        paintReachability(s);
      })
      .catch(() => { s.probing = false; });
    // Keep the metric graph current from the server's authoritative history.
    loadHistory(s, s.graphRange);
  }

  /** Unreachable overrides the health verdict: stale data is not health. */
  function paintReachability(s) {
    if (!s.subtabs) return;
    if (s.reachable === false) {
      subDot(s, 'overview', 'err');
      subTint(s, 'overview', 'critical');
      setTab(s, 'critical');
      if (s.healthStatus) {
        clear(s.healthStatus);
        s.healthStatus.appendChild(el('span', 'pill crit', 'not answering SNMP'));
      }
    } else if (s.health) {
      applyHealthState(s, overallSeverity(s));
    }
  }

  /**
   * Traps: what the switch chose to interrupt us about. Same shape as the
   * syslog panel -- a live list that fills as things happen -- because it
   * answers the same kind of question and there is no reason for it to
   * look different.
   */
  /** Live delivery, so a trap appears the moment the switch sends it. */
  function startTrapStream(s) {
    if (s.trapStream || !s.host) return;
    try {
      s.trapStream = new EventSource('/api/traps/stream?host=' + encodeURIComponent(s.host));
    } catch (e) { return; }
    s.trapStream.onmessage = (ev) => {
      let m;
      try { m = JSON.parse(ev.data); } catch (e) { return; }

      // Keep the held copy current, not just the table. The trap-driven
      // refresh repaints the panel a moment later, and a repaint from a
      // stale copy would erase the very trap that caused it.
      if (s.traps && Array.isArray(s.traps.messages)) {
        s.traps.messages.unshift(m);
        s.traps.total = (s.traps.total || 0) + 1;
        if (s.traps.messages.length > 300) s.traps.messages.pop();
      }
      // Traps are off by default in the Events view. The held copy above is
      // kept current regardless (so the count is right and ticking Traps on
      // shows them immediately), but a live row is only inserted into the table
      // when traps are actually being shown - otherwise a hidden trap would pop
      // in and then vanish on the next repaint.
      const showTraps = !s.eventSources || s.eventSources.trap;
      if (showTraps && s.eventTable && s.eventTable.isConnected) {
        const search = (s.trapSearch || '').toLowerCase();
        if (!(search && m.name.toLowerCase().indexOf(search) < 0 &&
          !m.varbinds.some((v) => String(v.value).toLowerCase().indexOf(search) >= 0))) {
          const row = eventRow({
            at: m.at, kind: 'trap', severity: m.severity, what: m.name,
            detail: m.varbinds.map((v) => v.name.replace(/\.\d+$/, '') + ' ' + v.value).join('  \u00b7  ')
          });
          row.classList.add('syslog-new');   // background flash only, no layout shift
          s.eventTable.insertBefore(row, s.eventTable.firstChild);
          while (s.eventTable.children.length > 300) s.eventTable.lastChild.remove();
          setTimeout(() => row.classList.remove('flash'), 1200);
        }
      } else if (!s.eventTable || !s.eventTable.isConnected) {
        if (!s.traps) s.traps = null;
      }
      // A trap is the switch saying something changed; act on it regardless of
      // whether it is shown.
      onTrap(s, m);
    };
  }

  /**
   * A trap says something changed. Use it as a *trigger* to re-read the
   * part of the switch it concerns, not as the value itself.
   *
   * The distinction matters. A trap is UDP with no retransmission, and it
   * only arrives at all if the switch has been configured to send it, so a
   * counter maintained from traps drifts silently the moment one is
   * dropped and is simply absent on a switch nobody has configured. Polling
   * stays the source of truth; traps decide *when* to poll, which is where
   * the saving is -- the dashboard reacts in a second instead of waiting
   * out the refresh interval, and the interval itself can be long because
   * anything urgent announces itself.
   *
   * Refreshes are coalesced: a switch reloading sends a burst of linkUps
   * and re-reading the interface table once at the end is enough.
   */
  const TRAP_SUBJECTS = [
    // A link up/down affects the interface table (and the "X of Y up" figure
    // derived from it), so re-read ONLY the interfaces panel - not the whole
    // switch. A port flapping during a speed/auto-neg change would otherwise
    // trigger a full re-walk of every table per flap, hammering the CPU.
    { match: /link(up|down)/, panel: 'interfaces' },
    // 802.1X port-status traps (fired when a port re-authenticates - e.g. after
    // a speed/auto-neg bounce) must NOT re-walk the whole auth panel, which now
    // includes the RADIUS/TACACS server tables and the heavy per-host dot1x
    // counter tables. Re-read only the light dot1x session/lock tables.
    { match: /dot1xportstatus|portstatusauthorized|portstatusunauthorized/, tables: ['dot1xHosts', 'dot1xLocked'] },
    // A spanning-tree topology change mainly affects port roles/states and the
    // forwarding table - it does NOT need a whole-switch walk. Refresh the
    // interface panel only; the (on-demand) MAC table refreshes itself when the
    // Connected panel is open. A burst of these during a port-channel change
    // would otherwise each trigger a full poll.
    { match: /topologychange|newroot/, panel: 'interfaces' },
    // PoE and environment traps change derived totals across the picture, and a
    // restart invalidates everything - these genuinely warrant a full re-read.
    { match: /pethpse|poe|coldstart|warmstart|envmon|fan|temperature|power/, full: true },
    // Other authentication traps re-read the auth panel's session tables only.
    { match: /authentication|dot1x|locked/, tables: ['mgmtSessions', 'sshSessions', 'telnetSessions', 'dot1xHosts', 'dot1xLocked'] }
  ];

  // A flapping link must not turn into a collection per flap.
  const TRAP_REFRESH_FLOOR_MS = 10000;

  // Pull the affected interface's ifIndex out of a trap's varbinds. linkUp and
  // linkDown bind the standard ifIndex object (1.3.6.1.2.1.2.2.1.1.<N>); its
  // value, or the trailing N in the OID, is the port. Returns null if absent.
  function trapIfIndex(m) {
    for (const vb of (m && m.varbinds) || []) {
      const oid = String(vb.oid || vb.name || '');
      if (/1\.3\.6\.1\.2\.1\.2\.2\.1\.1\b/.test(oid) || /ifIndex/i.test(String(vb.name || ''))) {
        const v = parseInt(vb.value, 10);
        if (Number.isFinite(v)) return v;
        const m2 = oid.match(/\.(\d+)$/);
        if (m2) return parseInt(m2[1], 10);
      }
    }
    return null;
  }

  function onTrap(s, m) {
    const name = String(m && m.name || '').toLowerCase();
    if (!name || !s.target) return;

    // A restart invalidates everything on screen, not one panel.
    if (/coldstart|warmstart/.test(name)) {
      appLog('info', 'Trap reports the switch restarted; re-reading everything', {
        host: s.host, trap: m.name
      });
      scheduleTrapRefresh(s, null);
      return;
    }

    // A link up/down trap carries the affected port's ifIndex in its varbinds
    // (the standard ifIndex object, 1.3.6.1.2.1.2.2.1.1.N). When we can read it,
    // refresh JUST that port's row - the lightest possible reaction - instead of
    // re-walking the interface panel. This is the switch telling us exactly what
    // changed; we act on only that.
    if (/link(up|down)/.test(name)) {
      if (s._ifWriteUntil && Date.now() < s._ifWriteUntil) return;   // our own bounce
      const ifx = trapIfIndex(m);
      if (ifx != null) {
        appLog('info', 'Link trap: refreshing one port', { host: s.host, ifIndex: ifx, trap: m.name });
        // Debounce lightly per-port so a flapping link doesn't spam reads.
        s._linkTrapSeen = s._linkTrapSeen || new Map();
        const last = s._linkTrapSeen.get(ifx) || 0;
        if (Date.now() - last > 2000) { s._linkTrapSeen.set(ifx, Date.now()); setTimeout(() => refreshOnePort(s, ifx, true), 800); }
        return;
      }
      // No ifIndex in the trap: fall through to the panel-level refresh below.
    }

    for (const subject of TRAP_SUBJECTS) {
      if (subject.match.test(name)) {
        // When the app just made an interface change itself, the resulting port
        // bounce (and its link / 802.1X re-auth traps) is expected and the
        // editor does its own targeted re-read. Ignore the reactive refresh for
        // a few seconds so a self-induced bounce does not trigger table walks.
        if ((subject.panel === 'interfaces' || subject.tables) && s._ifWriteUntil && Date.now() < s._ifWriteUntil) {
          return;
        }
        if (subject.full) scheduleTrapRefresh(s, '*');
        else if (subject.tables) scheduleTrapRefresh(s, { tables: subject.tables });
        else scheduleTrapRefresh(s, subject.panel);
        return;
      }
    }
  }

  function scheduleTrapRefresh(s, key) {
    s.trapPending = s.trapPending || new Set();
    s.trapPendingTables = s.trapPendingTables || new Set();
    if (key === null || key === '*') s.trapPending.add('*');
    else if (key && key.tables) { for (const t of key.tables) s.trapPendingTables.add(t); }
    else s.trapPending.add(key);
    if (s.trapRefreshTimer) return;
    const since = Date.now() - (s.lastTrapRefresh || 0);
    const wait = Math.max(1500, TRAP_REFRESH_FLOOR_MS - since);
    s.trapRefreshTimer = setTimeout(() => {
      s.trapRefreshTimer = null;
      s.lastTrapRefresh = Date.now();
      const keys = Array.from(s.trapPending);
      const tables = Array.from(s.trapPendingTables);
      s.trapPending.clear(); s.trapPendingTables.clear();
      appLog('info', 'Refreshed after a trap', { host: s.host, scope: keys.concat(tables).join(', ') });
      if (keys.indexOf('*') >= 0) { loadHealth(s, true); return; }
      // Specific-table refresh: walk only those tables and repaint the panels
      // that use them (cheaper than a whole-panel refresh).
      if (tables.length) { refreshTables(s, tables); }
      for (const key of keys) {
        const panel = s.panels.find((p) => p.kind === 'builtin' && p.key === key);
        if (panel) refreshPanel(s, panel);
      }
    }, wait);
  }

  // Re-read just ONE interface's row (admin/oper status and operational speed)
  // with a handful of GETs, update it in s.health.interfaces, and repaint the
  // interfaces panel. Used after the app changes one port (speed/duplex/auto-
  // neg/admin/PoE) so the table reflects the new state without re-walking every
  // port. The port may renegotiate for a moment, so this is normally called a
  // couple of seconds after the change.
  const RLIF_COLS = {
    rlifPresentAdminStatus: '1.3.6.1.4.1.9.6.1.101.54.43.1.7',
    rlifPresentOperStatus: '1.3.6.1.4.1.9.6.1.101.54.43.1.8',
    rlifPresentHighSpeed: '1.3.6.1.4.1.9.6.1.101.54.43.1.37'
  };
  function refreshOnePort(s, ifIndex, reactive) {
    if (!s.target || ifIndex === null || ifIndex === undefined) return Promise.resolve();
    // A reactive (trap-driven) read is skipped while a write is in progress, so
    // an unrelated port's link trap can't fire a GET mid-write. Deliberate
    // post-edit re-reads pass reactive=false and always run.
    if (reactive && s.writeBusy) return Promise.resolve();
    const oids = Object.values(RLIF_COLS).map((o) => o + '.' + ifIndex);
    return apiPost('/api/snmp/get', { target: s.target, oids })
      .then(({ body }) => {
        if (!body || body.error || !s.health || !Array.isArray(s.health.interfaces)) return;
        const row = s.health.interfaces.find((x) => String(x.index) === String(ifIndex));
        if (!row) return;
        const wanted = new Set(Object.keys(RLIF_COLS));
        let changed = false;
        for (const vb of (body.results || [])) {
          if (vb.error) continue;
          // Prefer the resolved column name from the server; fall back to the
          // OID's second-to-last arc mapped through RLIF_COLS.
          let name = vb.column;
          if (!name || !wanted.has(name)) {
            const parts = String(vb.oid || '').split('.');
            const colOid = parts.slice(0, -1).join('.');
            name = Object.keys(RLIF_COLS).find((k) => RLIF_COLS[k] === colOid);
          }
          if (!name || !wanted.has(name)) continue;
          row[name] = (vb.display !== undefined && vb.display !== null && vb.display !== String(vb.value))
            ? { value: vb.value, display: vb.display } : { value: vb.value };
          changed = true;
        }
        if (changed) {
          // Reconcile the keyed interfaces panel so only this row's changed
          // cells patch (the shut button flips in place); fall back to a full
          // repaint if it isn't a keyed panel.
          const ip = s.panels && s.panels.find((x) => x.kind === 'builtin' && x.key === 'interfaces' && x._body);
          if (!ip || !reconcilePanelInPlace(s, ip)) repaintPanel(s, 'interfaces');
        }
      })
      .catch(() => {});
  }

  // Re-read specific SCALAR objects (by name -> base OID, instance .0) with a
  // single batched GET and update s.health.scalars in place. Targeted panel
  // refreshes skip scalars, so any setting stored as a scalar must be re-read
  // this way after a write. Light (one GET) and exact. Reusable for any future
  // scalar-based settings.
  // Call after any config-changing write. Immediately re-reads the cheap
  // running-vs-startup scalar so the "unsaved" badge updates at once (rather
  // than waiting for the next health poll), and - if the config comparison
  // overlay is open - auto-refreshes the line diff so the panel shows what
  // changed. The expensive TFTP diff is only pulled when the overlay is open,
  // and debounced so a burst of changes triggers one refresh, not many.
  // Call this after EVERY successful configuration change, from any module.
  // Pass the control(s) the user changed (a single node, or an array) and they
  // are highlighted so the change is felt; omit them if there is no on-screen
  // control to highlight (e.g. a row that vanishes). This one call is the single
  // place that (a) flips the "unsaved" badge and (b) runs the changed-field
  // highlight - so any new or existing module gets BOTH behaviours consistently
  // just by calling markConfigDirty(s, theChangedControls) on success.
  // Repaint the panels that show the "Config saved" badge. The badge card lives
  // in the METRICS panel (the summary panel also reads the scalar for its
  // identical-configs logic), so both must repaint for the badge to flip
  // instantly - repainting only 'summary'/'health' left the visible badge stale
  // until the next full poll (now 300s), which is why it felt slow.
  function repaintConfigBadge(s) {
    for (const key of ['metrics', 'summary']) {
      const p = s.panels && s.panels.find((x) => x.kind === 'builtin' && x.key === key && x._body);
      if (p) repaintPanel(s, key);
    }
    // The saved-config scalar feeds the overall severity (via liveAlerts), so the
    // Attention tab/hero badge must re-evaluate too - otherwise a save clears the
    // summary banner but leaves "Attention" stuck with nothing to explain it.
    if (s.health) applyHealthState(s, overallSeverity(s));
  }

  function markConfigDirty(s, changed) {
    if (!s || !s.target) return;
    // Highlight the changed control(s). Accepts a node, an array, or nothing.
    if (changed) { if (Array.isArray(changed)) flashValues(changed); else flashValue(changed); }
    const repaintBadge = () => repaintConfigBadge(s);
    // A change we just made means running now differs from startup, full stop -
    // so flip the badge to "unsaved" immediately and treat that as AUTHORITATIVE.
    // We deliberately do NOT follow up with a background scalar read: on this
    // firmware the rlRunningCDBequalToStartupCDB flag updates at different speeds
    // for different setting types (fast for interface settings, lagging for
    // 802.1X), so a confirming read could momentarily return "saved" and revert
    // the badge - exactly the inconsistency seen. The badge stays "unsaved"
    // until a save (which sets it back optimistically), which is always correct:
    // a write cannot leave running identical to startup.
    if (s.health && s.health.scalars) {
      s.health.scalars.rlRunningCDBequalToStartupCDB = { value: 2, display: 'false', oid: '1.3.6.1.4.1.9.6.1.101.1.13.0' };
      repaintBadge();
    }
    // The line-by-line diff requires pulling BOTH full configs over TFTP, which
    // is a copy operation on the switch - the single most CPU-heavy thing we can
    // ask of it. Doing that automatically on every change (even debounced) was
    // the dominant load. So we do NOT auto-fetch here. If the config comparison
    // overlay is open, mark its current diff as stale and show a one-click
    // "refresh" affordance; the user pulls the fresh diff only when they want it.
    if (s.cfgOverlay && s.cfgOverlay.classList.contains('open')) {
      s.cfgStale = true;
      repaintConfig(s);
    }
  }

  function refreshScalars(s, nameToOid) {
    const names = Object.keys(nameToOid || {});
    if (!s.target || !names.length) return Promise.resolve();
    const oids = names.map((n) => nameToOid[n] + '.0');
    return apiPost('/api/snmp/get', { target: s.target, oids })
      .then(({ body }) => {
        if (!body || body.error || !s.health) return;
        s.health.scalars = s.health.scalars || {};
        // Map each returned varbind back to its scalar NAME via the OID.
        const oidToName = {};
        for (const n of names) oidToName[nameToOid[n]] = n;
        for (const vb of (body.results || [])) {
          if (vb.error) continue;
          const base = String(vb.oid || '').replace(/\.0$/, '');
          const name = oidToName[base] || vb.column;
          if (!name) continue;
          // Always keep a display string: some panels read .display directly,
          // so dropping it (when display equals the raw value) left them blank.
          const disp = (vb.display !== undefined && vb.display !== null) ? vb.display : String(vb.value);
          s.health.scalars[name] = { value: vb.value, display: disp };
        }
      })
      .catch(() => {});
  }

  // Light re-read of just the port-channel (LAG) tables, merged into s.health,
  // then repaint the interfaces panel. Returns the total member count across
  // all channels (so a caller can tell whether a channel has re-formed). Keeps
  // the switch load minimal - only the small LAG tables are walked.
  function refreshLagTables(s) {
    const tables = ['lagCreation', 'lagAgg', 'lagMembers', 'lagPortKey'];
    return fetch('/api/health', { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: s.target, only: tables }) })
      .then((r) => r.json())
      .then((body) => {
        if (!body || body.error) return 0;
        for (const key of body.keys || []) if (s.health) s.health[key] = body[key];
        const ip = s.panels.find((p) => p.kind === 'builtin' && p.key === 'interfaces');
        // Preserve the page scroll position across the repaint so a channel
        // change does not jump the user to the top of the panel.
        const restoreLag = scrollKeeper(s);
        // Reconcile in place (keyed) so a channel change patches only the rows
        // that changed - no teardown, no scroll jump; fall back to full repaint.
        if (ip && ip._body) { if (!reconcilePanelInPlace(s, ip)) repaintPanel(s, 'interfaces'); }
        restoreLag();
        // Count CONFIGURED members across all channels: ports whose actor admin
        // key points at a real aggregator (not their own ifIndex / 0). This
        // reflects configured membership even when a member link is down (the
        // active bitmap would miss those).
        let total = 0;
        const dvv = (c) => (c && (c.display !== undefined && c.display !== null && c.display !== '') ? c.display : (c && c.value !== undefined ? c.value : ''));
        for (const r of (s.health && s.health.lagPortKey) || []) {
          const k = String(dvv(r.dot3adAggPortActorAdminKey) || '').replace(/[,\s]/g, '');
          if (k && k !== '0' && k !== String(r.index)) total++;
        }
        return total;
      })
      .catch(() => 0);
  }

  // Walk only the named tables and merge into s.health, then repaint affected
  // panels. Used by trap-driven refreshes that need just a couple of tables.
  // Which built-in panels depend on which health tables, so a targeted refresh
  // repaints only the panels that actually changed - avoids reflowing (and
  // visually jolting) unrelated panels on every small update.
  const PANEL_TABLE_DEPS = {
    interfaces: ['interfaces', 'poe', 'lagAgg', 'lagMembers', 'lagCreation', 'lagPortKey', 'bridgePorts', 'dot1xPortCfg', 'dot1xPortMethod', 'dot1xHostMode', 'vlans', 'vlansCurrent', 'portModes', 'portL2L3', 'portAccessVlan', 'portNativeVlan', 'sviAddrs'],
    vlans: ['vlans', 'vlansCurrent', 'interfaces', 'sviAddrs', 'portModes', 'portL2L3', 'voiceOUI', 'voiceLocalSrc', 'scalars'],
    summary: ['vlans', 'interfaces', 'sviAddrs', 'scalars', 'poe'],
    auth: ['mgmtSessions', 'sshSessions', 'telnetSessions', 'dot1xHosts', 'dot1xLocked', 'radius', 'tacacs', 'radiusServers', 'radiusStats', 'tacacsServers'],
    connected: ['macTable', 'interfaces', 'bridgePorts', 'dot1xHosts'],
    stp: ['stpPorts', 'stpExtPorts', 'interfaces', 'bridgePorts', 'mstpPorts', 'mstpInstances',
          'pvstPorts', 'pvstVlans', 'pvstInconsistencies', 'stpxInconsistencies'],
    routing: ['sviAddrs', 'interfaces', 'vlans', 'portL2L3', 'routeTable', 'staticRoutes', 'dnsDomains', 'dnsServersV2', 'dnsHosts', 'scalars'],
    acl: ['aclNames', 'aclAces', 'aclTuples'],
    // SNMP configuration, Flash files and Packet capture have their own
    // loaders (17-snmp-config.js, 16-flash-capture.js); no health table feeds
    // them, so a table refresh never repaints them.
    snmpcfg: [],
    flash: [],
    capture: []
  };
  function panelDependsOn(key, changedTables) {
    const deps = PANEL_TABLE_DEPS[key];
    if (!deps) return true;   // unknown/other panel: repaint to be safe
    return changedTables.some((t) => deps.indexOf(t) !== -1);
  }

  // Views that live OUTSIDE the panel grid (overlays, badges) but still derive
  // their content from health data, and so must be re-rendered when that data
  // changes - otherwise a message driven by a value (e.g. the config overlay's
  // "differs from startup" banner, driven by the saved-state scalar) stays stuck
  // showing an old state after the value updates. Each reconciler declares which
  // health keys it depends on and how to re-render; reconcileViews() runs the
  // ones whose data changed. Register new state-driven views here rather than
  // scattering repaint calls, so every such message refreshes consistently.
  const VIEW_RECONCILERS = [
    {
      // The config comparison: its badge and the overlay's unsaved/differs
      // banner both read rlRunningCDBequalToStartupCDB and the fetched files.
      keys: ['scalars'],
      run: (s) => { repaintConfigBadge(s); if (s.cfgOverlay && s.cfgOverlay.classList.contains('open')) repaintConfig(s); }
    }
  ];
  // Run every reconciler whose declared keys intersect the changed set. Pass
  // changedKeys = null to run them all (e.g. after a full collection).
  function reconcileViews(s, changedKeys) {
    const all = !changedKeys;
    const changed = new Set(changedKeys || []);
    for (const rec of VIEW_RECONCILERS) {
      if (all || rec.keys.some((k) => changed.has(k))) {
        try { rec.run(s); } catch (e) { /* a view error must not break the refresh */ }
      }
    }
  }

  function refreshTables(s, tables) {
    if (!s.target || !tables.length) return Promise.resolve();
    // Don't run a partial walk on top of a full collection or a config write -
    // two walks hitting the same agent at once adds to the switch's CPU input
    // rate. Defer briefly and retry; the full collection will refresh these
    // tables anyway, so a short wait is harmless. The returned promise resolves
    // when the deferred walk (and its repaint) finish, so a caller can wait for
    // the UI to actually reflect the change.
    if (s._healthInFlight || s.writeBusy) {
      if (!s._deferredTables) s._deferredTables = new Set();
      for (const t of tables) s._deferredTables.add(t);
      if (!s._deferredWaiters) s._deferredWaiters = [];
      const waiter = new Promise((res) => s._deferredWaiters.push(res));
      if (!s._deferTimer) {
        s._deferTimer = setTimeout(() => {
          s._deferTimer = null;
          const pending = s._deferredTables ? Array.from(s._deferredTables) : [];
          s._deferredTables = null;
          const waiters = s._deferredWaiters || []; s._deferredWaiters = null;
          const done = pending.length ? refreshTables(s, pending) : Promise.resolve();
          done.then(() => { for (const w of waiters) w(); });
        }, 1500);
      }
      return waiter;
    }
    return fetch('/api/health', { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: s.target, only: tables }) })
      .then((r) => r.json())
      .then((body) => {
        if (!body || body.error) return;
        const changed = body.keys || [];
        for (const key of changed) {
          if (!s.health) continue;
          if (key === 'scalars') {
            // Merge scalars (the partial read only covers the health batch) so
            // we don't drop the system scalars, and feed the metrics graph. The
            // view reconcilers below refresh anything that reads these scalars.
            s.health.scalars = Object.assign({}, s.health.scalars, body.scalars || {});
            const cpuCell = s.health.scalars.rlCpuUtilDuringLast5Minutes;
            recordSample(s, {
              cpu: cpuCell ? (cpuCell.value !== undefined ? cpuCell.value : cpuCell.display) : null,
              poeW: body.summary && body.summary.poeUsedW,
              cpuPps: body.summary && body.summary.cpuInputPps
            });
          } else {
            s.health[key] = body[key];
          }
        }
        // Repaint panels whose data changed. A converted panel reconciles its
        // keyed tables in place (no teardown, no reflow, no scroll move); an
        // unconverted one does a full repaint, so we still preserve the page
        // scroll position for those as a fallback.
        const restoreRt = scrollKeeper(s);
        for (const p of s.panels) {
          if (p.kind !== 'builtin' || !p._body || !panelDependsOn(p.key, changed)) continue;
          const forceFull = (PANEL_FULL_REPAINT_TABLES[p.key] || []).some((t) => changed.indexOf(t) !== -1);
          if (forceFull || !reconcilePanelInPlace(s, p)) repaintPanel(s, p.key);
        }
        restoreRt();
        // Reconcile non-panel views (overlays, badges) whose data just changed,
        // so their state-driven messages reflect the new values.
        reconcileViews(s, changed);
      })
      .catch(() => {});
  }

  function stopTrapStream(s) {
    if (s.trapStream) { try { s.trapStream.close(); } catch (e) {} s.trapStream = null; }
  }

  /** The sessions this app is holding, for the authentication panel. */
  function loadSessions(s) {
    return fetch('/api/sessions')
      .then((r) => r.json())
      .then((body) => {
        s.appSessions = body.sessions || [];
        repaintPanel(s, 'auth');
      })
      .catch(() => {});
  }

  // Apply a full health object (from a live walk OR the server snapshot) to the
  // dashboard: carry forward on-demand tables, store it, and repaint. The one
  // place that turns a health payload into rendered panels, so a live load and
  // a snapshot read render identically.
  function applyFullHealth(s, body) {
    // On-demand tables (MAC table, the ACL panel's three raw tables) are not in
    // the regular poll, so a fresh full health has them empty. Carry the last
    // fetched copy forward rather than wiping it - otherwise an open panel that
    // needs it would re-fetch on every update ("ACL/MAC reloads on every open").
    // An empty list that was actually read is carried too (a switch with no
    // ACLs), so the panel does not fall back to "Waiting for data".
    if (s.health) {
      for (const k of ['macTable', 'aclNames', 'aclAces', 'aclTuples']) {
        if ((!body[k] || !body[k].length) && Array.isArray(s.health[k]) && (s.health[k].length || !Array.isArray(body[k]))) body[k] = s.health[k];
      }
    }
    s.health = body;
    // The server-detected product line (C1200 / C1300 / C1300X) drives the MIB
    // Explorer default and feature gating. Keep a prior value if a refresh
    // comes back without one.
    if (body.product && body.product.line) { s.product = body.product; if (s.productPaint) s.productPaint(); }
    paintTopoButton();
    const named = body.scalars && body.scalars.sysName;
    s.sysName = named
      ? String(named.display !== undefined && named.display !== null ? named.display : named.value).trim()
      : '';
    renderSwitch(s);
    reconcileViews(s, null);   // a full collection refreshed everything
    loadSessions(s);
  }

  // Viewer sync: show the server's latest snapshot WITHOUT the browser walking
  // the switch. opts.nudge asks the server to poll now first (manual Refresh /
  // first open); otherwise the cached snapshot is read. Metric history is read
  // from the server's store (loadHistory), not sampled by the browser.
  function syncView(s, opts) {
    if (!s.host) return Promise.resolve();
    const nudge = !!(opts && opts.nudge);
    if (nudge && s.refreshBtn) { showSpinner(s, true); s.refreshBtn.disabled = true; }
    const req = nudge
      ? fetch('/api/collect/now', { method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ target: s.target }) })
          .then((r) => r.json().then((b) => ({ at: b && b.at, data: b && b.data, error: b && b.error })))
      : fetch('/api/collector/snapshot?host=' + encodeURIComponent(s.host) +
          (s.health && s.health.collectedAt ? '&have=' + encodeURIComponent(s.health.collectedAt) : ''))
          .then((r) => (r.status === 404 ? { none: true } : r.json()));
    return req.then((res) => {
      if (nudge && s.refreshBtn) { showSpinner(s, false); s.refreshBtn.disabled = false; }
      if (res.none) {
        // No snapshot yet (switch just added / collector hasn't polled). Nudge
        // once to populate; if a nudge already came back empty, wait a cycle.
        return nudge ? undefined : syncView(s, { nudge: true });
      }
      if (res.unchanged) {
        // The server still holds the collection this page shows: nothing to
        // download or repaint. The switch answered its last probe, and the
        // metric graph moves every 30 s, so those still update.
        const wasDown = s.reachable === false;
        s.reachable = true;
        if (wasDown) paintReachability(s);
        s.snapshotAt = res.at || Date.now();
        loadHistory(s, s.graphRange);
        return;
      }
      if (res.error && !res.data) {
        s.reachable = false;
        appLog('warn', 'Switch not answering (server view)', { host: s.host, error: res.error });
        paintReachability(s);
        return;
      }
      if (res.data) {
        s.reachable = true;
        applyFullHealth(s, res.data);
        s.snapshotAt = res.at || Date.now();
        loadHistory(s, s.graphRange);
      }
    }).catch((e) => {
      if (nudge && s.refreshBtn) { showSpinner(s, false); s.refreshBtn.disabled = false; }
      appLog('error', 'View sync failed', { host: s.host, message: e.message });
    });
  }

  function loadHealth(s, quiet) {
    if (!s.target) return Promise.resolve();
    // Never walk the switch while a config copy/save or an SNMP write is in
    // flight. A config copy is CPU-heavy on the switch, and piling a full
    // multi-table health walk on top of it can destabilise a fragile agent
    // (observed as a crash after a community add + config save). The caller's
    // own completion handlers refresh health once the write finishes.
    if (s.writeBusy) { if (!quiet) showSpinner(s, false); return Promise.resolve(); }
    // Coalesce REACTIVE (quiet) full loads so a burst of triggers - several
    // traps during a port-channel change, a config save, the auto-timer all
    // landing close together - doesn't run the whole-switch walk over and over.
    // A quiet load is skipped if one is already in flight, or finished within
    // the last 12s. User-initiated loads (quiet=false) always run.
    if (quiet) {
      if (s._healthInFlight) return Promise.resolve();
      if (s._lastFullHealth && Date.now() - s._lastFullHealth < 12000) return Promise.resolve();
    }
    s._healthInFlight = true;
    subDot(s, 'overview', 'busy');
    if (!quiet) showSpinner(s, true);
    s.refreshBtn.disabled = true;
    if (!s.health) {
      clear(s.grid);
    }
    return fetch('/api/health', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: s.target })
    })
      .then((r) => r.json().then((b) => ({ ok: r.ok, body: b })))
      .then(({ ok, body }) => {
        s.refreshBtn.disabled = false;
        showSpinner(s, false);
        if (!ok || body.error) {
          const m = (body && body.error) || 'Health collection failed.';
          appLog('error', 'Health collection failed', { host: s.host, message: m });
          setTab(s, 'critical', s.host);
          subDot(s, 'overview', 'err');
          subTint(s, 'overview', 'critical');
          s.healthStatus.textContent = 'error: ' + m;
          if (!s.health) { clear(s.grid); s.grid.appendChild(el('div', 'empty-state', m)); }
          return;
        }
        // Render exactly as a snapshot read does. History is the server's job
        // now (the collector records every poll), so a live walk no longer
        // samples into the graph here - loadHistory reads it back from the
        // server's store.
        applyFullHealth(s, body);
      })
      .catch((e) => {
        s.refreshBtn.disabled = false;
        showSpinner(s, false);
        appLog('error', 'Health request failed', { host: s.host, message: e.message });
        subDot(s, 'overview', 'err');
        s.healthStatus.textContent = 'request failed: ' + e.message;
      })
      .finally(() => { s._healthInFlight = false; s._lastFullHealth = Date.now(); });
  }

  /** Refresh one panel: its OID, its tables, or the whole switch. */
  function refreshPanel(s, p, btn) {
    if (!s.target) return;
    if (p.kind === 'oid') { loadPanelData(s, p); return; }
    // Syslog comes from the receiver in this app, not from the switch.
    if (p.key === 'events') { loadEvents(s, p); return; }
    if (p.key === 'auth') { loadSessions(s); }
    // SNMP configuration, Flash files and Packet capture re-run their own
    // loaders (server endpoints, not health tables) and reconcile in place.
    const ownLoader = { snmpcfg: snmpLoad, flash: flashLoad, capture: captureLoad }[p.key];
    if (ownLoader) {
      if (btn) { btn.disabled = true; btn.classList.add('spin'); }
      ownLoader(s).catch(() => {}).then(() => { if (btn) { btn.disabled = false; btn.classList.remove('spin'); } });
      return;
    }

    const tables = PANEL_TABLES[p.key];
    if (!tables) { loadHealth(s); return; }   // whole-switch panel

    if (btn) { btn.disabled = true; btn.classList.add('spin'); }
    appLog('info', 'Refreshing panel', { host: s.host, panel: p.title, tables: tables.join(',') });
    fetch('/api/health', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: s.target, only: tables })
    })
      .then((r) => r.json().then((b) => ({ ok: r.ok, body: b })))
      .then(({ ok, body }) => {
        if (btn) { btn.disabled = false; btn.classList.remove('spin'); }
        if (!ok || body.error) {
          appLog('error', 'Panel refresh failed', { host: s.host, panel: p.title, message: body.error });
          return;
        }
        // Merge only what was asked for; the rest of the page keeps the
        // values from its last full collection.
        for (const key of body.keys || []) s.health[key] = body[key];
        const keep = p._body ? p._body.scrollTop : 0;
        paintPanelBody(s, p);
        if (p._body) p._body.scrollTop = keep;
      })
      .catch((e) => {
        if (btn) { btn.disabled = false; btn.classList.remove('spin'); }
        appLog('error', 'Panel refresh failed', { host: s.host, panel: p.title, message: e.message });
      });
  }

  function loadPanelData(s, panel) {
    if (!s.target || panel.kind !== 'oid') return;
    panel.loading = true;
    paintPanelBody(s, panel);
    const path = panel.op === 'walk' ? '/api/snmp/walk' : '/api/snmp/get';
    const payload = panel.op === 'walk' ? { oid: panel.oid } : { oids: [panel.oid] };
    fetch(path, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(Object.assign({ target: s.target }, payload))
    })
      .then((r) => r.json().then((b) => ({ ok: r.ok, body: b })))
      .then(({ ok, body }) => {
        panel.loading = false;
        if (!ok || body.error) {
          panel.error = body.error || 'request failed';
          panel.results = null;
        } else {
          panel.error = null;
          panel.results = body.results;
          panel.at = new Date();
        }
        paintPanelBody(s, panel);
      })
      .catch((e) => {
        panel.loading = false; panel.error = e.message; panel.results = null;
        paintPanelBody(s, panel);
      });
  }
