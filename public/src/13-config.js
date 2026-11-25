  // =================================================================
  // 13-config.js: The Configuration page: fetch, compare, history, save and backup.
  // =================================================================

  // ---------- configuration panel ----------
  // One place to pull every file off the switch: running-config,
  // startup-config and show tech-support. Whatever has been fetched stays
  // held and selectable, so comparing does not throw away the document you
  // were reading, and switching back costs nothing.
  // Configurations only. show tech-support is collected and read on its
  // own page: it comes over SSH rather than SNMP, it is two orders of
  // magnitude larger, and it has a section browser these do not need.
  const CFG_DOCS = [
    { key: 'running', label: 'Running', how: 'snmp' },
    { key: 'startup', label: 'Startup', how: 'snmp' }
  ];

  function paintConfigPanel(s, body) {
    s.docs = s.docs || {};
    if (!s.target) {
      body.appendChild(el('div', 'empty-state',
        'Set a switch target on the Health tab first \u2014 pulling files reuses it.'));
      return;
    }

    // --- actions ---
    const bar = el('div', 'cfg-bar');
    const mk = (label, cls, fn, disabled, title) => {
      const b = el('button', 'btn ' + (cls || ''), label);
      b.type = 'button'; b.style.width = 'auto';
      if (title) b.title = title;
      if (disabled) b.disabled = true; else b.addEventListener('click', fn);
      bar.appendChild(b);
      return b;
    };
    const held = (k) => s.docs[k] && s.docs[k].text;

    // One action: pull both and diff them. Fetching one without the other
    // was never the interesting case -- what you want to know is what the
    // switch is running and whether it will survive a reload.
    const have = held('running') && held('startup');
    mk(have ? 'Refetch both' : 'Fetch configurations', '',
      () => fetchConfigs(s), s.cfgBusy,
      'Pulls running-config and startup-config, then compares them');
    body.appendChild(bar);

    // --- what is held, and which is on screen ---
    const chips = el('div', 'cfg-chips');
    const view = (key) => { s.cfgView = key; repaintConfig(s); };
    let any = false;
    for (const d of CFG_DOCS) {
      const doc = s.docs[d.key];
      if (!doc || !doc.text) continue;
      any = true;
      const chip = el('button', 'cfg-chip' + (s.cfgView === d.key ? ' active' : ''), d.label);
      chip.type = 'button';
      chip.title = doc.lines.toLocaleString() + ' lines \u00b7 fetched ' + doc.at.toLocaleTimeString();
      chip.appendChild(el('span', 'chip-meta', doc.lines.toLocaleString() + ' lines'));
      chip.addEventListener('click', () => view(d.key));
      chips.appendChild(chip);
    }
    if (s.cfgDiff) {
      any = true;
      const chip = el('button', 'cfg-chip' + (s.cfgView === 'diff' ? ' active' : ''), 'Differences');
      chip.type = 'button';
      chip.appendChild(el('span', 'chip-meta', s.cfgDiff.filter((d) => d.t !== ' ').length + ' lines'));
      chip.addEventListener('click', () => view('diff'));
      chips.appendChild(chip);
    }
    // Stored versions live on the server (config-history.js), so this chip is
    // there before anything has been fetched in this browser.
    {
      const h = s.cfgHist;
      const chip = el('button', 'cfg-chip' + (s.cfgView === 'history' ? ' active' : ''), 'History');
      chip.type = 'button';
      chip.title = 'Earlier running configurations of this switch, kept each time it changed';
      if (h && h.versions) chip.appendChild(el('span', 'chip-meta', h.versions.length + ' stored'));
      chip.addEventListener('click', () => { s.cfgView = 'history'; loadConfigHistory(s); });
      chips.appendChild(chip);
      any = true;
    }
    if (any) {
      body.appendChild(chips);
    }

    // --- content ---
    const out = el('div', 'cfg-out');
    body.appendChild(out);

    if (s.cfgBusy) { out.appendChild(el('div', 'card-sub', s.cfgBusy)); return; }
    if (s.cfgError) {
      const err = el('div', 'panel-err', s.cfgError);
      err.style.whiteSpace = 'pre-wrap';   // the failure lists what was tried
      out.appendChild(err);
    }
    // The config changed on the switch since this diff was fetched. Rather than
    // auto-pull both configs over TFTP (a heavy switch copy op) on every change,
    // show a gentle prompt and let the user refresh on demand.
    if (s.cfgStale && s.docs && (s.docs.running || s.docs.startup)) {
      const banner = el('div', 'cfg-stale');
      banner.appendChild(el('span', '', 'The configuration changed since this was fetched.'));
      const rb = el('button', 'btn btn-small', 'Refresh comparison'); rb.type = 'button';
      rb.addEventListener('click', () => { s.cfgStale = false; fetchConfigs(s, true).then(() => { s.cfgView = 'diff'; repaintConfig(s); }); });
      banner.appendChild(rb);
      out.appendChild(banner);
    }

    if (s.cfgView === 'diff' && s.cfgDiff) { renderDiff(out, s.cfgDiff, s); return; }
    if (s.cfgView === 'history') { renderConfigHistory(out, s); return; }

    const doc = s.docs[s.cfgView];
    if (doc && doc.text) {
      const meta = el('div', 'card-sub',
        doc.label + ' \u00b7 ' + doc.lines.toLocaleString() + ' lines \u00b7 ' +
        doc.bytes.toLocaleString() + ' bytes \u00b7 ' + doc.via + ' at ' + doc.at.toLocaleTimeString());
      out.appendChild(meta);
      const pre = document.createElement('pre');
      pre.textContent = doc.text;
      out.appendChild(pre);
      return;
    }

    if (!s.cfgError) {
      out.appendChild(el('div', 'card-sub',
        'Fetch the configurations to see the running config, the startup config and the ' +
        'differences between them. The switch uploads each over TFTP to the receiver built ' +
        'into this app, which needs SNMP write access and reachability on UDP 69. ' +
        'What you fetch stays here until you refetch. ' +
        'show tech-support is collected on its own page.'));
    }
  }

  async function loadConfigHistory(s) {
    s.cfgHist = Object.assign(s.cfgHist || {}, { busy: 'Loading stored versions\u2026', error: null });
    repaintConfig(s);
    try {
      const body = await getJson('/api/config/history?host=' + encodeURIComponent(s.host));
      s.cfgHist.versions = body.versions || [];
    } catch (e) {
      s.cfgHist.error = 'Could not load the stored versions: ' + e.message;
      appLog('error', 'Config history load failed', { host: s.host, message: e.message });
    }
    s.cfgHist.busy = null;
    repaintConfig(s);
  }

  /** Open one stored version, as text ('view') or against a baseline ('compare'). */
  async function showConfigVersion(s, v, mode) {
    const h = s.cfgHist;
    h.busy = 'Opening the version from ' + new Date(v.at).toLocaleString() + '\u2026';
    h.error = null;
    repaintConfig(s);
    try {
      const url = (id) => '/api/config/history/version?host=' + encodeURIComponent(s.host) + '&id=' + encodeURIComponent(id);
      const picked = await getJson(url(v.id));
      let against = null;
      if (mode === 'compare') {
        const running = s.docs && s.docs.running;
        if (running && running.text) {
          against = { label: 'the running configuration fetched at ' + running.at.toLocaleTimeString(), text: running.text };
        } else {
          const newest = h.versions[0];
          const n = await getJson(url(newest.id));
          against = { label: 'the newest stored version (' + new Date(newest.at).toLocaleString() + ')', text: n.text };
        }
      }
      h.shown = { version: picked, mode, against, diff: against ? diffLines(picked.text, against.text) : null };
    } catch (e) {
      h.error = 'Could not open that version: ' + e.message;
      appLog('error', 'Config history version failed', { host: s.host, id: v.id, message: e.message });
    }
    h.busy = null;
    repaintConfig(s);
  }

  function renderConfigHistory(host, s) {
    const h = s.cfgHist || {};
    if (h.busy) { host.appendChild(el('div', 'card-sub', h.busy)); return; }
    if (h.error) host.appendChild(el('div', 'panel-err', h.error));
    const versions = h.versions || [];
    if (!versions.length) {
      if (!h.error) {
        host.appendChild(el('div', 'card-sub',
          'No versions are stored for ' + s.host + ' yet. A copy of the running configuration is ' +
          'kept, encrypted, the first time the app pulls it and each time it changes after that ' +
          '(the background check pulls it when the switch reports unsaved changes or a save, after ' +
          'a reboot, and after a change made from this app; fetching it here counts too).'));
      }
      return;
    }
    const canCompareNewest = !!(s.docs && s.docs.running && s.docs.running.text);
    host.appendChild(el('div', 'card-sub', versions.length + ' stored version(s), newest first. ' +
      'Compare shows what changed from that version to ' +
      (canCompareNewest ? 'the running configuration fetched here.' : 'the newest stored version.')));
    const rows = versions.map((v, i) => [
      new Date(v.at).toLocaleString() + (i === 0 ? ' (newest)' : ''),
      v.hash,
      actGroup([
        actBtn('View', () => showConfigVersion(s, v, 'view'), null, 'Show this version'),
        // The newest compared with itself says nothing unless running is held.
        (i > 0 || canCompareNewest)
          ? actBtn('Compare', () => showConfigVersion(s, v, 'compare'), null, 'What changed since this version')
          : null
      ])
    ]);
    host.appendChild(plainTable(s, ['Stored', 'Fingerprint', ''], rows));

    const shown = h.shown;
    if (!shown) return;
    const when = new Date(shown.version.at).toLocaleString();
    if (shown.mode === 'view') {
      host.appendChild(el('div', 'card-sub', 'Stored version from ' + when + ' \u00b7 ' +
        shown.version.text.split('\n').length.toLocaleString() + ' lines'));
      const pre = document.createElement('pre');
      pre.textContent = shown.version.text;
      host.appendChild(pre);
      return;
    }
    const changed = shown.diff.filter((d) => d.t !== ' ').length;
    host.appendChild(el('div', 'card-sub', changed
      ? changed + ' differing line(s) from the version of ' + when + ' to ' + shown.against.label +
        '. "+" was added since; "\u2212" was there then and is gone now.'
      : 'The version of ' + when + ' is identical to ' + shown.against.label + '.'));
    if (changed) host.appendChild(diffPre(shown.diff));
  }

  function storeDoc(s, key, text, via) {
    s.docs = s.docs || {};
    const label = (CFG_DOCS.find((d) => d.key === key) || {}).label || key;
    s.docs[key] = {
      key, label, text, via,
      bytes: text.length,
      lines: text.split('\n').length,
      at: new Date()
    };
    s.cfgView = key;
  }

  /**
   * Pull both configurations and diff them in one action. They are fetched
   * one after the other rather than together: each is a separate TFTP
   * transfer triggered by a row in rlCopyTable, and switches do not
   * reliably handle two in flight at once.
   */
  async function fetchConfigs(s, skipHealthReload) {
    if (!s.target) return;
    // Pause background polling while fetching configs over TFTP (the config
    // check). If syncConfigs already set the flag, leave it for that caller
    // to clear; only this call owns it when it set it itself.
    const ownsBusy = !s.writeBusy;
    if (ownsBusy) s.writeBusy = true;
    s.cfgError = null;
    try {
      for (const kind of ['running', 'startup']) {
        s.cfgBusy = 'Fetching ' + kind + '-config over TFTP\u2026';
        repaintConfig(s);
        const r = await fetch('/api/config/fetch', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ target: s.target, kind })
        });
        const body = await r.json();
        if (!r.ok || body.error) throw new Error(body.error || 'fetch failed');
        storeDoc(s, kind, body.text, 'received over TFTP');
      }
      s.cfgBusy = null;
      /**
       * Startup first, running second, so the marks read the way the
       * question is asked. The saved configuration is the baseline and
       * the running one is what the switch is doing now, which makes "+"
       * a line that is running but unsaved -- what a reload would lose --
       * and "-" a line that is saved but no longer in effect. The other
       * way round the signs are technically true and consistently read
       * backwards.
       */
      s.cfgStale = false;   // fresh pull - the diff is current again
      if (s.cfgHist) s.cfgHist.versions = null;   // the fetch may have stored a version
      s.cfgDiff = diffLines(s.docs.startup.text, s.docs.running.text);
      const changed = s.cfgDiff.filter((d) => d.t !== ' ').length;
      // Open on the comparison when there are differences, and also when
      // the switch says it has unsaved changes but the two files match --
      // that combination needs explaining, and the explanation lives on
      // the comparison view.
      s.cfgView = (changed || switchSaysUnsaved(s)) ? 'diff' : 'running';
      appLog('info', 'Configurations fetched and compared', { host: s.host, changed });
    } catch (e) {
      s.cfgBusy = null; s.cfgError = e.message;
      appLog('error', 'Configuration fetch failed', { host: s.host, message: e.message });
    }
    // Fetching configs does not change any switch state (interfaces, VLANs,
    // etc.) - it just pulls the running/startup files - so there is no reason to
    // re-walk all 44 health tables here. Refresh only the cheap saved-state
    // scalar so the "config saved" badge is current. (The auto-diff path passes
    // skipHealthReload and does its own badge refresh, so it skips even this.)
    if (ownsBusy) {
      s.writeBusy = false;
      if (!skipHealthReload) {
        refreshScalars(s, { rlRunningCDBequalToStartupCDB: '1.3.6.1.4.1.9.6.1.101.1.13' })
          .then(() => { repaintConfigBadge(s); repaintConfig(s); })   // overlay banner reflects the fresh flag too
          .catch(() => {});
      }
    }
    repaintConfig(s);
    repaintConfigBadge(s);
  }

  /**
   * Save the running configuration over startup, then re-read both so the
   * page proves the result rather than asserting it: after a successful
   * sync the diff should be empty, and if it is not the user needs to see
   * that immediately.
   */
  async function syncConfigs(s) {
    if (!s.target) return;
    // Suspend background polling for the whole save: a config copy is heavy on
    // the switch and must not share the agent with health walks or probes.
    s.writeBusy = true;
    // Held for the whole write, including the re-read that proves it: the
    // window stays put until there is an answer to show.
    s.cfgSaving = true;
    s.cfgBusy = 'Saving the running configuration to startup\u2026';
    s.cfgError = null;
    repaintConfig(s);
    appLog('info', 'Saving running-config to startup', { host: s.host });
    // Optimistic badge: the user asked to save, so show "saved" at once rather
    // than waiting the ~3-4s the switch takes to write flash. If the save fails
    // the catch below reverts it. This makes the dashboard feel instant.
    const prevSavedScalar = s.health && s.health.scalars ? s.health.scalars.rlRunningCDBequalToStartupCDB : undefined;
    if (s.health && s.health.scalars) {
      s.health.scalars.rlRunningCDBequalToStartupCDB = { value: 1, display: 'true', oid: '1.3.6.1.4.1.9.6.1.101.1.13.0' };
      repaintConfigBadge(s);
    }
    // Close the config overlay NOW so the user actually SEES the badge flip -
    // it sits on the dashboard behind the overlay, so keeping the overlay open
    // during the ~3-4s flash write hid the update. The save proceeds in the
    // background; a failure re-opens with the error (handled in catch).
    s.cfgSaving = false; s.cfgBusy = null;
    closeOverlays(s);
    try {
      const r = await fetch('/api/config/sync', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: s.target, from: 'running', to: 'startup' })
      });
      const body = await r.json();
      if (!r.ok || body.error) throw new Error(body.error || 'sync failed');
      appLog('info', 'Running configuration saved to startup', {
        host: s.host, state: body.state, method: body.method, shape: body.shape
      });
      // The switch's own response is the authoritative confirmation: when it
      // says startup now matches running, trust it rather than pulling BOTH
      // configs over TFTP again just to re-diff (two switch copy operations per
      // save - the dominant load). Mark the local diff clean and move on. If the
      // switch did NOT report a clean match, fall back to the re-fetch so the
      // user can see what did not take.
      const switchConfirmsClean = body.state && /match|equal|same/i.test(String(body.state));
      let left;
      if (switchConfirmsClean) {
        // Startup == running now: reflect that locally without a TFTP pull.
        if (s.docs && s.docs.running && s.docs.startup) { s.docs.startup = Object.assign({}, s.docs.running, { label: s.docs.startup.label, key: 'startup' }); }
        s.cfgDiff = (s.docs && s.docs.running && s.docs.startup) ? diffLines(s.docs.startup.text, s.docs.running.text) : s.cfgDiff;
        s.cfgStale = false;
        left = 0;
      } else {
        s.cfgBusy = 'Saved. Re-reading both configurations to confirm\u2026';
        repaintConfig(s);
        await fetchConfigs(s, true);
        s.cfgView = 'diff';
        left = s.cfgDiff ? s.cfgDiff.filter((d) => d.t !== ' ').length : 0;
      }
      if (left) {
        // Still differing after a reported success: the optimistic "saved" was
        // wrong, so revert the badge and re-open the viewer with the detail.
        if (s.health && s.health.scalars && prevSavedScalar !== undefined) {
          s.health.scalars.rlRunningCDBequalToStartupCDB = prevSavedScalar;
          const hpr = s.panels && s.panels.find((p) => p.kind === 'builtin' && p.key === 'health');
          repaintConfigBadge(s);
        }
        s.cfgError = 'The switch reported the copy finished, but the two configurations ' +
          'still differ by ' + left + ' line(s). Check the differences below.';
        s.writeBusy = false; s.cfgSaving = false; s.cfgBusy = null;
        openConfigDiff(s);   // re-open so the user sees what did not take
        repaintConfig(s);
      } else {
        // Clean save confirmed by the switch. The overlay was already closed on
        // click and the badge already shows "saved" optimistically, so there is
        // nothing more to do here but settle the flags and confirm the badge.
        s.writeBusy = false;
        // The switch already confirmed "startup now matches running" in its sync
        // response, so update the saved-state badge INSTANTLY from that - set the
        // scalar locally and repaint, with ZERO extra traffic to the switch. (A
        // confirming scalar read is unnecessary when the switch just told us.)
        if (s.health && s.health.scalars) {
          s.health.scalars.rlRunningCDBequalToStartupCDB = { value: 1, display: 'true', oid: '1.3.6.1.4.1.9.6.1.101.1.13.0' };
        }
        repaintConfigBadge(s);
        return;
      }
    } catch (e) {
      s.cfgBusy = null;
      s.cfgError = 'Could not save the configuration: ' + e.message;
      appLog('error', 'Configuration sync failed', { host: s.host, message: e.message });
      // The save failed, so undo the optimistic "saved" badge and bring the
      // overlay back (it was closed on click) with the error visible.
      if (s.health && s.health.scalars && prevSavedScalar !== undefined) {
        s.health.scalars.rlRunningCDBequalToStartupCDB = prevSavedScalar;
        const hpf = s.panels && s.panels.find((p) => p.kind === 'builtin' && p.key === 'health');
        repaintConfigBadge(s);
      }
      if (typeof toast === 'function') toast('Could not save the configuration: ' + e.message, 'error');
      s.cfgSaving = false; s.cfgBusy = null; s.writeBusy = false;
      openConfigDiff(s);
      repaintConfig(s);
      return;
    }
    s.cfgSaving = false;
    s.cfgBusy = null;
    s.writeBusy = false;
    repaintConfig(s);
    // No full health walk after a save: a save changes only the saved-vs-running
    // state (already reflected in the badge), not interfaces/VLANs/etc.
  }

  /** Fetch one configuration and save it straight to disk. */
  function backupConfig(s, kind) {
    if (!s.target) return;
    s.cfgBusy = 'Fetching ' + kind + '-config\u2026';
    s.cfgError = null;
    repaintPanel(s, 'summary');
    appLog('info', 'Backing up configuration', { host: s.host, kind });
    fetch('/api/config/fetch', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: s.target, kind })
    })
      .then((r) => r.json().then((b) => ({ ok: r.ok, body: b })))
      .then(({ ok, body }) => {
        s.cfgBusy = null;
        if (!ok || body.error) {
          s.cfgError = body.error || 'Configuration fetch failed.';
          appLog('error', 'Backup failed', { host: s.host, kind, message: s.cfgError });
          openConfigDiff(s);            // the error belongs where the detail is
        } else {
          storeDoc(s, kind, body.text, 'received over TFTP');
          download(kind + '-' + safeHost(s.host) + '-' + stamp() + '.txt', body.text);
          appLog('info', 'Configuration backed up', { host: s.host, kind, bytes: body.bytes });
        }
        repaintPanel(s, 'summary');
        repaintConfig(s);
      })
      .catch((e) => {
        s.cfgBusy = null; s.cfgError = e.message;
        repaintPanel(s, 'summary');
      });
  }

  /** Open the configuration overlay, fetching and diffing if needed. */
  function openConfigDiff(s) {
    openOverlay(s, 'cfgOverlay');
    repaintConfig(s);
    const have = s.docs && s.docs.running && s.docs.startup;
    // Always re-fetch when opening this from the "not saved" card: the whole
    // point is to show the CURRENT difference, and the configs on file may be
    // stale from a previous view (which is why the second click used to show old
    // data and force a manual Fetch). Also fetch when nothing is on file yet or
    // a tool change is pending. Skip only if a fetch/save is already running.
    if (!s.cfgBusy && !s.cfgSaving) {
      s.cfgPendingFromTool = false;
      fetchConfigs(s, true);   // show the up-to-date diff; no whole-switch walk
    } else if (!have) {
      // A fetch is in flight already; nothing to do.
    }
  }

  /** What the switch itself says about whether it has been saved. */
  function switchSaysUnsaved(s) {
    const cell = s.health && s.health.scalars && s.health.scalars.rlRunningCDBequalToStartupCDB;
    if (!cell) return false;
    // TruthValue: true(1) = equal = saved. Prefer the raw value (robust to any
    // display format), fall back to the display text.
    if (cell.value !== undefined && cell.value !== null) {
      return !(Number(cell.value) === 1 || /true|yes|equal/i.test(String(cell.value)));
    }
    return !/true|yes|equal/i.test(String(cell.display));
  }

  function repaintConfig(s) {
    if (!s.cfgBody) return;
    clear(s.cfgBody);
    s.cfgStatus.textContent = s.target ? s.host : '';
    /**
     * While the switch is being written to, the way out is removed rather
     * than merely discouraged. Closing mid-save looks to the operator like
     * the save was abandoned -- and they cannot tell that it was not,
     * which is the worst possible thing to be unsure about after pressing
     * a button that overwrites a configuration.
     */
    const saving = !!s.cfgSaving;
    s.cfgClose.style.display = saving ? 'none' : '';
    s.cfgOverlay.classList.toggle('busy', saving);
    paintConfigPanel(s, s.cfgBody);
  }

  /**
   * Line diff via a longest-common-subsequence table. Configurations are a
   * few hundred lines, so the quadratic table is comfortably affordable and
   * gives a genuine minimal diff rather than a naive line-by-line compare
   * that reports everything after an insertion as changed.
   */
  /**
   * Line diff, by longest common subsequence.
   *
   * The LCS table is quadratic -- two 16,000-line configurations would ask
   * for a gigabyte and take about five seconds -- so the parts that
   * obviously match are removed first. Two configurations from the same
   * switch share almost everything; trimming the common head and tail
   * leaves the handful of lines that actually differ, and the expensive
   * algorithm only ever sees those.
   */
  function diffLines(aText, bText) {
    const aAll = String(aText || '').replace(/\r/g, '').split('\n');
    const bAll = String(bText || '').replace(/\r/g, '').split('\n');

    let head = 0;
    while (head < aAll.length && head < bAll.length && aAll[head] === bAll[head]) head++;
    let tail = 0;
    while (tail < aAll.length - head && tail < bAll.length - head &&
      aAll[aAll.length - 1 - tail] === bAll[bAll.length - 1 - tail]) tail++;

    const a = aAll.slice(head, aAll.length - tail);
    const b = bAll.slice(head, bAll.length - tail);
    const n = a.length, m = b.length;
    const lcs = Array.from({ length: n + 1 }, () => new Uint32Array(m + 1));
    for (let i = n - 1; i >= 0; i--) {
      for (let j = m - 1; j >= 0; j--) {
        lcs[i][j] = a[i] === b[j] ? lcs[i + 1][j + 1] + 1 : Math.max(lcs[i + 1][j], lcs[i][j + 1]);
      }
    }
    const out = [];
    let i = 0, j = 0;
    while (i < n && j < m) {
      if (a[i] === b[j]) { out.push({ t: ' ', text: a[i] }); i++; j++; }
      else if (lcs[i + 1][j] >= lcs[i][j + 1]) { out.push({ t: '-', text: a[i] }); i++; }
      else { out.push({ t: '+', text: b[j] }); j++; }
    }
    while (i < n) out.push({ t: '-', text: a[i++] });
    while (j < m) out.push({ t: '+', text: b[j++] });

    // Put the trimmed parts back, so callers still see whole documents and
    // the block-aware context has the headers it needs.
    const result = [];
    for (let k = 0; k < head; k++) result.push({ t: ' ', text: aAll[k] });
    for (const row of out) result.push(row);
    for (let k = aAll.length - tail; k < aAll.length; k++) result.push({ t: ' ', text: aAll[k] });
    return result;
  }

  function renderDiff(host, diff, s) {
    const changed = diff.filter((d) => d.t !== ' ').length;
    const unsaved = switchSaysUnsaved(s);
    host.appendChild(el('div', 'card-sub', changed
      // Said in terms of the running configuration, because that is the
      // one being changed: a "+" is something you added and have not
      // saved, a "-" is something you removed that a reload would bring
      // back.
      ? changed + ' differing line(s). "+" was added to the running configuration; ' +
        '"\u2212" was removed from it and is still in startup.'
      : 'running-config and startup-config are identical.'));

    /**
     * The switch's "unsaved" flag and the file contents answer different
     * questions. The flag means something has been written since the last
     * save; the files can still match if a setting was changed and changed
     * back. Power-cycling a PoE port does exactly that -- it writes the
     * port's admin state twice -- so the pair can disagree without either
     * being wrong, and the disagreement is worth explaining rather than
     * leaving as a dead end.
     */
    if (!changed && unsaved) {
      host.appendChild(el('div', 'panel-note',
        'The switch still reports unsaved changes even though the two files match. ' +
        'That happens when a setting was changed and changed back \u2014 power-cycling ' +
        'a PoE port does it, since the port\u2019s admin state is written twice. ' +
        'Saving clears the flag; nothing in the configuration will change.'));
    }

    // Offer the save whenever the switch considers itself unsaved, whether
    // or not that shows up as differing lines.
    if ((changed || unsaved) && s) {
      const bar = el('div', 'cfg-sync');
      bar.appendChild(el('div', 'card-sub', changed
        ? 'The running configuration has not been saved. A reload would revert these ' +
          changed + ' line(s) to the startup configuration.'
        : 'The switch reports unsaved changes. Saving clears that.'));
      const go = el('button', 'btn btn-amber', 'Save running to startup');
      go.type = 'button'; go.style.width = 'auto';
      go.title = 'Copies running-config over startup-config on the switch';
      // Two taps (B8): the first arms the button, the second overwrites startup.
      withConfirm(go, () => syncConfigs(s), { danger: true, confirmText: 'Tap again to overwrite startup' });

      bar.appendChild(go);
      host.appendChild(bar);
    }
    host.appendChild(diffPre(diff));
  }

  /**
   * A diffLines result as a <pre class="diff">: "+"/"\u2212" lines with their
   * block context, unchanged runs folded. The one renderer for every diff
   * view (startup vs running, and config history).
   */
  function diffPre(diff) {
    const pre = document.createElement('pre');
    pre.className = 'diff';
    const show = visibleDiffLines(diff);
    let run = 0;
    for (let k = 0; k < diff.length; k++) {
      const d = diff[k];
      if (!show.has(k)) { run++; continue; }
      if (run) { pre.appendChild(el('span', 'diff-skip', '  \u22ef ' + run + ' unchanged line(s)\n')); run = 0; }
      pre.appendChild(el('span', d.t === '+' ? 'diff-add' : (d.t === '-' ? 'diff-del' : 'diff-same'),
        (d.t === ' ' ? '  ' : d.t + ' ') + d.text + '\n'));
    }
    if (run) pre.appendChild(el('span', 'diff-skip', '  \u22ef ' + run + ' unchanged line(s)\n'));
    return pre;
  }

  /**
   * Which lines to print around each change.
   *
   * A few lines of context is the wrong unit for a switch configuration.
   * "snmp trap link-status" added to two ports shows up as two identical
   * one-line changes, and three lines either side often does not reach the
   * `interface` header -- so the diff tells you *what* changed and leaves
   * you to work out *where*, which is the part you actually needed.
   *
   * A configuration is made of blocks: an unindented header with indented
   * lines under it. So a change inside a block shows the whole block, and
   * the header names the interface, the VLAN, the line. Changes outside
   * any block keep the usual few lines of context.
   */
  function visibleDiffLines(diff, contextLines) {
    const context = contextLines === undefined ? 3 : contextLines;
    const show = new Set();
    const isHeader = (text) => /^\S/.test(text) && !/^!/.test(text);
    const isBlank = (text) => !String(text).trim();

    for (let k = 0; k < diff.length; k++) {
      if (diff[k].t === ' ') continue;

      // Walk back to the header of the block this line sits in.
      let start = k;
      let inBlock = false;
      for (let i = k; i >= 0; i--) {
        const text = diff[i].text;
        if (isBlank(text)) break;
        if (isHeader(text)) {
          // A header only opens a block if the changed line is indented
          // under it; otherwise the change *is* a top-level line.
          if (i < k && /^\s/.test(diff[k].text)) { start = i; inBlock = true; }
          else if (i === k) { start = i; }
          break;
        }
        start = i;
      }

      if (!inBlock) {
        for (let i = Math.max(0, k - context); i <= Math.min(diff.length - 1, k + context); i++) {
          show.add(i);
        }
        continue;
      }

      // Forward to the end of the block: the next unindented line, or a
      // blank, whichever comes first.
      let end = k;
      for (let i = start + 1; i < diff.length; i++) {
        const text = diff[i].text;
        if (isBlank(text) || isHeader(text)) break;
        end = i;
      }
      for (let i = start; i <= end; i++) show.add(i);
    }
    return show;
  }
