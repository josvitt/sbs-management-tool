  // =================================================================
  // 06-panels.js: Panel layout and rendering: panel shells, sparklines, popouts and the port detail dialog.
  // =================================================================

  // Reconcile a panel in place: re-run its paint logic with the reconcile flag
  // set, so its mountKeyedTable calls patch the existing tables instead of
  // rebuilding. Returns true if the panel handled it (is converted), false if it
  // has no mounted keyed tables yet (caller should fall back to a full repaint).
  // panelIsConverted lists the keys that use keyed tables for every table they
  // render; a converted panel is safe to reconcile without a full repaint.
  const KEYED_PANELS = new Set(['interfaces', 'hardware', 'auth', 'vlans', 'connected', 'routing', 'acl', 'snmpcfg', 'stp', 'flash', 'capture', 'maint', 'system', 'portfeatures', 'stpsettings', 'security', 'ipv6']);
  // A converted panel may still have sections built on a full paint only (auth's
  // 802.1X editor). When a refresh changes a table those read, full-repaint
  // instead of reconciling.
  const PANEL_FULL_REPAINT_TABLES = {
    auth: ['radius', 'tacacs', 'dot1xPortCfg', 'dot1xPortMethod', 'dot1xHostMode']
    // (routing's scalar-driven status pills update in place during reconcile -
    // see paintRoutingPanel - so it does not need a forced full repaint.)
  };
  function reconcilePanelInPlace(s, p) {
    if (!p || !p._body || p.collapsed) return false;
    if (!KEYED_PANELS.has(p.key)) return false;
    const prev = s._ktReconcile, prevSeen = s._ktSeen, prevStruct = s._ktStructural;
    s._ktReconcile = true;
    s._ktSeen = new Set();
    s._ktStructural = false;
    let ok = true;
    try { paintBuiltin(s, p.key, p._body, p); }
    catch (e) { ok = false; appLog('error', 'Panel reconcile failed', { panel: p.title, message: e.message }); }
    // A table mounted before but not produced this pass has disappeared - also
    // structural.
    if (ok && p._kt) {
      for (const id of Object.keys(p._kt)) {
        if (!s._ktSeen.has(id) && p._body.contains(p._kt[id].node)) { s._ktStructural = true; break; }
      }
    }
    const structural = s._ktStructural;
    s._ktReconcile = prev; s._ktSeen = prevSeen; s._ktStructural = prevStruct;
    if (!ok) return false;
    if (structural) { repaintPanel(s, p.key); return true; }
    return true;
  }

  // The dashboard reflects live SNMP only. A tech-support capture is a
  // point-in-time text dump collected on demand; mixing it in made it
  // ambiguous whether a panel was showing the switch now or an hour ago.
  // The single source of truth for "what alerts are active right now". The
  // switch's baked-in alerts (h.alerts) are a snapshot from collection time, but
  // the saved-config state changes live (an optimistic save, a light refresh) -
  // so the CONFIG alert must be re-derived from the current scalar rather than
  // trusted from the snapshot. EVERY consumer - the Attention badge severity AND
  // the findings list the user reads - goes through here, so the badge can never
  // disagree with the messages shown (the bug where "Attention" showed with no
  // reason, because the badge counted a stale CONFIG alert the findings dropped).
  function liveAlerts(s) {
    const h = s.health;
    if (!h || !Array.isArray(h.alerts)) return [];
    const list = h.alerts.slice().filter((x) => String(x.area).toLowerCase() !== 'config');
    if (switchSaysUnsaved(s)) {
      list.push({ severity: 'warning', area: 'Config', message: 'Running configuration differs from startup - changes will be lost on reload.' });
    }
    return list;
  }

  function overallSeverity(s) {
    if (!s.health) return 'ok';
    const real = liveAlerts(s).filter((x) => x.severity !== 'ok');
    return ['critical', 'warning', 'info'].find((x) => real.some((y) => y.severity === x)) || 'ok';
  }

  /**
   * A panel whose contents do not fit gets given its full height and moved
   * to the end of the grid, so the page scrolls once instead of the page
   * scrolling past a box that scrolls too. Scrolling inside a scroll is
   * the worst way to read a table.
   *
   * A panel the user has sized by hand is left exactly as they set it.
   */
  function reflowTallPanels(s, opts) {
    if (!s.grid || s.reflowing) return;
    // A panel whose contents overflow gets its full height (auto-grow) so you
    // don't scroll inside a scroll. It is NEVER moved: panels stay exactly
    // where they are and only change position when the user drags/reorders
    // them. (Earlier this function relocated overflowing panels to the bottom,
    // which made modules like Events "bounce" down on a refresh.)
    s.reflowing = true;
    for (const p of s.panels) {
      const box = p._box;
      if (!box || !box.isConnected || p.collapsed || p.userSized) continue;
      const body = p._body;
      if (!body) continue;
      const overflows = body.scrollHeight > body.clientHeight + 4;
      if (overflows && !p.autoGrow) {
        p.autoGrow = true;
      } else if (!overflows && p.autoGrow && !p.h) {
        p.autoGrow = false;
      }
      box.classList.toggle('auto-grow', !!p.autoGrow);
      if (p.autoGrow) box.style.height = '';
    }
    s.reflowing = false;
  }

  function renderSwitch(s) {
    if (!s.health) return;
    // A refresh landing mid-drag would rebuild the grid under the pointer
    // and throw away the resize in progress. Defer until the drag ends.
    if (s.grid && s.grid.querySelector('.panel.resizing')) {
      s.renderPending = true;
      return;
    }
    const sev = overallSeverity(s);
    setTab(s, sev, s.host || 'switch');
    applyHealthState(s, sev);

    s.healthStatus.textContent = 'SNMP last checked: ' + new Date(s.health.collectedAt).toLocaleTimeString() +
      (s.health.failed.length ? '  \u00b7  ' + s.health.failed.length + ' OID(s) unavailable' : '');

    // On a refresh the panels themselves have not changed, only their
    // contents. Rebuilding every shell threw away scroll positions inside
    // tables and churned the whole grid every 30 seconds, so repaint the
    // bodies in place when the set of visible panels is the same.
    const visible = s.panels.filter((p) => {
      const def = p.kind === 'builtin' ? builtinDef(p.key) : null;
      if (def && def.needs && !def.needs(s)) return false;     // runtime: no data
      if (def && !productSupports(s, def)) return false;       // MIB: product lacks the feature
      return true;
    });
    const sameSet = s.renderedIds &&
      s.renderedIds.length === visible.length &&
      visible.every((p, i) => s.renderedIds[i] === p.id);

    if (sameSet) {
      // Preserve the dashboard scroll container's position too: repainting a
      // panel body briefly changes its height, which otherwise jolts the view on
      // every background refresh. (The window does not scroll here - .scroll-body
      // does - so scrollKeeper restores the right element.)
      const restoreRs = scrollKeeper(s);
      for (const p of visible) {
        if (p.kind === 'oid') continue;     // owns its own refresh cycle
        const keepScroll = p._body ? p._body.scrollTop : 0;
        paintPanelBody(s, p);
        if (p._body) p._body.scrollTop = keepScroll;
      }
      reflowTallPanels(s);
      restoreRs();
      return;
    }

    clear(s.grid);
    for (const p of visible) s.grid.appendChild(buildPanel(s, p));
    s.renderedIds = visible.map((p) => p.id);
    reflowTallPanels(s);
    if (!s.grid.children.length) {
      s.grid.appendChild(el('div', 'empty-state',
        'Every panel has been removed. Use "+ Add panel" to bring one back.'));
    }
  }

  /**
   * A collapsed panel keeps its header and gives up its height, so the
   * grid closes over it instead of leaving a hole. The pixel height is
   * remembered so expanding restores what it was.
   */
  function applyCollapsed(box, p) {
    box.classList.toggle('collapsed', !!p.collapsed);
    if (p.collapsed) {
      box.style.height = '';
    } else if (p.h) {
      box.style.height = p.h + 'px';
    }
  }

  function buildPanel(s, p) {
    const box = el('div', 'panel');
    box.style.gridColumn = 'span ' + Math.max(2, Math.min(GRID_COLS, p.span || 12));
    if (p.h) { box.style.height = p.h + 'px'; }
    box.dataset.id = p.id;

    const head = el('div', 'panel-head');
    // Only the grip starts a drag. With the whole header draggable, a
    // press on the title was the beginning of a drag gesture as far as the
    // browser was concerned, and it suppressed the click that followed --
    // which is why folding a panel often took two attempts.
    const grip = el('span', 'grip', '\u2630');
    grip.draggable = true;
    grip.title = 'Drag to reorder';
    head.appendChild(grip);
    // The title is the obvious thing to click to fold a panel, and a
    // bigger target than the caret.
    const titleEl = el('span', 'panel-title clickable', p.title);
    titleEl.title = 'Show or hide this panel';
    head.appendChild(titleEl);

    // Refresh just this panel. For most built-ins that means re-walking
    // only the tables it shows; for the whole-switch panels there is
    // nothing smaller to ask for, so it is a full collection.
    const rb = el('button', 'panel-act', '\u27F3');
    rb.type = 'button';
    rb.title = 'Refresh this panel';
    rb.addEventListener('click', (e) => { e.stopPropagation(); refreshPanel(s, p, rb); });
    head.appendChild(rb);

    if (p.kind === 'oid') {
      const ed = el('button', 'panel-act', '\u270E');
      ed.type = 'button'; ed.title = 'Edit panel';
      ed.addEventListener('click', (e) => { e.stopPropagation(); openPanelDialog(s, p); });
      head.appendChild(ed);
    }

    // Collapse to just the header. Sits between refresh and close because
    // that is where the eye already is, and it is remembered with the rest
    // of the layout so a folded panel stays folded.
    const min = el('button', 'panel-act', p.collapsed ? '\u25B8' : '\u25BE');
    min.type = 'button';
    min.title = p.collapsed ? 'Expand panel' : 'Minimise panel';
    const toggle = (e) => {
      e.stopPropagation();
      p.collapsed = !p.collapsed;
      applyCollapsed(box, p);
      min.textContent = p.collapsed ? '\u25B8' : '\u25BE';
      min.title = p.collapsed ? 'Expand panel' : 'Minimise panel';
      // A collapsed panel is not painted -- there is nothing to see and
      // building a thousand table rows for a folded box is waste. So an
      // expanding panel has to be filled now, or it opens empty.
      if (!p.collapsed) {
        paintPanelBody(s, p);
        reflowTallPanels(s, { keepOrder: true });
      }
      saveLayout(s);
    };
    min.addEventListener('click', toggle);
    // The whole header folds the panel, not just the text of the title.
    // The title is a line of text a few pixels tall inside a header three
    // times that; clicking the obvious target and having nothing happen is
    // the app's fault, not the operator's.
    head.addEventListener('click', (e) => {
      // The buttons and the grip do their own jobs.
      if (e.target.closest('.panel-act') || e.target.closest('.grip')) return;
      toggle(e);
    });
    head.appendChild(min);

    const rm = el('button', 'panel-act', '\u2715');
    rm.type = 'button'; rm.title = 'Remove panel';
    rm.addEventListener('click', (e) => {
      e.stopPropagation();
      s.panels = s.panels.filter((x) => x.id !== p.id);
      s.renderedIds = null;
      saveLayout(s);
      renderSwitch(s);
    });
    head.appendChild(rm);
    box.appendChild(head);

    const body = el('div', 'panel-body');
    box.appendChild(body);
    p._box = box;
    applyCollapsed(box, p);
    p._body = body;
    paintPanelBody(s, p);

    // ---- drag to reorder ----
    grip.addEventListener('dragstart', (e) => {
      e.dataTransfer.setData('text/plain', p.id);
      e.dataTransfer.effectAllowed = 'move';
      box.classList.add('dragging');
    });
    grip.addEventListener('dragend', () => box.classList.remove('dragging'));
    box.addEventListener('dragover', (e) => { e.preventDefault(); box.classList.add('drag-over'); });
    box.addEventListener('dragleave', () => box.classList.remove('drag-over'));
    box.addEventListener('drop', (e) => {
      e.preventDefault();
      box.classList.remove('drag-over');
      const from = e.dataTransfer.getData('text/plain');
      if (!from || from === p.id) return;
      const fi = s.panels.findIndex((x) => x.id === from);
      const ti = s.panels.findIndex((x) => x.id === p.id);
      if (fi < 0 || ti < 0) return;
      const [moved] = s.panels.splice(fi, 1);
      s.panels.splice(ti, 0, moved);
      s.renderedIds = null;
      saveLayout(s);
      renderSwitch(s);
    });

    // ---- resize ----
    // Three grab areas rather than one corner: the right edge for width,
    // the bottom edge for height, the corner for both. A 16px corner is
    // hard to find and, since most panels start full width, dragging it
    // right does nothing -- which reads as "resize is broken".
    const startResize = (e, mode) => {
      e.preventDefault(); e.stopPropagation();
      const handle = e.currentTarget;
      try { handle.setPointerCapture(e.pointerId); } catch (err) { /* older engines */ }
      const gridW = s.grid.getBoundingClientRect().width;
      const colW = gridW / GRID_COLS;
      const startX = e.clientX, startY = e.clientY;
      const startSpan = p.span || GRID_COLS;
      const startH = p.h || box.getBoundingClientRect().height;

      box.classList.add('resizing');
      const badge = el('div', 'resize-badge', '');
      box.appendChild(badge);
      const paint = () => {
        badge.textContent = (p.span || GRID_COLS) + '/' + GRID_COLS + ' wide  \u00b7  ' +
          Math.round(p.h || box.getBoundingClientRect().height) + 'px tall';
      };
      paint();

      const move = (ev) => {
        p.userSized = true;
        p.autoGrow = false;
        box.classList.remove('auto-grow');
        if (mode !== 'height') {
          const span = Math.max(2, Math.min(GRID_COLS, startSpan + Math.round((ev.clientX - startX) / colW)));
          box.style.gridColumn = 'span ' + span;
          p.span = span;
        }
        if (mode !== 'width') {
          const h = Math.max(120, startH + (ev.clientY - startY));
          box.style.height = h + 'px';
          p.h = Math.round(h);
        }
        paint();
      };
      const up = () => {
        handle.removeEventListener('pointermove', move);
        handle.removeEventListener('pointerup', up);
        window.removeEventListener('pointerup', up);
        box.classList.remove('resizing');
        badge.remove();
        saveLayout(s);
        // Apply anything that arrived while the pointer was down.
        if (s.renderPending) { s.renderPending = false; renderSwitch(s); }
      };
      handle.addEventListener('pointermove', move);
      handle.addEventListener('pointerup', up);
      window.addEventListener('pointerup', up);
    };

    for (const [cls, mode, tip] of [
      ['panel-resize-x', 'width', 'Drag to change width'],
      ['panel-resize-y', 'height', 'Drag to change height'],
      ['panel-resize', 'both', 'Drag to resize']
    ]) {
      const handle = el('div', cls, '');
      handle.title = tip;
      handle.addEventListener('pointerdown', (e) => startResize(e, mode));
      box.appendChild(handle);
    }

    return box;
  }

  /**
   * The highest value seen in the samples held. A rate is a snapshot of
   * one instant, and the instant you happened to look is rarely the
   * interesting one -- a switch punting 40,000 packets per second in
   * bursts reads as idle between them.
   */
  /**
   * The most recent sample for a metric. The cards are painted from the
   * last collection, but the probe keeps reading every 30 seconds -- so
   * without this the headline figure sits at whatever it was when the
   * collection ran and looks stuck, while the graph beneath it moves.
   */
  function latestOf(history, key) {
    for (let i = (history || []).length - 1; i >= 0; i--) {
      const v = history[i][key];
      if (v !== null && v !== undefined && Number.isFinite(v)) return v;
    }
    return null;
  }

  function peakOf(history, key, windowMs) {
    const since = windowMs ? Date.now() - windowMs : 0;
    let peak = null, at = null, samples = 0;
    for (const sample of history || []) {
      if (sample.t < since) continue;
      const v = sample[key];
      if (v === null || v === undefined || !Number.isFinite(v)) continue;
      samples++;
      if (peak === null || v > peak) { peak = v; at = sample.t; }
    }
    return peak === null ? null : { peak, at, samples };
  }

  /** "4m 12s" rather than 252. */
  function secs(n) {
    const v = Number(n) || 0;
    if (v < 60) return v + 's';
    if (v < 3600) return Math.floor(v / 60) + 'm ' + (v % 60) + 's';
    return Math.floor(v / 3600) + 'h ' + Math.floor((v % 3600) / 60) + 'm';
  }

  /**
   * A sparkline: the shape of the last hour, drawn small enough to sit on
   * a metric card. Values speak for themselves; the line says whether the
   * value is going anywhere.
   */
  // Downsample a time series to at most `maxPoints` by time-bucketing: the
  // series is divided into equal time windows and each window contributes its
  // PEAK value (so a spike is never averaged away) at its own timestamp. The
  // card sparkline uses this - a glanceable 100px line needs the shape, not
  // every one of a week's ~20k points; the full graph still draws them all.
  function downsampleSeries(pts, maxPoints) {
    if (!pts || pts.length <= maxPoints) return pts || [];
    const t0 = pts[0].t, t1 = pts[pts.length - 1].t;
    const span = (t1 - t0) || 1;
    const bucketMs = span / maxPoints;
    const out = [];
    let bucketEnd = t0 + bucketMs, best = null;
    for (const p of pts) {
      if (p.t > bucketEnd && best) { out.push(best); best = null; while (p.t > bucketEnd) bucketEnd += bucketMs; }
      if (best === null || p.v > best.v) best = p;
    }
    if (best) out.push(best);
    return out;
  }

  function sparkline(samples, opts) {
    let pts = (samples || []).filter((p) =>
      p && p.v !== null && p.v !== undefined && Number.isFinite(p.v));
    if (pts.length < 3) return null;
    const rawCount = pts.length;
    // A 100px-wide card line needs no more than ~120 points; downsample by time
    // so a week of 30s data (~20k points) doesn't render thousands of segments
    // into 100px. The full graph (drawGraph) does not downsample.
    if (!(opts && opts.full)) pts = downsampleSeries(pts, 120);
    const w = 100, h = 22;
    const vals = pts.map((p) => p.v);
    const min = Math.min.apply(null, vals);
    const max = Math.max.apply(null, vals);
    // A flat line should look flat, not like noise amplified to full scale.
    const span = (max - min) < 1e-6 ? 1 : (max - min);
    // Spaced by the clock, not by sample number: readings arrive on a
    // timer and whenever someone hits refresh, so a burst of manual
    // refreshes would otherwise stretch a few seconds across half the
    // graph and make a quiet hour look eventful.
    const t0 = pts[0].t, t1 = pts[pts.length - 1].t;
    const tspan = (t1 - t0) || 1;
    const path = pts.map((p, i) =>
      (i ? 'L' : 'M') + (((p.t - t0) / tspan) * w).toFixed(1) + ' ' +
      (h - ((p.v - min) / span) * (h - 3) - 1.5).toFixed(1)
    ).join(' ');

    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 ' + w + ' ' + h);
    svg.setAttribute('preserveAspectRatio', 'none');
    svg.setAttribute('class', 'spark' + (opts && opts.cls ? ' ' + opts.cls : ''));
    const line = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    line.setAttribute('d', path);
    svg.appendChild(line);
    svg.setAttribute('title', rawCount + ' samples over ' +
      secs(Math.round(tspan / 1000)) + ' \u00b7 ' +
      (opts && opts.unit ? min + '-' + max + ' ' + opts.unit : min + '-' + max));
    return svg;
  }

  /**
   * The two actions worth having on a port. Both write to the switch, so
   * both ask first, name the port in the question, and report what the
   * port looked like afterwards rather than assuming it worked.
   */
  // Per-interface detail popout. Shows the static per-port fields already held
  // from the walk, then fetches the full live counter set on demand (so these
  // 17 counters are never walked for every port on every refresh — only pulled
  // for the one port the user opened).
  // Each row lists its OID variants in preference order; fetchPortCounters uses
  // the first that the switch actually answers. The vendor rlifPresent* columns
  // come first (populated on C1200/C1300), then the standard ifXTable/ifTable
  // equivalents (same ifIndex). This matters because the C1300X firmware
  // (4.10.3.26) does NOT implement the rlifPresent counter columns - it returns
  // noSuchInstance for them (confirmed on the wire) - but does populate the
  // standard interface counters. Trying both, in order, means counters show on
  // every line without branching on product (the switch decides).
  const PORT_COUNTERS = [
    ['In octets', 'rlifPresentHCInOctets', 'rlifPresentInOctets', 'ifHCInOctets', 'ifInOctets'],
    ['Out octets', 'rlifPresentHCOutOctets', 'rlifPresentOutOctets', 'ifHCOutOctets', 'ifOutOctets'],
    ['In unicast', 'rlifPresentHCInUcastPkts', 'rlifPresentInUcastPkts', 'ifHCInUcastPkts', 'ifInUcastPkts'],
    ['Out unicast', 'rlifPresentHCOutUcastPkts', 'rlifPresentOutUcastPkts', 'ifHCOutUcastPkts', 'ifOutUcastPkts'],
    ['In multicast', 'rlifPresentHCInMulticastPkts', 'rlifPresentInMulticastPkts', 'ifHCInMulticastPkts', 'ifInMulticastPkts'],
    ['Out multicast', 'rlifPresentHCOutMulticastPkts', 'rlifPresentOutMulticastPkts', 'ifHCOutMulticastPkts', 'ifOutMulticastPkts'],
    ['In broadcast', 'rlifPresentHCInBroadcastPkts', 'rlifPresentInBroadcastPkts', 'ifHCInBroadcastPkts', 'ifInBroadcastPkts'],
    ['Out broadcast', 'rlifPresentHCOutBroadcastPkts', 'rlifPresentOutBroadcastPkts', 'ifHCOutBroadcastPkts', 'ifOutBroadcastPkts'],
    ['In discards', 'rlifPresentInDiscards', 'ifInDiscards'],
    ['Out discards', 'rlifPresentOutDiscards', 'ifOutDiscards'],
    ['In errors', 'rlifPresentInErrors', 'ifInErrors'],
    ['Out errors', 'rlifPresentOutErrors', 'ifOutErrors'],
    ['Unknown protos', 'rlifPresentInUnknownProtos', 'ifInUnknownProtos'],
    ['Out queue len', 'rlifPresentOutQLen', 'ifOutQLen']
  ];

  // A read-only detail pop-out: a title, a list of [label, value] pairs, and
  // optional named sub-sections each with their own pairs (per-host 802.1X
  // counters, a port channel without write access). The standard tabbed
  // pop-out with one Details tab, so it closes with Esc like every other.
  function openDetailDialog(s, title, pairs, sections) {
    const grid = (ps) => {
      const dl = el('dl', 'port-detail-grid');
      for (const [k, v] of ps) { if (v === undefined || v === null || v === '') continue; dl.appendChild(el('dt', '', k)); dl.appendChild(el('dd', '', enumWord(String(v)))); }
      return dl;
    };
    openTabbedPopout(s, title, [{ label: 'Details', fill: (pane) => {
      pane.appendChild(grid(pairs));
      if (sections) for (const name in sections) {
        pane.appendChild(el('div', 'port-detail-sub', name));
        pane.appendChild(grid(sections[name]));
      }
    } }], []);
  }

  // A popout with any number of tabs. tabs: [{ label, fill(pane, close), onShow }].
  // Returns { close, showTab, panes }. Panes are created lazily-filled up front but only
  // the first is visible; onShow (optional) fires each time a tab is selected
  // (used by the counters tab to know when it is visible).
  function openTabbedPopout(s, title, tabs, popTimers) {
    const prev = document.querySelector('.port-detail-back');
    if (prev) prev.remove();
    const back = el('div', 'port-detail-back');
    const pop = el('div', 'port-detail');
    // Esc closes it (A5). The listener goes with the pop-out however it closes,
    // so a later Esc cannot close the next one opened.
    const esc = (e) => { if (e.key === 'Escape') close(); };
    const close = () => { for (const t of (popTimers || [])) clearInterval(t); back.remove(); document.removeEventListener('keydown', esc); };
    back.addEventListener('click', (e) => { if (e.target === back) close(); });
    document.addEventListener('keydown', esc);
    const head = el('div', 'port-detail-head');
    head.appendChild(el('h3', '', title));
    const x = el('button', 'port-detail-x', '\u00d7'); x.type = 'button';
    x.addEventListener('click', close); head.appendChild(x);
    pop.appendChild(head);

    const strip = el('div', 'pd-tabs');
    const panes = [];
    const btns = [];
    const show = (i) => {
      panes.forEach((p, j) => { p.style.display = i === j ? '' : 'none'; });
      btns.forEach((b, j) => b.classList.toggle('active', i === j));
      const t = tabs[i]; if (t && t.onShow) t.onShow();
    };
    tabs.forEach((t, i) => {
      const b = el('button', 'pd-tab' + (i === 0 ? ' active' : ''), t.label); b.type = 'button';
      b.addEventListener('click', () => show(i));
      strip.appendChild(b); btns.push(b);
    });
    pop.appendChild(strip);
    tabs.forEach((t, i) => {
      const pane = el('div', 'pd-pane'); if (i !== 0) pane.style.display = 'none';
      pop.appendChild(pane); panes.push(pane);
      t.fill(pane, close);
    });
    back.appendChild(pop);
    document.body.appendChild(back);
    return { close, showTab: show, panes };
  }

  function openPortDetail(s, detail, opts) {
    opts = opts || {};
    const hasIf = detail.ifIndex !== null && detail.ifIndex !== undefined;
    const popTimers = [];
    const tabs = [];
    // Extra leading tabs (e.g. a port channel's Membership tab) go first.
    for (const t of (opts.leadingTabs || [])) tabs.push(t);

    // ---- Port tab: identity fields + PoE ----
    // ---- Port tab: identity fields + PoE, then physical settings below ----
    tabs.push({ label: 'Port', fill: (pane) => {
      const defs = el('dl', 'port-detail-grid');
      const addField = (k, v) => { if (v === undefined || v === null || v === '') return; defs.appendChild(el('dt', '', k)); defs.appendChild(el('dd', '', enumWord(String(v)))); };
      for (const k in (detail.fields || {})) addField(k, detail.fields[k]);
      if (detail.poe) { for (const k in detail.poe) addField('PoE ' + k, detail.poe[k]); }
      if (defs.children.length) pane.appendChild(defs);
      // Physical interface settings (on-demand) stacked under the identity grid.
      if (hasIf) {
        pane.appendChild(el('div', 'port-detail-sub', 'Interface settings'));
        const setWrap = el('div');
        setWrap.appendChild(el('div', 'card-sub', 'Loading settings\u2026'));
        pane.appendChild(setWrap);
        fetchIfSettings(s, detail.ifIndex).then((st) => { clear(setWrap); setWrap.appendChild(buildInterfaceSettings(s, detail, st)); })
          .catch((e) => { clear(setWrap); setWrap.appendChild(el('div', 'sw-err', 'Could not read settings: ' + e.message)); });
      }
      if (!defs.children.length && !hasIf) pane.appendChild(el('div', 'card-sub', 'No port details available.'));
    } });

    // ---- Switchport tab ----
    // A routed port's address is set in the IPv4 Addressing panel, not here.
    if (hasIf && detail.sw) {
      tabs.push({ label: 'Switchport', fill: (pane) => { pane.appendChild(buildSwitchportEditor(s, detail)); } });
    }

    // ---- 802.1X tab ----
    if (detail.dot1x && hasIf) {
      tabs.push({ label: '802.1X', fill: (pane) => { pane.appendChild(buildDot1xEditor(s, detail)); } });
    }

    // ---- Voice VLAN tab: per-port candidacy + QoS mode. Only when Voice VLAN is
    // in OUI-based mode (adminState=3) - per-port candidacy is an OUI-mode concept;
    // in auto/disabled modes the port isn't configured here. ----
    const voiceAdmScalar = s.health && s.health.scalars && s.health.scalars.vlanVoiceAdminState;
    const voiceOuiMode = voiceAdmScalar && parseInt(voiceAdmScalar.value, 10) === 3;
    if (hasIf && voiceOuiMode) {
      tabs.push({ label: 'Voice VLAN', fill: (pane) => {
        const wrap = el('div');
        wrap.appendChild(el('div', 'card-sub', 'Loading Voice VLAN settings\\u2026'));
        pane.appendChild(wrap);
        fetchIfSettings(s, detail.ifIndex, ['voiceEnable', 'voiceSecure', 'voiceQos', 'voiceMembership'])
          .then((st) => { clear(wrap); wrap.appendChild(buildVoiceVlanEditor(s, detail, st)); })
          .catch((e) => { clear(wrap); wrap.appendChild(el('div', 'sw-err', 'Could not read Voice VLAN settings: ' + e.message)); });
      } });
    }

    // ---- Features tab: PoE, port security, storm control, discovery, cable
    // test (28-port-features.js). Front-panel ports only. ----
    if (hasIf && Number(detail.ifIndex) < 1000) tabs.push(portFeaturesTab(s, Number(detail.ifIndex)));
    // ---- Spanning tree tab: cost, priority, PortFast, BPDU guard (29-stp-settings.js). ----
    if (hasIf) tabs.push(stpPortTab(s, Number(detail.ifIndex)));
    // ---- Security tab: trusted for DHCP snooping and ARP inspection (30-switch-security.js). ----
    if (hasIf && Number(detail.ifIndex) < 1000) tabs.push(secPortTab(s, Number(detail.ifIndex)));

    // ---- ACL tab: ACLs bound to this interface (input/output + default) ----
    if (hasIf) {
      tabs.push({ label: 'ACL', fill: (pane) => { buildIfAclBinding(s, detail, pane); } });
    }

    // ---- Counters tab: live counters + clear ----
    if (hasIf) {
      tabs.push({ label: 'Counters', onShow: () => {}, fill: (pane, close) => {
        const ctrWrap = el('div', 'port-detail-counters');
        ctrWrap.appendChild(el('div', 'card-sub', 'Loading live counters\u2026'));
        fetchPortCounters(s, detail.ifIndex, ctrWrap);
        pane.appendChild(ctrWrap);
        const ctrTimer = setInterval(() => {
          if (!document.body.contains(ctrWrap)) { clearInterval(ctrTimer); return; }
          if (pane.style.display !== 'none') fetchPortCounters(s, detail.ifIndex, ctrWrap, true);
        }, 10000);
        popTimers.push(ctrTimer);
        const cActions = el('div', 'snmp-form-actions'); cActions.style.marginTop = '8px';
        const clearBtn = el('button', 'btn btn-small btn-danger', 'Clear counters'); clearBtn.type = 'button';
        const cMsg = el('div', 'sw-msg');
        clearBtn.addEventListener('click', (ev) => {
          clear(cMsg);
          runButtonAction(ev.currentTarget, {
            failLabel: 'Clear counters', spinLabel: 'Clearing\u2026',
            run: () => clearPortCounters(s, detail.ifIndex),
            ok: (res) => res && res.ok,
            error: (res) => { cMsg.appendChild(el('div', 'sw-err', 'Could not clear counters: ' + ((res && res.error) || 'failed'))); return (res && res.error) || 'failed'; },
            settle: () => { clear(ctrWrap); ctrWrap.appendChild(el('div', 'card-sub', 'Loading live counters\u2026')); setTimeout(() => fetchPortCounters(s, detail.ifIndex, ctrWrap), 800); return Promise.resolve(); }
          });
        });
        cActions.appendChild(clearBtn); pane.appendChild(cActions); pane.appendChild(cMsg);
      } });
    }

    openTabbedPopout(s, (opts.title || ('Interface ' + detail.name)), tabs, popTimers);
  }
