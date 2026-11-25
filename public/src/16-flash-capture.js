  // =================================================================
  // 16-flash-capture.js: Flash files and packet capture (OPC) panels.
  // =================================================================

  // Both are keyed panels with their own loader (standard B1 family b2), like
  // SNMP configuration: the rows come from a server endpoint read on demand
  // (/api/flash/list, /api/opc/list), not from the health walk. The paint
  // follows B2: scaffolding on a full paint, mountInto tables with stable
  // keys, counts in stable nodes, and a load or a write reconciles in place.
  //
  // s._flash = { data, fetchedAt, loading, highlight }
  // s._capture = { data, fetchedAt, loading }
  // data is the endpoint's reply; data.error is set when it failed.

  // POST to the local server; resolves its reply, or { ok:false, error }.
  async function sidePost(url, payload) {
    try {
      const { body } = await apiPost(url, payload);
      return body || { ok: false, error: 'no reply from the local server' };
    } catch (e) { return { ok: false, error: 'lost contact with the local server: ' + e.message }; }
  }

  // Reconcile a b2 panel after its loader or a write, or repaint it when the
  // pass is structural. Does nothing when the panel is closed or collapsed.
  function sideRepaint(s, key) {
    const p = s.panels && s.panels.find((x) => x.kind === 'builtin' && x.key === key);
    if (!p || !p._body || p.collapsed) return;
    if (!reconcilePanelInPlace(s, p)) repaintPanel(s, key);
  }
  // Load once per visit: on open, unless a load is running or ran in the last
  // 30 s. `st` is the panel's state object, `load` its loader.
  function sideEnsure(s, st, load) {
    if (!s.target || !st) return;
    if (st.data && st.collected) return;            // the snapshot carries it (adoptCollectedModules)
    if (st.loading || Date.now() - (st.fetchedAt || 0) < 30000) return;
    load(s);
  }
  const fmtFlashSize = (n) => {
    const v = Number(n); if (!Number.isFinite(v)) return String(n);
    if (v >= 1048576) return (v / 1048576).toFixed(1) + ' MB';
    if (v >= 1024) return (v / 1024).toFixed(1) + ' KB';
    return v + ' B';
  };
  const bareFlashName = (n) => String(n || '').replace(/^flash:\/\//i, '').replace(/^flash:/i, '');

  // ---- Flash files ----
  // Lists the switch's flash; any file can be downloaded (TFTP to this app,
  // then to the browser) and a writable one deleted (rlFileRowStatus destroy).
  // Delete is not offered for directories or files the switch marks read-only.

  // Read the listing and reconcile. highlight (a file name) flashes that row
  // once, so a capture exported from the Packet capture panel is easy to spot.
  function flashLoad(s, highlight) {
    s._flash = s._flash || {};
    const st = s._flash;
    if (highlight) st.highlight = bareFlashName(highlight);
    if (st.loading) return st.loading;
    st.fetchedAt = Date.now();
    st.liveAt = Date.now();
    st.loading = sidePost('/api/flash/list', { target: s.target })
      .then((b) => { st.data = (b && !b.error) ? b : { error: (b && b.error) || 'no answer' }; })
      .finally(() => { st.loading = null; sideRepaint(s, 'flash'); });
    return st.loading;
  }

  // Copy a flash file to the browser. Resolves { ok, error }.
  async function flashDownload(s, fileName) {
    s.writeBusy = true;
    try {
      const b = await sidePost('/api/opc/fetch-flash', { target: s.target, flashFileName: fileName });
      if (!(b && b.ok && b.pcapBase64)) return { ok: false, error: (b && b.error) || 'unknown error' };
      const bytes = atob(b.pcapBase64);
      const arr = new Uint8Array(bytes.length);
      for (let i = 0; i < bytes.length; i++) arr[i] = bytes.charCodeAt(i);
      const url = URL.createObjectURL(new Blob([arr], { type: 'application/octet-stream' }));
      const a = document.createElement('a');
      a.href = url; a.download = bareFlashName(fileName);
      document.body.appendChild(a); a.click(); document.body.removeChild(a); URL.revokeObjectURL(url);
      return { ok: true };
    } finally { s.writeBusy = false; }
  }

  function paintFlashPanel(s, body, p) {
    if (!s._ktReconcile) clear(body);
    if (!s.target) { if (!s._ktReconcile) body.appendChild(el('div', 'card-sub', 'Connect with SNMP to browse flash.')); return; }
    s._flash = s._flash || {};
    if (!s._ktReconcile) sideEnsure(s, s._flash, flashLoad);
    const d = s._flash.data;
    // The shape: waiting, an error, no files, or the table.
    const shape = !d ? 'wait' : (d.error ? 'error' : ((d.files || []).length ? 'files' : 'empty'));
    if (s._ktReconcile && p._flashShape !== shape) { s._ktStructural = true; return; }
    p._flashShape = shape;
    if (shape === 'wait') { if (!s._ktReconcile) body.appendChild(el('div', 'card-sub', 'Waiting for data\u2026')); return; }
    if (shape === 'error') { if (!s._ktReconcile) body.appendChild(el('div', 'panel-err', 'Could not list flash: ' + d.error)); return; }

    const files = d.files || [];
    if (!s._ktReconcile) {
      const st = el('div', 'section-title', 'Flash files');
      p._flashNote = el('span', 'st-note', '');
      st.appendChild(p._flashNote);
      body.appendChild(st);
    }
    p._flashNote.textContent = files.length + ' entr' + (files.length === 1 ? 'y' : 'ies') +
      (d.flash && d.flash.free != null ? '  \u00b7  ' + fmtFlashSize(d.flash.free) + ' free of ' + fmtFlashSize(d.flash.total) : '');
    if (shape === 'empty') { if (!s._ktReconcile) body.appendChild(el('div', 'card-sub', 'No files found.')); return; }

    const hl = s._flash.highlight; s._flash.highlight = null;
    mountInto(body, s, p, 'flash:files', ['Name', 'Perm', 'Size', 'Modified', ''], files.map((f) => {
      const permKnown = f.permByte !== undefined && f.permByte !== null;
      const deletable = !f.isDir && !(permKnown && f.writable === false);
      const btns = [];
      if (!f.isDir) {
        btns.push(actBtn('Download', (e) => runButtonAction(e.currentTarget, {
          failLabel: 'Download', spinLabel: 'Fetching\u2026',
          run: () => flashDownload(s, f.name),
          ok: (r) => r && r.ok,
          error: (r) => (r && r.error) || 'unknown error'
        }), 'primary', 'Download this file'));
      }
      if (deletable) {
        btns.push(actBtnConfirm('Delete', (e) => runButtonAction(e.currentTarget, {
          failLabel: 'Delete',
          run: async () => { s.writeBusy = true; try { return await sidePost('/api/flash/delete', { target: s.target, fileName: f.name }); } finally { s.writeBusy = false; } },
          ok: (r) => r && r.ok,
          error: (r) => (r && r.error) || 'unknown error',
          settle: () => flashLoad(s)
        }), 'danger', 'Delete this file'));
      }
      const actCell = actGroup(btns);
      if (f.isDir) actCell.appendChild(el('span', 'card-sub', ' directory'));
      else if (!deletable) actCell.appendChild(el('span', 'card-sub', ' read-only'));
      return { key: 'file:' + f.name, cells: [
        { v: f.isDir ? f.name + '/' : f.name, _flash: !!hl && bareFlashName(f.name) === hl },
        { v: permKnown ? '0x' + Number(f.permByte).toString(16).padStart(2, '0') : '?' },
        { v: f.isDir ? '' : (f.size !== undefined ? fmtFlashSize(f.size) : '') },
        { v: [f.date, f.time].filter(Boolean).join(' ') },
        { cellNode: actCell, sig: (f.isDir ? 'd' : 'f') + (deletable ? 'w' : 'r') }] };
    }));
  }

  // ---- Packet capture ----
  // Lists the captures on the switch, each with Start/Stop, Export, Clear and
  // Delete. + New capture, or a capture's name, opens the settings in the
  // standard pop-out. While any capture is running the list re-reads every
  // 15 s, so its packet counts move without a refresh.

  function captureLoad(s) {
    s._capture = s._capture || {};
    const st = s._capture;
    if (st.loading) return st.loading;
    st.fetchedAt = Date.now();
    st.liveAt = Date.now();
    st.loading = sidePost('/api/opc/list', { target: s.target })
      .then((b) => {
        st.data = (b && !b.error) ? b : { error: (b && b.error) || 'no answer' };
        st.anyActive = !st.data.error && (st.data.captures || []).some((c) => c.stateText === 'active');
      })
      .finally(() => { st.loading = null; sideRepaint(s, 'capture'); captureTimer(s); });
    return st.loading;
  }

  // The 15 s poll runs only while a capture is active and the panel is open,
  // and skips a tick while a write is running. A capture's state does not
  // change second to second, and each read walks the capture table.
  function captureTimer(s) {
    const st = s._capture || {};
    const p = s.panels && s.panels.find((x) => x.kind === 'builtin' && x.key === 'capture');
    const open = p && p._body && !p.collapsed && document.body.contains(p._body);
    if (st.anyActive && open) {
      if (!s._captureStatsTimer) {
        s._captureStatsTimer = setInterval(() => {
          if (!s.writeBusy && !(s._capture && s._capture.loading)) captureLoad(s);
        }, 15000);
      }
    } else if (s._captureStatsTimer) { clearInterval(s._captureStatsTimer); s._captureStatsTimer = null; }
  }

  // One capture action (start, stop, clear, delete, configure). Resolves
  // { ok, error, body } for runButtonAction.
  async function captureWrite(s, url, payload) {
    s.writeBusy = true;
    try {
      const b = await sidePost(url, Object.assign({ target: s.target }, payload));
      return { ok: !!(b && b.ok), error: (b && b.error) || 'unknown error', body: b };
    } finally { s.writeBusy = false; }
  }

  // Export a stopped, non-empty capture: copy it to a flash .pcap through the
  // rlCopyTable engine (sourceFileType=pcap -> capture://), the proven
  // non-crashing path, then download that file. The button spins through both
  // and says Done only once the file has downloaded.
  function captureExport(s, btn, name) {
    let copy = null;
    return runButtonAction(btn, {
      failLabel: 'Export',
      run: () => apiPost('/api/copy/capture-to-flash', { target: s.target, name, confirm: true })
        .then((res) => { copy = res.body; return res; }),
      // Success means the copy to flash finished (the server waits for it).
      ok: (res) => res && res.ok && res.body && res.body.ok && res.body.flashFileName,
      error: (res) => {
        const b = res && res.body;
        if (b && b.finished === false && !b.failed) {
          // Still being written (a capture larger than the server waits for):
          // show it in Flash files so it can be fetched once it finishes.
          if (b.flashFileName) flashLoad(s, b.flashFileName);
          return 'still writing to flash - it will appear in the Flash files list shortly; download it from there once it finishes';
        }
        return (b && b.error) || 'unknown error';
      },
      settle: () => {
        const fn = copy && copy.flashFileName;
        if (!fn) return Promise.resolve();
        flashLoad(s, fn);
        return flashDownload(s, fn).then((r) => { if (!r.ok) throw new Error('download from flash failed: ' + r.error); });
      }
    }).catch(() => { /* the helper has shown the failure */ });
  }

  function paintCapturePanel(s, body, p) {
    if (!s._ktReconcile) clear(body);
    if (!s.target) { if (!s._ktReconcile) body.appendChild(el('div', 'card-sub', 'Connect with SNMP to use packet capture.')); return; }
    s._capture = s._capture || {};
    if (!s._ktReconcile) { sideEnsure(s, s._capture, captureLoad); captureTimer(s); }
    const d = s._capture.data;
    const caps = (d && !d.error && d.captures) || [];
    const shape = !d ? 'wait' : (d.error ? 'error' : (caps.length ? 'list' : 'empty'));
    if (s._ktReconcile && p._capShape !== shape) { s._ktStructural = true; return; }
    p._capShape = shape;
    if (shape === 'wait') { if (!s._ktReconcile) body.appendChild(el('div', 'card-sub', 'Waiting for data\u2026')); return; }
    if (shape === 'error') { if (!s._ktReconcile) body.appendChild(el('div', 'panel-err', 'Could not list captures: ' + d.error)); return; }

    if (!s._ktReconcile) {
      const st = el('div', 'section-title', 'Captures on the switch');
      p._capNote = el('span', 'st-note', '');
      st.appendChild(p._capNote);
      body.appendChild(st);
      body.appendChild(addControl('New capture', () => openCaptureForm(s, null)));
    }
    p._capNote.textContent = caps.length ? caps.length + ' found' : '';
    if (shape === 'empty') { if (!s._ktReconcile) body.appendChild(el('div', 'card-sub', 'No captures on the switch.')); return; }

    // Every action spins until the list has been re-read (B6).
    const act = (label, url, payload) => (e) => runButtonAction(e.currentTarget, {
      failLabel: label,
      run: () => captureWrite(s, url, payload),
      ok: (r) => r && r.ok,
      error: (r) => (r && r.error) || 'unknown error',
      settle: () => captureLoad(s)
    });
    mountInto(body, s, p, 'capture:list', ['Name', 'State', 'Buffer', 'Filter', 'Packets', 'Dropped', 'Used', 'Pkts/s', ''], caps.map((cap) => {
      const nm = cap.name;
      const active = cap.stateText === 'active';
      const empty = (Number(cap.packets) || 0) <= 0;
      const btns = [active
        ? actBtn('Stop', act('Stop', '/api/opc/action', { name: nm, action: 'stop' }), '', 'Stop capturing')
        : actBtn('Start', act('Start', '/api/opc/action', { name: nm, action: 'start' }), '', 'Start capturing')];
      const exp = actBtn('Export', (e) => captureExport(s, e.currentTarget, nm), '', 'Export to a flash .pcap and download it');
      // Clear empties the buffer so the same capture can run again without
      // being deleted and recreated; it needs a stopped capture with packets.
      const clr = actBtnConfirm('Clear', act('Clear', '/api/opc/action', { name: nm, action: 'clear' }), '', 'Empty the capture buffer so you can capture again (keeps the capture configured)');
      if (active || empty) {
        exp.disabled = true; clr.disabled = true;
        exp.title = active ? 'Stop the capture before exporting.' : 'Nothing to export yet \u2014 this capture has no packets.';
        clr.title = active ? 'Stop the capture before clearing.' : 'Nothing to clear \u2014 this capture has no packets.';
      }
      btns.push(exp, clr, actBtnConfirm('Delete', act('Delete', '/api/opc/delete', { name: nm }), 'danger', 'Delete this capture'));
      return { key: 'cap:' + nm, cells: [
        { v: nm, click: { open: () => openCaptureForm(s, nm) } },
        { pill: true, v: cap.stateText || '' },
        { v: (cap.bufferTypeText || '') + (Number(cap.bufferSize) ? ' ' + cap.bufferSize + 'MB' : '') },
        { v: cap.filterText === 'acl' ? 'acl ' + (cap.aclName || '') : (cap.filterText || '') },
        { v: cap.packets === undefined ? '' : String(cap.packets) },
        { v: cap.dropped === undefined ? '' : String(cap.dropped) },
        { v: cap.bufferUsed === undefined ? '' : String(cap.bufferUsed) },
        { v: cap.pps === undefined ? '' : String(cap.pps) },
        { cellNode: actGroup(btns), sig: (active ? 'a' : 's') + (empty ? 'e' : 'p') }] };
    }));
  }

  // New or existing capture settings in the standard pop-out (A5): one tap to
  // apply (B8), the failure as a red line under the button, Esc closes.
  function openCaptureForm(s, name) {
    const caps = (s._capture && s._capture.data && s._capture.data.captures) || [];
    const cap = name ? caps.find((c) => c.name === name) : null;
    if (name && !cap) return;
    openTabbedPopout(s, cap ? 'Capture \u00b7 ' + cap.name : 'New packet capture', [{ label: 'Settings', fill: (pane, close) => {
      const form = el('div', 'snmp-form acl-form');
      const sec = formSection('Capture');
      sec.body.classList.add('acl-stack');
      const nameIn = textInput(cap ? cap.name : (s.captureName || 'capture1')); nameIn.maxLength = 32;
      if (cap) nameIn.disabled = true;
      sec.body.appendChild(field('Capture name', nameIn));
      const dirSel = selectInput(['both', 'in', 'out'].map((v) => ({ label: v, value: v })), 'both');
      sec.body.appendChild(field('Control-plane direction', dirSel));
      const bufSel = selectInput(['linear', 'circular'].map((v) => ({ label: v, value: v })), (cap && cap.bufferTypeText) || 'linear');
      sec.body.appendChild(field('Buffer type', bufSel));
      const num = (v, ph) => { const i = el('input'); i.type = 'number'; i.min = '0'; i.placeholder = ph; if (Number(v) > 0) i.value = String(v); return i; };
      const sizeIn = num(cap && cap.bufferSize, 'MB (optional)');
      sec.body.appendChild(field('Buffer size (MB)', sizeIn));
      const filterSel = selectInput([{ label: 'match any', value: 'any' }, { label: 'match ACL', value: 'acl' }], cap && cap.filterText === 'acl' ? 'acl' : 'any');
      sec.body.appendChild(field('Filter', filterSel));
      const aclIn = textInput(cap && cap.filterText === 'acl' ? (cap.aclName || '') : '', 'ACL name'); aclIn.maxLength = 32;
      const aclField = field('ACL name', aclIn);
      sec.body.appendChild(aclField);
      const syncFilter = () => { aclField.style.display = filterSel.value === 'acl' ? '' : 'none'; };
      filterSel.addEventListener('change', syncFilter); syncFilter();
      const durIn = num(cap && cap.limitDuration, 'seconds (0 = none)');
      sec.body.appendChild(field('Limit: duration', durIn));
      const pktIn = num(cap && cap.limitPackets, 'packets (0 = none)');
      sec.body.appendChild(field('Limit: packets', pktIn));
      form.appendChild(sec.sec);

      const { actions, apply, msg } = applyActions(cap ? 'Save' : 'Create capture');
      apply.addEventListener('click', (ev) => {
        clear(msg);
        const nm = (nameIn.value || '').trim();
        if (!nm) { msg.appendChild(el('div', 'sw-err', 'Enter a capture name.')); return; }
        if (!cap && caps.some((c) => c.name === nm)) { msg.appendChild(el('div', 'sw-err', 'A capture named \u201c' + nm + '\u201d already exists.')); return; }
        if (filterSel.value === 'acl' && !(aclIn.value || '').trim()) { msg.appendChild(el('div', 'sw-err', 'Enter the ACL name to match.')); return; }
        s.captureName = nm;
        runButtonAction(ev.currentTarget, {
          failLabel: cap ? 'Save capture' : 'Create capture', spinLabel: cap ? 'Saving\u2026' : 'Creating\u2026',
          run: () => captureWrite(s, '/api/opc/configure', {
            name: nm, direction: dirSel.value, bufferType: bufSel.value, bufferSizeMb: parseInt(sizeIn.value, 10),
            filter: filterSel.value, aclName: (aclIn.value || '').trim(),
            limitDurationSec: parseInt(durIn.value, 10), limitPackets: parseInt(pktIn.value, 10), existing: !!cap }),
          ok: (r) => r && r.ok,
          error: (r) => { const e = (r && r.error) || 'unknown error'; msg.appendChild(el('div', 'sw-err', (cap ? 'Save' : 'Create') + ' failed: ' + e)); return e; },
          settle: () => captureLoad(s).then(() => close())
        });
      });
      form.appendChild(actions); form.appendChild(msg);
      pane.appendChild(form);
      if (!cap) nameIn.focus();
    } }], []);
  }
