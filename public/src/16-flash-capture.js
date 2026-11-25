  // =================================================================
  // 16-flash-capture.js: Flash files and packet capture (OPC) panels.
  // =================================================================

  // delete it (rlFileRowStatus destroy). Delete is suppressed for directory
  // entries and anything the switch marks non-writable (system files).
  function paintFlashPanel(s, body) {
    clear(body);
    if (!s.target) { body.appendChild(el('div', 'card-sub', 'Connect with SNMP to browse flash.')); return; }

    const fmtSize = (n) => {
      const v = Number(n); if (!Number.isFinite(v)) return String(n);
      if (v >= 1048576) return (v / 1048576).toFixed(1) + ' MB';
      if (v >= 1024) return (v / 1024).toFixed(1) + ' KB';
      return v + ' B';
    };

    const title = el('div', 'section-title', 'Flash files');
    const note = el('span', 'st-note', ''); title.appendChild(note);
    body.appendChild(title);

    const listBody = el('div', 'flash-files'); listBody.style.marginTop = '8px'; body.appendChild(listBody);
    const msg = el('div', 'sw-msg'); body.appendChild(msg);

    // Download a flash file over TFTP (flash -> this app -> browser).
    const download = (fileName) => {
      clear(msg);
      s.writeBusy = true;
      return fetch('/api/opc/fetch-flash', { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: s.target, flashFileName: fileName }) })
        .then((r) => r.json().then((b) => ({ ok: r.ok, b })))
        .then(({ ok, b }) => {
          s.writeBusy = false;
          if (ok && b.ok && b.pcapBase64) {
            const bytes = atob(b.pcapBase64);
            const arr = new Uint8Array(bytes.length);
            for (let i = 0; i < bytes.length; i++) arr[i] = bytes.charCodeAt(i);
            const blob = new Blob([arr], { type: 'application/octet-stream' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url; a.download = String(fileName).replace(/^flash:\/\//i, '').replace(/^flash:/i, '');
            document.body.appendChild(a); a.click(); document.body.removeChild(a); URL.revokeObjectURL(url);
            return true;
          }
          // Only surface a message on failure.
          clear(msg); msg.appendChild(el('div', 'sw-err', 'Download failed: ' + (b.error || 'unknown error')));
          return false;
        })
        .catch((e) => { s.writeBusy = false; clear(msg); msg.appendChild(el('div', 'sw-err', 'Download failed: ' + e.message)); return false; });
    };

    // The Delete button confirms itself (two-tap), so this acts directly.
    const doDeleteFlash = (f) => {
      clear(msg); s.writeBusy = true;
      return fetch('/api/flash/delete', { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: s.target, fileName: f.name }) })
        .then((r) => r.json().then((bb) => ({ ok: r.ok, bb })))
        .then(({ ok, bb }) => {
          s.writeBusy = false;
          // No success text — the file just disappears from the reloaded list.
          if (ok && bb.ok) { load(); return true; }
          clear(msg); msg.appendChild(el('div', 'sw-err', 'Delete failed: ' + (bb.error || 'unknown error')));
          return false;
        })
        .catch((e) => { s.writeBusy = false; clear(msg); msg.appendChild(el('div', 'sw-err', 'Delete failed: ' + e.message)); return false; });
    };

    const load = (highlightName) => {
      clear(listBody); clear(msg);
      listBody.appendChild(el('div', 'card-sub', 'Listing flash\u2026'));
      fetch('/api/flash/list', { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: s.target }) })
        .then((r) => r.json())
        .then((b) => {
          clear(listBody);
          // Normalise the name to highlight (strip any flash:// prefix so it
          // matches the listing's bare names).
          const hl = highlightName ? String(highlightName).replace(/^flash:\/\//i, '').replace(/^flash:/i, '') : null;
          if (!b || b.error) { listBody.appendChild(el('div', 'card-sub', 'Could not list flash: ' + ((b && b.error) || 'error'))); return; }
          const files = b.files || [];
          note.textContent = files.length + ' entr' + (files.length === 1 ? 'y' : 'ies') +
            (b.flash && b.flash.free != null ? '  \u00b7  ' + fmtSize(b.flash.free) + ' free of ' + fmtSize(b.flash.total) : '');
          if (!files.length) { listBody.appendChild(el('div', 'card-sub', 'No files found.')); return; }
          // Render the file list through plainTable (the keyed render helper) so
          // it diffs cells and stays consistent with every other data table
          // (standard A5/B3), instead of a hand-built <table>.
          const cols = ['Name', 'Perm', 'Size', 'Modified', ''];
          const rows = files.map((f) => {
            const permKnown = (f.permByte !== undefined && f.permByte !== null);
            const nameCell = el('span', '', f.isDir ? (f.name + '/') : f.name);
            if (hl && String(f.name).replace(/^flash:\/\//i, '').replace(/^flash:/i, '') === hl) {
              nameCell.className = 'flash-new';
              setTimeout(() => { nameCell.classList.remove('flash-new'); }, 6000);
            }
            const btns = [];
            // Download for anything that isn't a directory. Routed through
            // runButtonAction (standard B6) so it spins until the TFTP copy +
            // browser download resolves, then shows Done.
            if (!f.isDir) btns.push(actBtn('Download', (e) => {
              runButtonAction(e.currentTarget, {
                failLabel: 'Download', spinLabel: 'Fetching\u2026',
                run: () => download(f.name),
                ok: (okFlag) => okFlag === true,
                settle: () => Promise.resolve()
              });
            }, 'primary', 'Download this file'));
            // Delete rules: never for directories or read-only (system) files;
            // offered for writable or unknown-permission files.
            let noteLabel = null;
            if (f.isDir) { noteLabel = ' directory'; }
            else if (permKnown && f.writable === false) { noteLabel = ' read-only'; }
            else {
              btns.push(actBtnConfirm('Delete', (e) => {
                runButtonAction(e.currentTarget, {
                  failLabel: 'Delete',
                  run: () => doDeleteFlash(f),
                  ok: (okFlag) => okFlag === true,
                  settle: () => Promise.resolve()   // doDeleteFlash reloads the list itself
                });
              }, 'danger', 'Delete this file'));
            }
            // A span.tbl-acts (from actGroup) is detected by ktRenderCell as an
            // action cell (clicks stopped); append the informational note, if any.
            const actCell = actGroup(btns);
            if (noteLabel) actCell.appendChild(el('span', 'card-sub', noteLabel));
            return [
              nameCell,
              permKnown ? ('0x' + Number(f.permByte).toString(16).padStart(2, '0')) : '?',
              f.isDir ? '' : (f.size !== undefined ? fmtSize(f.size) : ''),
              [f.date, f.time].filter(Boolean).join(' '),
              actCell
            ];
          });
          listBody.appendChild(plainTable(s, cols, rows));
        })
        .catch((e) => { clear(listBody); listBody.appendChild(el('div', 'card-sub', 'Could not list flash: ' + e.message)); });
    };

    // Expose so the capture panel's Export can download a file and reload this
    // list without the user switching panels.
    s._flashDownload = download;
    s._flashReload = load;
    load();
  }

  function paintCapturePanel(s, body) {
    clear(body);
    if (!s.target) {
      body.appendChild(el('div', 'card-sub', 'Connect with SNMP to use packet capture.'));
      return;
    }
    // Existing captures on the switch, discovered by walking the capture table.
    const existing = el('div', 'capture-existing'); existing.style.margin = '10px 0';
    body.appendChild(existing);

    const grid = el('div', 'snmp-form-grid'); grid.style.marginTop = '10px';

    const nameIn = el('input'); nameIn.type = 'text'; nameIn.maxLength = 32; nameIn.value = s.captureName || 'capture1';
    nameIn.addEventListener('input', () => { s._captureExisting = false; });
    grid.appendChild(field('Capture name', nameIn));

    const dirSel = el('select');
    for (const d of ['both', 'in', 'out']) { const o = el('option', '', d); o.value = d; dirSel.appendChild(o); }
    grid.appendChild(field('Control-plane direction', dirSel));

    const bufSel = el('select');
    for (const b2 of ['linear', 'circular']) { const o = el('option', '', b2); o.value = b2; bufSel.appendChild(o); }
    grid.appendChild(field('Buffer type', bufSel));

    const sizeIn = el('input'); sizeIn.type = 'number'; sizeIn.min = '1'; sizeIn.placeholder = 'MB (optional)';
    grid.appendChild(field('Buffer size (MB)', sizeIn));

    const filterSel = el('select');
    for (const f2 of ['any', 'acl']) { const o = el('option', '', f2 === 'any' ? 'match any' : 'match ACL'); o.value = f2; filterSel.appendChild(o); }
    grid.appendChild(field('Filter', filterSel));

    const aclIn = el('input'); aclIn.type = 'text'; aclIn.maxLength = 32; aclIn.placeholder = 'ACL name';
    const aclField = field('ACL name', aclIn);
    grid.appendChild(aclField);

    const durIn = el('input'); durIn.type = 'number'; durIn.min = '0'; durIn.placeholder = 'seconds (0 = none)';
    grid.appendChild(field('Limit: duration', durIn));

    const pktIn = el('input'); pktIn.type = 'number'; pktIn.min = '0'; pktIn.placeholder = 'packets (0 = none)';
    grid.appendChild(field('Limit: packets', pktIn));

    body.appendChild(grid);
    const syncFilter = () => { aclField.style.display = filterSel.value === 'acl' ? '' : 'none'; };
    filterSel.addEventListener('change', syncFilter); syncFilter();

    const msg = el('div', 'sw-msg');

    // Per-capture status (state, packets, dropped, buffer) is shown inline in
    // the captures list, so "refresh status" just reloads that list rather than
    // maintaining a separate, redundant status block.
    const readStatus = () => { if (s._captureListReload) s._captureListReload(); };

    const cfg = () => ({
      target: s.target, name: (nameIn.value || '').trim(), direction: dirSel.value,
      bufferType: bufSel.value, bufferSizeMb: parseInt(sizeIn.value, 10),
      filter: filterSel.value, aclName: (aclIn.value || '').trim(),
      limitDurationSec: parseInt(durIn.value, 10), limitPackets: parseInt(pktIn.value, 10),
      existing: !!s._captureExisting
    });
    const run = (label, url, payload, after) => {
      clear(msg);
      s.writeBusy = true;
      return fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) })
        .then((r) => r.json().then((b) => ({ ok: r.ok, b })))
        .then(({ ok, b }) => {
          s.writeBusy = false;
          // No success text — the list updates to reflect the new state. Only
          // surface failures.
          if (ok && b.ok) { if (after) after(b); readStatus(); if (s._captureListReload) s._captureListReload(); }
          else { clear(msg); msg.appendChild(el('div', 'sw-err', label + ' failed: ' + (b.error || 'unknown error'))); }
          return { ok: ok && b.ok, b };
        })
        .catch((e) => { s.writeBusy = false; clear(msg); msg.appendChild(el('div', 'sw-err', label + ' failed: ' + e.message)); return { ok: false }; });
    };

    const actions = el('div', 'snmp-form-actions'); actions.style.marginTop = '10px';
    const applyBtn = el('button', 'btn btn-small btn-blue', 'Configure'); applyBtn.type = 'button';

    const nameOf = () => (nameIn.value || '').trim();
    const needName = () => { if (!nameOf()) { clear(msg); msg.appendChild(el('div', 'sw-err', 'Enter a capture name.')); return false; } return true; };

    applyBtn.addEventListener('click', () => { if (needName()) { s.captureName = nameOf(); run('Configure', '/api/opc/configure', cfg()); } });
    actions.appendChild(applyBtn);
    body.appendChild(actions);

    body.appendChild(msg);

    // Export a stopped, non-empty capture to a flash .pcap via the rlCopyTable
    // copy engine (sourceFileType=pcap -> capture://). This is the proven,
    // non-crashing path. Exposed on s so the inline per-capture Export button
    // (in the list above) can call it.
    s._exportCapture = (captureName, btn) => {
      clear(msg);
      // The export button spins through the WHOLE operation - copying the capture
      // to a flash file AND the TFTP download of that file - and only says Done
      // once the file has actually downloaded. The copy result is carried from
      // run() into settle() so the download targets the right flash file.
      let copyResult = null;
      runButtonAction(btn, {
        failLabel: 'Export',
        run: () => apiPost('/api/copy/capture-to-flash', { target: s.target, name: captureName, confirm: true })
          .then((res) => { copyResult = res.body; return res; }),
        // Success means the copy to flash genuinely finished (server waits for it).
        ok: (res) => res && res.ok && res.body && res.body.ok && res.body.flashFileName,
        error: (res) => {
          const b = res && res.body;
          if (b && b.finished === false && !b.failed) {
            // Still being written (a very large capture beyond the server's wait):
            // show the file in the Flash list so the user can grab it when ready.
            if (b.flashFileName && s._flashReload) s._flashReload(b.flashFileName);
            return 'still writing to flash - it will appear in the Flash files list shortly; download it from there once it finishes';
          }
          return (b && b.error) || 'unknown error';
        },
        // settle = the TFTP download. The button keeps spinning until it lands,
        // and a failed download rejects so the helper reports it rather than
        // showing a false Done.
        settle: () => {
          const fn = copyResult && copyResult.flashFileName;
          if (!fn) return Promise.resolve();
          if (s._flashReload) s._flashReload(fn);
          if (!s._flashDownload) return Promise.resolve();
          return Promise.resolve(s._flashDownload(fn)).then((okDl) => { if (okDl === false) throw new Error('download from flash failed'); });
        }
      }).catch(() => { /* toast already shown by the helper */ });
    };

    // Populate the config form from an existing capture object.
    const loadIntoForm = (cap) => {
      nameIn.value = cap.name || '';
      s.captureName = cap.name;
      s._captureExisting = true;
      if (cap.bufferTypeText) bufSel.value = cap.bufferTypeText;
      if (Number(cap.bufferSize) > 0) sizeIn.value = String(cap.bufferSize); else sizeIn.value = '';
      if (cap.filterText === 'acl') { filterSel.value = 'acl'; aclIn.value = cap.aclName || ''; }
      else filterSel.value = 'any';
      syncFilter();
      durIn.value = Number(cap.limitDuration) > 0 ? String(cap.limitDuration) : '';
      pktIn.value = Number(cap.limitPackets) > 0 ? String(cap.limitPackets) : '';
      readStatus();
    };

    // Discover and render existing captures.
    const loadCaptureList = () => {
      clear(existing);
      existing.appendChild(el('div', 'card-sub', 'Looking for existing captures\u2026'));
      fetch('/api/opc/list', { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: s.target }) })
        .then((r) => r.json())
        .then((b) => {
          const caps = (b && !b.error) ? (b.captures || []) : null;
          if (caps) s._anyCaptureActive = caps.some((c) => c.stateText === 'active');
          // Render with scroll preserved around the rebuild (standard B5), and
          // through plainTable (the keyed render helper) like every other table.
          selfManagedRender(s, () => {
            clear(existing);
            if (!caps) { existing.appendChild(el('div', 'card-sub', 'Could not list captures: ' + ((b && b.error) || 'error'))); return; }
            // Nothing to show when there are no captures — the create form below
            // is how one is made, so this section simply stays hidden.
            if (!caps.length) return;
            const title = el('div', 'section-title', 'Captures on the switch');
            title.appendChild(el('span', 'st-note', caps.length + ' found'));
            existing.appendChild(title);
            const cols = ['Name', 'State', 'Buffer', 'Filter', 'Packets', 'Dropped', 'Used', 'Pkts/s', ''];
            const rows = caps.map((cap) => {
              const nm = cap.name;
              const btns = [];
              // Every capture action goes through runButtonAction: spinner on
              // click, held until the switch state (and the capture list) actually
              // reflect the change, then Done - consistent with the rest of the app.
              const captureAction = (btn, label, url, payload) => runButtonAction(btn, {
                failLabel: label,
                run: () => apiPost(url, payload),
                ok: (r) => r && r.ok && r.body && r.body.ok,
                error: (r) => (r && r.body && r.body.error) || 'unknown error',
                onApplied: () => { readStatus(); },
                settle: () => selfManagedReload(s, s._captureListReload)
              });
              if (cap.stateText === 'active') {
                btns.push(actBtn('Stop', (e) => captureAction(e.currentTarget, 'Stop', '/api/opc/action', { target: s.target, name: nm, action: 'stop' }), '', 'Stop capturing'));
              } else {
                btns.push(actBtn('Start', (e) => captureAction(e.currentTarget, 'Start', '/api/opc/action', { target: s.target, name: nm, action: 'start' }), '', 'Start capturing'));
              }
              btns.push(actBtn('Edit', () => loadIntoForm(cap), '', 'Load this capture into the form below to reconfigure'));
              const exp = actBtn('Export', (e) => { if (s._exportCapture) s._exportCapture(nm, e.currentTarget); }, '', 'Export to a flash .pcap and download it');
              const capPkts = Number(cap.packets) || 0;
              if (cap.stateText === 'active' || capPkts <= 0) {
                exp.disabled = true;
                exp.title = cap.stateText === 'active' ? 'Stop the capture before exporting.' : 'Nothing to export yet — this capture has no packets.';
              }
              btns.push(exp);
              // Clear empties the capture buffer so the same capture can be
              // re-run without deleting and recreating it. Only meaningful when it
              // is stopped and actually has captured packets.
              const clr = actBtnConfirm('Clear', (e) => captureAction(e.currentTarget, 'Clear', '/api/opc/action', { target: s.target, name: nm, action: 'clear' }), '', 'Empty the capture buffer so you can capture again (keeps the capture configured)');
              if (cap.stateText === 'active' || capPkts <= 0) {
                clr.disabled = true;
                clr.title = cap.stateText === 'active' ? 'Stop the capture before clearing.' : 'Nothing to clear \u2014 this capture has no packets.';
              }
              btns.push(clr);
              btns.push(actBtnConfirm('Delete', (e) => captureAction(e.currentTarget, 'Delete', '/api/opc/delete', { target: s.target, name: nm }), 'danger', 'Delete this capture'));
              return [
                cap.name,
                cap.stateText,
                (cap.bufferTypeText || '') + (Number(cap.bufferSize) ? ' ' + cap.bufferSize + 'MB' : ''),
                cap.filterText === 'acl' ? ('acl ' + (cap.aclName || '')) : (cap.filterText || ''),
                cap.packets === undefined ? '' : String(cap.packets),
                cap.dropped === undefined ? '' : String(cap.dropped),
                cap.bufferUsed === undefined ? '' : String(cap.bufferUsed),
                cap.pps === undefined ? '' : String(cap.pps),
                actGroup(btns)
              ];
            });
            existing.appendChild(plainTable(s, cols, rows));
          });
        })
        .catch((e) => { clear(existing); existing.appendChild(el('div', 'card-sub', 'Could not list captures: ' + e.message)); });
    };
    // Expose so action handlers can refresh the list after changes.
    s._captureListReload = loadCaptureList;
    s._captureLoadIntoForm = loadIntoForm;

    loadCaptureList();

    // Auto-update the capture stats every 3s while any capture is running, so
    // packet counts update live without a refresh button. The timer is torn
    // down when the panel is repainted (a fresh paint starts a new one) or when
    // no capture is active, and pauses during writes.
    if (s._captureStatsTimer) { clearInterval(s._captureStatsTimer); s._captureStatsTimer = null; }
    // Capture status is walked from the switch each time, so poll gently - a
    // packet capture's state does not change second-to-second, and a 3s loop was
    // a constant SNMP drain whenever the capture panel sat open with an active
    // capture. 15s is responsive enough for status while far lighter.
    s._captureStatsTimer = setInterval(() => {
      // Stop if this panel is gone from the DOM.
      if (!document.body.contains(existing)) { clearInterval(s._captureStatsTimer); s._captureStatsTimer = null; return; }
      if (s._anyCaptureActive && !s.writeBusy) loadCaptureList();
    }, 15000);
    readStatus();
  }
