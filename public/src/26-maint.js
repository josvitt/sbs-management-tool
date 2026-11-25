  // =================================================================
  // 26-maint.js: The Reboot and firmware panel.
  // =================================================================

  // A keyed panel with a server-side reader (standard B1 family b2), like
  // Flash files. Its actions are server operations, not single SETs: a
  // firmware install has the switch pull the image from this app over TFTP
  // (switch-maint.js pushFile), and a reboot can drop the app's own SNMP
  // path. The view joins the reboot schedule and two image tables per unit.
  // The data rides the server collection as `maint` (module-collection.js).
  //
  // s._maint = { data, fetchedAt, loading, liveAt, collected, file, staged }
  // data is /api/maint/status's reply; data.error is set when it failed.

  function maintLoad(s) {
    s._maint = s._maint || {};
    const st = s._maint;
    if (st.loading) return st.loading;
    st.fetchedAt = Date.now();
    st.liveAt = Date.now();
    st.loading = sidePost('/api/maint/status', { target: s.target })
      .then((b) => { st.data = (b && !b.error) ? b : { error: (b && b.error) || 'no answer' }; })
      .finally(() => { st.loading = null; sideRepaint(s, 'maint'); });
    return st.loading;
  }

  // How long until a reboot, in words.
  function inWords(secs) {
    if (secs < 90) return secs + ' seconds';
    if (secs < 5400) return Math.round(secs / 60) + ' minutes';
    const h = Math.floor(secs / 3600), m = Math.round((secs % 3600) / 60);
    return h + ' h' + (m ? ' ' + m + ' min' : '');
  }

  const REBOOT_DELAYS = [
    { label: 'In 5 minutes', value: '300' },
    { label: 'In 15 minutes', value: '900' },
    { label: 'In 30 minutes', value: '1800' },
    { label: 'In 1 hour', value: '3600' },
    { label: 'In 2 hours', value: '7200' },
    { label: 'In 4 hours', value: '14400' },
    { label: 'In 8 hours', value: '28800' }
  ];

  function switchLabel(s) { return s.sysName || s.host; }

  function rebootAction(btn, s, seconds) {
    return runButtonAction(btn, {
      failLabel: 'Reboot',
      spinLabel: seconds ? 'Scheduling…' : 'Rebooting…',
      run: async () => {
        s.writeBusy = true;
        try { return await sidePost('/api/maint/reboot', { target: s.target, seconds }); }
        finally { s.writeBusy = false; }
      },
      ok: (r) => r && r.ok,
      error: (r) => (r && r.error) || 'unknown error',
      onApplied: (r) => {
        appLog('warn', 'Reboot requested', { host: s.host, inSeconds: r.inSeconds });
        toast(seconds ? switchLabel(s) + ' will reboot in ' + inWords(r.inSeconds) + '.'
          : switchLabel(s) + ' is rebooting. It is usually back in two to three minutes.', 'info');
      },
      settle: () => (seconds ? maintLoad(s) : null)
    });
  }

  // Upload the chosen file to this app, then have the switch pull it.
  async function installFirmware(s, file) {
    const st = s._maint;
    s.writeBusy = true;
    try {
      let staged;
      try {
        const r = await fetch('/api/firmware/stage?name=' + encodeURIComponent(file.name), {
          method: 'POST', headers: { 'Content-Type': 'application/octet-stream' }, body: file
        });
        staged = await r.json().catch(() => ({ error: 'HTTP ' + r.status }));
        if (!r.ok || !staged.ok) return { ok: false, error: staged.error || ('HTTP ' + r.status) };
      } catch (e) { return { ok: false, error: 'lost contact with the local server: ' + e.message }; }
      appLog('info', 'Firmware uploaded to the app', { host: s.host, name: staged.name, bytes: staged.bytes, sha256: staged.sha256 });
      const b = await sidePost('/api/firmware/install', { target: s.target, id: staged.id });
      if (b && b.ok && b.status) { st.data = b.status; st.liveAt = Date.now(); }
      return b;
    } finally { s.writeBusy = false; }
  }

  function paintMaintPanel(s, body, p) {
    if (!s._ktReconcile) clear(body);
    if (!s.target) { if (!s._ktReconcile) body.appendChild(el('div', 'card-sub', 'Connect with SNMP to see firmware and reboot.')); return; }
    s._maint = s._maint || {};
    const st = s._maint;
    if (!s._ktReconcile) sideEnsure(s, st, maintLoad);
    const d = st.data;
    const units = (d && d.units) || [];
    const shape = !d ? 'wait' : (d.error ? 'error' : 'ready:' + units.length + ':' + (units.length > 1 ? 'multi' : 'one'));
    if (s._ktReconcile && p._maintShape !== shape) { s._ktStructural = true; return; }
    p._maintShape = shape;
    if (shape === 'wait') { if (!s._ktReconcile) body.appendChild(el('div', 'card-sub', 'Waiting for data…')); return; }
    if (shape === 'error') { if (!s._ktReconcile) body.appendChild(el('div', 'panel-err', 'Could not read the firmware and reboot state: ' + d.error)); return; }

    // ---- Firmware ----
    if (!s._ktReconcile) {
      const t = el('div', 'section-title', 'Firmware');
      p._maintFwNote = el('span', 'st-note', '');
      t.appendChild(p._maintFwNote);
      body.appendChild(t);
    }
    const multi = units.length > 1;
    const u1 = units[0] || {};
    p._maintFwNote.textContent = units.length
      ? (multi ? units.length + ' units' : 'running ' + (u1.active || 'unknown') + '  ·  boots ' + (u1.nextBoot || 'unknown') + ' next')
      : 'the switch did not report its images';
    const rows = [];
    for (const u of units) {
      for (const img of u.images) {
        const running = img.slot === u.active, next = img.slot === u.nextBoot;
        const status = [running ? 'running' : '', next ? 'boots next' : ''].filter(Boolean).join(', ') || 'stored';
        const btns = [];
        if (!next) {
          btns.push(actBtnConfirm('Boot this next', (e) => runButtonAction(e.currentTarget, {
            failLabel: 'Boot this next',
            run: async () => { s.writeBusy = true; try { return await sidePost('/api/maint/next-boot', { target: s.target, unit: u.unit, image: img.slot }); } finally { s.writeBusy = false; } },
            ok: (r) => r && r.ok,
            error: (r) => (r && r.error) || 'unknown error',
            settle: () => maintLoad(s)
          }), null, 'Make this the image the switch starts after its next reboot'));
        }
        const cells = [];
        if (multi) cells.push({ v: String(u.unit) });
        cells.push({ v: img.slot === 'image1' ? 'Image 1' : 'Image 2' },
          { v: img.version || '' }, { v: img.name || '' }, { v: img.date || '' },
          { pill: running ? 'good' : (next ? 'warn' : true), v: status },
          { cellNode: actGroup(btns), sig: next ? 'n' : 'b' });
        rows.push({ key: 'img:' + u.unit + ':' + img.slot, cells });
      }
    }
    const cols = (multi ? ['Unit'] : []).concat(['Image', 'Version', 'File', 'Built', 'Status', '']);
    if (rows.length) mountInto(body, s, p, 'maint:images', cols, rows);
    else if (!s._ktReconcile) body.appendChild(el('div', 'card-sub', 'The switch did not list any images.'));

    if (!s._ktReconcile) {
      const row = el('div', 'maint-row');
      const file = el('input'); file.type = 'file'; file.accept = '.bin,.ros,application/octet-stream';
      const go = el('button', 'btn', 'Install firmware');
      go.type = 'button'; go.disabled = true;
      file.addEventListener('change', () => { go.disabled = !file.files.length; });
      withConfirm(go, (e) => runButtonAction(e.currentTarget, {
        failLabel: 'Install firmware',
        spinLabel: 'Installing… this takes several minutes',
        minSpinMs: 0,
        run: () => installFirmware(s, file.files[0]),
        ok: (r) => r && r.ok,
        error: (r) => (r && r.error) || 'unknown error',
        onApplied: () => { file.value = ''; go.disabled = true; toast('Firmware installed on ' + switchLabel(s) + '. Check which image boots next, then reboot.', 'info'); },
        settle: () => { sideRepaint(s, 'maint'); return null; }
      }), { danger: false, confirmText: () => 'Tap again to install on ' + switchLabel(s) });
      row.appendChild(field('Firmware file', file));
      row.appendChild(go);
      body.appendChild(row);
      body.appendChild(el('div', 'card-sub', 'The switch copies the file from this computer over TFTP into the image ' +
        'it is not running, then starts it after the next reboot. The running image stays as a fallback.'));
    }

    // ---- Reboot ----
    if (!s._ktReconcile) {
      body.appendChild(el('div', 'section-title', 'Reboot'));
      p._maintReboot = el('div', 'card-sub');
      body.appendChild(p._maintReboot);
      p._maintUnsaved = el('div', 'sw-warn', '');
      body.appendChild(p._maintUnsaved);
      const row = el('div', 'maint-row');
      const now = el('button', 'btn btn-danger', 'Reboot now');
      now.type = 'button';
      withConfirm(now, (e) => rebootAction(e.currentTarget, s, 0),
        { danger: true, confirmText: () => 'Tap again to reboot ' + switchLabel(s) });
      const when = selectInput(REBOOT_DELAYS, '3600');
      const later = el('button', 'btn btn-danger', 'Schedule reboot');
      later.type = 'button';
      withConfirm(later, (e) => rebootAction(e.currentTarget, s, Number(when.value)),
        { danger: true, confirmText: () => 'Tap again to schedule ' + switchLabel(s) });
      p._maintCancel = el('button', 'btn btn-blue', 'Cancel scheduled reboot');
      p._maintCancel.type = 'button';
      p._maintCancel.addEventListener('click', (e) => runButtonAction(e.currentTarget, {
        failLabel: 'Cancel reboot',
        run: async () => { s.writeBusy = true; try { return await sidePost('/api/maint/reboot/cancel', { target: s.target }); } finally { s.writeBusy = false; } },
        ok: (r) => r && r.ok,
        error: (r) => (r && r.error) || 'unknown error',
        settle: () => maintLoad(s)
      }));
      row.appendChild(now);
      row.appendChild(field('Later', when));
      row.appendChild(later);
      row.appendChild(p._maintCancel);
      body.appendChild(row);
    }
    const rb = d.reboot || {};
    p._maintReboot.textContent = !rb.readable ? 'The switch did not report whether a reboot is scheduled.'
      : (rb.scheduled ? 'A reboot is scheduled in about ' + inWords(rb.inSeconds) + '.' : 'No reboot is scheduled.');
    p._maintCancel.hidden = !rb.scheduled;
    const unsaved = switchSaysUnsaved(s);
    p._maintUnsaved.textContent = unsaved
      ? 'The running configuration has unsaved changes. A reboot loses them unless you save first.' : '';
    p._maintUnsaved.hidden = !unsaved;
  }
