  // =================================================================
  // 19-oid-panels.js: Custom OID panels and the add/edit panel dialog.
  // =================================================================

  // ---------- OID panel body ----------
  function paintOidPanel(s, p, body) {
    if (p.loading && !p.results) { body.appendChild(el('div', 'card-sub', 'Querying\u2026')); return; }
    if (p.error) { body.appendChild(el('div', 'panel-err', p.error)); return; }
    if (!p.results) {
      const b = el('button', 'btn', 'Run ' + p.op.toUpperCase());
      b.type = 'button';
      b.style.width = 'auto';
      b.addEventListener('click', () => loadPanelData(s, p));
      body.appendChild(b);
      return;
    }
    renderResultsInto(body, p.results);
    body.appendChild(el('div', 'panel-note',
      p.op.toUpperCase() + ' ' + p.oid + (p.at ? '  \u00b7  ' + p.at.toLocaleTimeString() : '') +
      '  \u00b7  ' + p.results.length + ' value' + (p.results.length === 1 ? '' : 's')));
  }

  /**
   * Shared result rendering: scalars as key/value, tables pivoted to one
   * row per instance, single-column walks as index/value.
   */
  function renderResultsInto(host, results) {
    const usable = results.filter((r) => !r.error && r.column);
    const errors = results.filter((r) => r.error);
    const columns = [], indexes = [];
    for (const r of usable) {
      if (!columns.includes(r.column)) columns.push(r.column);
      const i = r.index === undefined ? '' : r.index;
      if (!indexes.includes(i)) indexes.push(i);
    }

    if (usable.length && indexes.length === 1 && (indexes[0] === '0' || indexes[0] === '')) {
      const t = el('table', 'data-table');
      for (const r of usable) {
        const tr = document.createElement('tr');
        tr.appendChild(el('td', 'col-name', r.column, r.description || ''));
        tr.appendChild(el('td', 'col-value', r.display !== undefined ? r.display : r.value));
        t.appendChild(tr);
      }
      host.appendChild(t);
    } else if (usable.length && columns.length >= 2 && indexes.length >= 2) {
      const byIndex = new Map();
      for (const r of usable) {
        const i = r.index === undefined ? '' : r.index;
        if (!byIndex.has(i)) byIndex.set(i, {});
        byIndex.get(i)[r.column] = { d: r.display !== undefined ? r.display : r.value, v: r.value };
      }
      const idx = Array.from(byIndex.keys()).sort((a, x) => {
        const na = Number(a), nb = Number(x);
        if (Number.isFinite(na) && Number.isFinite(nb)) return na - nb;
        return String(a).localeCompare(String(x));
      });
      // A column that merely repeats the row key adds nothing.
      const shown = columns.filter((c) => !idx.every((i) => {
        const cell = byIndex.get(i)[c];
        return cell === undefined || String(cell.v) === String(i);
      }));
      const cols = shown.length ? shown : columns;
      const wrap = el('div', 'table-scroll');
      const t = el('table', 'data-table wide');
      const hr = document.createElement('tr');
      hr.appendChild(el('th', 'sticky-col', 'index'));
      for (const c of cols) hr.appendChild(el('th', '', shortenColumn(c, cols), c));
      t.appendChild(hr);
      for (const i of idx) {
        const rd = byIndex.get(i); const tr = document.createElement('tr');
        tr.appendChild(el('td', 'col-index sticky-col', i));
        for (const c of cols) tr.appendChild(el('td', 'col-value', rd[c] === undefined ? '' : rd[c].d));
        t.appendChild(tr);
      }
      wrap.appendChild(t); host.appendChild(wrap);
    } else if (usable.length) {
      const t = el('table', 'data-table');
      const hr = document.createElement('tr');
      hr.appendChild(el('th', '', 'index')); hr.appendChild(el('th', '', columns[0] || 'value'));
      t.appendChild(hr);
      for (const r of usable) {
        const tr = document.createElement('tr');
        tr.appendChild(el('td', 'col-index', r.index));
        tr.appendChild(el('td', 'col-value', r.display !== undefined ? r.display : r.value));
        t.appendChild(tr);
      }
      host.appendChild(t);
    }

    if (errors.length) {
      const t = el('table', 'data-table');
      for (const r of errors) {
        const tr = document.createElement('tr');
        tr.appendChild(el('td', 'col-name', r.name || r.oid));
        tr.appendChild(el('td', 'col-value is-error', r.error));
        t.appendChild(tr);
      }
      host.appendChild(t);
    }
  }

  function shortenColumn(col, all) {
    if (all.length < 2) return col;
    let prefix = all[0];
    for (const c of all) {
      let i = 0;
      while (i < prefix.length && i < c.length && prefix[i] === c[i]) i++;
      prefix = prefix.slice(0, i);
      if (!prefix) break;
    }
    while (prefix && !/[a-z]$/.test(prefix)) prefix = prefix.slice(0, -1);
    if (prefix.length < 3) return col;
    const short = col.slice(prefix.length);
    return short && /^[A-Z]/.test(short) ? short : col;
  }

  function groupNum(n) {
    const v = Number(n);
    return Number.isFinite(v) ? v.toLocaleString() : String(n);
  }

  // ---------- add / edit panel dialog ----------
  const dlg = document.getElementById('panel-dialog');
  const dlgKind = dlg.querySelector('.f-dlg-kind');
  const dlgOidFields = dlg.querySelector('.f-dlg-oid-fields');
  const dlgOid = dlg.querySelector('.f-dlg-oid');
  const dlgSuggest = dlg.querySelector('.f-dlg-suggest');
  const dlgOp = dlg.querySelector('.f-dlg-op');
  const dlgName = dlg.querySelector('.f-dlg-name');
  const dlgErr = dlg.querySelector('.f-dlg-error');
  const dlgTitle = dlg.querySelector('.f-dlg-title');
  let dlgState = null;

  dlg.querySelector('.f-dlg-cancel').addEventListener('click', () => dlg.classList.remove('open'));
  dlg.addEventListener('click', (e) => { if (e.target === dlg) dlg.classList.remove('open'); });
  dlgKind.addEventListener('change', () => {
    dlgOidFields.style.display = dlgKind.value === 'oid' ? '' : 'none';
  });

  function openPanelDialog(s, editing) {
    loadMib().then(() => { for (const sw of switches.values()) updateMibStatus(sw); });
    dlgState = { s, editing: editing || null };
    showErr(dlgErr, '');
    dlgTitle.textContent = editing ? 'Edit panel' : 'Add panel';

    // Offer any built-in that is not already on the page, plus a custom OID.
    clear(dlgKind);
    const custom = document.createElement('option');
    custom.value = 'oid'; custom.textContent = 'Custom OID';
    dlgKind.appendChild(custom);
    if (!editing) {
      for (const b of BUILTIN) {
        if (s.panels.some((p) => p.kind === 'builtin' && p.key === b.key)) continue;
        const o = document.createElement('option');
        o.value = 'builtin:' + b.key;
        o.textContent = 'Built-in \u2014 ' + b.title;
        dlgKind.appendChild(o);
      }
    }

    dlgKind.value = 'oid';
    dlgKind.disabled = !!editing;
    dlgOidFields.style.display = '';
    dlgOid.value = editing ? editing.oid : '';
    dlgOp.value = editing ? editing.op : 'get';
    dlgName.value = editing ? editing.title : '';
    dlg.classList.add('open');
    setTimeout(() => dlgOid.focus(), 30);
  }

  dlg.querySelector('.f-dlg-ok').addEventListener('click', () => {
    if (!dlgState) return;
    const s = dlgState.s;

    if (dlgKind.value.indexOf('builtin:') === 0) {
      const key = dlgKind.value.slice(8);
      const def = builtinDef(key);
      s.panels.push({
        id: 'b:' + key, kind: 'builtin', key, title: def.title,
        span: def.span, h: def.h
      });
      s.renderedIds = null;
      dlg.classList.remove('open');
      saveLayout(s); renderSwitch(s);
      return;
    }

    const oid = dlgOid.value.trim();
    if (!oid) { showErr(dlgErr, 'An OID or MIB name is required.'); return; }
    // Resolve the name locally so a typo is caught before it reaches the
    // switch, and so the panel can be titled sensibly by default.
    const bare = oid.replace(/^\./, '').replace(/(\.\d+)+$/, '');
    const known = MIB.loaded && MIB.entries.find((e) => e.name.toLowerCase() === bare.toLowerCase());
    if (!/^\.?\d+(\.\d+)*$/.test(oid) && !known) {
      showErr(dlgErr, 'No MIB object called "' + oid + '". Pick one from the suggestions, or use a numeric OID.');
      return;
    }
    const title = dlgName.value.trim() || (known ? known.name : oid);

    if (dlgState.editing) {
      Object.assign(dlgState.editing, {
        oid, op: dlgOp.value, title, results: null, error: null
      });
      s.renderedIds = null;
      dlg.classList.remove('open');
      saveLayout(s); renderSwitch(s);
      loadPanelData(s, dlgState.editing);
      return;
    }

    const panel = {
      id: 'o:' + Date.now() + ':' + Math.random().toString(36).slice(2, 7),
      kind: 'oid', oid, op: dlgOp.value, title,
      span: dlgOp.value === 'walk' ? 6 : 4, h: dlgOp.value === 'walk' ? 300 : 0
    };
    s.panels.push(panel);
    s.renderedIds = null;
    dlg.classList.remove('open');
    saveLayout(s); renderSwitch(s);
    loadPanelData(s, panel);
    appLog('info', 'Panel added', { host: s.host, oid, op: panel.op });
  });

  // OID autocomplete inside the dialog
  (function wireDialogSuggest() {
    let items = [], index = -1, deb = null;
    const hide = () => { dlgSuggest.classList.remove('open'); items = []; index = -1; };
    const paint = () => dlgSuggest.querySelectorAll('.suggest-item')
      .forEach((k, i) => k.classList.toggle('active', i === index));
    const apply = (e) => {
      const columnar = isColumnar(e);
      // A scalar is read at instance .0; a table or a column of one is
      // walked from its base.
      dlgOid.value = columnar ? e.name : e.name + '.0';
      dlgOp.value = columnar ? 'walk' : 'get';
      if (!dlgName.value) dlgName.value = e.name;
      hide(); dlgOid.focus();
    };
    const render = () => {
      const q = dlgOid.value.trim();
      if (!q || !MIB.loaded) { hide(); return; }
      items = searchMib(q, 30);
      index = -1;
      clear(dlgSuggest);
      if (!items.length) {
        dlgSuggest.appendChild(el('div', 'suggest-empty', 'No MIB name matches. Numeric OIDs still work.'));
        dlgSuggest.classList.add('open');
        return;
      }
      items.forEach((m, i) => {
        const it = el('div', 'suggest-item');
        const nm = el('div', 'sug-name');
        const at = m.name.toLowerCase().indexOf(q.toLowerCase());
        if (at >= 0) {
          nm.appendChild(document.createTextNode(m.name.slice(0, at)));
          nm.appendChild(el('span', 'hl', m.name.slice(at, at + q.length)));
          nm.appendChild(document.createTextNode(m.name.slice(at + q.length)));
        } else nm.textContent = m.name;
        it.appendChild(nm);
        const meta = el('div', 'sug-meta');
        meta.appendChild(el('span', 'sug-oid', m.oid));
        if (m.access) meta.appendChild(el('span', 'sug-acc',
          ({ r: 'read-only', rw: 'read-write', rc: 'read-create', n: 'not-accessible', w: 'write-only', afn: 'notify' })[m.access] || m.access));
        if (m.syntax) meta.appendChild(el('span', '', m.syntax));
        it.appendChild(meta);
        it.addEventListener('mousedown', (ev) => { ev.preventDefault(); apply(m); });
        it.addEventListener('mouseenter', () => { index = i; paint(); });
        dlgSuggest.appendChild(it);
      });
      dlgSuggest.classList.add('open');
    };
    dlgOid.addEventListener('input', () => { clearTimeout(deb); deb = setTimeout(render, 90); });
    dlgOid.addEventListener('keydown', (e) => {
      if (!dlgSuggest.classList.contains('open')) return;
      if (e.key === 'ArrowDown') { e.preventDefault(); index = (index + 1) % items.length; paint(); }
      else if (e.key === 'ArrowUp') { e.preventDefault(); index = (index - 1 + items.length) % items.length; paint(); }
      else if (e.key === 'Enter' && index >= 0) { e.preventDefault(); apply(items[index]); }
      else if (e.key === 'Escape') hide();
    });
  })();
