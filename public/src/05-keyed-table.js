  // =================================================================
  // 05-keyed-table.js: The keyed table reconciliation engine (keyedTable, mountKeyedTable, plainTable).
  // =================================================================

  // ---------- rendering ----------
  const SEV_ORDER = { critical: 0, warning: 1, info: 2, ok: 3 };
  const stateClass = (v) => /normal|^on\b|^up|^ok$/i.test(v) ? 'good'
    : (/critical|shutdown|notFunctioning|faulty|fail/i.test(v) ? 'crit'
    : (/notPresent|notAvailable|^off|^down/i.test(v) ? 'idle' : 'warn'));

  // ============================================================================
  // Keyed table reconciliation engine
  // ----------------------------------------------------------------------------
  // The dashboard's single source of truth is s.health; panels render tables
  // from it. The naive model - on any change, clear the panel body and rebuild
  // every row - is correct but heavy: it tears down hundreds of DOM nodes to
  // reflect one changed cell, which reflows the layout and bounces the viewport.
  //
  // keyedTable renders a table ONCE and then reconciles in place: given a fresh
  // row set, it matches rows by a stable key, updates only the cells whose
  // content actually changed, and adds/removes rows as needed - touching nothing
  // else. A cell that did not change keeps its exact DOM node (and its event
  // handlers), so the viewport cannot move and editable controls are undisturbed.
  //
  // Cell specs are the same shapes the legacy table() builder accepts:
  //   plain string/number            -> text cell
  //   { v, pill }                    -> coloured status pill
  //   { v, click:{open} }            -> row-opens-detail link cell
  //   { actions }                    -> port action buttons (via portActionsCell)
  //   { vlanDelete }                 -> VLAN delete cell
  //   { cellNode }                   -> a caller-built DOM node (buttons, etc.)
  // Value cells diff by their value; node-bearing cells (cellNode/actions/...)
  // carry an explicit `sig` string the caller sets to whatever determines their
  // content (e.g. a shut button's admin state). When sig is unchanged the node
  // is kept as-is; when it changes - or when no sig is given - the cell is
  // rebuilt. `key` on each row gives its identity; `_flash:true` on a cell
  // highlights it after an update.
  // ============================================================================

  // Build one <td> for a cell spec. Extracted so the first render and every
  // later patch produce identical DOM. `s` is the session (action cells need it).
  function ktRenderCell(s, c) {
    // A raw DOM node (the legacy snmpTable style) or an explicit { node } spec:
    // wrap it in a cell. If the node is an action group, its clicks must not
    // bubble to a row-click handler.
    if (c instanceof Node) {
      const isAct = c.classList && (c.classList.contains('tbl-acts') || c.classList.contains('tbl-act-btn'));
      const td = el('td', isAct ? 'tbl-act' : '');
      if (isAct) td.addEventListener('click', (e) => e.stopPropagation());
      td.appendChild(c);
      return td;
    }
    if (c && c.node instanceof Node) {
      const td = el('td', c.actCell ? 'tbl-act' : '');
      if (c.actCell) td.addEventListener('click', (e) => e.stopPropagation());
      td.appendChild(c.node);
      return td;
    }
    if (c && c.actions) {
      const cell = portActionsCell(s, c.actions);
      cell.addEventListener('click', (e) => e.stopPropagation());
      return cell;
    }
    if (c && c.vlanDelete) {
      const td = el('td', 'tbl-act');
      td.addEventListener('click', (e) => e.stopPropagation());
      buildVlanDeleteCell(s, td, c.vlanDelete);
      return td;
    }
    if (c && c.cellNode) {
      const td = el('td', 'tbl-act');
      td.addEventListener('click', (e) => e.stopPropagation());
      td.appendChild(c.cellNode);
      return td;
    }
    if (c && c.click) {
      const td = el('td', 'col-value');
      td.appendChild(el('span', 'port-link', c.v === undefined || c.v === null ? '' : c.v));
      return td;
    }
    const pillText = c && c.pill ? String(c.v === undefined || c.v === null ? '' : c.v).trim() : '';
    if (c && c.pill && pillText) {
      const td = document.createElement('td');
      td.appendChild(el('span', 'pill ' + stateClass(pillText), c.v));
      return td;
    }
    if (c && c.pill) return el('td', 'col-value', '');
    const text = (c && typeof c === 'object')
      ? (c.v === undefined || c.v === null ? '' : c.v)
      : (c === undefined || c === null ? '' : c);
    return el('td', 'col-value', typeof text === 'object' ? '' : text);
  }

  // A stable signature of a cell's rendered content, used to decide whether a
  // patch needs to touch the DOM. Value cells hash their shape + value; cells
  // that carry a live DOM node use the caller-supplied `sig` (and when none is
  // given, a random signature forces a rebuild every time, which is safe).
  function ktCellSig(c) {
    if (c === null || c === undefined) return 't:';
    if (c instanceof Node) return 'dom:\u0000rand' + Math.random();   // raw node: always rebuild unless wrapped with a sig
    if (typeof c !== 'object') return 't:' + c;
    // Cells carrying a live DOM node diff by a caller-supplied sig; without one
    // they rebuild every reconcile (safe default).
    if (c.actions || c.cellNode || c.vlanDelete || (c.node instanceof Node)) {
      return 'n:' + (c.sig !== undefined ? c.sig : ('\u0000rand' + Math.random()));
    }
    const kind = c.pill ? 'p' : (c.click ? 'c' : 'v');
    const val = c.v === undefined || c.v === null ? '' : c.v;
    return kind + ':' + val;
  }

  // Whether a row is clickable, and wiring its handler - matches table()'s rule.
  // A cell's row-detail "click" spec - but only plain-object cell specs count.
  // A raw DOM node (e.g. a <button>) has a native .click METHOD, so it must be
  // excluded or it would be mistaken for a { click } cell.
  function ktClickOf(cells) {
    const c = cells.find((x) => x && typeof x === 'object' && !(x instanceof Node) && x.click);
    return c ? c.click : null;
  }
  function ktWireRow(s, tr, rowCells, onRowClick) {
    const rowDetail = ktClickOf(rowCells);
    tr._ktRowKey = tr._ktKey;
    if (rowDetail) {
      tr.classList.add('row-clickable');
      if (typeof rowDetail.open === 'function') {
        tr.title = 'Show details';
        tr._ktOpen = () => rowDetail.open();
      } else {
        tr.title = 'Show interface detail, counters, and switchport settings';
        tr._ktOpen = () => openPortDetail(s, rowDetail);
      }
      tr.addEventListener('click', () => { if (tr._ktOpen) tr._ktOpen(); });
    } else if (onRowClick) {
      // Row-level edit action (the SNMP config / ACL edit-row pattern): the whole
      // row is clickable to edit, addressed by key so it survives reconciles.
      tr.classList.add('row-clickable');
      tr.title = 'Edit';
      tr.addEventListener('click', () => onRowClick(tr._ktRowKey, tr));
    }
  }

  // Create a keyed, reconcilable table. Returns { node, reconcile(newRows) }.
  //   cols     : header labels (array)
  //   rows     : array of { key, cells:[...] }
  // The node is a .table-scroll wrapper, same as table(), so it drops in
  // wherever a table() result went.
  function keyedTable(s, cols, rows, opts) {
    opts = opts || {};
    const ROW_CAP = opts.cap || 250;        // max rows shown before a "Show all"
    const pageSize = opts.pageSize || 0;    // >0 paginates; 0 = no pagination
    const onRowClick = opts.onRowClick;     // (key, tr) => edit this row
    const wrap = el('div', 'table-scroll');
    const t = el('table', 'data-table');
    const thead = el('thead'); const htr = document.createElement('tr');
    for (const x of cols) htr.appendChild(el('th', (x === '' ? 'tbl-act-h' : ''), x));
    thead.appendChild(htr); t.appendChild(thead);
    const tb = el('tbody'); t.appendChild(tb);
    const controls = el('div', 'kt-controls');   // pager / show-all live here
    wrap.appendChild(t); wrap.appendChild(controls);
    // Legacy snmpTable exposed these for editor-row anchoring; keep them.
    wrap._tbody = tb; wrap._colspan = cols.length;

    let allRows = rows.slice();   // the full logical row set (reconcile replaces it)
    let page = 0;
    let showAll = false;          // non-paginated: reveal rows past the cap

    const flash = (td) => { td.classList.add('value-changed'); setTimeout(() => { td.classList.remove('value-changed'); }, 1700); };

    // Build one <tr> for a row spec, recording per-cell signatures for diffing.
    const buildRow = (row) => {
      const tr = document.createElement('tr');
      tr._ktKey = String(row.key);
      tr._ktSigs = [];
      ktWireRow(s, tr, row.cells, onRowClick);
      row.cells.forEach((c) => {
        const td = ktRenderCell(s, c);
        tr.appendChild(td);
        tr._ktSigs.push(ktCellSig(c));
        if (c && c._flash) flash(td);
      });
      return tr;
    };

    // Patch an existing <tr> in place from a fresh row spec.
    const patchRow = (tr, row) => {
      const tds = tr.children;
      row.cells.forEach((c, i) => {
        const sig = ktCellSig(c);
        if (tr._ktSigs[i] !== sig) {
          const td = ktRenderCell(s, c);
          if (tds[i]) tr.replaceChild(td, tds[i]); else tr.appendChild(td);
          tr._ktSigs[i] = sig;
          if (c && c._flash) flash(td);
        } else if (c && c._flash && tds[i]) { flash(tds[i]); }
      });
      // Always refresh the row-open closure (captures current row values) and
      // the row-edit key, so a reconciled row never fires a stale handler.
      const detail = ktClickOf(row.cells);
      tr._ktOpen = detail ? (typeof detail.open === 'function' ? () => detail.open() : () => openPortDetail(s, detail)) : null;
      tr._ktRowKey = String(row.key);
      const wasClk = tr.classList.contains('row-clickable');
      const clickable = !!detail || !!onRowClick;
      if (clickable && !wasClk) tr.classList.add('row-clickable');
      if (!clickable && wasClk) tr.classList.remove('row-clickable');
    };

    // Which rows are visible right now (pagination / cap applied).
    const visibleSlice = () => {
      if (pageSize > 0) { const start = page * pageSize; return allRows.slice(start, start + pageSize); }
      if (!showAll && allRows.length > ROW_CAP) return allRows.slice(0, ROW_CAP);
      return allRows;
    };

    // Render the pager / show-all control to match the current state.
    const renderControls = () => {
      clear(controls);
      if (pageSize > 0 && allRows.length > pageSize) {
        const pageCount = Math.ceil(allRows.length / pageSize);
        if (page > pageCount - 1) page = pageCount - 1; if (page < 0) page = 0;
        const start = page * pageSize;
        const pager = el('div', 'tbl-pager');
        const prev = el('button', 'btn btn-small', '\u2039 Prev'); prev.type = 'button'; prev.disabled = page === 0;
        const next = el('button', 'btn btn-small', 'Next \u203a'); next.type = 'button'; next.disabled = page >= pageCount - 1;
        const lbl = el('span', 'tbl-pager-lbl', 'Showing ' + (start + 1) + '\u2013' + Math.min(start + pageSize, allRows.length) + ' of ' + allRows.length.toLocaleString() + '  \u00b7  page ' + (page + 1) + '/' + pageCount);
        prev.addEventListener('click', () => { if (page > 0) { page--; syncRows(); reflowTallPanels(s); } });
        next.addEventListener('click', () => { if (page < pageCount - 1) { page++; syncRows(); reflowTallPanels(s); } });
        pager.appendChild(prev); pager.appendChild(lbl); pager.appendChild(next);
        controls.appendChild(pager);
      } else if (pageSize === 0 && !showAll && allRows.length > ROW_CAP) {
        const note = el('div', 'panel-note', 'Showing ' + ROW_CAP.toLocaleString() + ' of ' + allRows.length.toLocaleString() + ' rows.  ');
        note.style.marginBottom = '6px';
        const more = el('button', 'raw-toggle', 'Show all'); more.type = 'button';
        more.addEventListener('click', () => { showAll = true; syncRows(); renderControls(); reflowTallPanels(s); });
        note.appendChild(more); controls.appendChild(note);
      }
    };

    // Reconcile the tbody to exactly the visible slice: patch matched rows, add
    // new, remove gone, reorder. The engine's core.
    const syncRows = () => {
      const slice = visibleSlice();
      const existing = new Map();
      for (const tr of Array.from(tb.children)) { if (tr._ktKey !== undefined) existing.set(tr._ktKey, tr); }
      let anchor = null;   // rows go after this (null = tbody start)
      for (const row of slice) {
        const key = String(row.key);
        let tr = existing.get(key);
        if (!tr) {
          tr = buildRow(row);
          if (anchor) { if (anchor.nextSibling) tb.insertBefore(tr, anchor.nextSibling); else tb.appendChild(tr); }
          else if (tb.firstChild) tb.insertBefore(tr, tb.firstChild); else tb.appendChild(tr);
        } else {
          existing.delete(key);
          patchRow(tr, row);
          const want = anchor ? anchor.nextSibling : tb.firstChild;
          if (want !== tr) { if (anchor) { if (anchor.nextSibling) tb.insertBefore(tr, anchor.nextSibling); else tb.appendChild(tr); } else tb.insertBefore(tr, tb.firstChild); }
        }
        anchor = tr;
      }
      for (const tr of existing.values()) tr.remove();   // drop rows not in the slice
    };

    syncRows();
    renderControls();

    // Public reconcile: swap in a fresh full row set and re-render.
    function reconcile(newRows) {
      allRows = newRows.slice();
      if (pageSize > 0) { const pc = Math.max(1, Math.ceil(allRows.length / pageSize)); if (page > pc - 1) page = pc - 1; }
      syncRows();
      renderControls();
    }

    // Expose an anchor lookup so callers can mount an inline editor row beneath a
    // data row (the SNMP config panels do this), addressed by row key.
    wrap._rowByKey = (key) => Array.from(tb.children).find((tr) => tr._ktKey === String(key)) || null;

    return { node: wrap, reconcile };
  }

  // ---- panel integration -----------------------------------------------------
  // A converted panel calls mountKeyedTable(s, p, id, cols, rows) wherever it
  // would have done body.appendChild(table(cols, rows)). On a normal (full) paint
  // it builds the keyed table, remembers it on the panel under `id`, and appends
  // its node. On a reconcile pass (s._ktReconcile set) it instead updates the
  // already-mounted table in place and appends nothing - so the body is never
  // cleared and the viewport cannot move. `rows` are { key, cells } objects.
  //
  // Panels that have not been converted keep using table(); they simply do a
  // full repaint as before. This lets the conversion happen panel by panel.
  function mountKeyedTable(s, p, id, cols, rows, opts) {
    p._kt = p._kt || {};
    if (s._ktSeen) s._ktSeen.add(id);   // record tables produced this pass
    const mounted = p._kt[id] && p._body && p._body.contains(p._kt[id].node);
    if (s._ktReconcile) {
      // A table that appeared, or whose column count changed, is a structural
      // change - signal a full repaint rather than an in-place patch.
      if (!mounted || (p._kt[id].cols || 0) !== cols.length) s._ktStructural = true;
      if (mounted && (p._kt[id].cols || 0) === cols.length) {
        p._kt[id].reconcile(rows);
        return p._kt[id].node;
      }
    }
    const kt = keyedTable(s, cols, rows, opts);
    kt.cols = cols.length;
    p._kt[id] = kt;
    return kt.node;   // caller appends it (full-paint path)
  }

  // Place a keyed table into `container`, correctly across BOTH full paint and
  // in-place reconcile. This exists because `body.appendChild(mountKeyedTable(...))`
  // is only safe for a panel with ONE table: on a reconcile, mountKeyedTable
  // reconciles the existing node in place and returns it, and re-appending that
  // already-attached node MOVES it to the end of the container - so a panel with
  // several interleaved tables piles them all at the bottom, detached from their
  // section titles (the routing-panel "tables jump to the bottom" bug). mountInto
  // appends only when the node is not already in the container, leaving an
  // in-place-reconciled node exactly where it sits. Every panel that mounts more
  // than one keyed table MUST use this instead of a bare appendChild.
  function mountInto(container, s, p, id, cols, rows, opts) {
    const node = mountKeyedTable(s, p, id, cols, rows, opts);
    if (node && container && node.parentNode !== container) container.appendChild(node);
    return node;
  }

  // Turn plain cell-arrays into keyed rows for mountKeyedTable. keyFn(row,i)->key.
  function keyedRowsFrom(cellArrays, dataRows, keyFn) {
    return cellArrays.map((cells, i) => ({ key: String(keyFn(dataRows[i], i)), cells: cells }));
  }

  // A one-shot keyed table for panels that manage their OWN container and
  // rebuild it wholesale on their own refresh (SNMP config, ACL) - they don't
  // participate in the panel reconcile system, so they just need the standard
  // table markup. Rows are plain cell-arrays (cells may be values or DOM nodes,
  // the legacy snmpTable style). onRowClick(i, tr) is supported for edit rows.
  // Returns the node; keeps _tbody/_colspan/_rowByKey for editor anchoring.
  function plainTable(s, cols, rows, onRowClick) {
    const krows = rows.map((cells, i) => ({ key: 'r' + i, cells: cells }));
    const kt = keyedTable(s, cols, krows, onRowClick ? { onRowClick: (key, tr) => onRowClick(parseInt(String(key).slice(1), 10), tr) } : undefined);
    return kt.node;
  }
