  // =================================================================
  // 23-mib-explorer.js: The MIB Explorer.
  // =================================================================

  // =================================================================
  // MIB Explorer
  // =================================================================
  // Finding the right object in 11k of them is the hard part of using SNMP
  // on this platform, so search covers descriptions as well as names, the
  // results say what shape each object is, and common tasks are one click.
  // Anything found can be dropped straight onto the active switch's
  // dashboard, which is the reason you were looking it up.

  const mibPanel = document.getElementById('mib-panel');
  const mibQ = document.getElementById('mib-q');
  const mibAccess = document.getElementById('mib-access');
  const mibShape = document.getElementById('mib-shape');
  const mibTree = document.getElementById('mib-tree');
  const mibResults = document.getElementById('mib-results');
  const mibDetail = document.getElementById('mib-detail');
  const mibNote = document.querySelector('.mib-note');
  const mibProduct = document.getElementById('mib-product');
  const VENDOR_ROOT = '1.3.6.1.4.1.9.6.1.101';
  let mibSelected = null;

  document.getElementById('mib-toggle').addEventListener('click', () => {
    // The MIB explorer covers whatever tab is showing, the topology
    // included; leaving both open would stack two full-screen panels.
    leaveTopology();
    openMib();
  });
  document.getElementById('mib-close').addEventListener('click', () => mibPanel.classList.remove('open'));
  let mibDeb = null;
  mibQ.addEventListener('input', () => {
    clearTimeout(mibDeb);
    mibDeb = setTimeout(runMibSearch, 160);
  });
  for (const sel of [mibAccess, mibShape, mibTree]) sel.addEventListener('change', runMibSearch);
  // Switching product reloads that product's MIB set and re-runs the search.
  if (mibProduct) {
    mibProduct.addEventListener('change', () => {
      loadMib(mibProduct.value).then(() => { updateMibNote(); runMibSearch(); });
    });
  }

  function updateMibNote() {
    const prod = productByLine(MIB.product);
    const label = prod ? prod.label : 'Catalyst 1200/1300';
    mibNote.textContent = MIB.loaded
      ? MIB.entries.length.toLocaleString() + ' objects from the ' + label + ' MIB set'
      : 'MIB database unavailable';
  }

  function openMib() {
    mibPanel.classList.add('open');
    loadProducts().then(() => {
      // Populate the product picker once, from the registry.
      if (mibProduct && !mibProduct.options.length) {
        for (const p of PRODUCTS.products) {
          const o = document.createElement('option');
          o.value = p.line; o.textContent = p.label;
          mibProduct.appendChild(o);
        }
      }
      // Default to the product of the switch whose tab is showing (override-aware).
      const active = activeId && switches.get(activeId);
      const line = (active && effectiveProductLine(active)) || PRODUCTS.default;
      if (mibProduct) mibProduct.value = line;
      return loadMib(line);
    }).then(() => { updateMibNote(); runMibSearch(); });
  }

  /** scalar | column | table, decided from the MIB tree rather than the name. */
  function mibShapeOf(e) {
    if (/Table$/.test(e.name)) return 'table';
    if (/Entry$/.test(e.name)) return 'table';
    return isColumnar(e) ? 'column' : 'scalar';
  }

  function runMibSearch() {
    if (!MIB.loaded) return;
    const q = mibQ.value.trim().toLowerCase();
    const terms = q.split(/\s+/).filter(Boolean);
    const acc = mibAccess.value, shape = mibShape.value, tree = mibTree.value;

    const scored = [];
    for (const e of MIB.entries) {
      if (tree === 'vendor' && e.oid.indexOf(VENDOR_ROOT) !== 0) continue;
      if (tree === 'standard' && e.oid.indexOf('1.3.6.1.2.1') !== 0) continue;
      if (acc === 'readable' && !(e.access === 'r' || e.access === 'rw' || e.access === 'rc')) continue;
      if (acc === 'writable' && !(e.access === 'rw' || e.access === 'rc' || e.access === 'w')) continue;
      const sh = mibShapeOf(e);
      if (shape && sh !== shape) continue;

      let score = 0;
      if (!terms.length) score = 1;
      for (const t of terms) {
        const n = e.name.toLowerCase();
        // Name matches outrank description matches: searching "fan" should
        // put rlEnvMonFanState above every object that merely mentions fans.
        if (n === t) score += 100;
        else if (n.indexOf(t) === 0) score += 50;
        else if (n.indexOf(t) >= 0) score += 25;
        else if (e.oid.indexOf(t) === 0) score += 20;
        else if ((e.description || '').toLowerCase().indexOf(t) >= 0) score += 6;
        else if ((e.mib || '').toLowerCase().indexOf(t) >= 0) score += 3;
        else { score = 0; break; }          // every term must match somewhere
      }
      if (score <= 0) continue;
      // Prefer things you can actually read.
      if (e.access === 'r' || e.access === 'rw') score += 4;
      scored.push({ e, score, shape: sh });
    }

    scored.sort((a, b) => b.score - a.score || a.e.name.localeCompare(b.e.name));
    const top = scored.slice(0, 300);

    clear(mibResults);
    mibNote.textContent = scored.length.toLocaleString() + ' of ' +
      MIB.entries.length.toLocaleString() + ' objects match' +
      (scored.length > top.length ? ' (showing first ' + top.length + ')' : '');

    if (!top.length) {
      mibResults.appendChild(el('div', 'empty-state',
        'Nothing matches. Try a single keyword \u2014 search covers names, OIDs and descriptions.'));
      return;
    }

    for (const r of top) {
      const row = el('div', 'mib-row');
      const nm = el('div', 'r-name');
      const first = terms[0];
      const at = first ? r.e.name.toLowerCase().indexOf(first) : -1;
      if (at >= 0) {
        nm.appendChild(document.createTextNode(r.e.name.slice(0, at)));
        nm.appendChild(el('span', 'hl', r.e.name.slice(at, at + first.length)));
        nm.appendChild(document.createTextNode(r.e.name.slice(at + first.length)));
      } else nm.textContent = r.e.name;
      row.appendChild(nm);

      const meta = el('div', 'r-meta');
      meta.appendChild(el('span', 'r-oid', r.e.oid));
      meta.appendChild(el('span', 'r-tag', r.shape));
      if (r.e.access) meta.appendChild(el('span', 'r-tag', ACCESS_LABEL[r.e.access] || r.e.access));
      if (r.e.syntax) meta.appendChild(el('span', '', r.e.syntax));
      row.appendChild(meta);
      if (r.e.description) row.appendChild(el('div', 'r-desc', r.e.description));

      row.addEventListener('click', () => {
        mibSelected = r.e;
        Array.from(mibResults.children).forEach((c) => c.classList.remove('active'));
        row.classList.add('active');
        showMibDetail(r.e);
      });
      mibResults.appendChild(row);
    }
    if (!mibSelected || !top.some((r) => r.e === mibSelected)) {
      mibResults.firstChild.click();
    }
  }

  const ACCESS_LABEL = {
    r: 'read-only', rw: 'read-write', rc: 'read-create',
    n: 'not-accessible', w: 'write-only', afn: 'notify'
  };

  function showMibDetail(e) {
    clear(mibDetail);
    mibDetail.appendChild(el('h3', '', e.name));
    mibDetail.appendChild(el('div', 'd-oid', e.oid));

    const shape = mibShapeOf(e);
    const kv = (k, v) => {
      if (!v) return;
      const row = el('div', 'kv-row');
      row.appendChild(el('div', 'k', k));
      row.appendChild(el('div', 'v', v));
      mibDetail.appendChild(row);
    };
    kv('Shape', shape);
    kv('Access', ACCESS_LABEL[e.access] || e.access || 'unknown');
    kv('Syntax', e.syntax);
    kv('Units', e.units);
    kv('Defined in', e.mib);
    if (e.description) mibDetail.appendChild(el('div', 'd-desc', e.description));

    if (e.enum) {
      mibDetail.appendChild(el('div', 'section-title', 'Values'));
      const list = el('div', 'enum-list');
      for (const k of Object.keys(e.enum)) list.appendChild(el('span', '', e.enum[k] + ' (' + k + ')'));
      mibDetail.appendChild(list);
    }

    // What to do with it, on the switch you are actually looking at.
    const active = activeId && switches.get(activeId);
    const acts = el('div', 'mib-actions');
    const op = shape === 'scalar' ? 'get' : 'walk';
    const oid = shape === 'scalar' ? e.name + '.0' : e.name;

    const add = el('button', 'btn', 'Add as panel' + (active && active.host ? ' to ' + active.host : ''));
    add.type = 'button';
    add.disabled = !(active && active.target);
    add.title = add.disabled ? 'Set a switch target on the Health tab first' : '';
    add.addEventListener('click', () => {
      const panel = {
        id: 'o:' + Date.now() + ':' + Math.random().toString(36).slice(2, 7),
        kind: 'oid', oid, op, title: e.name,
        span: op === 'walk' ? 6 : 4, h: op === 'walk' ? 300 : 0
      };
      active.panels.push(panel);
      active.renderedIds = null;
      saveLayout(active);
      renderSwitch(active);
      loadPanelData(active, panel);
      mibPanel.classList.remove('open');
      showView(active, 'health');
      appLog('info', 'Panel added from MIB Explorer', { host: active.host, oid, op });
    });
    acts.appendChild(add);

    const copy = el('button', 'btn btn-amber', 'Copy OID');
    copy.type = 'button';
    copy.addEventListener('click', () => {
      const text = e.oid;
      if (navigator.clipboard) navigator.clipboard.writeText(text).catch(() => {});
      copy.textContent = 'Copied';
      setTimeout(() => { copy.textContent = 'Copy OID'; }, 1200);
    });
    acts.appendChild(copy);
    mibDetail.appendChild(acts);
    if (add.disabled) {
      mibDetail.appendChild(el('div', 'card-sub',
        'Set a switch target on the Health tab to add this as a panel.'));
    }

    // Walking the tree is often how you find the object you actually
    // wanted: siblings of a column are the rest of that table.
    const parentOid = e.oid.split('.').slice(0, -1).join('.');
    const parentName = MIB.byOid.get(parentOid);
    const children = MIB.entries
      .filter((x) => x.oid.indexOf(e.oid + '.') === 0 &&
        x.oid.split('.').length === e.oid.split('.').length + 1)
      .slice(0, 60);
    const siblings = MIB.entries
      .filter((x) => x !== e && x.oid.indexOf(parentOid + '.') === 0 &&
        x.oid.split('.').length === e.oid.split('.').length)
      .slice(0, 60);

    const treeRow = (label, entry) => {
      const r = el('div', 'mib-tree-row', label);
      r.appendChild(el('span', 't-oid', entry.oid));
      r.addEventListener('click', () => { mibSelected = entry; showMibDetail(entry); });
      return r;
    };
    if (parentName) {
      mibDetail.appendChild(el('div', 'section-title', 'Parent'));
      const pe = MIB.entries.find((x) => x.oid === parentOid);
      if (pe) mibDetail.appendChild(treeRow(parentName, pe));
    }
    if (children.length) {
      mibDetail.appendChild(el('div', 'section-title', 'Children (' + children.length + ')'));
      for (const c of children) mibDetail.appendChild(treeRow(c.name, c));
    }
    if (siblings.length) {
      mibDetail.appendChild(el('div', 'section-title', 'Siblings (' + siblings.length + ')'));
      for (const c of siblings) mibDetail.appendChild(treeRow(c.name, c));
    }
  }
