  // =================================================================
  // 14-acl.js: IP access lists (the QoS ACL tables) and their interface/VLAN
  // bindings.
  // =================================================================

  // ACL is a keyed panel (standard B1b), built like VLANs and IPv4 Addressing.
  // Its three tables (aclNames/aclAces/aclTuples) are raw-mode health tables,
  // loaded on demand once per visit (B4) and refreshed through refreshTables
  // (B5). The panel joins them client-side: ACL header -> ACEs -> tuple values.
  const ACL_TABLES = ['aclNames', 'aclAces', 'aclTuples'];
  function aclRefresh(s) {
    if (!s.target) return Promise.resolve();
    s._aclFetchedAt = Date.now();
    return refreshTables(s, ACL_TABLES);
  }
  function ensureAclLoaded(s) {
    if (s._aclFetching || !s.target) return;
    if (Date.now() - (s._aclFetchedAt || 0) < 30000) return;
    s._aclFetching = true;
    aclRefresh(s).then(() => { s._aclFetching = false; }, () => { s._aclFetching = false; });
  }
  // The ACL tables have been read at least once (an empty list is still an
  // answer). Until then the panel says "Waiting for data", not "no lists".
  function aclLoaded(s) { return !!(s.health && Array.isArray(s.health.aclNames)); }

  // --- QoS ACL tables (where this switch actually stores ACLs) ---
  const QOS_ACL = {
    // ACL table (88.7), indexed by aclIndex.
    name:   '1.3.6.1.4.1.9.6.1.101.88.7.1.2',   // rlQosAclName
    type:   '1.3.6.1.4.1.9.6.1.101.88.7.1.3',   // rlQosAclType (AclObjectType: mac1 ip2 ipv6 3)
    aclStatus:'1.3.6.1.4.1.9.6.1.101.88.7.1.4', // rlQosAclStatus (RowStatus)
    numAces:'1.3.6.1.4.1.9.6.1.101.88.7.1.5',
    bound:  '1.3.6.1.4.1.9.6.1.101.88.7.1.6',  // rlQosAclIsBoundToInterface (TruthValue)
    origin: '1.3.6.1.4.1.9.6.1.101.88.7.1.8',  // rlQosAclOriginType (static 1 / dynamic 2 / system 3)
    // ACE table (88.31), indexed by aclIndex.aceIndex.
    aceTidx:'1.3.6.1.4.1.9.6.1.101.88.31',
    aceAction:'1.3.6.1.4.1.9.6.1.101.88.31.1.3',  // rlQosAceTidxAction
    aceType:'1.3.6.1.4.1.9.6.1.101.88.31.1.4',    // rlQosAceTidxType
    aceTupleBase: '1.3.6.1.4.1.9.6.1.101.88.31.1.', // +col, see ACE_TUPLE_COLS
    aceStatus:'1.3.6.1.4.1.9.6.1.101.88.31.1.14', // rlQosAceTidxStatus (RowStatus)
    // Tuple table (88.5), indexed by tupleIndex.
    tuple:  '1.3.6.1.4.1.9.6.1.101.88.5',
    tupType:'1.3.6.1.4.1.9.6.1.101.88.5.1.2',   // rlQosTupleType (ClassTupleType)
    tupVal1:'1.3.6.1.4.1.9.6.1.101.88.5.1.3',   // rlQosTupleValue1 (INTEGER)
    tupVal2:'1.3.6.1.4.1.9.6.1.101.88.5.1.4',   // rlQosTupleValue2 (OctetString value||mask)
    tupStatus:'1.3.6.1.4.1.9.6.1.101.88.5.1.5'  // rlQosTupleStatus (RowStatus)
  };
  // The column of each ACE Tuple pointer, from CISCOSB-qosclimib: Tuple1..8 are
  // columns 5..12 and Tuple9..11 are 17..19 (13 is Accounting, 14 the RowStatus,
  // 15 the time range, so the pointers are not one contiguous run).
  const ACE_TUPLE_COLS = [5, 6, 7, 8, 9, 10, 11, 12, 17, 18, 19];
  // Reverse maps for building writes.
  const TUPLE_TYPE_VAL = { protocol: 1, 'ip-src': 2, 'ip-dest': 3, 'tcp-src': 8, 'tcp-dst': 9, 'udp-src': 6, 'udp-dst': 7, 'tcp-flags': 18 };
  const ACE_TYPE_VAL = { ip: 1, 'ip-tcp': 2, 'ip-udp': 3 };
  // ACE action enum (rlQosAceTidxAction / AceActionType), verified from the MIB.
  const ACE_ACTION = { 1: 'permit', 2: 'deny', 3: 'deny-shutdown', 4: 'deny-log', 5: 'permit-log' };
  // ACE type enum (AceObjectType).
  const ACE_TYPE = { 1: 'ip', 2: 'ip-tcp', 3: 'ip-udp', 4: 'ip-offset', 5: 'mac', 6: 'mac-offset', 7: 'ip-icmp', 8: 'ip-igmp', 9: 'ipv6' };
  // ClassTupleType -> field name.
  const TUPLE_TYPE = { 1: 'protocol', 2: 'ip-src', 3: 'ip-dest', 4: 'dscp', 5: 'ip-prec',
    6: 'udp-src', 7: 'udp-dst', 8: 'tcp-src', 9: 'tcp-dst', 10: 'mac-src', 11: 'mac-dest',
    12: 'vlan', 13: 'in-port', 14: 'out-port', 17: 'ethertype', 18: 'tcp-flags',
    19: 'icmp-type', 20: 'icmp-code', 23: 'ipv6-src', 24: 'ipv6-dest' };

  // Build a lookup of tuple index -> { type, value1Hex, value2Hex }.
  function buildTupleMap(tupleRows) {
    const m = new Map();
    for (const r of tupleRows) {
      const ix = String(r.index);
      if (!m.has(ix)) m.set(ix, {});
      const t = m.get(ix);
      const col = r.column || '';
      if (/TupleType$/.test(col)) t.type = parseInt(aclNum(r), 10);
      else if (/TupleValue1$/.test(col)) t.v1 = aclHex(r);
      else if (/TupleValue2$/.test(col)) t.v2 = aclHex(r);
    }
    return m;
  }
  // Numeric value from a cell (strip "(n)" display formatting).
  function aclNum(cell) { const s = String(dvc(cell)); const m = s.match(/\((\d+)\)/) || s.match(/^(\d+)/); return m ? m[1] : s; }
  // Raw hex bytes from a cell's value/display.
  function aclHex(cell) {
    const s = String(cell && (cell.display !== undefined ? cell.display : cell.value) || '');
    const hex = s.replace(/0x|\s|\(hex\)|:/gi, '');
    return /^[0-9a-f]*$/i.test(hex) ? hex.toLowerCase() : '';
  }
  // Decode a tuple (type + value2 which holds value||mask) to a human string.
  function decodeTuple(t) {
    if (!t || t.type === undefined) return null;
    const field = TUPLE_TYPE[t.type] || ('type' + t.type);
    const hex = t.v2 || t.v1 || '';
    // ip-src/ip-dest: 8 bytes = 4 value + 4 wildcard-mask.
    if ((t.type === 2 || t.type === 3) && hex.length >= 8) {
      const ip = [0, 2, 4, 6].map((i) => parseInt(hex.substr(i, 2), 16)).join('.');
      let pref = 32;
      if (hex.length >= 16) {
        const wild = parseInt(hex.substr(8, 8), 16) >>> 0;
        const net = (~wild) >>> 0;
        pref = (net.toString(2).match(/1/g) || []).length;
      }
      return { field: t.type === 2 ? 'src' : 'dst', text: ip + '/' + pref };
    }
    // protocol: 1 byte value + 1 byte mask.
    if (t.type === 1 && hex.length >= 2) {
      const p = parseInt(hex.substr(0, 2), 16);
      const names = { 1: 'icmp', 6: 'tcp', 17: 'udp' };
      return { field: 'proto', text: names[p] || ('proto ' + p) };
    }
    // L4 ports.
    if ((t.type >= 6 && t.type <= 9) && hex.length >= 2) {
      const port = parseInt(hex.substr(0, 4) || hex.substr(0, 2), 16);
      return { field: field, text: field + ' ' + port };
    }
    // tcp-flags: byte1 = value (1=Set, 0=Unset), byte2 = don't-care mask
    // (1=don't care, 0=care). Verified against the switch UI: pnp "11 00" =
    // ACK+FIN Set, the rest Unset, all cared about. Show only the flags we care
    // about, with a + for Set and - for Unset.
    if (t.type === 18 && hex.length >= 2) {
      const val = parseInt(hex.substr(0, 2), 16);
      const dc = hex.length >= 4 ? parseInt(hex.substr(2, 2), 16) : 0;
      const parts = [];
      for (const [name, bit] of TCP_FLAGS) { if (!(dc & bit)) parts.push((val & bit ? '+' : '-') + name); }
      return { field: 'flags', text: parts.length ? ('flags ' + parts.join(' ')) : 'flags any' };
    }
    // Fallback: show the field name and raw hex.
    return { field: field, text: field + '=' + hex };
  }
  // TCP flag bit layout and helpers.
  const TCP_FLAGS = [['urg', 0x20], ['ack', 0x10], ['psh', 0x08], ['rst', 0x04], ['syn', 0x02], ['fin', 0x01]];

  // "192.168.1.0/24" -> { any:false, ip:'192.168.1.0', pref:24 } for pre-filling.
  function parseCidr(text) {
    const m = String(text).match(/^(\d+\.\d+\.\d+\.\d+)\/(\d+)$/);
    if (!m) return { any: true };
    return { any: false, ip: m[1], pref: parseInt(m[2], 10) };
  }
  // A tcp-flags tuple -> { <flag>: 'set'|'unset'|'care' } per-flag state, from
  // byte1 (value) and byte2 (don't-care mask).
  function parseFlagsTuple(t) {
    const hex = (t && (t.v2 || t.v1)) || '';
    if (hex.length < 2) return null;
    const val = parseInt(hex.substr(0, 2), 16);
    const dc = hex.length >= 4 ? parseInt(hex.substr(2, 2), 16) : 0;
    const out = {};
    for (const [name, bit] of TCP_FLAGS) {
      out[name] = (dc & bit) ? 'care' : (val & bit ? 'set' : 'unset');
    }
    return out;   // e.g. { ack:'set', fin:'set', urg:'unset', ... }
  }

  // ---- The joined model ----
  // Join the three raw tables into ACLs -> rules, the one place the panel, the
  // write paths and the binding editor read them from. Only ACLs with a name
  // row are listed (as before); an ACE whose ACL is unknown is ignored.
  function aclModel(h) {
    h = h || {};
    const byIdx = new Map();
    for (const r of (h.aclNames || [])) {
      if (!/QosAclName$/.test(r.column || '')) continue;
      const idx = String(r.index);
      byIdx.set(idx, { idx, name: String(dvc(r)), type: null, aces: new Map() });
    }
    for (const r of (h.aclNames || [])) {
      const acl = byIdx.get(String(r.index));
      if (acl && /QosAclType$/.test(r.column || '')) acl.type = parseInt(aclNum(r), 10);
    }
    for (const r of (h.aclAces || [])) {
      const parts = String(r.index).split('.');
      if (parts.length < 2) continue;
      const acl = byIdx.get(parts[0]);
      if (!acl) continue;
      const aceIdx = parts.slice(1).join('.');
      if (!acl.aces.has(aceIdx)) acl.aces.set(aceIdx, { idx: aceIdx, tuples: [] });
      const ace = acl.aces.get(aceIdx);
      const col = r.column || '';
      if (/TidxAction$/.test(col)) ace.action = parseInt(aclNum(r), 10);
      else if (/TidxType$/.test(col)) ace.type = parseInt(aclNum(r), 10);
      else if (/TidxTuple\d+$/.test(col)) { const ptr = parseInt(dvc(r), 10); if (ptr > 0) ace.tuples.push(String(ptr)); }
    }
    const acls = Array.from(byIdx.values());
    for (const a of acls) a.aceList = Array.from(a.aces.values()).sort((x, y) => parseInt(x.idx, 10) - parseInt(y.idx, 10));
    return { acls, byIdx, tupleMap: buildTupleMap(h.aclTuples || []) };
  }

  // One rule as the table shows it, plus the values that pre-fill its editor.
  function aclRuleView(ace, tupleMap) {
    const action = ACE_ACTION[ace.action] || (ace.action ? ('action ' + ace.action) : '?');
    let proto = ACE_TYPE[ace.type] || 'ip', src = 'any', dst = 'any';
    const extra = [];
    const init = { action: ace.action, proto: 'ip', src: { any: true }, dst: { any: true } };
    if (ace.type === 2) init.proto = 'tcp'; else if (ace.type === 3) init.proto = 'udp';
    for (const tp of ace.tuples) {
      const t = tupleMap.get(tp);
      const dec = decodeTuple(t);
      if (!dec) continue;
      if (dec.field === 'src') { src = dec.text; init.src = parseCidr(dec.text); }
      else if (dec.field === 'dst') { dst = dec.text; init.dst = parseCidr(dec.text); }
      else if (dec.field === 'proto') proto = dec.text;
      else if (dec.field === 'flags') { extra.push(dec.text); init.flags = parseFlagsTuple(t); }
      else extra.push(dec.text);
    }
    return { action, isPermit: /permit/.test(action), proto, src, dst, extra, init };
  }

  // The panel (standard B2): scaffolding on a full paint only, keyed tables
  // through mountInto on every pass, and each ACL's rule count kept in a stable
  // note refreshed in place so it stays right after a write.
  function paintAclPanel(s, body, p) {
    if (!s._ktReconcile) clear(body);
    if (!s.target) { if (!s._ktReconcile) body.appendChild(el('div', 'card-sub', 'Add SNMP credentials for this switch first.')); return; }
    if (!s._ktReconcile) ensureAclLoaded(s);
    if (!aclLoaded(s)) {
      if (!s._ktReconcile) { body.appendChild(el('div', 'card-sub', 'Waiting for data\u2026')); p._aclWaiting = true; }
      return;
    }
    // The first load arrived while "Waiting for data" was showing: that is a
    // structural change (no tables existed yet), so ask for a full repaint.
    if (s._ktReconcile && p._aclWaiting) { s._ktStructural = true; return; }
    p._aclWaiting = false;

    const section = (title, note, addLabel, onAdd) => {
      if (s._ktReconcile) return null;
      const st = el('div', 'section-title', title);
      const noteEl = el('span', 'st-note', note || '');
      st.appendChild(noteEl);
      body.appendChild(st);
      if (addLabel && s.target) body.appendChild(addControl(addLabel, onAdd));
      return noteEl;
    };
    const emptyNote = (msg) => { if (!s._ktReconcile) body.appendChild(el('div', 'card-sub', msg)); };

    const model = aclModel(s.health);
    section('Access lists', model.acls.length ? model.acls.length + ' list(s)' : '', 'New ACL', () => openAclRuleForm(s, { newAcl: true }));
    if (!model.acls.length) { emptyNote('No access lists configured.'); return; }

    if (!s._ktReconcile) p._aclNotes = {};
    const cols = ['#', 'Action', 'Protocol', 'Source', 'Destination', 'Extra', ''];
    for (const acl of model.acls) {
      const noteEl = section('ACL \u00b7 ' + acl.name, '', 'Add rule', () => openAclRuleForm(s, { aclIdx: acl.idx, aclName: acl.name }));
      if (noteEl) p._aclNotes[acl.idx] = noteEl;
      const note = p._aclNotes && p._aclNotes[acl.idx];
      if (note) note.textContent = acl.aceList.length + ' rule(s)';
      if (!acl.aceList.length) { emptyNote('No rules.'); continue; }
      const rows = acl.aceList.map((ace) => {
        const v = aclRuleView(ace, model.tupleMap);
        const del = actGroup([actBtnConfirm('Delete', (e) => {
          runButtonAction(e.currentTarget, {
            failLabel: 'Delete rule',
            run: () => deleteQosAce(s, acl.idx, ace.idx),
            ok: (r) => r && r.ok,
            error: (r) => (r && r.error) || 'the switch rejected it',
            onApplied: () => markConfigDirty(s),
            settle: () => aclRefresh(s)
          });
        }, 'danger', 'Delete rule ' + ace.idx)]);
        return { key: 'ace:' + acl.idx + '.' + ace.idx, cells: [
          { v: ace.idx, click: { open: () => openAclRuleEditor(s, acl.idx, ace.idx) } },
          { cellNode: el('span', 'pill ' + (v.isPermit ? 'good' : 'warn'), v.action), sig: 'a:' + v.action },
          { v: v.proto }, { v: v.src }, { v: v.dst }, { v: v.extra.join(', ') || '\u2014' },
          { cellNode: del, sig: 'del' } ] };
      });
      mountInto(body, s, p, 'acl:' + acl.idx, cols, rows);
    }
  }

  // ---- Interface / VLAN ACL binding (rlQosIfPolicyTable, base 88.13) ----
  // Indexed by { ifIndex, ifType } where ifType is port(2) or vlan(1).
  const QOS_IFPOL = {
    aclIn:   '1.3.6.1.4.1.9.6.1.101.88.13.1.14',   // rlQosIfAclIn  (ACL index, 0=none)
    aclOut:  '1.3.6.1.4.1.9.6.1.101.88.13.1.15',   // rlQosIfAclOut
    defIn:   '1.3.6.1.4.1.9.6.1.101.88.13.1.12',   // rlQosAclDefaultAction (ingress)
    defOut:  '1.3.6.1.4.1.9.6.1.101.88.13.1.22'    // rlQosAclDefaultActionOut
  };
  const IFTYPE_PORT = 2, IFTYPE_VLAN = 1;

  // Read the current binding for an interface (ifIndex + ifType). Returns
  // { inAcl, outAcl, defIn, defOut } as numbers (ACL index / action enum).
  async function readIfAclBinding(s, ifIndex, ifType) {
    const suffix = ifIndex + '.' + ifType;
    const oids = [QOS_IFPOL.aclIn + '.' + suffix, QOS_IFPOL.aclOut + '.' + suffix, QOS_IFPOL.defIn + '.' + suffix, QOS_IFPOL.defOut + '.' + suffix];
    const results = await snmpGet(s, oids);
    const byOid = {};
    for (const r of results) { if (!r.error) byOid[String(r.oid).replace(/^\./, '')] = r.value; }
    const pick = (base) => { const k = Object.keys(byOid).find((o) => o.indexOf(base) !== -1); return k ? parseInt(byOid[k], 10) : null; };
    return { inAcl: pick(QOS_IFPOL.aclIn), outAcl: pick(QOS_IFPOL.aclOut), defIn: pick(QOS_IFPOL.defIn), defOut: pick(QOS_IFPOL.defOut) };
  }

  // Build the ACL-binding editor for an interface. ifType port(2) or vlan(1).
  // For VLANs, pass opts.noDirection to show a single (default-action-only) set.
  // The list of ACLs comes from the panel's own tables (loaded first if the
  // panel has not been opened this visit), not a separate walk.
  async function buildIfAclBinding(s, detail, pane, opts) {
    opts = opts || {};
    const ifType = opts.ifType || IFTYPE_PORT;
    const ifIndex = detail.ifIndex;
    pane.appendChild(el('div', 'card-sub', 'Loading ACL binding\u2026'));
    try {
      if (!aclLoaded(s)) await aclRefresh(s);
      const bind = await readIfAclBinding(s, ifIndex, ifType);
      clear(pane);
      renderIfAclBinding(s, pane, ifIndex, ifType, aclModel(s.health).acls, bind, opts);
    } catch (e) { clear(pane); pane.appendChild(el('div', 'sw-err', 'Could not read ACL binding: ' + e.message)); }
  }

  function renderIfAclBinding(s, pane, ifIndex, ifType, acls, bind, opts) {
    // The in/out columns hold an IPv4 ACL (IPv6 ACLs have their own columns),
    // so offer the IP lists, plus whatever is bound now if it is something else.
    const aclOptions = [{ label: '(none)', value: '0' }];
    for (const a of acls) {
      const current = String(a.idx) === String(bind.inAcl) || String(a.idx) === String(bind.outAcl);
      if (a.type === 2 || a.type == null || current) aclOptions.push({ label: a.name, value: String(a.idx) });
    }
    const defOptions = [{ label: 'Deny Any', value: '1' }, { label: 'Permit Any (forward)', value: '2' }];

    const form = el('div', 'snmp-form acl-form');
    const mkDir = (titleWord, aclOid, defOid, curAcl, curDef) => {
      const sec = formSection(titleWord);
      const aclSel = selectInput(aclOptions, curAcl != null ? String(curAcl) : '0');
      sec.body.appendChild(field(opts.noDirection ? 'IPv4-based ACL' : (titleWord + ' ACL'), aclSel));
      const defSel = selectInput(defOptions, curDef === 2 ? '2' : '1');
      sec.body.appendChild(field('Default action', defSel));
      form.appendChild(sec.sec);
      return { aclSel, defSel, aclOid, defOid };
    };

    const controls = [];
    if (opts.noDirection) {
      // VLAN: a single binding (no in/out direction), default action only.
      controls.push(mkDir('Access list', QOS_IFPOL.aclIn, QOS_IFPOL.defIn, bind.inAcl, bind.defIn));
    } else {
      controls.push(mkDir('Input', QOS_IFPOL.aclIn, QOS_IFPOL.defIn, bind.inAcl, bind.defIn));
      controls.push(mkDir('Output', QOS_IFPOL.aclOut, QOS_IFPOL.defOut, bind.outAcl, bind.defOut));
    }

    // Binding an ACL can stop traffic on the interface, so this keeps its
    // two-tap confirm (standard B8: confirm when the click is drastic).
    const { actions, apply, msg } = applyActions('Apply binding');
    withConfirm(apply, (ev) => {
      const suffix = ifIndex + '.' + ifType;
      const vbs = [];
      const changedCtls = [];
      for (const c of controls) {
        vbs.push({ oid: c.aclOid + '.' + suffix, type: 'Integer', value: parseInt(c.aclSel.value, 10) });
        vbs.push({ oid: c.defOid + '.' + suffix, type: 'Integer', value: parseInt(c.defSel.value, 10) });
        changedCtls.push(c.aclSel, c.defSel);
      }
      clear(msg);
      runButtonAction(ev.currentTarget, {
        failLabel: 'Apply binding',
        run: () => snmpSet(s, vbs).then(() => ({ ok: true }), (e) => ({ ok: false, error: e.message })),
        ok: (r) => r && r.ok,
        error: (r) => { msg.appendChild(el('div', 'sw-err', 'Could not apply binding \u2014 ' + ((r && r.error) || 'failed'))); return (r && r.error) || 'failed'; },
        onApplied: () => markConfigDirty(s, changedCtls),
        // Read the binding back and re-read the ACL tables, so the form shows
        // what the switch now holds before the spinner turns to Done.
        settle: () => Promise.all([
          readIfAclBinding(s, ifIndex, ifType).then((b) => {
            const vals = opts.noDirection ? [[b.inAcl, b.defIn]] : [[b.inAcl, b.defIn], [b.outAcl, b.defOut]];
            vals.forEach(([a, d], i) => { if (controls[i]) { controls[i].aclSel.value = String(a || 0); controls[i].defSel.value = d === 2 ? '2' : '1'; } });
          }).catch(() => {}),
          aclRefresh(s)
        ])
      });
    });
    form.appendChild(actions); form.appendChild(msg);
    pane.appendChild(form);
  }

  // ---- ACL writes (QoS tuple model) ----
  // An ACE is a row in rlQosAceTidxTable that points (via Tuple columns) at
  // value rows in rlQosTupleTable, all under an ACL in rlQosAclTable. So
  // creating a rule is:
  //   1. ensure the ACL exists (create it if the name is new),
  //   2. create one tuple row per match field (type + value||mask + createAndGo),
  //   3. create the ACE row (action, type, the tuple pointers, createAndGo).
  // Every step is a single atomic SET and its result is checked, so a rejection
  // is attributed to the exact step. Indices are chosen as max-existing + 1
  // because this firmware exposes no free-index scalar for these tables.

  // Highest index currently in a walked set of rows (by their first index arc).
  function maxIndex(rows) {
    let m = 0;
    for (const r of rows || []) {
      const first = parseInt(String(r.index).split('.')[0], 10);
      if (Number.isFinite(first) && first > m) m = first;
    }
    return m;
  }

  // Delete one ACE with the shared rowStatusDelete (destroy, falling back to
  // notInService -> destroy). Returns { ok, error } for runButtonAction.
  async function deleteQosAce(s, aclIdx, aceIdx) {
    try { return interpretSet(await rowStatusDelete(s, QOS_ACL.aceStatus + '.' + aclIdx + '.' + aceIdx)); }
    catch (e) { return { ok: false, error: e.message }; }
  }

  // Build the value||mask octet string for an ip-src/ip-dest tuple from a
  // dotted IP and prefix length: 4 value bytes + 4 wildcard-mask bytes.
  function ipTupleHex(ip, pref) {
    const v = ipv4ToHex(ip);
    if (!v) return null;
    const p = Math.max(0, Math.min(32, parseInt(pref, 10) || 32));
    const netMask = p === 0 ? 0 : (0xffffffff << (32 - p)) >>> 0;
    const wild = (~netMask) >>> 0;
    const wildHex = wild.toString(16).padStart(8, '0');
    return v + wildHex;
  }
  // protocol tuple value||mask: 1 value byte + 1 exact mask (ff).
  function protoTupleHex(proto) { return proto.toString(16).padStart(2, '0') + 'ff'; }

  // Create a rule. cfg: { aclName, aclType(2 ip), action, aceType, srcAny, srcIp,
  // srcPref, dstAny, dstIp, dstPref, proto, tcpFlags }. Throws with the failing
  // step on error.
  async function createQosAce(s, cfg) {
    const h = s.health || {};
    // 1. Resolve or create the ACL by name.
    let aclIdx = null;
    for (const a of aclModel(h).acls) { if (a.name === cfg.aclName) aclIdx = a.idx; }
    if (aclIdx === null) {
      aclIdx = String(maxIndex(h.aclNames) + 1);
      try {
        await snmpSet(s, [
          { oid: QOS_ACL.aclStatus + '.' + aclIdx, type: 'Integer', value: 4 },         // createAndGo
          { oid: QOS_ACL.name + '.' + aclIdx, type: 'OctetString', value: cfg.aclName },
          { oid: QOS_ACL.type + '.' + aclIdx, type: 'Integer', value: cfg.aclType || 2 } // ip
        ]);
      } catch (e) { throw new Error('creating ACL "' + cfg.aclName + '": ' + e.message); }
    }

    // 2. Create the tuple rows for each requested match field.
    let nextTuple = maxIndex(h.aclTuples) + 1;
    const pointers = [];   // tuple indices this ACE will reference
    const addTuple = async (typeVal, valueHex) => {
      const tIdx = String(nextTuple++);
      try {
        await snmpSet(s, [
          { oid: QOS_ACL.tupStatus + '.' + tIdx, type: 'Integer', value: 4 },     // createAndGo
          { oid: QOS_ACL.tupType + '.' + tIdx, type: 'Integer', value: typeVal },
          { oid: QOS_ACL.tupVal2 + '.' + tIdx, type: 'OctetString', valueHex }
        ]);
      } catch (e) { throw new Error('creating tuple (type ' + typeVal + '): ' + e.message); }
      pointers.push(tIdx);
    };
    if (cfg.proto) await addTuple(TUPLE_TYPE_VAL.protocol, protoTupleHex(cfg.proto));
    if (!cfg.srcAny) { const hx = ipTupleHex(cfg.srcIp, cfg.srcPref); if (!hx) throw new Error('bad source address'); await addTuple(TUPLE_TYPE_VAL['ip-src'], hx); }
    if (!cfg.dstAny) { const hx = ipTupleHex(cfg.dstIp, cfg.dstPref); if (!hx) throw new Error('bad destination address'); await addTuple(TUPLE_TYPE_VAL['ip-dest'], hx); }
    // TCP flags tuple: byte1 = value (Set bits), byte2 = don't-care mask.
    // e.g. ACK+FIN Set, rest Unset-and-cared -> "11 00" (matches the switch).
    if (cfg.tcpFlags) {
      const fh = cfg.tcpFlags.val.toString(16).padStart(2, '0') + cfg.tcpFlags.dc.toString(16).padStart(2, '0');
      await addTuple(TUPLE_TYPE_VAL['tcp-flags'], fh);
    }

    // 3. Create the ACE under the ACL, pointing at the tuples.
    let maxAce = 0;
    for (const r of (h.aclAces || [])) { const parts = String(r.index).split('.'); if (parts[0] === aclIdx) { const a = parseInt(parts[1], 10); if (a > maxAce) maxAce = a; } }
    const aceIdx = String(maxAce + 1);
    const suffix = aclIdx + '.' + aceIdx;
    const vbs = [
      { oid: QOS_ACL.aceStatus + '.' + suffix, type: 'Integer', value: 4 },  // createAndGo
      { oid: QOS_ACL.aceAction + '.' + suffix, type: 'Integer', value: cfg.action },
      { oid: QOS_ACL.aceType + '.' + suffix, type: 'Integer', value: cfg.aceType }
    ];
    pointers.forEach((tIdx, i) => {
      if (i < ACE_TUPLE_COLS.length) vbs.push({ oid: QOS_ACL.aceTupleBase + ACE_TUPLE_COLS[i] + '.' + suffix, type: 'Integer', value: parseInt(tIdx, 10) });
    });
    try { await snmpSet(s, vbs); } catch (e) { throw new Error('creating ACE: ' + e.message); }
  }

  // Edit an ACE. The tuple model has no clean in-place "change the match fields"
  // operation (the ACE points at tuple rows; changing the match means different
  // tuples), so editing is: remove the old ACE, re-read the tables through the
  // panel's refresh, then create the replacement under the same ACL.
  async function editQosAce(s, aclIdx, aceIdx, cfg) {
    const del = await deleteQosAce(s, aclIdx, aceIdx);
    if (!del.ok) throw new Error('removing the old rule: ' + del.error);
    await aclRefresh(s);   // so createQosAce picks free indices after the delete
    await createQosAce(s, cfg);
  }
  // An address group: "Any" toggle + IP + prefix, wired so the inputs enable
  // only when "Any" is off. init: { any, ip, pref }.
  function addressGroup(labelWord, init) {
    init = init || {};
    const wrap = el('div', 'acl-addr');
    const anyLab = el('label', 'acl-any');
    const any = el('input'); any.type = 'checkbox'; any.checked = init.any !== false;
    anyLab.appendChild(any); anyLab.appendChild(el('span', '', 'Any ' + labelWord));
    wrap.appendChild(anyLab);
    const detail = el('div', 'acl-addr-detail');
    const ip = el('input'); ip.type = 'text'; ip.placeholder = '192.168.1.0'; ip.className = 'acl-ip-in';
    if (init.ip) ip.value = init.ip;
    const pref = el('input'); pref.type = 'number'; pref.min = '0'; pref.max = '32'; pref.value = init.pref != null ? String(init.pref) : '24'; pref.className = 'acl-pref-in';
    const slash = el('span', 'acl-slash', '/');
    detail.appendChild(ip); detail.appendChild(slash); detail.appendChild(pref);
    wrap.appendChild(detail);
    const sync = () => { const off = any.checked; ip.disabled = off; pref.disabled = off; detail.classList.toggle('is-off', off); };
    any.addEventListener('change', sync); sync();
    return { wrap, any, ip, pref };
  }

  // The create/edit-rule form (QoS tuple model). opts:
  //   { fixedAcl: name }          -> add a rule to that existing ACL
  //   { newAcl: true }            -> create a new ACL by name
  //   { edit: {aclIdx, aceIdx, aclName, init} } -> edit an existing ACE

  // Open the rule form in the standard popout (Esc or x closes it). opts:
  //   { newAcl: true }              -> create a new ACL by name with its first rule
  //   { aclIdx, aclName }           -> add a rule to that existing ACL
  //   { edit: {aclIdx, aceIdx, aclName, init} } -> edit an existing rule
  function openAclRuleForm(s, opts) {
    const title = opts.edit ? ('ACL \u00b7 ' + opts.edit.aclName + ' \u00b7 rule ' + opts.edit.aceIdx)
      : (opts.newAcl ? 'New access list' : ('Add rule to ' + opts.aclName));
    const tab = opts.edit ? 'Rule' : (opts.newAcl ? 'New ACL' : 'Add rule');
    openTabbedPopout(s, title, [{ label: tab, fill: (pane, close) => aclRuleForm(s, pane, close, opts) }], []);
  }
  // A table row opens its rule, looked up from the current tables so the form
  // is always pre-filled with what the switch holds now.
  function openAclRuleEditor(s, aclIdx, aceIdx) {
    const model = aclModel(s.health);
    const acl = model.byIdx.get(String(aclIdx));
    const ace = acl && acl.aces.get(String(aceIdx));
    if (!acl || !ace) return;
    openAclRuleForm(s, { edit: { aclIdx: acl.idx, aceIdx: ace.idx, aclName: acl.name, init: aclRuleView(ace, model.tupleMap).init } });
  }

  function aclRuleForm(s, pane, close, opts) {
    const editing = !!opts.edit;
    const init = (opts.edit && opts.edit.init) || {};
    const aclName = opts.aclName || (opts.edit && opts.edit.aclName) || '';
    const form = el('div', 'snmp-form acl-form');

    // --- Section: the list (only when naming a new one) + the basics ---
    const basics = formSection(opts.newAcl ? 'List & rule' : 'Rule');
    let nameIn = null;
    if (opts.newAcl) {
      nameIn = el('input'); nameIn.type = 'text'; nameIn.maxLength = 32; nameIn.placeholder = 'list name';
      basics.body.appendChild(field('ACL name', nameIn));
    }
    const actionSel = selectInput([
      { label: 'permit', value: '1' }, { label: 'deny', value: '2' },
      { label: 'deny + log', value: '4' }, { label: 'permit + log', value: '5' }
    ], init.action ? String(init.action) : '1');
    basics.body.appendChild(field('Action', actionSel));
    const protoSel = selectInput([
      { label: 'any IP', value: 'ip' }, { label: 'TCP', value: 'tcp' }, { label: 'UDP', value: 'udp' }
    ], init.proto || 'ip');
    basics.body.appendChild(field('Protocol', protoSel));
    form.appendChild(basics.sec);

    // --- Section: match (source, then destination stacked below it so each
    //     address line - IP / prefix - has the full width and is never cut) ---
    const match = formSection('Match');
    match.body.classList.add('acl-stack');
    const src = addressGroup('source', init.src || { any: true });
    const dst = addressGroup('destination', init.dst || { any: true });
    match.body.appendChild(field('Source', src.wrap));
    match.body.appendChild(field('Destination', dst.wrap));
    form.appendChild(match.sec);

    // --- Section: TCP flags (only for TCP). Each flag is tri-state: Set (must
    //     be 1), Unset (must be 0), or Don't care (ignored) - matching the
    //     switch's value + don't-care-mask encoding. ---
    const flagsSec = formSection('TCP flags');
    const flagRow = el('div', 'acl-flags-row');
    const flagCtl = {};
    const initFlags = (init.flags && typeof init.flags === 'object') ? init.flags : {};
    for (const [name] of TCP_FLAGS) {
      const cell = el('div', 'acl-flag-cell');
      cell.appendChild(el('div', 'acl-flag-name', name.toUpperCase()));
      const state = initFlags[name] || 'care';   // default don't care
      const radios = {};
      for (const opt of [['set', 'Set'], ['unset', 'Unset'], ['care', "Don't care"]]) {
        const rl = el('label', 'acl-flag-opt');
        const r = el('input'); r.type = 'radio'; r.name = 'flag-' + name + '-' + (editing ? 'e' : 'n'); r.value = opt[0];
        if (state === opt[0]) r.checked = true;
        rl.appendChild(r); rl.appendChild(el('span', '', opt[1]));
        cell.appendChild(rl);
        radios[opt[0]] = r;
      }
      flagRow.appendChild(cell);
      flagCtl[name] = radios;
    }
    flagsSec.body.appendChild(flagRow);
    form.appendChild(flagsSec.sec);
    const syncFlagsVisible = () => { flagsSec.sec.style.display = (protoSel.value === 'tcp') ? '' : 'none'; };
    protoSel.addEventListener('change', syncFlagsVisible);
    syncFlagsVisible();

    // Adding is one tap; saving an edit replaces the rule, so it asks for a
    // second tap (standard B8: confirm only when the click is drastic).
    const { actions, apply, msg } = applyActions(editing ? 'Save rule' : (opts.newAcl ? 'Create ACL' : 'Add rule'));
    withConfirm(apply, (ev) => {
      const name = aclName || (nameIn ? (nameIn.value || '').trim() : '');
      clear(msg);
      if (!name) { msg.appendChild(el('div', 'sw-err', 'Enter an ACL name.')); return; }
      if (opts.newAcl && aclModel(s.health).acls.some((a) => a.name === name)) { msg.appendChild(el('div', 'sw-err', 'An ACL named \u201c' + name + '\u201d already exists. Use its Add rule instead.')); return; }
      if (!src.any.checked && !ipv4ToHex(src.ip.value)) { msg.appendChild(el('div', 'sw-err', 'Enter a valid source IPv4 address.')); return; }
      if (!dst.any.checked && !ipv4ToHex(dst.ip.value)) { msg.appendChild(el('div', 'sw-err', 'Enter a valid destination IPv4 address.')); return; }
      const protoName = protoSel.value;
      const proto = protoName === 'tcp' ? 6 : (protoName === 'udp' ? 17 : 0);
      const aceType = protoName === 'tcp' ? ACE_TYPE_VAL['ip-tcp'] : (protoName === 'udp' ? ACE_TYPE_VAL['ip-udp'] : ACE_TYPE_VAL.ip);
      let tcpFlags = null;
      if (protoName === 'tcp') {
        let val = 0, dc = 0;
        for (const [nm, bit] of TCP_FLAGS) {
          const st = flagCtl[nm].set.checked ? 'set' : (flagCtl[nm].unset.checked ? 'unset' : 'care');
          if (st === 'care') dc |= bit; else if (st === 'set') val |= bit;
        }
        // Only emit a flags tuple if at least one flag is actually constrained.
        if (dc !== 0x3f) tcpFlags = { val, dc };
      }
      const cfg = {
        aclName: name, aclType: 2, action: parseInt(actionSel.value, 10), aceType, proto: proto || 0,
        srcAny: src.any.checked, srcIp: src.ip.value, srcPref: parseInt(src.pref.value, 10),
        dstAny: dst.any.checked, dstIp: dst.ip.value, dstPref: parseInt(dst.pref.value, 10),
        tcpFlags
      };
      runButtonAction(ev.currentTarget, {
        failLabel: editing ? 'Save rule' : 'Add rule',
        spinLabel: editing ? 'Saving\u2026' : (opts.newAcl ? 'Creating\u2026' : 'Adding\u2026'),
        run: async () => {
          try {
            if (editing) await editQosAce(s, opts.edit.aclIdx, opts.edit.aceIdx, cfg);
            else await createQosAce(s, cfg);
            return { ok: true };
          } catch (e) { return { ok: false, error: e.message }; }
        },
        ok: (r) => r && r.ok,
        error: (r) => { msg.appendChild(el('div', 'sw-err', (editing ? 'Could not save rule \u2014 ' : 'Could not add rule \u2014 ') + ((r && r.error) || 'failed'))); return (r && r.error) || 'failed'; },
        onApplied: () => markConfigDirty(s),
        settle: () => aclRefresh(s).then(() => close())
      });
    }, { when: () => editing });
    form.appendChild(actions); form.appendChild(msg);
    pane.appendChild(form);
  }
