  // =================================================================
  // 14-acl.js: IP access lists and QoS ACEs, and their interface/VLAN bindings.
  // =================================================================

  // Packet capture (OPC) panel. The C1300's onboard capture records
  // control-plane traffic only. A single named capture point: configure buffer
  // and filter, start/stop, and export (to flash, then copied to this app over
  // TFTP for download). All actions are writes guarded by writeBusy.
  // Flash files module: list the switch flash, download a file over TFTP, or
  // ===================================================================
  // IP access-list module (standard IP ACLs: rlIpStdAclTable).
  // ===================================================================
  // A rule (ACE) is indexed by { aclName, aceIndex }. The SNMP index arrives as
  // dotted sub-identifiers: <nameLen>.<name bytes...>.<aceIndex>. Decode it.
  const ACL_OIDS = {
    srcClass: '1.3.6.1.4.1.9.6.1.101.207.1.1.3',
    srcType:  '1.3.6.1.4.1.9.6.1.101.207.1.1.4',
    srcAddr:  '1.3.6.1.4.1.9.6.1.101.207.1.1.5',
    srcPref:  '1.3.6.1.4.1.9.6.1.101.207.1.1.6',
    dstClass: '1.3.6.1.4.1.9.6.1.101.207.1.1.7',
    dstType:  '1.3.6.1.4.1.9.6.1.101.207.1.1.8',
    dstAddr:  '1.3.6.1.4.1.9.6.1.101.207.1.1.9',
    dstPref:  '1.3.6.1.4.1.9.6.1.101.207.1.1.10',
    action:   '1.3.6.1.4.1.9.6.1.101.207.1.1.11',
    rowStatus:'1.3.6.1.4.1.9.6.1.101.207.1.1.12',
    freeAce:  '1.3.6.1.4.1.9.6.1.101.207.2.0'
  };
  const ACL_CLASS = { 1: 'any', 2: 'ipv4', 3: 'ipv6any', 4: 'ipv6' };
  const ACL_ACTION = { 1: 'drop', 2: 'permit' };

  // Turn an ACL table row index ("<len>.<bytes>.<ace>") into { name, ace }.
  function parseAclIndex(idx) {
    const parts = String(idx).split('.').map((n) => parseInt(n, 10));
    if (!parts.length) return null;
    const len = parts[0];
    if (!Number.isFinite(len) || parts.length < len + 2) return null;
    const name = parts.slice(1, 1 + len).map((c) => String.fromCharCode(c)).join('');
    const ace = parts[1 + len];
    return { name, ace };
  }
  // Build the index suffix for a given ACL name + ACE index.
  function aclIndexSuffix(name, ace) {
    const bytes = String(name).split('').map((ch) => ch.charCodeAt(0));
    return [bytes.length].concat(bytes).concat([ace]).join('.');
  }

  // ACL is a keyed panel (standard B1b): its three tables (aclNames/aclAces/
  // aclTuples) are raw-mode health tables, loaded on demand and refreshed on the
  // health cycle. The panel reads them via s._acl.{acls,aces,tuples} pointers set
  // from s.health, so the existing client-side join (renderAclPanel) is unchanged.
  const ACL_TABLES = ['aclNames', 'aclAces', 'aclTuples'];
  function aclSyncFromHealth(s) {
    s._acl = s._acl || {};
    s._acl.acls = (s.health && s.health.aclNames) || [];
    s._acl.aces = (s.health && s.health.aclAces) || [];
    s._acl.tuples = (s.health && s.health.aclTuples) || [];
  }
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
  function paintAclPanel(s, body) {
    if (!s._ktReconcile) clear(body);
    if (!s.target) { if (!s._ktReconcile) body.appendChild(el('div', 'card-sub', 'Add SNMP credentials for this switch first.')); return; }
    s._acl = s._acl || {};
    if (!s._ktReconcile) {
      const root = el('div', 'acl-cfg');
      body.appendChild(root);
      s._acl.root = root;
      ensureAclLoaded(s);
    }
    aclSyncFromHealth(s);
    if (s._acl.root) renderAclPanel(s);
  }

  // --- QoS ACL tables (where this switch actually stores ACLs) ---
  const QOS_ACL = {
    // ACL table (88.7), indexed by aclIndex.
    name:   '1.3.6.1.4.1.9.6.1.101.88.7.1.2',   // rlQosAclName
    type:   '1.3.6.1.4.1.9.6.1.101.88.7.1.3',   // rlQosAclType (AclObjectType: mac1 ip2 ipv6 3)
    aclStatus:'1.3.6.1.4.1.9.6.1.101.88.7.1.4', // rlQosAclStatus (RowStatus)
    numAces:'1.3.6.1.4.1.9.6.1.101.88.7.1.5',
    // ACE table (88.31), indexed by aclIndex.aceIndex.
    aceTidx:'1.3.6.1.4.1.9.6.1.101.88.31',
    aceAction:'1.3.6.1.4.1.9.6.1.101.88.31.1.3',  // rlQosAceTidxAction
    aceType:'1.3.6.1.4.1.9.6.1.101.88.31.1.4',    // rlQosAceTidxType
    aceTupleBase: '1.3.6.1.4.1.9.6.1.101.88.31.1.', // +col (5..15) for Tuple1..11
    aceStatus:'1.3.6.1.4.1.9.6.1.101.88.31.1.14', // rlQosAceTidxStatus (RowStatus)
    // Tuple table (88.5), indexed by tupleIndex.
    tuple:  '1.3.6.1.4.1.9.6.1.101.88.5',
    tupType:'1.3.6.1.4.1.9.6.1.101.88.5.1.2',   // rlQosTupleType (ClassTupleType)
    tupVal1:'1.3.6.1.4.1.9.6.1.101.88.5.1.3',   // rlQosTupleValue1 (INTEGER)
    tupVal2:'1.3.6.1.4.1.9.6.1.101.88.5.1.4',   // rlQosTupleValue2 (OctetString value||mask)
    tupStatus:'1.3.6.1.4.1.9.6.1.101.88.5.1.5'  // rlQosTupleStatus (RowStatus)
  };
  // The Tuple column index for each ACE Tuple pointer (Tuple1..11 -> cols 5..15).
  const ACE_TUPLE_COLS = [5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
  // Reverse maps for building writes.
  const TUPLE_TYPE_VAL = { protocol: 1, 'ip-src': 2, 'ip-dest': 3, 'tcp-src': 8, 'tcp-dst': 9, 'udp-src': 6, 'udp-dst': 7, 'tcp-flags': 18 };
  const ACE_ACTION_VAL = { permit: 1, deny: 2, 'deny-shutdown': 3, 'deny-log': 4, 'permit-log': 5 };
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
  function tcpFlagNames(flags, mask) {
    const out = [];
    for (const [name, bit] of TCP_FLAGS) { if ((mask & bit) && (flags & bit)) out.push(name); }
    return out;
  }
  // A routable unicast IPv4: first octet 1-223, not loopback/link-local. Rules
  // out the 0.x / uninitialised placeholders a DHCP interface shows before it
  // has a lease. Shared by the VLAN table and the IPv4 editor.
  function isRealIp(ip) {
    const o = String(ip).split('.').map(Number);
    return o.length === 4 && o.every((n) => n >= 0 && n <= 255) && o[0] >= 1 && o[0] <= 223 && o[0] !== 127 && !(o[0] === 169 && o[1] === 254);
  }

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

  function renderAclPanel(s) {
    const root = s._acl.root;
    // ACL is a keyed panel: scroll is preserved by repaintPanel's scrollKeeper
    // around the reconcile paint (standard A7), so this just clears and rebuilds.
    clear(root);
    // ACL names: index -> name.
    const nameByIdx = new Map();
    const typeByIdx = new Map();
    for (const r of (s._acl.acls || [])) {
      const col = r.column || '';
      if (/QosAclName$/.test(col)) nameByIdx.set(String(r.index), String(dvc(r)));
      else if (/QosAclType$/.test(col)) typeByIdx.set(String(r.index), aclNum(r));
    }
    // Tuple values.
    const tupleMap = buildTupleMap(s._acl.tuples || []);
    // ACEs grouped by ACL index. Each ACE index is "<aclIdx>.<aceIdx>".
    const aceByAcl = new Map();   // aclIdx -> Map(aceIdx -> {action, type, tuples:[]})
    for (const r of (s._acl.aces || [])) {
      const parts = String(r.index).split('.');
      if (parts.length < 2) continue;
      const aclIdx = parts[0], aceIdx = parts.slice(1).join('.');
      if (!aceByAcl.has(aclIdx)) aceByAcl.set(aclIdx, new Map());
      const bucket = aceByAcl.get(aclIdx);
      if (!bucket.has(aceIdx)) bucket.set(aceIdx, { tuples: [] });
      const ace = bucket.get(aceIdx);
      const col = r.column || '';
      if (/TidxAction$/.test(col)) ace.action = parseInt(aclNum(r), 10);
      else if (/TidxType$/.test(col)) ace.type = parseInt(aclNum(r), 10);
      else if (/TidxTuple\d+$/.test(col)) { const p = parseInt(dvc(r), 10); if (p > 0) ace.tuples.push(String(p)); }
    }


    if (!nameByIdx.size) {
      root.appendChild(el('div', 'card-sub', 'No access lists found.'));
    }

    for (const [aclIdx, name] of nameByIdx) {
      const aces = aceByAcl.get(aclIdx) || new Map();
      const aceList = Array.from(aces.entries()).sort((a, b) => parseInt(a[0], 10) - parseInt(b[0], 10));
      section2(root, 'ACL \u00b7 ' + name, aceList.length + ' rule(s)');
      const cols = ['#', 'Action', 'Protocol', 'Source', 'Destination', 'Extra', ''];
      const rowClicks = [];
      const trows = aceList.map(([aceIdx, ace]) => {
        const action = ACE_ACTION[ace.action] || (ace.action ? ('action ' + ace.action) : '?');
        const isPermit = /permit/.test(action);
        const actionPill = el('span', 'pill ' + (isPermit ? 'good' : 'warn'), action);
        // Resolve the ACE's tuples - both for display and to pre-fill an edit.
        let proto = ACE_TYPE[ace.type] || 'ip', src = 'any', dst = 'any', extra = [];
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
        const openEdit = () => openEditPopout(s, 'Edit rule', (pane) => qosAceAddForm(s, pane, null, { edit: { aclIdx, aceIdx, aclName: name, init } }));
        rowClicks.push(openEdit);
        const editBtn = actBtn('Edit', openEdit);
        const delBtn = actBtnConfirm('Delete', () => deleteQosAce(s, aclIdx, aceIdx), 'danger', 'Delete this rule');
        const delCell = actGroup([editBtn, delBtn]);
        return [String(aceIdx), actionPill, proto, src, dst, extra.join(', ') || '\u2014', delCell];
      });
      // Clicking a row (anywhere but the action buttons) opens its edit pane.
      root.appendChild(plainTable(s, cols, trows, (rowIdx) => { const h = rowClicks[rowIdx]; if (h) h(); }));
      // Per-ACL add control: the ACL is known, so no list picker is needed.
      root.appendChild(addControl('Add rule to ' + name, () => openEditPopout(s, 'Add rule to ' + name, (pane, close) => qosAceAddForm(s, pane, close, { fixedAcl: name }))));
    }

    // Top-level control: create a brand-new ACL (and its first rule).
    const newRow = el('div', 'acl-new-row');
    newRow.appendChild(addControl('New ACL', () => openEditPopout(s, 'New access list', (pane, close) => qosAceAddForm(s, pane, close, { newAcl: true }))));
    root.appendChild(newRow);
  }

  // ---- Interface / VLAN ACL binding (rlQosIfPolicyTable, base 88.13) ----
  // Indexed by { ifIndex, ifType } where ifType is port(2) or vlan(1).
  const QOS_IFPOL = {
    aclIn:   '1.3.6.1.4.1.9.6.1.101.88.13.1.14',   // rlQosIfAclIn  (ACL index, 0=none)
    aclOut:  '1.3.6.1.4.1.9.6.1.101.88.13.1.15',   // rlQosIfAclOut
    defIn:   '1.3.6.1.4.1.9.6.1.101.88.13.1.12',   // rlQosAclDefaultAction (ingress)
    defOut:  '1.3.6.1.4.1.9.6.1.101.88.13.1.22'    // rlQosAclDefaultActionOut
  };
  const ACL_DEFACTION = { 1: 'deny-all', 2: 'forward-all', 3: 'application-specific' };
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
  async function buildIfAclBinding(s, detail, pane, opts) {
    opts = opts || {};
    const ifType = opts.ifType || IFTYPE_PORT;
    const ifIndex = detail.ifIndex;
    pane.appendChild(el('div', 'card-sub', 'Loading ACL binding\u2026'));
    // Need the list of ACLs (index -> name) to offer in the picker.
    let acls = [];
    try {
      const [aclRes, bind] = await Promise.all([
        apiPost('/api/snmp/walk', { target: s.target, oid: QOS_ACL.name, mode: 'getbulk' }),
        readIfAclBinding(s, ifIndex, ifType)
      ]);
      acls = (aclRes.body && aclRes.body.results) || [];
      clear(pane);
      renderIfAclBinding(s, pane, ifIndex, ifType, acls, bind, opts);
    } catch (e) { clear(pane); pane.appendChild(el('div', 'sw-err', 'Could not read ACL binding: ' + e.message)); }
  }

  function renderIfAclBinding(s, pane, ifIndex, ifType, aclRows, bind, opts) {
    const aclOptions = [{ label: '(none)', value: '0' }];
    const nameByIdx = {};
    for (const r of aclRows) { if (/QosAclName$/.test(r.column || '')) { const idx = String(r.index); nameByIdx[idx] = String(dvc(r)); aclOptions.push({ label: String(dvc(r)), value: idx }); } }
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

    const { actions, apply } = applyActions('Apply binding');
    const msg = el('div', 'port-detail-msg');
    withConfirm(apply, async () => {
      const suffix = ifIndex + '.' + ifType;
      const vbs = [];
      const changedCtls = [];
      for (const c of controls) {
        vbs.push({ oid: c.aclOid + '.' + suffix, type: 'Integer', value: parseInt(c.aclSel.value, 10) });
        vbs.push({ oid: c.defOid + '.' + suffix, type: 'Integer', value: parseInt(c.defSel.value, 10) });
        changedCtls.push(c.aclSel, c.defSel);
      }
      clear(msg);
      runButtonAction(apply, {
        failLabel: 'Apply binding',
        run: () => snmpSet(s, vbs).then(() => ({ ok: true }), (e) => ({ ok: false, error: e.message })),
        ok: (r) => r && r.ok,
        error: (r) => { msg.appendChild(el('div', 'sw-err', 'Could not apply binding \u2014 ' + ((r && r.error) || 'failed'))); return (r && r.error) || 'failed'; },
        onApplied: () => markConfigDirty(s, changedCtls),
        settle: () => Promise.resolve()
      });
    });
    form.appendChild(actions); form.appendChild(msg);
    pane.appendChild(form);
  }

  // ---- ACL writes (QoS tuple model) ----
  // The write path mirrors what we learned from the live data: an ACE is a row
  // in rlQosAceTidxTable that points (via Tuple columns) at value rows in
  // rlQosTupleTable, all under an ACL in rlQosAclTable. So creating a rule is:
  //   1. ensure the ACL exists (create it if the name is new),
  //   2. create one tuple row per match field (type + value||mask + createAndGo),
  //   3. create the ACE row (action, type, the tuple pointers, createAndGo).
  // Every step is a single atomic SET and its result is checked, so a rejection
  // is attributed to the exact step. Indices are chosen as max-existing + 1
  // because this firmware exposes no free-index scalar for these tables.

  // Highest index currently in a walked set of rows (by their first index arc).
  function maxIndex(rows, firstArcOnly) {
    let m = 0;
    for (const r of rows || []) {
      const first = parseInt(String(r.index).split('.')[0], 10);
      if (Number.isFinite(first) && first > m) m = first;
    }
    return m;
  }

  // Delete one ACE: destroy its rlQosAceTidxTable row via the shared
  // rowStatusDelete (so it gets the notInService->destroy fallback for a row the
  // switch won't destroy directly), consistent with every other RowStatus delete.
  function deleteQosAce(s, aclIdx, aceIdx) {
    const suffix = aclIdx + '.' + aceIdx;
    rowStatusDelete(s, QOS_ACL.aceStatus + '.' + suffix)
      .then((res) => {
        if (!res.ok || (res.body && res.body.error)) { toast('Could not delete rule: ' + ((res.body && res.body.error) || 'the switch rejected it'), 'error'); return; }
        markConfigDirty(s);
        aclRefresh(s);
      }).catch((e) => toast('Could not delete rule: ' + e.message, 'error'));
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

  // Create a rule. cfg: { aclName, aclType(1 ip), action, aceType, srcAny, srcIp,
  // srcPref, dstAny, dstIp, dstPref, proto }. Returns on success, throws with the
  // failing step on error.
  async function createQosAce(s, cfg) {
    // 1. Resolve or create the ACL by name.
    let aclIdx = null;
    for (const r of (s._acl.acls || [])) { if (/QosAclName$/.test(r.column || '') && String(dvc(r)) === cfg.aclName) aclIdx = String(r.index); }
    if (aclIdx === null) {
      aclIdx = String(maxIndex(s._acl.acls || []) + 1);
      try {
        await snmpSet(s, [
          { oid: QOS_ACL.aclStatus + '.' + aclIdx, type: 'Integer', value: 4 },         // createAndGo
          { oid: QOS_ACL.name + '.' + aclIdx, type: 'OctetString', value: cfg.aclName },
          { oid: QOS_ACL.type + '.' + aclIdx, type: 'Integer', value: cfg.aclType || 2 } // ip
        ]);
      } catch (e) { throw new Error('creating ACL "' + cfg.aclName + '": ' + e.message); }
    }

    // 2. Create the tuple rows for each requested match field.
    const tupleRows = s._acl.tuples || [];
    let nextTuple = maxIndex(tupleRows) + 1;
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
    if (!cfg.srcAny) { const h = ipTupleHex(cfg.srcIp, cfg.srcPref); if (!h) throw new Error('bad source address'); await addTuple(TUPLE_TYPE_VAL['ip-src'], h); }
    if (!cfg.dstAny) { const h = ipTupleHex(cfg.dstIp, cfg.dstPref); if (!h) throw new Error('bad destination address'); await addTuple(TUPLE_TYPE_VAL['ip-dest'], h); }
    // TCP flags tuple: byte1 = value (Set bits), byte2 = don't-care mask.
    // e.g. ACK+FIN Set, rest Unset-and-cared -> "11 00" (matches the switch).
    if (cfg.tcpFlags) {
      const fh = cfg.tcpFlags.val.toString(16).padStart(2, '0') + cfg.tcpFlags.dc.toString(16).padStart(2, '0');
      await addTuple(TUPLE_TYPE_VAL['tcp-flags'], fh);
    }

    // 3. Create the ACE under the ACL, pointing at the tuples.
    const aceRows = s._acl.aces || [];
    let maxAce = 0;
    for (const r of aceRows) { const parts = String(r.index).split('.'); if (parts[0] === aclIdx) { const a = parseInt(parts[1], 10); if (a > maxAce) maxAce = a; } }
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
  // tuples), so editing is: destroy the old ACE, then create the replacement
  // under the same ACL. The ACE index may change - fine, ACEs are index-ordered.
  async function editQosAce(s, aclIdx, aceIdx, cfg) {
    try {
      await snmpSet(s, { oid: QOS_ACL.aceStatus + '.' + aclIdx + '.' + aceIdx, type: 'Integer', value: 6 });
    } catch (e) { throw new Error('removing the old rule: ' + e.message); }
    // Re-read so createQosAce picks correct free indices after the delete.
    try {
      const [aces, tuples] = await Promise.all([
        apiPost('/api/snmp/walk', { target: s.target, oid: QOS_ACL.aceTidx, mode: 'getbulk' }),
        apiPost('/api/snmp/walk', { target: s.target, oid: QOS_ACL.tuple, mode: 'getbulk' })
      ]);
      s._acl.aces = (aces.body && aces.body.results) || [];
      s._acl.tuples = (tuples.body && tuples.body.results) || [];
    } catch (e) { /* fall back to existing cached rows */ }
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
  function qosAceAddForm(s, pane, close, opts) {
    opts = opts || {};
    const editing = !!opts.edit;
    const init = (opts.edit && opts.edit.init) || {};
    const aclName = opts.fixedAcl || (opts.edit && opts.edit.aclName) || '';
    const form = el('div', 'snmp-form acl-form');
    const title = editing ? ('Edit rule \u00b7 ' + aclName) : (opts.fixedAcl ? ('Add rule to ' + opts.fixedAcl) : 'New access list');
    form.appendChild(el('h5', '', title));

    // --- Section: the list (only when naming a new one) + the basics ---
    const basics = formSection(editing ? 'Rule' : (opts.fixedAcl ? 'Rule' : 'List & rule'));
    let nameIn = null;
    if (!opts.fixedAcl && !editing) {
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

    const { actions, apply } = applyActions(editing ? 'Save rule' : (opts.fixedAcl ? 'Add rule' : 'Create ACL'));
    const msg = el('div', 'port-detail-msg');
    withConfirm(apply, async () => {
      const name = aclName || (nameIn ? (nameIn.value || '').trim() : '');
      clear(msg);
      if (!name) { msg.appendChild(el('div', 'sw-err', 'Enter an ACL name.')); return; }
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
      clear(msg);
      runButtonAction(apply, {
        failLabel: editing ? 'Save rule' : 'Add rule',
        spinLabel: editing ? 'Saving\u2026' : (opts.fixedAcl ? 'Adding\u2026' : 'Creating\u2026'),
        run: async () => {
          try {
            if (editing) await editQosAce(s, opts.edit.aclIdx, opts.edit.aceIdx, cfg);
            else await createQosAce(s, cfg);
            return { ok: true };
          } catch (e) { return { ok: false, error: e.message }; }
        },
        ok: (r) => r && r.ok,
        error: (r) => { msg.appendChild(el('div', 'sw-err', (editing ? 'Could not save rule \u2014 ' : 'Could not add rule \u2014 ') + ((r && r.error) || 'failed'))); return (r && r.error) || 'failed'; },
        onApplied: () => { const pop = pane.closest && pane.closest('.port-detail-back'); if (pop) pop.remove(); markConfigDirty(s); },
        settle: () => aclRefresh(s)
      });
    });
    form.appendChild(actions); form.appendChild(msg);
    pane.appendChild(form);
  }
