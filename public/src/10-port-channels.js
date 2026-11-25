  // =================================================================
  // 10-port-channels.js: Port lists and LAG/port-channel panels.
  // =================================================================

  // Is a given port's bit set in a PortList hex bitmap? (octet 0 = ports 1-8,
  // MSB = lowest port.)
  function portBitSet(hex, portNum) {
    if (!hex || !Number.isFinite(portNum) || portNum < 1) return false;
    const bit = portNum - 1;
    const byteIdx = Math.floor(bit / 8);
    if (byteIdx * 2 + 2 > hex.length) return false;
    const byte = parseInt(hex.substr(byteIdx * 2, 2), 16);
    return !!((byte >> (7 - (bit % 8))) & 1);
  }
  // Return a new PortList hex bitmap with one port's bit set or cleared,
  // preserving all other bits. Grows the bitmap if needed to reach the port.
  function setPortBit(hex, portNum, on) {
    const bit = portNum - 1;
    const needBytes = Math.floor(bit / 8) + 1;
    const bytes = [];
    for (let i = 0; i < Math.max(needBytes, hex.length / 2); i++) {
      bytes.push(i * 2 + 2 <= hex.length ? parseInt(hex.substr(i * 2, 2), 16) : 0);
    }
    const mask = 0x80 >> (bit % 8);
    if (on) bytes[Math.floor(bit / 8)] |= mask; else bytes[Math.floor(bit / 8)] &= ~mask;
    return bytes.map((b) => (b & 0xff).toString(16).padStart(2, '0')).join('');
  }

  // Decode a PortList bitmap (hex string or bytes) into the list of member port
  // numbers. Octet 0 covers ports 1-8, MSB = the lowest port (same scheme as
  // buildPortListBit / the VLAN bitmaps).
  function decodePortList(raw) {
    if (raw == null) return [];
    let hex = String(raw).replace(/0x/gi, '').replace(/[^0-9a-fA-F]/g, '');
    if (hex.length % 2) hex = '0' + hex;
    const ports = [];
    for (let i = 0; i < hex.length; i += 2) {
      const byte = parseInt(hex.substr(i, 2), 16);
      const base = (i / 2) * 8;
      for (let bit = 0; bit < 8; bit++) {
        if ((byte >> (7 - bit)) & 1) ports.push(base + bit + 1);
      }
    }
    return ports;
  }

  // Port channels (LAGs) section for the Interfaces panel: lists every
  // aggregator the switch supports, its mode (static/LACP), members, key and
  // aggregating state - and lets a channel be created/edited (mode + members)
  // or cleared. Members join by setting their port's actor admin key to the
  // aggregator's key; a static trunk / LACP is set on the creation table.
  // Build an interface-detail object for a port channel so it can open the same
  // tabbed popout a physical port uses. The channel's ifIndex is its aggregator
  // index; switchport mode/VLAN come from the per-port mode and configured-VLAN
  // tables (same source the port table uses), so the Switchport tab is prefilled.
  function buildChannelDetail(s, h, chIfx, chName, extra) {
    const cvn = (c) => { const v = c && (c.value !== undefined ? c.value : c.display); const n = parseInt(v, 10); return Number.isFinite(n) ? n : null; };
    const key = String(chIfx);
    const ifRow = (h.interfaces || []).find((r) => String(r.index) === key) || null;
    const dvc = (c) => (c && (c.display !== undefined && c.display !== null ? c.display : c.value)) || '';
    // Switchport mode (11=access, 12=trunk) and configured VLAN.
    let modeStr = '';
    const mRow = (h.portModes || []).find((r) => String(r.index) === key);
    const mCode = mRow ? cvn(mRow.vlanPortModeState) : null;
    if (mCode === 11) modeStr = 'access'; else if (mCode === 12) modeStr = 'trunk';
    const accRow = (h.portAccessVlan || []).find((r) => String(r.index) === key);
    const natRow = (h.portNativeVlan || []).find((r) => String(r.index) === key);
    const accV = accRow ? cvn(accRow.vlanAccessPortModeVlanId) : null;
    const natV = natRow ? cvn(natRow.vlanTrunkPortModeNativeVlanId) : null;
    const allVlans = (h.vlans || []).map((v) => Number(v.index)).filter(Boolean).sort((a, b) => a - b);
    const sw = {
      mode: modeStr,
      l2l3: '',
      untagged: modeStr === 'access' && accV ? [String(accV)] : (modeStr === 'trunk' && natV ? [String(natV)] : []),
      tagged: [],
      allVlans,
      uplink: null
    };
    const fields = {};
    if (ifRow) {
      fields['Admin status'] = dvc(ifRow.rlifPresentAdminStatus);
      fields['Oper status'] = dvc(ifRow.rlifPresentOperStatus);
      if (extra && extra.mode) fields['LAG mode'] = extra.mode;
      if (extra && extra.memNames) fields['Members'] = extra.memNames;
    }
    return { name: chName, ifIndex: chIfx, fields, sw, dot1x: null };
  }

  function buildPortChannels(s, body, h, section, p) {
    const dv2 = (c) => (c && (c.display !== undefined && c.display !== null && c.display !== '') ? c.display : (c && c.value !== undefined ? c.value : ''));
    const dv = dv2;   // local alias (the interfaces-case dv is out of scope here)
    const truthy = (c) => /true|1|yes|enabled/i.test(String(dv2(c)));

    // Enumerate EVERY port-channel slot, configured or not, by unioning all
    // sources: the interface table (configured channels appear as present
    // interfaces named Po#/ch#/LAG# etc.), the creation table, and the standard
    // dot3ad aggregator table - then synthesising any remaining slots up to the
    // switch's supported count so empty channels still show.
    const CH_NAME = /^(po|ch|port-?channel|lag|trunk)\s*\d+/i;
    const creationByIdx = new Map(); for (const r of (h.lagCreation || [])) creationByIdx.set(String(r.index), r);
    const nameOfIf = new Map();
    for (const r of (h.interfaces || [])) nameOfIf.set(String(r.index), dv(r.rlifPresentName) || '');

    // Collect candidate aggregator ifIndexes from every source.
    const slotIdx = new Map();   // ifIndex -> display name
    for (const r of (h.interfaces || [])) {
      const nm = String(dv(r.rlifPresentName) || '');
      if (CH_NAME.test(nm)) slotIdx.set(String(r.index), nm);
    }
    for (const r of (h.lagCreation || [])) if (!slotIdx.has(String(r.index))) slotIdx.set(String(r.index), nameOfIf.get(String(r.index)) || null);
    for (const r of (h.lagAgg || [])) if (!slotIdx.has(String(r.index))) slotIdx.set(String(r.index), nameOfIf.get(String(r.index)) || null);

    // Synthesise the full slot set. The aggregator ifIndexes form a contiguous
    // block; derive its base/stride from the known slots and extend to the
    // supported count so empty channels appear too.
    const scN = (h.scalars && h.scalars.rlDot3adAggNumOfTrunks);
    const supported = scN ? parseInt(dv2(scN), 10) : 0;
    const known = Array.from(slotIdx.keys()).map(Number).filter(Number.isFinite).sort((a, b) => a - b);
    if (supported > 0 && known.length) {
      // Stride between consecutive aggregator ifIndexes (usually 1); extend from
      // the lowest known slot up to the supported count so empty slots appear.
      const stride = known.length >= 2 ? Math.max(1, known[1] - known[0]) : 1;
      for (let i = 0; i < supported; i++) {
        const idx = String(known[0] + i * stride);
        if (!slotIdx.has(idx)) slotIdx.set(idx, null);
      }
    }
    // The aggregator ifIndexes form a contiguous block. Derive the base (the
    // lowest slot = channel 1) so an unnamed/synthesised slot can be labelled
    // "Po<N>" by its position, rather than "Po/<ifIndex>".
    const aggBase = known.length ? known[0] : null;
    const chLabel = (idx) => {
      const nm = slotIdx.get(String(idx)) || nameOfIf.get(String(idx));
      if (nm) return nm;                                   // the switch's own name
      if (aggBase != null) return 'Po' + (Number(idx) - aggBase + 1);   // derived number
      return 'Po/' + idx;
    };
    // The set of real LAG aggregator ifIndexes (for the "already a member"
    // check): only these count as "another channel".
    const lagSlots = new Set(Array.from(slotIdx.keys()).map(String));

    // Build the channel list, ordered by ifIndex, merging the creation row.
    let lagCreate = Array.from(slotIdx.keys()).map(Number).filter(Number.isFinite).sort((a, b) => a - b)
      .map((idx) => Object.assign(
        { index: idx, _name: chLabel(idx) },
        creationByIdx.get(String(idx)) || {}));
    if (!lagCreate.length) return;   // nothing to show at all

    // Index the supporting tables by aggregator ifIndex.
    const aggByIdx = new Map(); for (const r of (h.lagAgg || [])) aggByIdx.set(String(r.index), r);
    const memByIdx = new Map(); for (const r of (h.lagMembers || [])) memByIdx.set(String(r.index), r);
    // Map agg key -> agg ifIndex, and gather each port's actor key.
    const portKey = new Map();   // portIfIndex -> actor admin key
    const portAttached = new Map(); // portIfIndex -> attached agg id
    const portState = new Map();  // portIfIndex -> actor admin state (hex; a2=LACP, empty=static)
    for (const r of (h.lagPortKey || [])) {
      portKey.set(String(r.index), dv2(r.dot3adAggPortActorAdminKey));
      portAttached.set(String(r.index), dv2(r.dot3adAggPortAttachedAggID));
      portState.set(String(r.index), String(dv2(r.dot3adAggPortActorAdminState) || '').trim());
    }
    // Interface names by ifIndex, for showing member/port names.
    const nameByIdx = new Map();
    for (const r of (h.interfaces || [])) nameByIdx.set(String(r.index), dv(r.rlifPresentName) || String(r.index));

    const sc = (k) => (h.scalars && h.scalars[k]);
    const maxTrunks = sc('rlDot3adAggNumOfTrunks') ? dv2(sc('rlDot3adAggNumOfTrunks')) : lagCreate.length;
    const maxPorts = sc('rlDot3adAggMaxPortsInTrunks') ? dv2(sc('rlDot3adAggMaxPortsInTrunks')) : '';

    section('Port channels', lagCreate.length + ' available' + (maxPorts ? ' \u00b7 up to ' + maxPorts + ' ports each' : ''));

    const editable = (s._snmp && s._snmp.editable) || s._aaaEditable || true;   // writes allowed; switch enforces access
    const OIDS = {
      createTrunk: '1.3.6.1.4.1.9.6.1.101.65.6.1.1',
      createLacp: '1.3.6.1.4.1.9.6.1.101.65.6.1.2',
      aggAdminKey: '1.2.840.10006.300.43.1.1.1.1.6',
      portActorKey: '1.2.840.10006.300.43.1.2.1.1.4',
      portActorState: '1.2.840.10006.300.43.1.2.1.1.20',
      balanceLayer: '1.3.6.1.4.1.9.6.1.101.65.2.1.2'
    };

    const setVb = (varbinds) => snmpSetResult(s, varbinds).then((res) => ({ ok: res.ok, b: res.body }));

    // Build the channel table rows.
    const cols = ['Channel', 'Mode', 'Members', 'Key', 'Aggregating', 'Status'].concat(editable ? [''] : []);
    const rows = lagCreate.map((c) => {
      const aggIdx = String(c.index);
      const agg = aggByIdx.get(aggIdx);
      const mem = memByIdx.get(aggIdx);
      // A port is a CONFIGURED member when its actor admin key equals this
      // aggregator's key (= the aggregator ifIndex). The bitmap
      // (dot3adAggPortListPorts) only lists ACTIVELY aggregated ports, so a
      // configured-but-down member would be missed. Prefer the key match, and
      // fall back to the bitmap if no key matches.
      const keyMembers = [];
      const normKey = (v) => String(v == null ? '' : v).replace(/[,\s]/g, '');
      for (const [pIdx, k] of portKey) { if (normKey(k) === aggIdx && pIdx !== aggIdx) keyMembers.push(Number(pIdx)); }
      const bitMembers = mem ? decodePortList(mem.dot3adAggPortListPorts && (mem.dot3adAggPortListPorts.value !== undefined ? mem.dot3adAggPortListPorts.value : mem.dot3adAggPortListPorts.display)) : [];
      const members = keyMembers.length ? keyMembers.sort((a, b) => a - b) : bitMembers;
      // Mode from the members' actual actor state (the creation-table flags are
      // not writable/reliable): a member running LACP has a non-empty state
      // (e.g. "a2"); a static member's state is empty/zero.
      const memStates = members.map((p) => String(portState.get(String(p)) || '').replace(/0x|\s|\(hex\)|"/gi, ''));
      const anyLacp = memStates.some((st) => st && !/^0*$/.test(st));
      const mode = !members.length ? '\u2014' : (anyLacp ? 'LACP' : 'static');
      const isTrunk = members.length > 0;
      const isLacp = anyLacp;
      const memNames = members.map((p) => nameByIdx.get(String(p)) || ('if' + p)).join(', ') || '\u2014';
      const key = agg ? dv2(agg.dot3adAggActorOperKey) || dv2(agg.dot3adAggActorAdminKey) : '';
      const aggregating = agg ? dv2(agg.dot3adAggAggregateOrIndividual) : '';
      const chName = c._name || nameByIdx.get(aggIdx) || ('Po/' + aggIdx);
      const memberKeyInfo = members.map((p) => (nameByIdx.get(String(p)) || ('if' + p)) + ' key=' + (portKey.get(String(p)) || '?')).join(', ') || '\u2014';
      const detail = () => openDetailDialog(s, 'Port channel ' + chName, [
        ['Channel', chName], ['Aggregator ifIndex', aggIdx], ['Mode', mode],
        ['Members', memNames], ['Member keys', memberKeyInfo],
        ['Actor key (admin)', agg ? dv2(agg.dot3adAggActorAdminKey) : ''],
        ['Actor key (oper)', agg ? dv2(agg.dot3adAggActorOperKey) : ''],
        ['Aggregating', aggregating], ['System ID', agg ? dv2(agg.dot3adAggActorSystemID) : '']
      ]);
      // Row-click opens the full interface detail (a port channel IS an
      // interface - its aggregator ifIndex), with the same tabs a physical port
      // has (Port settings, Switchport, 802.1X, ACL, Counters) PLUS a leading
      // Membership tab (the channel's mode + member ports). Read-only detail is
      // shown when not editable.
      const chIfxNum = parseInt(aggIdx, 10);
      const openIt = () => {
        if (!editable) { detail(); return; }
        if (!Number.isFinite(chIfxNum)) { openEditPopout(s, 'Port channel ' + chName, (pane, close) => editChannel(c, agg, members, pane, close)); return; }
        const chDetail = buildChannelDetail(s, h, chIfxNum, chName, { mode, memNames, memberKeyInfo });
        const membershipTab = { label: 'Membership', fill: (pane, close) => { editChannel(c, agg, members, pane, close); } };
        openPortDetail(s, chDetail, { title: 'Port channel ' + chName, leadingTabs: [membershipTab] });
      };
      const row = [
        { click: { open: openIt }, v: chName },
        { v: mode }, { v: memNames }, { v: key }, { v: aggregating },
        { pill: true, v: (isTrunk || isLacp) ? 'configured' : 'empty' }
      ];
      if (editable) {
        const acts = [];
        // Shut / No-shut: a port channel is an interface (its aggregator
        // ifIndex), so ifAdminStatus applies exactly as it does to a physical
        // port. Read the channel's current admin state to label the action.
        const chIfx = parseInt(aggIdx, 10);
        if (Number.isFinite(chIfx)) {
          const chRow = (s.health && s.health.interfaces || []).find((x) => String(x.index) === String(chIfx));
          const adminUp = chRow ? !/down|disabled/i.test(String(dv(chRow.rlifPresentAdminStatus) || '')) : true;
          acts.push(actBtnConfirm(adminUp ? 'Shut' : 'No shut', (e) => {
            runButtonAction(e.currentTarget, {
              failLabel: adminUp ? 'Shut' : 'No shut',
              run: () => apiPost('/api/port/admin', { target: s.target, ifIndex: chIfx, action: adminUp ? 'down' : 'up' }),
              onApplied: () => markConfigDirty(s),
              settle: () => refreshTables(s, ['interfaces', 'lagAgg', 'lagMembers', 'lagCreation', 'lagPortKey'])
            });
          }, adminUp ? 'danger' : '', (adminUp ? 'Administratively disable ' : 'Re-enable ') + chName));
        }
        acts.push(actBtnConfirm('Clear', (e) => clearChannel(c, members), 'danger', 'Remove all members and unconfigure'));
        // sig captures what the action buttons depend on: the channel's admin
        // state (Shut/No-shut label) and whether it has members (Clear present).
        const chRow2 = (s.health && s.health.interfaces || []).find((x) => String(x.index) === aggIdx);
        const admUp = chRow2 ? !/down|disabled/i.test(String(dv(chRow2.rlifPresentAdminStatus) || '')) : true;
        row.push({ cellNode: actGroup(acts), sig: (admUp ? 'up' : 'down') + '|' + members.length });
      }
      row._key = 'ch:' + aggIdx;
      return row;
    });
    mountInto(body, s, p, 'channels', cols,
      rows.map((cells) => ({ key: cells._key, cells: cells })));
    // Editors render into this host, placed immediately below the channel table.
    // On reconcile the host already exists; reuse it rather than appending a
    // second one (which would strand an open editor).
    let chEditHost = s._ktReconcile ? body.querySelector('.ch-edit-host') : null;
    if (!chEditHost) { chEditHost = el('div', 'ch-edit-host'); if (!s._ktReconcile) body.appendChild(chEditHost); }

    // --- editors ---
    function closeChEditors() { clear(chEditHost); }

    function editChannel(c, agg, currentMembers, pane, popClose) {
      const aggIdx = String(c.index);
      const aggKey = agg ? parseInt(dv2(agg.dot3adAggActorAdminKey), 10) : NaN;
      // Render into the popout pane when given one; else the old inline host.
      const inPopout = !!pane;
      if (!inPopout) closeChEditors();
      const host = pane || el('div', 'ch-editor aaa-form');
      if (!inPopout) host.appendChild(el('h5', '', 'Edit port channel ' + (nameByIdx.get(aggIdx) || aggIdx)));
      const grid = el('div', 'snmp-form-grid');
      // Mode: off / static / LACP.
      const modeSel = el('select');
      for (const m of [['off', 'off'], ['static', 'static'], ['lacp', 'LACP']]) { const o = el('option', '', m[1]); o.value = m[0]; modeSel.appendChild(o); }
      // Current mode from members' actor state (not the unreliable creation flags).
      const curStates = currentMembers.map((p) => String(portState.get(String(p)) || '').replace(/0x|\s|\(hex\)|"/gi, ''));
      modeSel.value = !currentMembers.length ? 'off' : (curStates.some((st) => st && !/^0*$/.test(st)) ? 'lacp' : 'static');
      { const f = el('div', 'snmp-field'); f.appendChild(el('label', '', 'Mode')); f.appendChild(modeSel); grid.appendChild(f); }
      host.appendChild(grid);

      // Members: a checkbox list of physical ports (those not already in a
      // different channel). Current members pre-checked.
      host.appendChild(el('div', 'aaa-sub', 'Member ports'));
      const memWrap = el('div', 'ch-members');
      const cur = new Set(currentMembers.map(String));
      const physPorts = (h.interfaces || []).filter((r) => {
        const nm = String(dv(r.rlifPresentName) || '');
        return /^(gi|te|fa|fo|tw|fi|hu)/i.test(nm) || /ethernet/i.test(nm);   // physical ports only
      });
      const checks = [];
      for (const r of physPorts) {
        const pIdx = String(r.index);
        const lab = el('label', 'ch-member');
        const cb = el('input'); cb.type = 'checkbox'; cb.checked = cur.has(pIdx); cb.dataset.port = pIdx;
        // A port is only unavailable if it is a member of a DIFFERENT real LAG
        // slot. The standard dot3adAggPortAttachedAggID returns a port's own
        // individual aggregator (its own ifIndex) when it is standalone - that
        // is NOT another channel, so only disable when the attached id is one of
        // our LAG aggregator slots and isn't this one.
        const att = String(portAttached.get(pIdx) || '');
        const inOtherLag = att && att !== '0' && att !== aggIdx && lagSlots.has(att);
        if (inOtherLag && !cur.has(pIdx)) { cb.disabled = true; lab.title = 'In another channel'; }
        lab.appendChild(cb); lab.appendChild(el('span', '', dv(r.rlifPresentName) || pIdx));
        memWrap.appendChild(lab); checks.push(cb);
      }
      host.appendChild(memWrap);

      const cancel = el('button', 'btn btn-small', 'Cancel'); cancel.type = 'button';
      cancel.addEventListener('click', () => { if (inPopout && popClose) popClose(); else closeChEditors(); });
      const { actions, apply: save, msg } = applyActions('Save', { extra: [cancel] });
      withConfirm(save, (ev) => {
        clear(msg);
        const mode = modeSel.value;
        // The creation-table flags (rlDot3adAggCreationTrunk/Lacp) are NotWritable
        // on this firmware - they describe capability, not config. Channel
        // membership is driven entirely by the port's actor admin KEY: setting a
        // port's key to the aggregator's key (= its ifIndex here, e.g. 1000 for
        // Po1) joins it; setting the key back to the port's own ifIndex (its
        // individual aggregator) removes it. Static vs LACP is the LACP_Activity
        // bit of the actor admin STATE (bit 0): LACP = active, static = cleared.
        const want = new Set(checks.filter((cb) => cb.checked).map((cb) => cb.dataset.port));
        // CONFIRMED from CLI-configured members in BOTH modes (LAG debug):
        //   - key is always the aggregator ifIndex (1000 for Po1), in both modes.
        //   - LACP ("mode auto"): ActorAdminState = 0xa2 (LACP_Activity +
        //     Aggregation + Defaulted).
        //   - static ("mode on"): ActorAdminState = empty / all-zero (LACP off).
        // So the ONLY mode difference is the state octet; the key is identical.
        const keyVal = parseInt(aggIdx, 10);
        const stateHex = (mode === 'lacp') ? 'a2' : '00';   // confirmed: LACP=a2, static=0
        // The switch will NOT change a member's mode in place (WrongValue). So
        // the mode is changed by BREAKING the port out of the LAG (key->0) and
        // RE-ADDING it with the new state. We therefore split the writes into
        // two sequential phases: remove first, then add. A member whose mode is
        // unchanged is left alone.
        const curMode = (pIdx) => {
          const st = String(portState.get(String(pIdx)) || '').replace(/0x|\s|\(hex\)|"/gi, '');
          return (st && !/^0*$/.test(st)) ? 'lacp' : 'static';
        };
        const removeSteps = [];   // phase 1: key -> 0
        const addSteps = [];      // phase 2: state + key
        const rollbackSteps = [];  // restore phase-1 ports if phase 2 fails
        // The original state hex of a currently-LACP member is 0xa2; a static
        // member's is empty/00. Used to restore a mode-changed member on rollback.
        const origStateHex = (pIdx) => (curMode(pIdx) === 'lacp' ? 'a2' : '00');
        for (const cb of checks) {
          const pIdx = cb.dataset.port;
          const was = cur.has(pIdx);
          const now = want.has(pIdx);
          const modeChanged = was && now && (curMode(pIdx) !== mode);
          if (now && !was) {
            // New member: add with the chosen mode.
            addSteps.push({ oid: OIDS.portActorState + '.' + pIdx, type: 'OctetString', valueHex: stateHex });
            addSteps.push({ oid: OIDS.portActorKey + '.' + pIdx, type: 'Integer', value: keyVal });
          } else if (!now && was) {
            // Removed member: break out (intended removal - not rolled back).
            removeSteps.push({ oid: OIDS.portActorKey + '.' + pIdx, type: 'Integer', value: 0 });
          } else if (modeChanged) {
            // Staying, but mode changed: break out (phase 1) then re-add (phase 2).
            // Capture how to restore it if the re-add fails.
            removeSteps.push({ oid: OIDS.portActorKey + '.' + pIdx, type: 'Integer', value: 0 });
            removeSteps.push({ oid: OIDS.portActorState + '.' + pIdx, type: 'OctetString', valueHex: '00' });
            addSteps.push({ oid: OIDS.portActorState + '.' + pIdx, type: 'OctetString', valueHex: stateHex });
            addSteps.push({ oid: OIDS.portActorKey + '.' + pIdx, type: 'Integer', value: keyVal });
            rollbackSteps.push({ oid: OIDS.portActorState + '.' + pIdx, type: 'OctetString', valueHex: origStateHex(pIdx) });
            rollbackSteps.push({ oid: OIDS.portActorKey + '.' + pIdx, type: 'Integer', value: keyVal });
          }
        }
        if (!removeSteps.length && !addSteps.length) { msg.appendChild(el('div', 'card-sub', 'No changes.')); return; }
        runButtonAction(ev.currentTarget, {
          failLabel: 'Save channel', spinLabel: 'Saving\u2026',
          run: async () => {
            try {
              let failed = null;
              let phase1Done = false;
              if (removeSteps.length) { const r = await setVb(removeSteps); if (!r.ok || r.b.error) failed = r.b.error || 'remove failed'; else phase1Done = true; }
              if (!failed && addSteps.length) {
                await new Promise((res) => setTimeout(res, 400));
                const r2 = await setVb(addSteps); if (!r2.ok || r2.b.error) failed = r2.b.error || 'add failed';
              }
              if (failed && phase1Done && rollbackSteps.length) {
                try {
                  await new Promise((res) => setTimeout(res, 300));
                  const rb = await setVb(rollbackSteps);
                  if (!rb.ok || rb.b.error) toast('Mode change failed AND rollback failed \u2014 check the channel members manually: ' + (rb.b.error || failed), 'error');
                  else toast('Mode change failed; the channel members were restored.', 'error');
                } catch (e) { toast('Mode change failed AND rollback errored \u2014 verify the channel: ' + e.message, 'error'); }
              }
              return failed ? { ok: false, error: failed } : { ok: true };
            } catch (e) { return { ok: false, error: e.message }; }
          },
          ok: (r) => r && r.ok,
          error: (r) => { msg.appendChild(el('div', 'sw-err', 'Change failed: ' + ((r && r.error) || 'failed'))); return (r && r.error) || 'failed'; },
          onApplied: () => { markConfigDirty(s, modeSel); },
          settle: () => {
            const expect = want.size;
            const check = (attempt) => refreshLagTables(s).then((memCount) => {
              if (memCount < expect && attempt < 2) setTimeout(() => check(attempt + 1), 5000);
            });
            setTimeout(() => check(1), 4000);
            return Promise.resolve();
          }
        });
      });
      host.appendChild(actions); host.appendChild(msg);
      if (!inPopout) { chEditHost.appendChild(host); chEditHost.scrollIntoView({ block: 'nearest' }); }
    }

    function clearChannel(c, members) {
      closeChEditors();
      const aggIdx = String(c.index);
      const host = el('div', 'ch-editor aaa-form');
      host.appendChild(el('div', 'sw-warn', 'Remove all members and unconfigure port channel ' + (nameByIdx.get(aggIdx) || aggIdx) + '?'));
      const row = el('div', 'snmp-form-actions');
      const yes = actBtn('Clear', async () => {
        // Remove each member by resetting its actor key to its own ifIndex (its
        // individual aggregator = standalone). The creation-table flags are
        // NotWritable, so membership is managed purely through the port keys.
        const steps = [];
        for (const p of members) steps.push({ oid: OIDS.portActorKey + '.' + p, type: 'Integer', value: 0 });
        if (steps.length) {
          const r = await setVb(steps);
          if (!r.ok || r.b.error) { toast('Could not clear the channel: ' + (r.b.error || 'the switch rejected it'), 'error'); return; }
          markConfigDirty(s);   // members removed -> running differs from startup
        }
        closeChEditors();
        setTimeout(() => refreshLagTables(s), 2000);   // clearing is immediate; one light read
      }, 'danger');
      const no = actBtn('Cancel', closeChEditors);
      row.appendChild(yes); row.appendChild(no); host.appendChild(row);
      chEditHost.appendChild(host); chEditHost.scrollIntoView({ block: 'nearest' });
    }
  }
