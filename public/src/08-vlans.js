  // =================================================================
  // 08-vlans.js: VLANs: create, delete, edit, SVIs and the VLAN panel.
  // =================================================================

  // Create a VLAN via the standard Q-BRIDGE dot1qVlanStaticTable (the same
  // table the app reads). RowStatus createAndGo(4) and the name go in one SET,
  // keyed by the VLAN id. Returns { ok, error }.
  // This switch does not create VLANs through the standard Q-BRIDGE
  // dot1qVlanStaticRowStatus (that returns InconsistentValue). Cisco Small
  // Business switches create VLANs by setting the VLAN's bit in the static
  // VLAN-list bitmap (rldot1qVlanStaticList*, under the static(0) list index).
  // The 4094 VLAN space is split across four 1024-bit bitmaps.
  const VLAN_LIST_OIDS = [
    '1.3.6.1.4.1.9.6.1.101.48.69.1.2',  // 1..1024
    '1.3.6.1.4.1.9.6.1.101.48.69.1.3',  // 1025..2048
    '1.3.6.1.4.1.9.6.1.101.48.69.1.4',  // 2049..3072
    '1.3.6.1.4.1.9.6.1.101.48.69.1.5'   // 3073..4094
  ];
  const VLAN_LIST_STATIC = 0;   // rldot1qVlanStaticListIndex = static(0)
  // Robustly pull hex bytes out of a varbind cell whose display may be
  // "0A 00 .. (hex)", a plain hex string, or a byte string.
  function normalizeHex(cell) {
    const s = String(cell && (cell.display !== undefined && cell.display !== null ? cell.display : cell.value) || '');
    const hex = s.replace(/0x|\s|\(hex\)|:|"/gi, '');
    return /^[0-9a-f]*$/i.test(hex) ? hex.toLowerCase() : '';
  }

  async function createVlan(s, vlanId, name) {
    if (!s.target) return { ok: false, error: 'Not connected.' };
    if (!Number.isFinite(vlanId) || vlanId < 2 || vlanId > 4094) return { ok: false, error: 'VLAN id must be 2-4094.' };
    const ownsBusy = !s.writeBusy;
    if (ownsBusy) s.writeBusy = true;
    let out;
    try {
      // Which 1024-block, and the VLAN's position within it (1-based for the bit
      // helper, which treats bit 1 as the top bit of byte 0).
      const block = Math.floor((vlanId - 1) / 1024);
      const posInBlock = ((vlanId - 1) % 1024) + 1;
      const listOid = VLAN_LIST_OIDS[block] + '.' + VLAN_LIST_STATIC;
      // Read the current bitmap for this block, set the VLAN's bit, write back
      // at full width (matches what the switch holds).
      let curHex = '';
      try { const r = await snmpGet(s, [listOid]); const cell = r[0]; curHex = cell ? normalizeHex(cell) : ''; } catch (e) { curHex = ''; }
      curHex = curHex.padEnd(256, '0');
      const newHex = setPortBit(curHex, posInBlock, true);
      await snmpSet(s, { oid: listOid, type: 'OctetString', valueHex: newHex });
      // Name it (best-effort; the VLAN now exists so the name SET is accepted).
      if (name && name.length) { try { await snmpSet(s, { oid: 'dot1qVlanStaticName.' + vlanId, type: 'OctetString', value: name }); } catch (e) { /* VLAN created; name optional */ } }
      out = { ok: true };
    } catch (e) { out = { ok: false, error: e.message }; }
    if (ownsBusy) s.writeBusy = false;
    appLog(out.ok ? 'info' : 'error', 'Create VLAN', { host: s.host, vlanId, ok: out.ok });
    return out;
  }

  // Delete a VLAN: RowStatus destroy(6) on its row.
  async function deleteVlan(s, vlanId) {
    if (!s.target) return { ok: false, error: 'Not connected.' };
    if (vlanId === 1) return { ok: false, error: 'The default VLAN cannot be deleted.' };
    // Never delete the VLAN that carries our own connection to the switch.
    const sviIfx = await vlanSviIfIndex(s, vlanId);
    if (sviIfx != null && isManagementIf(s, sviIfx)) {
      return { ok: false, error: 'this is the management VLAN (it carries this app\u2019s connection to the switch). Deleting it would cut off access, so it is locked.' };
    }
    const ownsBusy = !s.writeBusy;
    if (ownsBusy) s.writeBusy = true;
    let out;
    try {
      // A VLAN with an IPv4 SVI cannot be removed from the static list while the
      // SVI exists, so tear the SVI down first (static address and/or DHCP
      // client), then clear the VLAN bit. This is safe here - the management SVI
      // was already excluded above.
      if (sviIfx != null) { try { await teardownSvi(s, sviIfx); } catch (e) { /* best effort; the bitmap write will report if it still blocks */ } }
      // Clear the VLAN's bit in the static list. Read the CURRENT full bitmap
      // first and write it back at the same width (the switch rejects a bitmap
      // whose length does not match what it holds - that is the InconsistentValue).
      const block = Math.floor((vlanId - 1) / 1024);
      const posInBlock = ((vlanId - 1) % 1024) + 1;
      const listOid = VLAN_LIST_OIDS[block] + '.' + VLAN_LIST_STATIC;
      let curHex = '';
      try { const r = await snmpGet(s, [listOid]); const cell = r[0]; curHex = cell ? normalizeHex(cell) : ''; } catch (e) { curHex = ''; }
      // Pad to the full 128-byte (1024-bit) width the switch expects for this
      // list, so clearing one bit returns a same-width bitmap.
      curHex = curHex.padEnd(256, '0');
      const newHex = setPortBit(curHex, posInBlock, false);
      await snmpSet(s, { oid: listOid, type: 'OctetString', valueHex: newHex });
      out = { ok: true };
    } catch (e) {
      // InconsistentValue on delete usually means the VLAN is still in use
      // (member ports, or an IPv4 SVI). Make that actionable.
      let msg = e.message;
      if (/InconsistentValue/i.test(msg)) msg = 'the switch refused it - the VLAN may still have member ports or an IPv4 interface. Remove those first (open the VLAN and clear its IPv4 tab / unassign ports), then delete.';
      out = { ok: false, error: msg };
    }
    if (ownsBusy) s.writeBusy = false;
    appLog(out.ok ? 'info' : 'error', 'Delete VLAN', { host: s.host, vlanId, ok: out.ok });
    return out;
  }

  // Refresh the panels that show VLANs after a create/delete, from the switch.
  // vlanNameTable (base 48.21): authoritative VLAN tag -> L3 ifIndex mapping.
  const VLAN_NAME = {
    tag:     '1.3.6.1.4.1.9.6.1.101.48.21.1.2',  // vlanNameTag
    ifIndex: '1.3.6.1.4.1.9.6.1.101.48.21.1.3'   // vlanNameIfIndex
  };
  // Look up a VLAN's SVI (L3) ifIndex. On this platform the SVI appears in the
  // interface table (rlifPresentTable) as a row whose NAME is the VLAN id, and
  // that row's index IS the real ifIndex (e.g. 100997) that rsIpAddrTable keys
  // on - vlanNameTable is empty here, so we read it from the interface table.
  // Prefer the already-loaded health data; fall back to a targeted walk.
  async function vlanSviIfIndex(s, vlanId) {
    const want = String(vlanId);
    // 1. From the in-memory interface list (no switch traffic). Interface cells
    // are { value, display } objects; read the display/value defensively.
    const cellStr = (c) => (c == null ? '' : String(c.display !== undefined && c.display !== null ? c.display : (c.value !== undefined ? c.value : c)));
    const ifs = (s.health && s.health.interfaces) || [];
    for (const r of ifs) {
      const nm = cellStr(r.rlifPresentName).trim();
      if (nm === want) { const ix = parseInt(r.index, 10); if (Number.isFinite(ix)) return ix; }
    }
    // 2. Fall back to walking the name column and matching.
    try {
      const { body } = await apiPost('/api/snmp/walk', { target: s.target, oid: '1.3.6.1.2.1.31.1.1.1.1', mode: 'getbulk' });  // ifName
      for (const r of ((body && body.results) || [])) {
        if (String(r.display !== undefined ? r.display : r.value).trim() === want) { const ix = parseInt(String(r.index), 10); if (Number.isFinite(ix)) return ix; }
      }
    } catch (e) { /* fall through */ }
    return null;
  }

  // SVI IP table (rsIpAddrTable, base 26.1), indexed by the IP address.
  const SVI_IP = {
    ifIndex: '1.3.6.1.4.1.9.6.1.101.26.1.1.2',  // rsIpAdEntIfIndex
    netmask: '1.3.6.1.4.1.9.6.1.101.26.1.1.3',  // rsIpAdEntNetMask
    status:  '1.3.6.1.4.1.9.6.1.101.26.1.1.6',  // rsIpAdEntStatus (RowStatus)
    owner:   '1.3.6.1.4.1.9.6.1.101.26.1.1.10'  // rsIpAdEntOwner static(1)/dhcp(2)/internal(3)/default(4)
  };
  const SVI_OWNER = { 1: 'static', 2: 'dhcp', 3: 'internal', 4: 'default' };
  // DHCP client action table (rlDhcpClActionTable, base 76.3), indexed by ifIndex.
  const DHCP_CL = {
    status:   '1.3.6.1.4.1.9.6.1.101.76.3.1.2',  // rlDhcpClActionStatus (RowStatus to enable)
    hostName: '1.3.6.1.4.1.9.6.1.101.76.3.1.3'
  };
  // Prefix length -> dotted netmask.
  function prefToMask(p) { p = Math.max(0, Math.min(32, p | 0)); const m = p === 0 ? 0 : (0xffffffff << (32 - p)) >>> 0; return [24, 16, 8, 0].map((sh) => (m >>> sh) & 0xff).join('.'); }
  // Dotted netmask -> prefix length.
  function maskToPref(mask) { const m = String(mask).split('.').map(Number); if (m.length !== 4) return null; let bits = 0; for (const o of m) bits += (o.toString(2).match(/1/g) || []).length; return bits; }

  // Edit a VLAN: rename, SVI IP address, and ACL binding (no direction).
  function openVlanEditor(s, vlan) {
    const tabs = [];

    // ---- General tab: rename ----
    tabs.push({ label: 'General', fill: (pane) => {
      const form = el('div', 'snmp-form acl-form');
      const sec = formSection('VLAN ' + vlan.id);
      const nameIn = el('input'); nameIn.type = 'text'; nameIn.maxLength = 32; nameIn.value = vlan.name || '';
      sec.body.appendChild(field('Name', nameIn));
      form.appendChild(sec.sec);
      const { actions, apply } = applyActions('Save name');
      const msg = el('div', 'port-detail-msg');
      withConfirm(apply, (ev) => {
        clear(msg);
        runButtonAction(ev.currentTarget, {
          failLabel: 'Rename VLAN',
          run: () => snmpSet(s, { oid: 'dot1qVlanStaticName.' + vlan.id, type: 'OctetString', value: (nameIn.value || '').trim() }).then(() => ({ ok: true }), (e) => ({ ok: false, error: e.message })),
          ok: (r) => r && r.ok,
          error: (r) => { msg.appendChild(el('div', 'sw-err', 'Could not rename \u2014 ' + ((r && r.error) || 'failed'))); return (r && r.error) || 'failed'; },
          onApplied: () => { markConfigDirty(s, nameIn); s._vlanFlash = vlan.id; },
          settle: () => refreshVlanPanels(s, { vlansOnly: true })
        });
      });
      form.appendChild(actions); form.appendChild(msg);
      pane.appendChild(form);
    } });

    // ---- IPv4 tab: the VLAN's SVI address (static or DHCP) ----
    // The SVI ifIndex is resolved from the authoritative vlanNameTable (tag ->
    // ifIndex), not guessed from the interface-table row, which is what caused
    // the earlier wrong-SVI match.
    tabs.push({ label: 'IPv4', fill: async (pane) => {
      pane.appendChild(el('div', 'card-sub', 'Reading IPv4 interface\u2026'));
      const ifx = await vlanSviIfIndex(s, vlan.id);
      clear(pane);
      buildSviEditor(s, vlan, ifx, pane);
    } });

    // ---- ACL tab: bind an ACL to the VLAN (default action only, no direction) ----
    tabs.push({ label: 'ACL', fill: async (pane) => {
      pane.appendChild(el('div', 'card-sub', 'Reading ACL binding\u2026'));
      const ifx = await vlanSviIfIndex(s, vlan.id);
      clear(pane);
      if (ifx != null) buildIfAclBinding(s, { ifIndex: ifx }, pane, { ifType: IFTYPE_VLAN, noDirection: true });
      else pane.appendChild(el('div', 'card-sub', 'This VLAN has no L3 interface yet. Add an IPv4 address on the IPv4 tab first, then an ACL can be bound to it.'));
    } });

    openTabbedPopout(s, 'VLAN ' + vlan.id + (vlan.name ? ' \u00b7 ' + vlan.name : ''), tabs, []);
  }

  // SVI IP editor: shows the current address (if any) and lets you set/replace
  // or remove it. Writing a management SVI wrong can cut access, so this reads
  // first and is explicit about what it will change.
  // The VLAN IPv4 (SVI) editor. Reads the address table, filters to real user
  // addresses on THIS VLAN's L3 interface (owner static/dhcp - internal/default
  // are system addresses and must be ignored, which is what produced the bogus
  // "0.193.134.170"), and offers Static or DHCP. When the VLAN has no SVI yet it
  // shows an "Add IPv4 SVI" button rather than a pre-filled form.
  async function buildSviEditor(s, vlan, sviIfIndex, pane) {
    // The management SVI (carrying this app's connection) is read-only: changing
    // or removing its address would cut off access to the switch.
    if (isManagementIf(s, sviIfIndex)) {
      const cv = (c) => (c == null ? '' : (c.value !== undefined ? c.value : (c.display !== undefined ? c.display : c)));
      let ipLine = s.target.host;
      for (const a of ((s.health && s.health.sviAddrs) || [])) { if (String(a.index) === String(s.target.host)) { const m = String(cv(a.rsIpAdEntNetMask) || ''); const p = m ? m.split('.').reduce((n, o) => n + ((parseInt(o, 10) || 0).toString(2).match(/1/g) || []).length, 0) : null; ipLine = s.target.host + (p ? '/' + p : ''); break; } }
      pane.appendChild(el('div', 'aaa-sub', 'Management interface'));
      pane.appendChild(el('div', 'card-sub', 'This VLAN\u2019s IPv4 interface (' + ipLine + ') carries this app\u2019s connection to the switch. It is locked to prevent accidentally cutting off access.'));
      return;
    }
    pane.appendChild(el('div', 'card-sub', 'Reading IPv4 interface\u2026'));
    // Find any user address whose ifIndex matches this SVI, skipping system
    // (internal/default) owners.
    let cur = null;   // { ip, mask, owner }
    let dhcpOn = false;
    try {
      const [ifx, masks, owners, dhcp] = await Promise.all([
        apiPost('/api/snmp/walk', { target: s.target, oid: SVI_IP.ifIndex, mode: 'getbulk' }),
        apiPost('/api/snmp/walk', { target: s.target, oid: SVI_IP.netmask, mode: 'getbulk' }),
        apiPost('/api/snmp/walk', { target: s.target, oid: SVI_IP.owner, mode: 'getbulk' }),
        apiPost('/api/snmp/walk', { target: s.target, oid: DHCP_CL.status, mode: 'getbulk' })
      ]);
      const maskByIp = {}, ownerByIp = {};
      for (const r of ((masks.body && masks.body.results) || [])) maskByIp[String(r.index)] = String(r.display !== undefined ? r.display : r.value);
      for (const r of ((owners.body && owners.body.results) || [])) ownerByIp[String(r.index)] = parseInt(r.value, 10);
      for (const r of ((ifx.body && ifx.body.results) || [])) {
        const ip = String(r.index);
        const owner = ownerByIp[ip];
        // Only real user addresses, on this SVI. A DHCP interface without a
        // lease has a 0.x placeholder - treat that as "DHCP, no address yet"
        // (dhcpOn below handles the display) rather than a real current address.
        if (sviIfIndex != null && parseInt(r.value, 10) === parseInt(sviIfIndex, 10) && (owner === 1 || owner === 2) && isRealIp(ip)) {
          cur = { ip, mask: maskByIp[ip] || null, owner };
          break;
        }
      }
      // Is DHCP client enabled on this SVI's ifIndex?
      for (const r of ((dhcp.body && dhcp.body.results) || [])) { if (parseInt(String(r.index), 10) === parseInt(sviIfIndex, 10)) dhcpOn = true; }
    } catch (e) { /* show the add path */ }
    clear(pane);

    // No SVI yet: offer an explicit "Add IPv4 SVI" button.
    if (!cur && !dhcpOn) {
      pane.appendChild(el('div', 'card-sub', 'VLAN ' + vlan.id + ' has no IPv4 interface configured.'));
      if (sviIfIndex == null) pane.appendChild(el('div', 'sw-err', 'Could not resolve this VLAN\u2019s L3 ifIndex (needed to add an address).'));
      const addRow = el('div', 'snmp-form-actions'); addRow.style.marginTop = '10px';
      const addBtn = el('button', 'btn btn-small btn-blue', 'Add IPv4 SVI'); addBtn.type = 'button';
      addBtn.disabled = sviIfIndex == null;
      addBtn.addEventListener('click', () => { clear(pane); sviConfigForm(s, vlan, sviIfIndex, pane, null, false); });
      addRow.appendChild(addBtn); pane.appendChild(addRow);
      return;
    }
    // Existing SVI: show the config form pre-filled.
    sviConfigForm(s, vlan, sviIfIndex, pane, cur, dhcpOn);
  }


  // The SVI configuration form - Static (IP + prefix) or DHCP.
  function sviConfigForm(s, vlan, sviIfIndex, pane, cur, dhcpOn) {
    const form = el('div', 'snmp-form acl-form');
    const sec = formSection('IPv4 interface');
    if (cur) sec.body.appendChild(el('div', 'card-sub', 'Current: ' + cur.ip + ' / ' + (cur.mask || '?') + ' (' + (SVI_OWNER[cur.owner] || 'static') + ')'));
    else if (dhcpOn) sec.body.appendChild(el('div', 'card-sub', 'Current: DHCP (awaiting lease)'));
    // Mode: Static or DHCP.
    const modeSel = selectInput([{ label: 'Static', value: 'static' }, { label: 'DHCP', value: 'dhcp' }], dhcpOn ? 'dhcp' : 'static');
    sec.body.appendChild(field('Addressing', modeSel));
    const ipIn = el('input'); ipIn.type = 'text'; ipIn.placeholder = '192.168.1.1'; if (cur) ipIn.value = cur.ip;
    const ipField = field('IP address', ipIn);
    sec.body.appendChild(ipField);
    const prefIn = el('input'); prefIn.type = 'number'; prefIn.min = '1'; prefIn.max = '32'; prefIn.value = cur && cur.mask ? String(maskToPref(cur.mask) || 24) : '24';
    const prefField = field('Prefix length', prefIn);
    sec.body.appendChild(prefField);
    const syncMode = () => { const dhcp = modeSel.value === 'dhcp'; ipField.style.display = dhcp ? 'none' : ''; prefField.style.display = dhcp ? 'none' : ''; };
    modeSel.addEventListener('change', syncMode); syncMode();
    form.appendChild(sec.sec);

    const { actions, apply } = applyActions(cur || dhcpOn ? 'Update IPv4' : 'Add IPv4');
    const msg = el('div', 'port-detail-msg');
    withConfirm(apply, (ev) => {
      clear(msg);
      const mode = modeSel.value;
      if (mode === 'static' && !ipv4ToHex(ipIn.value)) { msg.appendChild(el('div', 'sw-err', 'Enter a valid IPv4 address.')); return; }
      runButtonAction(ev.currentTarget, {
        failLabel: 'Set IPv4 interface',
        run: async () => {
          try {
            if (mode === 'dhcp') {
              if (cur && cur.owner === 1) { try { await snmpSet(s, { oid: SVI_IP.status + '.' + cur.ip, type: 'Integer', value: 2 }); } catch (e) { /* ignore */ } }
              await snmpSet(s, { oid: DHCP_CL.status + '.' + sviIfIndex, type: 'Integer', value: 4 });
            } else {
              if (dhcpOn) { try { await snmpSet(s, { oid: DHCP_CL.status + '.' + sviIfIndex, type: 'Integer', value: 6 }); } catch (e) { /* ignore */ } }
              const ip = (ipIn.value || '').trim();
              const mask = prefToMask(parseInt(prefIn.value, 10));
              if (cur && cur.ip !== ip) { try { await snmpSet(s, { oid: SVI_IP.status + '.' + cur.ip, type: 'Integer', value: 2 }); } catch (e) { /* ignore */ } }
              await snmpSet(s, [
                { oid: SVI_IP.status + '.' + ip, type: 'Integer', value: 1 },
                { oid: SVI_IP.ifIndex + '.' + ip, type: 'Integer', value: parseInt(sviIfIndex, 10) },
                { oid: SVI_IP.netmask + '.' + ip, type: 'IpAddress', value: mask }
              ]);
            }
            return { ok: true };
          } catch (e) { return { ok: false, error: e.message }; }
        },
        ok: (r) => r && r.ok,
        error: (r) => { msg.appendChild(el('div', 'sw-err', 'Could not set the IPv4 interface \u2014 ' + ((r && r.error) || 'failed'))); return (r && r.error) || 'failed'; },
        onApplied: () => { markConfigDirty(s, [modeSel, ipIn, prefIn]); s._vlanFlash = vlan.id; },
        settle: () => refreshSvi(s)
      });
    });
    form.appendChild(actions); form.appendChild(msg);
    // Remove button when something is configured.
    if (cur || dhcpOn) {
      const rm = actBtnConfirm('Remove IPv4', (e) => {
        clear(msg);
        runButtonAction(e.currentTarget, {
          failLabel: 'Remove IPv4',
          run: async () => {
            try {
              if (dhcpOn) await snmpSet(s, { oid: DHCP_CL.status + '.' + sviIfIndex, type: 'Integer', value: 6 });
              if (cur) await snmpSet(s, { oid: SVI_IP.status + '.' + cur.ip, type: 'Integer', value: 2 });
              return { ok: true };
            } catch (err) { return { ok: false, error: err.message }; }
          },
          ok: (r) => r && r.ok,
          error: (r) => { msg.appendChild(el('div', 'sw-err', 'Could not remove the IPv4 interface \u2014 ' + ((r && r.error) || 'failed'))); return (r && r.error) || 'failed'; },
          onApplied: () => markConfigDirty(s),
          settle: () => refreshSvi(s).then(() => { const pop = pane.closest && pane.closest('.port-detail-back'); if (pop) pop.remove(); })
        });
      }, 'danger', 'Remove this VLAN\u2019s IPv4 interface');
      const rmRow = el('div', 'snmp-form-actions'); rmRow.style.marginTop = '8px'; rmRow.appendChild(rm);
      form.appendChild(rmRow);
    }
    pane.appendChild(form);
  }

  // Refresh only the tables the VLAN view needs (the VLAN table, and the
  // interface table for SVI/membership changes) via a targeted partial walk,
  // rather than a full panel reload that re-walks everything. Keeps the switch
  // CPU impact minimal. opts.vlansOnly skips the heavier interface walk for a
  // rename (which changes nothing in the interface table).
  function refreshVlanPanels(s, opts) {
    opts = opts || {};
    // Always include sviAddrs so the VLAN table's IPv4 column reflects an SVI
    // that was just added/changed. A rename skips the heavier interface walk; a
    // Voice VLAN edit only needs the voice tables + scalars.
    const voice = ['voiceOUI', 'voiceLocalSrc', 'scalars'];
    const tables = opts.voiceOnly ? voice
      : opts.vlansOnly ? ['vlans', 'sviAddrs']
      : ['vlans', 'interfaces', 'sviAddrs'].concat(voice);
    // Return a promise that resolves once the (delayed) walk completes, so a
    // button action can spin until the VLAN table actually updates.
    return new Promise((res) => { setTimeout(() => { refreshTables(s, tables).then(res, res); }, 900); });
  }

  // Remove an SVI's IPv4 configuration for a given ifIndex: any static address
  // (rsIpAdEntStatus = invalid(2)) and the DHCP client (rlDhcpClActionStatus =
  // destroy(6)). Used before deleting a VLAN, and when clearing its IPv4 tab.
  async function teardownSvi(s, ifIndex) {
    const cv = (c) => (c == null ? '' : (c.value !== undefined ? c.value : (c.display !== undefined ? c.display : c)));
    // Remove any address rows that belong to this ifIndex.
    try {
      const { body } = await apiPost('/api/snmp/walk', { target: s.target, oid: SVI_IP.ifIndex, mode: 'getbulk' });
      for (const r of ((body && body.results) || [])) {
        if (parseInt(cv(r.value), 10) === parseInt(ifIndex, 10)) {
          try { await snmpSet(s, { oid: SVI_IP.status + '.' + String(r.index), type: 'Integer', value: 2 }); } catch (e) { /* ignore per-row */ }
        }
      }
    } catch (e) { /* ignore */ }
    // Disable the DHCP client on this ifIndex, if enabled.
    try { await snmpSet(s, { oid: DHCP_CL.status + '.' + ifIndex, type: 'Integer', value: 6 }); } catch (e) { /* not enabled */ }
  }

  // The ifIndex of the SVI carrying our SNMP connection: the address table row
  // whose IP equals the host we are talking to. Modifying or deleting this SVI
  // (or its VLAN) would cut the app's own connectivity, so it is protected.
  // Returns the ifIndex number, or null if not found (then nothing is locked).
  function managementIfIndex(s) {
    const host = s && s.target && s.target.host;
    if (!host) return null;
    const cv = (c) => (c == null ? '' : (c.value !== undefined ? c.value : (c.display !== undefined ? c.display : c)));
    for (const a of ((s.health && s.health.sviAddrs) || [])) {
      if (String(a.index) === String(host)) { const ix = parseInt(cv(a.rsIpAdEntIfIndex), 10); return Number.isFinite(ix) ? ix : null; }
    }
    return null;
  }
  // True if the given SVI ifIndex is the management interface.
  function isManagementIf(s, ifIndex) { const m = managementIfIndex(s); return m != null && ifIndex != null && parseInt(ifIndex, 10) === m; }

  // After an SVI/IPv4 change the switch needs a moment to create the L3
  // interface row (and, for DHCP, to obtain a lease). Refresh the VLAN + SVI
  // tables twice - soon, and again a few seconds later - so the table reflects
  // the change without the user having to reload. Light, targeted walks only.
  // Returns the first refresh's promise, so a write's runButtonAction settle
  // holds its spinner until the table shows the change (§B6).
  function refreshSvi(s) {
    setTimeout(() => refreshTables(s, ['vlans', 'interfaces', 'sviAddrs']), 4500);
    return new Promise((res) => { setTimeout(() => { refreshTables(s, ['vlans', 'interfaces', 'sviAddrs']).then(res, res); }, 1000); });
  }

  // The "add VLAN" control shown above the VLAN table.
  // Create-VLAN popout: id + name, then (after creation) the editor opens so the
  // IPv4/ACL tabs are available.
  function openVlanCreate(s) {
    const tabs = [{ label: 'New VLAN', fill: (pane, close) => {
      const form = el('div', 'snmp-form acl-form');
      const sec = formSection('VLAN');
      const idIn = el('input'); idIn.type = 'number'; idIn.min = '2'; idIn.max = '4094'; idIn.placeholder = '2-4094';
      sec.body.appendChild(field('VLAN id', idIn));
      const nameIn = el('input'); nameIn.type = 'text'; nameIn.maxLength = 32; nameIn.placeholder = 'optional';
      sec.body.appendChild(field('Name', nameIn));
      sec.body.appendChild(el('div', 'card-sub', 'After the VLAN is created, its editor opens so you can add an IPv4 interface and bind an ACL.'));
      form.appendChild(sec.sec);
      const { actions, apply } = applyActions('Create VLAN');
      const msg = el('div', 'port-detail-msg');
      withConfirm(apply, (ev) => {
        const id = parseInt(idIn.value, 10);
        clear(msg);
        if (!Number.isFinite(id) || id < 2 || id > 4094) { msg.appendChild(el('div', 'sw-err', 'Enter a VLAN id between 2 and 4094.')); return; }
        if ((s.health && s.health.vlans || []).some((v) => Number(v.index) === id)) { msg.appendChild(el('div', 'sw-err', 'VLAN ' + id + ' already exists.')); return; }
        const nm = (nameIn.value || '').trim();
        runButtonAction(ev.currentTarget, {
          failLabel: 'Create VLAN', spinLabel: 'Creating\u2026',
          run: () => createVlan(s, id, nm),
          ok: (res) => res && res.ok,
          error: (res) => { msg.appendChild(el('div', 'sw-err', 'Could not create VLAN: ' + ((res && res.error) || 'failed'))); return (res && res.error) || 'failed'; },
          onApplied: () => {
            markConfigDirty(s); s._vlanFlash = id;
            close();
            setTimeout(() => openVlanEditor(s, { id, name: nm }), 250);
          },
          settle: () => new Promise((res) => setTimeout(() => refreshVlanPanels(s).then(res, res), 1200))
        });
      });
      form.appendChild(actions); form.appendChild(msg);
      pane.appendChild(form);
    } }];
    openTabbedPopout(s, 'New VLAN', tabs, []);
  }

  // Add a Telephony OUI entry. The prefix (3-byte OUI) is the row index; set the
  // Description + RowStatus createAndGo in one PDU (a bare RowStatus set is
  // rejected, the lesson from the DNS tables).
  function openVoiceOuiForm(s) {
    const tabs = [{ label: 'Add OUI', fill: (pane, close) => {
      const form = el('div', 'snmp-form acl-form');
      const sec = formSection('Telephony OUI');
      const ouiIn = el('input'); ouiIn.type = 'text'; ouiIn.placeholder = 'AA-BB-CC (first 3 MAC bytes)';
      sec.body.appendChild(field('OUI prefix', ouiIn));
      const descIn = el('input'); descIn.type = 'text'; descIn.maxLength = 32; descIn.placeholder = 'e.g. Acme_phone';
      sec.body.appendChild(field('Description', descIn));
      form.appendChild(sec.sec);
      const { actions, apply } = applyActions('Add OUI');
      const msg = el('div', 'port-detail-msg');
      apply.addEventListener('click', (e) => {
        clear(msg);
        const idx = ouiToOidIndex(ouiIn.value);
        if (!idx) { msg.appendChild(el('div', 'sw-err', 'Enter an OUI as 3 hex octets, e.g. 00-11-22.')); return; }
        const descr = (descIn.value || '').trim();
        runButtonAction(e.currentTarget, {
          failLabel: 'Add OUI',
          run: () => snmpSetResult(s, [
            { oid: '1.3.6.1.4.1.9.6.1.101.48.54.12.4.1.2.' + idx, type: 'OctetString', value: descr },
            { oid: '1.3.6.1.4.1.9.6.1.101.48.54.12.4.1.3.' + idx, type: 'Integer', value: 4 }   // createAndGo
          ]),
          ok: (res) => res && res.ok && !(res.body && res.body.error),
          error: (res) => (res && res.body && res.body.error) || 'the switch rejected it',
          onApplied: () => markConfigDirty(s),
          settle: () => refreshVlanPanels(s, { voiceOnly: true }).then(() => close())
        });
      });
      form.appendChild(actions); form.appendChild(msg);
      pane.appendChild(form);
    } }];
    openTabbedPopout(s, 'Add Telephony OUI', tabs, []);
  }

  // Per-row delete control. VLAN 1 (the default VLAN) cannot be removed.
  function buildVlanDeleteCell(s, td, info) {
    if (info.id === 1) { td.appendChild(el('span', 'card-sub', '\u2014')); return; }
    const paint = () => {
      clear(td);
      // Two-tap confirm: first tap arms ("Confirm?"), second deletes. The title
      // carries the warning about ports losing the VLAN.
      td.appendChild(actGroup([actBtnConfirm('Delete', () => {
        clear(td); td.appendChild(el('span', 'card-sub', 'Deleting\u2026'));
        deleteVlan(s, info.id).then((res) => {
          // On success the VLAN row disappears on refresh - the change made visible.
          if (res.ok) { markConfigDirty(s); refreshVlanPanels(s); }
          else { clear(td); const e = el('div', 'sw-err', res.error); td.appendChild(e); td.appendChild(actGroup([actBtn('Back', paint)])); }
        });
      }, 'danger', 'Delete VLAN ' + info.id + (info.name ? ' (' + info.name + ')' : '') + ' — ports using it will lose this VLAN')]));
    };
    paint();
  }


  function paintVlanPanel(s, body, p) {
    if (!s._ktReconcile) clear(body);
    const h = s.health;
    if (!h || !h.vlans || !h.vlans.length) { if (!s._ktReconcile) body.appendChild(el('div', 'card-sub', 'No VLANs reported.')); return; }
    const dv = (c, fb) => (c == null ? (fb !== undefined ? fb : '') : (c.display !== undefined && c.display !== null ? c.display : (c.value !== undefined ? c.value : c)));

    // Map the VLAN id -> its SVI interface row (named after the VLAN id in the
    // interface table), for oper status and IPv4.
    const vlanIds = new Set(h.vlans.map((v) => String(v.index)));
    const sviByVlan = new Map();
    for (const r of (h.interfaces || [])) {
      const nm = String(dv(r.rlifPresentName) || '').trim();
      if (/^\d+$/.test(nm) && vlanIds.has(nm)) sviByVlan.set(nm, r);
    }

    if (!s._ktReconcile) {
      const st = el('div', 'section-title', 'VLANs');
      st.appendChild(el('span', 'st-note', h.vlans.length + ' defined'));
      body.appendChild(st);
      if (s.target) body.appendChild(addControl('New VLAN', () => openVlanCreate(s)));
    }

    const anySvi = sviByVlan.size > 0;
    // SVI ifIndex -> IPv4 "addr/mask", from rsIpAddrTable (owner static/dhcp, real IPs).
    const ipByIfIndex = new Map();
    const cellVal = (c) => (c == null ? '' : (c.value !== undefined ? c.value : (c.display !== undefined ? c.display : c)));
    for (const a of (h.sviAddrs || [])) {
      const owner = parseInt(cellVal(a.rsIpAdEntOwner), 10);
      if (owner !== 1 && owner !== 2) continue;
      const ifx = String(cellVal(a.rsIpAdEntIfIndex)); const ip = String(a.index);
      if (!ifx) continue;
      if (owner === 2) ipByIfIndex.set(ifx, isRealIp(ip) ? (ip + ' (DHCP)') : 'DHCP (no lease)');
      else if (isRealIp(ip)) {
        const mask = String(cellVal(a.rsIpAdEntNetMask) || '');
        const pref = mask ? ((mask.split('.').reduce((n, o) => n + ((parseInt(o, 10) || 0).toString(2).match(/1/g) || []).length, 0)) || '') : '';
        ipByIfIndex.set(ifx, pref ? ip + '/' + pref : ip);
      }
    }
    const vlanIp = (vlanIndex) => { const svi = sviByVlan.get(String(vlanIndex)); return svi ? (ipByIfIndex.get(String(svi.index)) || '') : ''; };

    const cols = ['VLAN', 'Name', 'Members', 'Untagged ports', 'Tagged ports']
      .concat(anySvi ? ['Interface', 'IPv4'] : [])
      .concat(s.target ? [''] : []);
    // VLANs that just changed should flash (one-shot).
    const flashVids = new Set();
    if (s._vlanFlash != null) flashVids.add(Number(s._vlanFlash));
    if (s._vlanFlashSet) for (const v of s._vlanFlashSet) flashVids.add(Number(v));
    s._vlanFlash = null; s._vlanFlashSet = null;

    const krows = h.vlans.map((r) => {
      const vid = Number(r.index);
      const svi = sviByVlan.get(String(r.index)) || null;
      const base = [
        { v: String(r.index), click: s.target ? { open: () => openVlanEditor(s, { id: vid, name: dv(r.name), svi }) } : undefined },
        { v: dv(r.name) }, { v: dv(r.memberCount) }, { v: dv(r.untagged) }, { v: dv(r.tagged) }
      ];
      const withSvi = anySvi
        ? base.concat([{ v: (sviByVlan.get(String(r.index)) ? dv(sviByVlan.get(String(r.index)).rlifPresentOperStatus) : '') }, { v: vlanIp(r.index) || '\u2014' }])
        : base;
      let cells = withSvi;
      if (s.target) {
        const delNode = vid !== 1
          ? actGroup([actBtnConfirm('Delete', (e) => {
              runButtonAction(e.currentTarget, {
                failLabel: 'Delete VLAN',
                run: () => deleteVlan(s, vid).then((res) => ({ ok: res.ok, body: { error: res.error } })),
                error: (res) => (res && res.body && res.body.error) || 'the switch rejected it',
                onApplied: () => markConfigDirty(s),
                settle: () => refreshVlanPanels(s)
              });
            }, 'danger', 'Delete VLAN ' + vid)])
          : el('span', '');
        cells = withSvi.concat([{ cellNode: delNode, sig: 'del' + (vid === 1 ? '0' : '1') }]);
      }
      if (flashVids.has(vid) && cells[0]) cells[0] = Object.assign({}, cells[0], { _flash: true });
      return { key: 'vlan:' + r.index, cells: cells };
    });
    mountInto(body, s, p, 'vlans', cols, krows);

    // ===== Voice VLAN (CISCOSB-vlanvoice.mib) =====
    const num = (c) => { const v = c && (c.value !== undefined ? c.value : c.display); const n = parseInt(v, 10); return Number.isFinite(n) ? n : null; };
    const sc = h.scalars || {};
    const scn = (name) => num(sc[name]);
    // A section title helper local to the voice sections (the VLAN table above
    // builds its own title inline; these match that style via section-title).
    const vsection = (title, note) => {
      if (s._ktReconcile) return;
      const stt = el('div', 'section-title', title);
      if (note) stt.appendChild(el('span', 'st-note', note));
      body.appendChild(stt);
    };
    const VOICE = {
      adminState: '1.3.6.1.4.1.9.6.1.101.48.54.6',
      adminVid:   '1.3.6.1.4.1.9.6.1.101.48.54.8',
      autoVpt:    '1.3.6.1.4.1.9.6.1.101.48.54.11.1.1',
      autoDscp:   '1.3.6.1.4.1.9.6.1.101.48.54.11.1.2',
      ouiPriority:'1.3.6.1.4.1.9.6.1.101.48.54.12.1',
      ouiRemark:  '1.3.6.1.4.1.9.6.1.101.48.54.12.2',
      ouiAging:   '1.3.6.1.4.1.9.6.1.101.48.54.12.6',
      ouiRowStatus:'1.3.6.1.4.1.9.6.1.101.48.54.12.4.1.3',
      ouiDescr:   '1.3.6.1.4.1.9.6.1.101.48.54.12.4.1.2',
      portEnable: '1.3.6.1.4.1.9.6.1.101.48.54.12.5.1.1'   // per-port Enable (for the OUI->auto guard)
    };
    const VOICE_MODE = { 0: 'Disabled', 1: 'Auto (dynamic)', 2: 'Auto (triggered)', 3: 'OUI-based' };
    const UC_TYPE = { 0: 'Default', 1: 'Static', 2: 'UC' };
    const voiceRefresh = () => refreshVlanPanels(s, { voiceOnly: true });

    // ---- Voice VLAN status (scalar, refreshed in place) ----
    if (!s._ktReconcile) {
      vsection('Voice VLAN');
      p._voiceStatus = el('div', 'card-sub'); body.appendChild(p._voiceStatus);
      if (s.target) { p._voiceControls = el('div', 'tbl-add'); body.appendChild(p._voiceControls); }
    }
    if (p._voiceStatus) {
      clear(p._voiceStatus);
      const adm = scn('vlanVoiceAdminState'), op = scn('vlanVoiceOperState');
      const vid = scn('vlanVoiceAdminVid'), opvid = scn('vlanVoiceOperVid');
      const cos = scn('vlanVoiceAutoOperVpt'), dscp = scn('vlanVoiceAutoOperDscp');
      p._voiceStatus.appendChild(el('span', 'pill ' + (adm && adm !== 0 ? 'good' : 'idle'),
        'Admin: ' + (VOICE_MODE[adm] || 'unknown')));
      const bits = [];
      bits.push('Oper: ' + (VOICE_MODE[op] || 'unknown'));
      if (vid != null) bits.push('VLAN ' + vid + (opvid != null && opvid !== vid ? ' (oper ' + opvid + ')' : ''));
      if (cos != null) bits.push('CoS ' + cos);
      if (dscp != null) bits.push('DSCP ' + dscp);
      p._voiceStatus.appendChild(document.createTextNode('  \u00b7  ' + bits.join('  \u00b7  ')));
    }
    if (p._voiceControls) {
      clear(p._voiceControls);
      const adm = scn('vlanVoiceAdminState');
      const modeSel = el('select', 'sw-mini-select');
      for (const v of [0, 1, 2, 3]) { const o = el('option', '', VOICE_MODE[v]); o.value = String(v); if (v === adm) o.selected = true; modeSel.appendChild(o); }
      // Voice VLAN ID + CoS + DSCP editors (compact).
      const vidIn = el('input'); vidIn.type = 'number'; vidIn.min = '1'; vidIn.max = '4094'; vidIn.style.width = '70px';
      vidIn.value = String(scn('vlanVoiceAdminVid') || '');
      const cosIn = el('input'); cosIn.type = 'number'; cosIn.min = '0'; cosIn.max = '7'; cosIn.style.width = '52px';
      cosIn.value = String(scn('vlanVoiceAutoAdminVpt') || '0');
      const dscpIn = el('input'); dscpIn.type = 'number'; dscpIn.min = '0'; dscpIn.max = '63'; dscpIn.style.width = '58px';
      dscpIn.value = String(scn('vlanVoiceAutoAdminDscp') || '0');
      const applyCfg = el('button', 'btn btn-small btn-blue', 'Apply'); applyCfg.type = 'button'; applyCfg.style.marginLeft = '6px';
      applyCfg.addEventListener('click', (e) => {
        const curMode = scn('vlanVoiceAdminState');
        const mode = parseInt(modeSel.value, 10);
        const vid = parseInt(vidIn.value, 10), cos = parseInt(cosIn.value, 10), dscp = parseInt(dscpIn.value, 10);
        // Non-mode settings (VLAN/CoS/DSCP) that changed.
        const cfgVbs = [];
        if (Number.isFinite(vid) && vid >= 1 && vid <= 4094 && vid !== scn('vlanVoiceAdminVid')) cfgVbs.push({ oid: VOICE.adminVid + '.0', type: 'Integer', value: vid });
        if (Number.isFinite(cos) && cos >= 0 && cos <= 7 && cos !== scn('vlanVoiceAutoAdminVpt')) cfgVbs.push({ oid: VOICE.autoVpt + '.0', type: 'Integer', value: cos });
        if (Number.isFinite(dscp) && dscp >= 0 && dscp <= 63 && dscp !== scn('vlanVoiceAutoAdminDscp')) cfgVbs.push({ oid: VOICE.autoDscp + '.0', type: 'Integer', value: dscp });
        const modeChanged = Number.isFinite(mode) && mode !== curMode;
        if (!modeChanged && !cfgVbs.length) return;
        runButtonAction(e.currentTarget, {
          failLabel: 'Apply Voice VLAN settings',
          run: async () => {
            if (modeChanged) {
              // Leaving OUI-based for an auto mode requires no ports still be
              // candidates in the Voice VLAN - remove them first. Auto modes are
              // 1 (auto-enabled) and 2 (auto-triggered); OUI is 3.
              if (curMode === 3 && (mode === 1 || mode === 2)) {
                const walk = await apiPost('/api/snmp/walk', { target: s.target, oid: VOICE.portEnable, mode: 'getbulk' }).catch(() => null);
                const rows = (walk && walk.body && walk.body.results) || [];
                const enabled = rows.filter((r) => { const v = r.value && (r.value.value !== undefined ? r.value.value : r.value); return parseInt(v, 10) === 1; }).length;
                if (enabled > 0) return { ok: false, body: { error: 'Remove all ' + enabled + ' port(s) from the Voice VLAN before switching to an auto mode (set each port\u2019s Voice VLAN to Disabled first).' } };
              }
              // A direct swap between two active modes isn't accepted; the switch
              // requires passing through Disabled. Set Disabled first, then target.
              if (curMode !== 0 && mode !== 0) {
                const r0 = await snmpSetResult(s, { oid: VOICE.adminState + '.0', type: 'Integer', value: 0 });
                if (!(r0 && r0.ok) || (r0.body && r0.body.error)) return r0;
              }
              const rm = await snmpSetResult(s, { oid: VOICE.adminState + '.0', type: 'Integer', value: mode });
              if (!(rm && rm.ok) || (rm.body && rm.body.error)) return rm;
            }
            if (cfgVbs.length) return snmpSetResult(s, cfgVbs);
            return { ok: true, body: {} };
          },
          ok: (res) => res && res.ok && !(res.body && res.body.error),
          error: (res) => (res && res.body && res.body.error) || 'the switch rejected it',
          onApplied: () => markConfigDirty(s), settle: () => voiceRefresh()
        });
      });
      p._voiceControls.appendChild(el('span', 'sw-mini-label', 'Mode')); p._voiceControls.appendChild(modeSel);
      p._voiceControls.appendChild(el('span', 'sw-mini-label', 'VLAN')); p._voiceControls.appendChild(vidIn);
      p._voiceControls.appendChild(el('span', 'sw-mini-label', 'CoS')); p._voiceControls.appendChild(cosIn);
      p._voiceControls.appendChild(el('span', 'sw-mini-label', 'DSCP')); p._voiceControls.appendChild(dscpIn);
      p._voiceControls.appendChild(applyCfg);
    }

    // ---- Voice VLAN local source table (read-only) ----
    const locals = (h.voiceLocalSrc || []);
    if (locals.length) {
      vsection('Voice VLAN local source', locals.length + ' entries');
      const lrows = locals.map((r) => {
        return { key: 'vsrc:' + r.index, cells: [
          { v: UC_TYPE[num(r.vlanVoiceUcDeviceType)] || dv(r.vlanVoiceUcDeviceType) },
          { v: dv(r.vlanVoiceUcDeviceMacAddress) || 'N/A' },
          { v: dv(r.vlanVoiceUcDeviceInterface) || 'N/A' },
          { v: dv(r.vlanVoiceUcDeviceVid) },
          { v: dv(r.vlanVoiceUcDeviceVpt) },
          { v: dv(r.vlanVoiceUcDeviceDscp) },
          { v: num(r.vlanVoiceUcDeviceIsBest) === 1 ? 'Yes' : 'No' } ] };
      });
      mountInto(body, s, p, 'voiceLocalSrc', ['Type', 'Source MAC', 'Interface', 'VLAN', 'CoS', 'DSCP', 'Best'], lrows);
    }

    // ---- Telephony OUI table + settings: only in OUI mode (adminState=3) ----
    // The OUI sections are structural scaffold, so a mode change that crosses the
    // OUI boundary must rebuild them. On a reconcile the scaffold isn't re-run, so
    // if visibility changed since the last full paint, request a full repaint.
    const ouiMode = (scn('vlanVoiceAdminState') === 3);
    if (s._ktReconcile && p._voiceOuiShown !== ouiMode) { repaintPanel(s, 'vlans'); return; }
    p._voiceOuiShown = ouiMode;
    if (!ouiMode) { p._voiceOuiCfg = null; }
    if (ouiMode) {
    // ---- Telephony OUI table (editable) ----
    const ouis = (h.voiceOUI || []);
    vsection('Telephony OUI', ouis.length ? ouis.length + ' entries' : '');
    if (!s._ktReconcile && s.target) body.appendChild(addControl('Add OUI', () => openVoiceOuiForm(s)));
    if (ouis.length) {
      const orows = ouis.map((r) => {
        // Index is the 3-byte OUI prefix (OctetString). Decode to AA-BB-CC.
        const prefix = ouiIndexToStr(r.index);
        const descr = dv(r.vlanVoiceOUIBasedDescription);
        const cells = [{ v: prefix }, { v: descr }];
        if (s.target && r.index) {
          const del = actGroup([actBtnConfirm('Delete', (e) => {
            runButtonAction(e.currentTarget, {
              failLabel: 'Delete OUI',
              run: () => rowStatusDelete(s, VOICE.ouiRowStatus + '.' + r.index),
              ok: (res) => res && res.ok && !(res.body && res.body.error),
              onApplied: () => markConfigDirty(s), settle: () => voiceRefresh()
            });
          }, 'danger', 'Delete OUI ' + prefix)]);
          cells.push({ cellNode: del, sig: 'del' });
        }
        return { key: 'oui:' + (r.index || prefix), cells: cells };
      });
      mountInto(body, s, p, 'voiceOUI', ['OUI prefix', 'Description'].concat(s.target ? [''] : []), orows);
    } else if (!s._ktReconcile) { body.appendChild(el('div', 'card-sub', 'No OUI entries.')); }

    // ---- OUI settings (scalars, refreshed in place) ----
    if (!s._ktReconcile && s.target) {
      vsection('OUI settings');
      p._voiceOuiCfg = el('div', 'tbl-add'); body.appendChild(p._voiceOuiCfg);
    }
    if (p._voiceOuiCfg) {
      clear(p._voiceOuiCfg);
      const cos = scn('vlanVoiceOUIBasedAdminPriority'), remark = scn('vlanVoiceOUIBasedAdminRemark'), aging = scn('vlanVoiceOUIBasedAgingTimeout');
      const cosIn = el('input'); cosIn.type = 'number'; cosIn.min = '0'; cosIn.max = '7'; cosIn.style.width = '52px'; cosIn.value = String(cos != null ? cos : 0);
      const remarkChk = el('input'); remarkChk.type = 'checkbox'; remarkChk.checked = (remark === 1);
      const agingIn = el('input'); agingIn.type = 'number'; agingIn.min = '1'; agingIn.max = '43200'; agingIn.style.width = '72px'; agingIn.value = String(aging != null ? aging : 1);
      const apply = el('button', 'btn btn-small btn-blue', 'Apply'); apply.type = 'button'; apply.style.marginLeft = '6px';
      apply.addEventListener('click', (e) => {
        const nc = parseInt(cosIn.value, 10), na = parseInt(agingIn.value, 10), nr = remarkChk.checked ? 1 : 2;
        const vbs = [];
        if (Number.isFinite(nc) && nc >= 0 && nc <= 7 && nc !== cos) vbs.push({ oid: VOICE.ouiPriority + '.0', type: 'Integer', value: nc });
        if (nr !== (remark === 1 ? 1 : 2)) vbs.push({ oid: VOICE.ouiRemark + '.0', type: 'Integer', value: nr });
        if (Number.isFinite(na) && na >= 1 && na <= 43200 && na !== aging) vbs.push({ oid: VOICE.ouiAging + '.0', type: 'Integer', value: na });
        if (!vbs.length) return;
        runButtonAction(e.currentTarget, {
          failLabel: 'Apply OUI settings',
          run: () => snmpSetResult(s, vbs),
          ok: (res) => res && res.ok && !(res.body && res.body.error),
          onApplied: () => markConfigDirty(s), settle: () => voiceRefresh()
        });
      });
      p._voiceOuiCfg.appendChild(el('span', 'sw-mini-label', 'CoS/802.1p')); p._voiceOuiCfg.appendChild(cosIn);
      const rl = el('label', 'sw-mini-label', 'Remark CoS'); rl.style.marginLeft = '8px'; rl.appendChild(remarkChk); p._voiceOuiCfg.appendChild(rl);
      p._voiceOuiCfg.appendChild(el('span', 'sw-mini-label', 'Aging (min)')); p._voiceOuiCfg.appendChild(agingIn);
      p._voiceOuiCfg.appendChild(apply);
    }
    } // end if (ouiMode)
  }
