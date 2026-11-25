  // =================================================================
  // 15-ipv4-addressing.js: IPv4 Addressing: interface addresses (VLAN SVIs
  // and routed ports, static or DHCP), IP routing and DNS.
  // =================================================================

  // =================================================================
  // IPv4 interface addresses. One editor for the address of any L3 interface
  // (a VLAN SVI or a routed port), its DHCP client, and the management lock.
  // =================================================================

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
  // A routable unicast IPv4: first octet 1-223, not loopback/link-local. Rules
  // out the 0.x / uninitialised placeholders a DHCP interface shows before it
  // has a lease.
  function isRealIp(ip) {
    const o = String(ip).split('.').map(Number);
    return o.length === 4 && o.every((n) => n >= 0 && n <= 255) && o[0] >= 1 && o[0] <= 223 && o[0] !== 127 && !(o[0] === 169 && o[1] === 254);
  }
  // Prefix length -> dotted netmask.
  function prefToMask(p) { p = Math.max(0, Math.min(32, p | 0)); const m = p === 0 ? 0 : (0xffffffff << (32 - p)) >>> 0; return [24, 16, 8, 0].map((sh) => (m >>> sh) & 0xff).join('.'); }
  // Dotted netmask -> prefix length.
  function maskToPref(mask) { const m = String(mask).split('.').map(Number); if (m.length !== 4) return null; let bits = 0; for (const o of m) bits += (o.toString(2).match(/1/g) || []).length; return bits; }


  // SVI IP editor: shows the current address (if any) and lets you set/replace
  // or remove it. Writing a management SVI wrong can cut access, so this reads
  // first and is explicit about what it will change.
  // The VLAN IPv4 (SVI) editor. Reads the address table, filters to real user
  // addresses on THIS VLAN's L3 interface (owner static/dhcp - internal/default
  // are system addresses and must be ignored, which is what produced the bogus
  // "0.193.134.170"), and offers Static or DHCP. When the VLAN has no SVI yet it
  // shows an "Add IPv4 SVI" button rather than a pre-filled form.
  //
  // The same editor serves a routed (no switchport) port: an L3 port carries its
  // address on its own ifIndex in the same rsIpAddrTable, exactly as an SVI
  // does, so only the wording differs. `iface` says what is being edited:
  // { name, noun, vlanId? } - see vlanIface() and l3Iface(). The management
  // lock below applies to both. `done` (optional) runs once a write has
  // settled - the IPv4 Addressing popouts pass their close.
  function vlanIface(vlan) { return { name: 'VLAN ' + vlan.id, noun: 'VLAN', vlanId: vlan.id, addLabel: 'Add IPv4 SVI' }; }
  async function buildSviEditor(s, iface, sviIfIndex, pane, done) {
    // The management SVI (carrying this app's connection) is read-only: changing
    // or removing its address would cut off access to the switch.
    if (isManagementIf(s, sviIfIndex)) {
      const cv = (c) => (c == null ? '' : (c.value !== undefined ? c.value : (c.display !== undefined ? c.display : c)));
      let ipLine = s.target.host;
      for (const a of ((s.health && s.health.sviAddrs) || [])) { if (String(a.index) === String(s.target.host)) { const m = String(cv(a.rsIpAdEntNetMask) || ''); const p = m ? m.split('.').reduce((n, o) => n + ((parseInt(o, 10) || 0).toString(2).match(/1/g) || []).length, 0) : null; ipLine = s.target.host + (p ? '/' + p : ''); break; } }
      pane.appendChild(el('div', 'aaa-sub', 'Management interface'));
      pane.appendChild(el('div', 'card-sub', 'This ' + iface.noun + '\u2019s IPv4 interface (' + ipLine + ') carries this app\u2019s connection to the switch. It is locked to prevent accidentally cutting off access.'));
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
      pane.appendChild(el('div', 'card-sub', iface.name + ' has no IPv4 interface configured.'));
      if (sviIfIndex == null) pane.appendChild(el('div', 'sw-err', 'Could not resolve this ' + iface.noun + '\u2019s L3 ifIndex (needed to add an address).'));
      const addRow = el('div', 'snmp-form-actions'); addRow.style.marginTop = '10px';
      const addBtn = el('button', 'btn btn-small btn-blue', iface.addLabel || 'Add IPv4 address'); addBtn.type = 'button';
      addBtn.disabled = sviIfIndex == null;
      addBtn.addEventListener('click', () => { clear(pane); sviConfigForm(s, iface, sviIfIndex, pane, null, false, done); });
      addRow.appendChild(addBtn); pane.appendChild(addRow);
      return;
    }
    // Existing SVI: show the config form pre-filled.
    sviConfigForm(s, iface, sviIfIndex, pane, cur, dhcpOn, done);
  }


  // The SVI configuration form - Static (IP + prefix) or DHCP.
  function sviConfigForm(s, iface, sviIfIndex, pane, cur, dhcpOn, done) {
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
        onApplied: () => { markConfigDirty(s, [modeSel, ipIn, prefIn]); if (iface.vlanId != null) s._vlanFlash = iface.vlanId; },
        settle: () => refreshSvi(s).then(() => { if (done) done(); })
      });
    }, { when: () => !!(cur || dhcpOn), confirmText: 'Tap again to change the address' });
    form.appendChild(actions); form.appendChild(msg);
    // Remove button when something is configured.
    if (cur || dhcpOn) {
      const rm = actBtnConfirm('Remove IPv4', (e) => {
        clear(msg);
        runButtonAction(e.currentTarget, {
          failLabel: 'Remove IPv4',
          run: () => removeIfAddress(s, sviIfIndex, cur, dhcpOn),
          ok: (r) => r && r.ok,
          error: (r) => { msg.appendChild(el('div', 'sw-err', 'Could not remove the IPv4 interface \u2014 ' + ((r && r.error) || 'failed'))); return (r && r.error) || 'failed'; },
          onApplied: () => markConfigDirty(s),
          settle: () => refreshSvi(s).then(() => { if (done) { done(); return; } const pop = pane.closest && pane.closest('.port-detail-back'); if (pop) pop.remove(); })
        });
      }, 'danger', 'Remove this ' + iface.noun + '\u2019s IPv4 interface');
      const rmRow = el('div', 'snmp-form-actions'); rmRow.style.marginTop = '8px'; rmRow.appendChild(rm);
      form.appendChild(rmRow);
    }
    pane.appendChild(form);
  }

  // Remove one interface's IPv4 configuration: its DHCP client (destroy(6))
  // when dhcpOn, then its static address row cur.ip (invalid(2)) when cur.
  // Returns { ok, error } for runButtonAction. Unlike teardownSvi it stops at
  // and reports the first rejection, because the user asked for this change.
  async function removeIfAddress(s, ifIndex, cur, dhcpOn) {
    try {
      if (dhcpOn) await snmpSet(s, { oid: DHCP_CL.status + '.' + ifIndex, type: 'Integer', value: 6 });
      if (cur) await snmpSet(s, { oid: SVI_IP.status + '.' + cur.ip, type: 'Integer', value: 2 });
      return { ok: true };
    } catch (err) { return { ok: false, error: err.message }; }
  }

  // Remove an SVI's IPv4 configuration for a given ifIndex: any static address
  // (rsIpAdEntStatus = invalid(2)) and the DHCP client (rlDhcpClActionStatus =
  // destroy(6)). Used before deleting a VLAN, and before a routed port goes back to a switchport.
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

  // What an L3 interface is called, from its ifIndex: a VLAN SVI (its row in
  // the interface table is named after the VLAN id, as vlanSviIfIndex reads
  // it) or a port (named like gi1/0/3). Returns an iface for buildSviEditor.
  function l3Iface(s, ifIndex) {
    const h = s.health || {};
    const cv = (c) => (c == null ? '' : String(c.display !== undefined && c.display !== null ? c.display : (c.value !== undefined ? c.value : c)));
    const row = (h.interfaces || []).find((r) => String(r.index) === String(ifIndex));
    const nm = row ? cv(row.rlifPresentName).trim() : '';
    if (/^\d+$/.test(nm) && (h.vlans || []).some((v) => String(v.index) === nm)) return vlanIface({ id: Number(nm) });
    if (nm) return { name: 'Port ' + nm, noun: 'port' };
    return { name: 'ifIndex ' + ifIndex, noun: 'interface' };
  }

  // The user IPv4 addresses on the switch's L3 interfaces: rsIpAddrTable rows
  // owned static(1) or dhcp(2) - internal(3)/default(4) are the switch's own
  // system addresses. A DHCP interface without a lease shows a 0.x
  // placeholder, reported as no address yet. Same source and filter as the
  // VLAN table's IPv4 column and the Interfaces table's routed-port address.
  function ipv4Addresses(s) {
    const cv = (c) => (c == null ? '' : (c.value !== undefined ? c.value : (c.display !== undefined ? c.display : c)));
    const out = [];
    for (const a of ((s.health && s.health.sviAddrs) || [])) {
      const owner = parseInt(cv(a.rsIpAdEntOwner), 10);
      if (owner !== 1 && owner !== 2) continue;
      const ip = String(a.index);
      const real = isRealIp(ip);
      if (owner === 1 && !real) continue;
      const ifIndex = parseInt(cv(a.rsIpAdEntIfIndex), 10);
      if (!Number.isFinite(ifIndex)) continue;
      const mask = String(cv(a.rsIpAdEntNetMask) || '');
      out.push({ ip, real, owner, ifIndex, mask, pref: real && mask ? maskToPref(mask) : null });
    }
    return out;
  }

  // The interfaces an address can be added to: every VLAN, and every routed
  // (no switchport) port, that has no user address yet. A VLAN's SVI ifIndex
  // may not be known until it is read (ifIndex null -> vlanSviIfIndex).
  function ipv4AddCandidates(s) {
    const h = s.health || {};
    const cv = (c) => (c == null ? '' : String(c.value !== undefined ? c.value : (c.display !== undefined && c.display !== null ? c.display : c)));
    const used = new Set(ipv4Addresses(s).map((a) => a.ifIndex));
    const sviByVlan = new Map();
    for (const r of (h.interfaces || [])) {
      const nm = cv(r.rlifPresentName).trim();
      if (/^\d+$/.test(nm)) sviByVlan.set(nm, parseInt(r.index, 10));
    }
    const out = [];
    for (const v of (h.vlans || [])) {
      const ifx = sviByVlan.has(String(v.index)) ? sviByVlan.get(String(v.index)) : null;
      if (ifx != null && (used.has(ifx) || isManagementIf(s, ifx))) continue;
      out.push({ iface: vlanIface({ id: Number(v.index) }), ifIndex: ifx });
    }
    for (const r of (h.portL2L3 || [])) {
      if (parseInt(cv(r.vlanSwitchPortModeCategory), 10) !== 2) continue;   // 2 = l3 routed
      const ifx = parseInt(r.index, 10);
      if (!Number.isFinite(ifx) || used.has(ifx) || isManagementIf(s, ifx)) continue;
      out.push({ iface: l3Iface(s, ifx), ifIndex: ifx });
    }
    return out;
  }

  // Edit one interface's address: the shared editor in its own popout, which
  // closes once a change has settled (the table then shows the result).
  function openIpv4Editor(s, iface, ifIndex) {
    openTabbedPopout(s, iface.name + ' \u00b7 IPv4', [{ label: 'IPv4', fill: (pane, close) => {
      buildSviEditor(s, iface, ifIndex, pane, close);
    } }], []);
  }

  // Add an address: pick the interface, then the shared Static/DHCP form.
  function openIpv4AddForm(s) {
    const cands = ipv4AddCandidates(s);
    openTabbedPopout(s, 'Add IPv4 address', [{ label: 'Add IPv4 address', fill: (pane, close) => {
      if (!cands.length) {
        pane.appendChild(el('div', 'card-sub', 'Every VLAN and routed port already has an IPv4 address. Create a VLAN, or make a port routed on its Switchport tab, to add another.'));
        return;
      }
      const pick = el('div', 'snmp-form acl-form');
      const sec = formSection('Interface');
      const sel = selectInput(cands.map((c, i) => ({ label: c.iface.name, value: String(i) })), '0');
      sec.body.appendChild(field('Interface', sel));
      pick.appendChild(sec.sec);
      pane.appendChild(pick);
      const formWrap = el('div');
      pane.appendChild(formWrap);
      let token = 0;   // a newer pick wins over a slower ifIndex read
      const show = async () => {
        const mine = ++token;
        const c = cands[parseInt(sel.value, 10)];
        clear(formWrap);
        let ifx = c.ifIndex;
        if (ifx == null && c.iface.vlanId != null) {
          formWrap.appendChild(el('div', 'card-sub', 'Reading IPv4 interface\u2026'));
          ifx = await vlanSviIfIndex(s, c.iface.vlanId);
          if (mine !== token) return;
          clear(formWrap);
        }
        if (ifx == null) { formWrap.appendChild(el('div', 'sw-err', 'Could not resolve this ' + c.iface.noun + '\u2019s L3 ifIndex (needed to add an address).')); return; }
        // A VLAN read just now may turn out to carry the management address:
        // the shared editor then shows the lock instead of a form.
        if (isManagementIf(s, ifx)) { buildSviEditor(s, c.iface, ifx, formWrap, close); return; }
        sviConfigForm(s, c.iface, ifx, formWrap, null, false, close);
      };
      sel.addEventListener('change', show);
      show();
    } }], []);
  }

  // ===========================================================================
  // IPv4 Addressing panel (panel key 'routing', kept so saved dashboard
  // layouts still place it). Read + write: the IPv4 interfaces section above
  // (every VLAN SVI and routed port address), global L3 status, the forwarding
  // table (paginated), editable static routes, DNS client status, nameservers
  // and static host mappings. Uses the keyed-table engine and runButtonAction
  // like every other module. OIDs are the standard ipForwarding/ipCidrRouteTable
  // and the Cisco rlIpStaticRoute/rlDnsCl tables (see health.js walks).
  //
  // Static route index (rlIpStaticRouteTable, plain IPv4): the row is addressed
  // by <dest>.<mask>.<tos>.<nextHop>; create via RowStatus createAndGo(4) with
  // Type set, delete via destroy(6). DNS domain/host/nameserver rows use their
  // own RowStatus with the indices documented inline below.
  // ===========================================================================
  const ROUTE_PROTO = { 1: 'other', 2: 'local', 3: 'netmgmt', 4: 'icmp', 5: 'egp',
    6: 'ggp', 7: 'hello', 8: 'rip', 9: 'isIs', 10: 'esIs', 11: 'ciscoIgrp',
    12: 'bbnSpfIgp', 13: 'ospf', 14: 'bgp' };
  const ROUTE_TYPE = { 1: 'other', 2: 'reject', 3: 'local', 4: 'remote' };
  const STATIC_ROUTE_TYPE = { 1: 'other', 2: 'reject', 3: 'local', 4: 'remote' };
  const DNS_ROUTE = {
    forwarding: '1.3.6.1.2.1.4.1',                       // ipForwarding scalar
    dnsEnable:  '1.3.6.1.4.1.9.6.1.101.93.2',            // rlDnsClEnable scalar
    // rlIpStaticRouteTable columns (26.17.1.1.C)
    srDest: '1.3.6.1.4.1.9.6.1.101.26.17.1.1.1', srMask: '1.3.6.1.4.1.9.6.1.101.26.17.1.1.2', srNextHop: '1.3.6.1.4.1.9.6.1.101.26.17.1.1.4',
    srType: '1.3.6.1.4.1.9.6.1.101.26.17.1.1.6', srMetric: '1.3.6.1.4.1.9.6.1.101.26.17.1.1.5',
    srRowStatus: '1.3.6.1.4.1.9.6.1.101.26.17.1.1.9',
    // rlDnsClDomainNameTable (93.3.1.C), indexed by the domain name as OID
    domOwner: '1.3.6.1.4.1.9.6.1.101.93.3.1.2', domRowStatus: '1.3.6.1.4.1.9.6.1.101.93.3.1.3',
    // rlDnsClNamesTable (93.6.1.C) static host mapping, indexed by name + index
    hostAddr: '1.3.6.1.4.1.9.6.1.101.93.6.1.4', hostRowStatus: '1.3.6.1.4.1.9.6.1.101.93.6.1.5',
    // rlDnsResConfigSbeltInetTable (93.9.1.C) - the Cisco WRITABLE nameserver
    // table (the standard MIB-II sbelt at 32.2.1.1.4 is read-only on this model).
    // Index: AddrType . <len>.<addr bytes> . SubTree(root=0) . Class(IN=1).
    nsInetName:   '1.3.6.1.4.1.9.6.1.101.93.9.1.3',   // rc: DnsName
    nsInetPref:   '1.3.6.1.4.1.9.6.1.101.93.9.1.5',   // rc: preference
    nsInetStatus: '1.3.6.1.4.1.9.6.1.101.93.9.1.8',   // rc: sbelt RowStatus (add path)
    // DNS-client-v2 servers table RowStatus - the delete path the switch accepts.
    v2ServerStatus: '1.3.6.1.4.1.9.6.1.101.93.15.1.8'
  };

  function paintRoutingPanel(s, body, p) {
    if (!s._ktReconcile) clear(body);
    const h = s.health;
    const dv = (c, fb) => (c == null ? (fb !== undefined ? fb : '') : (c.display !== undefined && c.display !== null ? c.display : (c.value !== undefined ? c.value : c)));
    const num = (c) => { const v = c && (c.value !== undefined ? c.value : c.display); const n = parseInt(v, 10); return Number.isFinite(n) ? n : null; };

    if (!h) { if (!s._ktReconcile) body.appendChild(el('div', 'card-sub', 'Waiting for data\u2026')); return; }

    // Load the module's on-demand tables once per visit (standard §4). Skip while
    // reconciling (we are mid-paint) to avoid re-entrancy.
    if (!s._ktReconcile) ensureRoutingLoaded(s);

    // Scaffolding helper (standard §2): builds a section title + optional add
    // control, and is a no-op during a reconcile pass so the keyed tables diff
    // in place without the panel being torn down.
    const section = (title, note, addLabel, onAdd) => {
      if (s._ktReconcile) return;
      const st = el('div', 'section-title', title);
      if (note) st.appendChild(el('span', 'st-note', note));
      body.appendChild(st);
      if (addLabel && s.target) body.appendChild(addControl(addLabel, onAdd));
    };
    const emptyNote = (msg) => { if (!s._ktReconcile) body.appendChild(el('div', 'card-sub', msg)); };
    const refresh = () => routingRefresh(s);   // single shared refresh (standard §5)

    // ---- IPv4 interfaces: the address of every VLAN SVI and routed port ----
    // From sviAddrs (periodic walk), so nothing extra is fetched. A row opens
    // that interface's editor (static or DHCP); Delete removes the address or
    // turns its DHCP client off. The management interface is locked (§B6).
    const addrs = ipv4Addresses(s);
    section('IPv4 interfaces', addrs.length ? addrs.length + ' address(es)' : '', 'Add IPv4 address', () => openIpv4AddForm(s));
    if (addrs.length) {
      const arows = addrs.map((a) => {
        const iface = l3Iface(s, a.ifIndex);
        const cells = [
          { v: iface.name, click: s.target ? { open: () => openIpv4Editor(s, iface, a.ifIndex) } : undefined },
          { v: a.real ? a.ip : '\u2014' },
          { v: a.pref != null ? '/' + a.pref : '' },
          { v: a.owner === 2 ? (a.real ? 'dhcp' : 'dhcp (no lease)') : 'static' } ];
        if (s.target) {
          if (isManagementIf(s, a.ifIndex)) {
            const locked = el('span', 'card-sub'); locked.textContent = '\uD83D\uDD12 locked';
            locked.title = 'This address carries this app\u2019s connection to the switch; changing or removing it could cut off access, so it is locked.';
            cells.push({ cellNode: locked, sig: 'locked' });
          } else {
            const dhcp = a.owner === 2;
            const del = actGroup([actBtnConfirm('Delete', (e) => {
              runButtonAction(e.currentTarget, {
                failLabel: 'Delete address',
                run: () => removeIfAddress(s, a.ifIndex, dhcp ? null : { ip: a.ip }, dhcp),
                ok: (r) => r && r.ok,
                error: (r) => (r && r.error) || 'the switch rejected it',
                onApplied: () => markConfigDirty(s),
                settle: () => refreshSvi(s)
              });
            }, 'danger', dhcp ? 'Turn off DHCP on ' + iface.name : 'Delete ' + a.ip + ' from ' + iface.name)]);
            cells.push({ cellNode: del, sig: 'del' });
          }
        }
        return { key: 'ip:' + a.ip + '@' + a.ifIndex, cells: cells };
      });
      mountInto(body, s, p, 'ipv4Addrs', ['Interface', 'Address', 'Prefix', 'Source'].concat(s.target ? [''] : []), arows);
    } else { emptyNote('No IPv4 addresses configured.'); }

    // ---- Global L3 status ----
    // The pill reads a scalar, so its VALUE can change on a reconcile even though
    // its DOM structure does not. Build the container once (full paint) and keep
    // a handle on it; refresh its contents every pass (including reconcile) so
    // the status updates in place without a structural change (no scroll jump).
    if (!s._ktReconcile) {
      section('Global L3 status');
      p._l3Line = el('div', 'card-sub');
      body.appendChild(p._l3Line);
    }
    if (p._l3Line) {
      const fwd = num(h.scalars && h.scalars.ipForwarding);
      clear(p._l3Line);
      p._l3Line.appendChild(el('span', 'pill ' + (fwd === 1 ? 'good' : 'idle'), fwd === 1 ? 'IP routing ON' : (fwd === 2 ? 'IP routing OFF' : 'unknown')));
    }

    // ---- Routing table (read-only, paginated) ----
    const routes = (h.routeTable || []);
    section('Routing table', routes.length ? routes.length + ' route(s)' : 'none');
    if (routes.length) {
      const rrows = routes.map((r) => {
        const dest = dv(r.ipCidrRouteDest), mask = dv(r.ipCidrRouteMask), nh = dv(r.ipCidrRouteNextHop);
        return { key: 'rt:' + dest + '/' + mask + '>' + nh, cells: [
          { v: dest }, { v: mask }, { v: nh || '\u2014' }, { v: dv(r.ipCidrRouteIfIndex) },
          { v: ROUTE_PROTO[num(r.ipCidrRouteProto)] || dv(r.ipCidrRouteProto) },
          { v: ROUTE_TYPE[num(r.ipCidrRouteType)] || dv(r.ipCidrRouteType) } ] };
      });
      mountInto(body, s, p, 'routeTable',
        ['Destination', 'Mask', 'Next hop', 'Interface', 'Protocol', 'Type'], rrows, { pageSize: 50 });
    } else { emptyNote('No routes reported.'); }

    // ---- Static routes (editable) ----
    const statics = (h.staticRoutes || []);
    section('Static routes', statics.length ? statics.length + ' configured' : '', 'Add static route', () => openStaticRouteForm(s));
    if (statics.length) {
      const srows = statics.map((r) => {
        const dest = dv(r.rlIpStaticRouteDest), mask = dv(r.rlIpStaticRouteMask), nh = dv(r.rlIpStaticRouteNextHop);
        const cells = [
          { v: dest }, { v: mask }, { v: nh || '\u2014' },
          { v: STATIC_ROUTE_TYPE[num(r.rlIpStaticRouteType)] || dv(r.rlIpStaticRouteType) },
          { v: dv(r.rlIpStaticRouteMetric) },
          { pill: true, v: num(r.rlIpStaticRouteForwardingStatus) === 1 ? 'active' : 'inactive' } ];
        if (s.target) {
          const risk = routeDeleteRisk(s, dest, mask, nh);
          if (risk) {
            // Locked: deleting this route could cut the app's SNMP path. Show a
            // disabled control with the reason, same protection as the mgmt SVI.
            const locked = el('span', 'card-sub'); locked.textContent = '\uD83D\uDD12 locked'; locked.title = risk;
            cells.push({ cellNode: locked, sig: 'locked' });
          } else {
            const del = actGroup([actBtnConfirm('Delete', (e) => {
              runButtonAction(e.currentTarget, {
                failLabel: 'Delete route',
                run: () => rowStatusDelete(s, DNS_ROUTE.srRowStatus + '.' + ipToOidIndex(dest) + '.' + ipToOidIndex(mask) + '.0.' + ipToOidIndex(nh)),
                ok: (res) => res && res.ok && !(res.body && res.body.error),
                onApplied: () => markConfigDirty(s), settle: () => routingRefresh(s)
              });
            }, 'danger', 'Delete static route ' + dest)]);
            cells.push({ cellNode: del, sig: 'del' });
          }
        }
        return { key: 'sr:' + dest + '/' + mask + '>' + nh, cells: cells };
      });
      const cols = ['Destination', 'Mask', 'Next hop', 'Type', 'Metric', 'Status'].concat(s.target ? [''] : []);
      mountInto(body, s, p, 'staticRoutes', cols, srows);
    } else { emptyNote('No static routes configured.'); }

    // ---- DNS client status ----
    // Same as L3 status: a scalar-driven pill + a toggle whose label depends on
    // the scalar. Stable container built once; contents refreshed every pass so
    // the pill and the toggle label update in place after a toggle write.
    if (!s._ktReconcile) {
      section('DNS client');
      p._dnsRow = el('div', 'tbl-add');
      body.appendChild(p._dnsRow);
    }
    if (p._dnsRow) {
      const en = num(h.scalars && h.scalars.rlDnsClEnable);
      clear(p._dnsRow);
      if (s.target) {
        // The button label and its colour carry the state: Disable (red = this
        // action turns a thing off) when on, Enable (green = default action) when
        // off. No separate status pill - the button already says which way it goes.
        const on = en === 1;
        const toggle = el('button', 'btn btn-small' + (on ? ' btn-danger' : ''), on ? 'Disable DNS' : 'Enable DNS'); toggle.type = 'button';
        toggle.addEventListener('click', (e) => {
          runButtonAction(e.currentTarget, {
            failLabel: 'DNS toggle',
            run: () => snmpSetResult(s, { oid: DNS_ROUTE.dnsEnable + '.0', type: 'Integer', value: on ? 2 : 1 }),
            ok: (res) => res && res.ok && !(res.body && res.body.error),
            onApplied: () => markConfigDirty(s), settle: () => refresh()
          });
        });
        p._dnsRow.appendChild(toggle);
      }
    }

    // ---- DNS domains / search suffixes (editable) ----
    const domains = (h.dnsDomains || []);
    section('Domain / search list', domains.length ? domains.length + ' entries' : '', 'Add domain', () => openDnsDomainForm(s));
    if (domains.length) {
      const drows = domains.map((r) => {
        const name = dnsNameIndexToStr(dv(r.index));   // domain name is the DnsNameAsIndex
        const cells = [{ v: name }];
        if (s.target && r.index) {
          // Delete by the row's authoritative index (what the switch stores),
          // consistent with the host and nameserver deletes.
          const del = actGroup([actBtnConfirm('Delete', (e) => {
            runButtonAction(e.currentTarget, {
              failLabel: 'Delete domain',
              run: () => rowStatusDelete(s, DNS_ROUTE.domRowStatus + '.' + r.index),
              ok: (res) => res && res.ok && !(res.body && res.body.error),
              onApplied: () => markConfigDirty(s), settle: () => routingRefresh(s)
            });
          }, 'danger', 'Delete domain ' + name)]);
          cells.push({ cellNode: del, sig: 'del' });
        }
        return { key: 'dom:' + (r.index || name), cells: cells };
      });
      mountInto(body, s, p, 'dnsDomains', ['Domain'].concat(s.target ? [''] : []), drows);
    }

    // ---- Nameservers (static sbelt + DHCP-learned) ----
    // Nameservers come from the DNS-client-v2 servers table (93.15) - the table
    // the CLI "ip name-server" uses and the only one whose RowStatus delete the
    // switch accepts. Everything is in the row index (address, source 1=static /
    // 3=dhcpv6 / 4=dhcpv4, preference); only RowStatus is a readable value.
    const serversV2 = (h.dnsServersV2 || []);
    section('Nameservers', serversV2.length + ' total', 'Add nameserver', () => openNameserverForm(s));
    if (serversV2.length) {
      const nrows = [];
      serversV2.forEach((r, i) => {
        const info = dnsV2ServerIndex(r.index);
        const addr = info ? info.addr : dv(r.index);
        const isStatic = info ? info.source === 1 : true;    // 1=static, 3/4=dhcp
        const source = (info && info.source !== 1) ? 'dhcp' : 'static';
        const cells = [{ v: addr }, { v: source }, { v: info ? String(info.pref) : '' }];
        if (s.target && r.index && isStatic) {
          // Delete via the v2 RowStatus with the row's own index (rule 6: the
          // authoritative index the switch stores). This is the path the switch
          // accepts, unlike the sbelt table.
          const del = actGroup([actBtnConfirm('Delete', (e) => {
            runButtonAction(e.currentTarget, {
              failLabel: 'Delete nameserver',
              run: () => rowStatusDelete(s, DNS_ROUTE.v2ServerStatus + '.' + r.index),
              ok: (res) => res && res.ok && !(res.body && res.body.error),
              onApplied: () => markConfigDirty(s), settle: () => routingRefresh(s)
            });
          }, 'danger', 'Delete nameserver ' + addr)]);
          cells.push({ cellNode: del, sig: 'del' });
        } else if (s.target) {
          // A dhcp-sourced server is switch-owned; no SNMP delete.
          const locked = el('span', 'card-sub'); locked.textContent = '\uD83D\uDD12';
          locked.title = 'DHCP-provided server (switch-owned) - remove it by changing DHCP.';
          cells.push({ cellNode: locked, sig: 'locked' });
        }
        nrows.push({ key: 'ns:' + (r.index || addr) + ':' + i, cells: cells });
      });
      const cols = ['Address', 'Source', 'Pref'].concat(s.target ? [''] : []);
      mountInto(body, s, p, 'nameservers', cols, nrows);
    } else { emptyNote('No nameservers configured or learned.'); }

    // ---- Static host mappings (editable) ----
    const hosts = (h.dnsHosts || []);
    section('Static host mappings', hosts.length ? hosts.length + ' entries' : '', 'Add host mapping', () => openDnsHostForm(s));
    if (hosts.length) {
      const hrows = hosts.map((r) => {
        // The row's full index (DnsNameAsIndex . Owner . Index) is authoritative -
        // use it for delete rather than reconstructing it. The readable name is the
        // DnsNameAsIndex component at the front.
        const name = dnsNameIndexToStr(dv(r.index));
        const addr = dv(r.rlDnsClNamesAddr);
        const cells = [{ v: name }, { v: addr }];
        if (s.target && r.index) {
          const del = actGroup([actBtnConfirm('Delete', (e) => {
            runButtonAction(e.currentTarget, {
              failLabel: 'Delete host',
              run: () => rowStatusDelete(s, DNS_ROUTE.hostRowStatus + '.' + r.index),
              ok: (res) => res && res.ok && !(res.body && res.body.error),
              onApplied: () => markConfigDirty(s), settle: () => routingRefresh(s)
            });
          }, 'danger', 'Delete host mapping ' + name)]);
          cells.push({ cellNode: del, sig: 'del' });
        }
        return { key: 'host:' + (r.index || name), cells: cells };
      });
      mountInto(body, s, p, 'dnsHosts', ['Host name', 'IP address'].concat(s.target ? [''] : []), hrows);
    }
  }

  // --- Add-forms for the routing/DNS writes ---
  // The single refresh for the routing/DNS module. Delegates to refreshTables -
  // the canonical table-refresh path every other module uses - so it inherits
  // the proven behavior: it captures/restores scroll around the reconcile (no
  // bounce), defers when a full collection or a write is already in flight (no
  // colliding double-walk), reconciles the keyed panel in place, and returns a
  // promise that resolves once the UI has reflected the change (so a button
  // action spins until then). The module's tables are on-demand, which only
  // means they are not in the periodic walk; an explicit refreshTables request
  // fetches them normally. Marking _routingFetchedAt keeps the panel's lazy-load
  // guard from firing a redundant fetch on the reconcile paint.
  // Includes 'scalars' so the global L3 status and DNS-client status (both read
  // from scalars, not tables) update after a toggle - refreshTables merges the
  // scalar batch and the reconcile below repaints the scalar sections.
  const ROUTING_TABLES = ['routeTable', 'staticRoutes', 'dnsDomains', 'dnsServersV2', 'dnsHosts', 'scalars'];
  function routingRefresh(s) {
    if (!s.target) return Promise.resolve();
    s._routingFetchedAt = Date.now();
    return refreshTables(s, ROUTING_TABLES);
  }
  // One-per-visit on-demand loader (standard §4): guard with both an in-flight
  // flag and a 30s timestamp so an empty result does not re-fetch every repaint.
  function ensureRoutingLoaded(s) {
    if (s._routingFetching || !s.target) return;
    if (Date.now() - (s._routingFetchedAt || 0) < 30000) return;
    s._routingFetching = true;
    routingRefresh(s).then(() => { s._routingFetching = false; },
                          () => { s._routingFetching = false; });
  }

  // Would deleting this static route risk cutting the app's own SNMP path to the
  // switch? True for the default route (0.0.0.0/0) - the usual way off-subnet
  // traffic (including ours, when the app is not on the switch's local subnet)
  // leaves the switch - and for any route whose destination network contains the
  // management IP we are talking to. Those routes get their Delete locked, the
  // same protection VLAN delete gives the management SVI. Returns a reason string
  // to show, or '' if the route is safe to delete.
  function routeDeleteRisk(s, dest, mask, nextHop) {
    const host = s && s.target && s.target.host;
    if (!host) return '';
    const toInt = (ip) => { const o = String(ip || '').split('.').map((n) => parseInt(n, 10)); return (o.length === 4 && o.every((n) => n >= 0 && n <= 255)) ? ((o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3]) >>> 0 : null; };
    const d = toInt(dest), m = toInt(mask), h = toInt(host);
    // The default route: destination and mask both 0.0.0.0.
    if (d === 0 && m === 0) return 'the default route (0.0.0.0/0) carries this app\u2019s traffic to the switch; deleting it could cut off SNMP access, so it is locked.';
    // A route whose network contains the management IP (dest == host & mask).
    if (d != null && m != null && h != null && (h & m) === (d & m) && m !== 0) {
      return 'this route covers the management IP (' + host + ') this app uses to reach the switch; deleting it could cut off access, so it is locked.';
    }
    return '';
  }

  // DNS write diagnostic. Every DNS write path (domain add, host add, nameserver
  // delete) is failing with a different SNMP error (NotWritable / NoCreation /
  // CommitFailed) even though the OIDs match the MIB, so rather than keep
  // inferring index structure we dump what the switch actually HAS: walk each DNS
  // subtree and print every raw OID suffix and value. The report shows the exact
  // index the switch uses for each existing row, which is what a create/delete
  // must match. Reuses /api/snmp/walk and the download() helper (no new endpoint).

  // Nameserver DELETE probe. The MIB says sbelt rows ARE deletable via SNMP
  // (confirmed by reading CISCOSB-dnscl.mib and rfc1612.mib), and the host-map
  // delete works on this firmware - yet destroy(6) on the sbelt row returns
  // CommitFailed. Rather than guess the right teardown, this tries each documented
  // variant in order, stops at the first that succeeds, and reports every result,
  // so the next run tells us exactly which delete path the switch accepts. It
  // targets ONE nameserver by address; if a variant succeeds the server is removed
  // (the desired outcome), if all fail the row is left intact.

  function openStaticRouteForm(s) {
    const tabs = [{ label: 'Add static route', fill: (pane, close) => {
      const form = el('div', 'snmp-form acl-form');
      const { sec, body } = formSection('Static route');
      const destIn = el('input'); destIn.type = 'text'; destIn.placeholder = '0.0.0.0 (destination network)';
      const maskIn = el('input'); maskIn.type = 'text'; maskIn.placeholder = '0.0.0.0 (mask)';
      const nhIn = el('input'); nhIn.type = 'text'; nhIn.placeholder = 'next-hop IP';
      const metricIn = el('input'); metricIn.type = 'number'; metricIn.min = '1'; metricIn.value = '1';
      body.appendChild(field('Destination', destIn));
      body.appendChild(field('Mask', maskIn));
      body.appendChild(field('Next hop', nhIn));
      body.appendChild(field('Metric', metricIn));
      form.appendChild(sec);
      const msg = el('div', 'port-detail-msg');
      const apply = el('button', 'btn btn-small btn-blue', 'Add route'); apply.type = 'button';
      apply.addEventListener('click', (e) => {
        const dest = destIn.value.trim(), mask = maskIn.value.trim(), nh = nhIn.value.trim();
        const metric = parseInt(metricIn.value, 10) || 1;
        if (!/^\d+\.\d+\.\d+\.\d+$/.test(dest) || !/^\d+\.\d+\.\d+\.\d+$/.test(mask) || !/^\d+\.\d+\.\d+\.\d+$/.test(nh)) {
          clear(msg); msg.appendChild(el('div', 'sw-err', 'Destination, mask and next hop must all be valid IPv4 addresses.')); return;
        }
        // Index = dest.mask.tos(0).nextHop; createAndGo(4) with type remote(4).
        const suffix = ipToOidIndex(dest) + '.' + ipToOidIndex(mask) + '.0.' + ipToOidIndex(nh);
        runButtonAction(e.currentTarget, {
          failLabel: 'Add route',
          run: () => snmpSetResult(s, [
            { oid: '1.3.6.1.4.1.9.6.1.101.26.17.1.1.6.' + suffix, type: 'Integer', value: 4 },   // type=remote
            { oid: '1.3.6.1.4.1.9.6.1.101.26.17.1.1.5.' + suffix, type: 'Integer', value: metric },
            { oid: '1.3.6.1.4.1.9.6.1.101.26.17.1.1.9.' + suffix, type: 'Integer', value: 4 }    // RowStatus createAndGo
          ]),
          ok: (res) => res && res.ok && !(res.body && res.body.error),
          onApplied: () => markConfigDirty(s),
          settle: () => routingRefresh(s).then(() => close())
        });
      });
      const row = el('div', 'tbl-add'); row.appendChild(apply);
      form.appendChild(row); form.appendChild(msg);
      pane.appendChild(form);
    } }];
    openTabbedPopout(s, 'Add static route', tabs, []);
  }

  function openDnsDomainForm(s) {
    const tabs = [{ label: 'Add domain', fill: (pane, close) => {
      const form = el('div', 'snmp-form acl-form');
      const { sec, body } = formSection('Domain / search suffix');
      const nameIn = el('input'); nameIn.type = 'text'; nameIn.placeholder = 'example.com';
      body.appendChild(field('Domain name', nameIn));
      form.appendChild(sec);
      const msg = el('div', 'port-detail-msg');
      const apply = el('button', 'btn btn-small btn-blue', 'Add domain'); apply.type = 'button';
      apply.addEventListener('click', (e) => {
        const name = nameIn.value.trim();
        if (!name) { clear(msg); msg.appendChild(el('div', 'sw-err', 'Enter a domain name.')); return; }
        const suffix = dnsNameIndex(name);
        runButtonAction(e.currentTarget, {
          failLabel: 'Add domain',
          // Set the mandatory Owner column WITH createAndGo in one PDU - a bare
          // RowStatus set returns NotWritable (the diagnostic showed the add of a
          // nameserver only worked when its columns were set together). Owner
          // static(1) marks it a user-defined entry.
          run: () => snmpSetResult(s, [
            { oid: DNS_ROUTE.domOwner + '.' + suffix, type: 'Integer', value: 1 },       // Owner = static
            { oid: DNS_ROUTE.domRowStatus + '.' + suffix, type: 'Integer', value: 4 }     // createAndGo
          ]),
          ok: (res) => res && res.ok && !(res.body && res.body.error),
          onApplied: () => markConfigDirty(s),
          settle: () => routingRefresh(s).then(() => close())
        });
      });
      const row = el('div', 'tbl-add'); row.appendChild(apply);
      form.appendChild(row); form.appendChild(msg);
      pane.appendChild(form);
    } }];
    openTabbedPopout(s, 'Add domain', tabs, []);
  }

  function openNameserverForm(s) {
    const tabs = [{ label: 'Add nameserver', fill: (pane, close) => {
      const form = el('div', 'snmp-form acl-form');
      const { sec, body } = formSection('Nameserver');
      const addrIn = el('input'); addrIn.type = 'text'; addrIn.placeholder = '8.8.8.8';
      body.appendChild(field('Server IP', addrIn));
      form.appendChild(sec);
      const msg = el('div', 'port-detail-msg');
      const apply = el('button', 'btn btn-small btn-blue', 'Add nameserver'); apply.type = 'button';
      apply.addEventListener('click', (e) => {
        const addr = addrIn.value.trim();
        const nsIdx = nameserverIndex(addr);
        if (!nsIdx) { clear(msg); msg.appendChild(el('div', 'sw-err', 'Enter a valid IPv4 address.')); return; }
        // rlDnsResConfigSbeltInetTable: create the row with its rc columns set in
        // the SAME PDU as createAndGo - a bare RowStatus set returns
        // InconsistentValue because the mandatory columns are not yet populated.
        // Pref 0 (default), Name = root ".".
        runButtonAction(e.currentTarget, {
          failLabel: 'Add nameserver',
          run: () => snmpSetResult(s, [
            { oid: DNS_ROUTE.nsInetName + '.' + nsIdx, type: 'OctetString', value: '.' },
            { oid: DNS_ROUTE.nsInetPref + '.' + nsIdx, type: 'Integer', value: 0 },
            { oid: DNS_ROUTE.nsInetStatus + '.' + nsIdx, type: 'Integer', value: 4 }   // createAndGo
          ]),
          ok: (res) => res && res.ok && !(res.body && res.body.error),
          onApplied: () => markConfigDirty(s),
          settle: () => routingRefresh(s).then(() => close())
        });
      });
      const row = el('div', 'tbl-add'); row.appendChild(apply);
      form.appendChild(row); form.appendChild(msg);
      pane.appendChild(form);
    } }];
    openTabbedPopout(s, 'Add nameserver', tabs, []);
  }

  function openDnsHostForm(s) {
    const tabs = [{ label: 'Add host mapping', fill: (pane, close) => {
      const form = el('div', 'snmp-form acl-form');
      const { sec, body } = formSection('Static host mapping');
      const nameIn = el('input'); nameIn.type = 'text'; nameIn.placeholder = 'hostname';
      const addrIn = el('input'); addrIn.type = 'text'; addrIn.placeholder = '10.0.0.5';
      body.appendChild(field('Host name', nameIn));
      body.appendChild(field('IP address', addrIn));
      form.appendChild(sec);
      const msg = el('div', 'port-detail-msg');
      const apply = el('button', 'btn btn-small btn-blue', 'Add mapping'); apply.type = 'button';
      apply.addEventListener('click', (e) => {
        const name = nameIn.value.trim(), addr = addrIn.value.trim();
        if (!name || !/^\d+\.\d+\.\d+\.\d+$/.test(addr)) { clear(msg); msg.appendChild(el('div', 'sw-err', 'Enter a host name and a valid IPv4 address.')); return; }
        // rlDnsClNamesTable index = name . index(1). Set the address + createAndGo.
        // Host index is DnsNameAsIndex . Owner . Index, exactly as the switch
        // stores it (decoded from a switch-created row: <wire-name> . 1 . 0).
        const suffix = dnsNameIndex(name) + '.1.0';
        runButtonAction(e.currentTarget, {
          failLabel: 'Add mapping',
          run: () => snmpSetResult(s, [
            { oid: '1.3.6.1.4.1.9.6.1.101.93.6.1.4.' + suffix, type: 'IpAddress', value: addr },
            { oid: '1.3.6.1.4.1.9.6.1.101.93.6.1.5.' + suffix, type: 'Integer', value: 4 }   // createAndGo
          ]),
          ok: (res) => res && res.ok && !(res.body && res.body.error),
          onApplied: () => markConfigDirty(s),
          settle: () => routingRefresh(s).then(() => close())
        });
      });
      const row = el('div', 'tbl-add'); row.appendChild(apply);
      form.appendChild(row); form.appendChild(msg);
      pane.appendChild(form);
    } }];
    openTabbedPopout(s, 'Add host mapping', tabs, []);
  }
