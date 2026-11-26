  // =================================================================
  // 30-switch-security.js: The Switching security panel and the port
  // popout's Security tab: IGMP and MLD snooping with the IGMP snooping
  // querier, DHCP snooping and ARP inspection (switch-security.js).
  // =================================================================

  // A keyed panel with a server-side reader (standard B1 family b2), like
  // Spanning tree settings. The data rides the server collection as
  // `security` (module-collection.js).
  //
  // s._secSet = { data, fetchedAt, loading, liveAt, collected }

  function secLoad(s) {
    s._secSet = s._secSet || {};
    const st = s._secSet;
    if (st.loading) return st.loading;
    st.fetchedAt = Date.now();
    st.liveAt = Date.now();
    st.loading = sidePost('/api/security/status', { target: s.target })
      .then((b) => { st.data = (b && !b.error) ? b : { error: (b && b.error) || 'no answer' }; })
      .finally(() => { st.loading = null; sideRepaint(s, 'security'); });
    return st.loading;
  }

  function secWrite(btn, s, url, payload, failLabel, onApplied) {
    return runButtonAction(btn, {
      failLabel,
      run: async () => {
        s.writeBusy = true;
        try { return await sidePost(url, Object.assign({ target: s.target }, payload)); }
        finally { s.writeBusy = false; }
      },
      ok: (r) => r && r.ok,
      error: (r) => (r && r.error) || 'unknown error',
      onApplied: (r) => { markConfigDirty(s); if (onApplied) onApplied(r); },
      settle: () => secLoad(s)
    });
  }

  const secOnOff = (v) => (v == null ? 'not reported' : (v ? 'on' : 'off'));
  const secPill = (v) => ({ pill: v ? 'good' : true, v: secOnOff(v) });
  const secQuerierAddr = (a) => (!a || a === '255.255.255.255' ? 'automatic' : a);
  const secPorts = (s, list) => (list && list.length ? list.map((n) => portNameOf(s, n)).join(', ') : '');
  const closePopoutOf = (pane) => () => { const pop = pane.closest && pane.closest('.port-detail-back'); if (pop) pop.remove(); };
  const onOffSelect = (v) => selectInput([{ label: 'on', value: '1' }, { label: 'off', value: '0' }], v ? '1' : '0');

  // A switch-wide on/off row: the setting, its state and a Turn on/off button.
  function secToggleRow(s, key, label, on, url, field, failWord, danger) {
    const btn = on == null ? { v: '' } : {
      cellNode: actGroup([on
        ? (danger ? actBtnConfirm : actBtn)('Turn off', (e) => secWrite(e.currentTarget, s, url, { [field]: false }, 'Turn off ' + failWord), danger ? 'danger' : undefined)
        : actBtn('Turn on', (e) => secWrite(e.currentTarget, s, url, { [field]: true }, 'Turn on ' + failWord))]),
      sig: on ? 'off' : 'on'
    };
    return { key, cells: [{ v: label }, secPill(on), btn] };
  }

  // ---- the multicast VLAN popout ----

  function buildSnoopVlan(s, vlan, pane) {
    const d = (s._secSet && s._secSet.data) || {};
    const v4 = ((d.igmp && d.igmp.vlans) || []).find((x) => x.vlan === vlan);
    const v6 = ((d.mld && d.mld.vlans) || []).find((x) => x.vlan === vlan);
    const q = ((d.igmp && d.igmp.queriers) || []).find((x) => x.vlan === vlan);
    if (!v4 && !v6 && !q) { pane.appendChild(el('div', 'card-sub', 'The switch reports no multicast settings for this VLAN.')); return; }
    const done = closePopoutOf(pane);

    if (v4) {
      const sec = formSection('IGMP snooping (IPv4)');
      const on = onOffSelect(v4.enabled);
      const leave = onOffSelect(v4.immediateLeave);
      const learn = onOffSelect(v4.routerLearn);
      sec.body.appendChild(field('Snooping', on));
      sec.body.appendChild(field('Immediate leave', leave));
      sec.body.appendChild(field('Learn router ports', learn));
      const { actions, apply } = applyActions('Apply');
      apply.addEventListener('click', (e) => {
        const body = { family: 'ipv4', vlan };
        if ((on.value === '1') !== !!v4.enabled) body.enabled = on.value === '1';
        if ((leave.value === '1') !== !!v4.immediateLeave) body.immediateLeave = leave.value === '1';
        if ((learn.value === '1') !== !!v4.routerLearn) body.routerLearn = learn.value === '1';
        if (Object.keys(body).length === 2) { toast('Nothing changed.', 'ok'); return; }
        secWrite(e.currentTarget, s, '/api/security/snoop-vlan', body, 'Apply', done);
      });
      sec.body.appendChild(actions);
      pane.appendChild(sec.sec);
    }

    if (q) {
      const sec = formSection('IGMP snooping querier');
      sec.body.appendChild(el('div', 'card-sub', q.active ? 'Sending queries now from ' + secQuerierAddr(q.activeAddress) + '.'
        : 'Not sending queries now.'));
      const on = onOffSelect(q.enabled);
      const addr = textInput(q.address && q.address !== '255.255.255.255' ? q.address : '', 'automatic'); addr.size = 16;
      const ver = selectInput([{ label: 'IGMPv2', value: '2' }, { label: 'IGMPv3', value: '3' }], String(q.version === 3 ? 3 : 2));
      const elect = onOffSelect(q.election);
      sec.body.appendChild(field('Querier', on));
      sec.body.appendChild(field('Source address', addr));
      sec.body.appendChild(field('Version', ver));
      sec.body.appendChild(field('Querier election', elect));
      sec.body.appendChild(el('div', 'card-sub', 'With no address the switch uses its own address on this VLAN. ' +
        'Election lets a router or another switch with a lower address take over.'));
      const { actions, apply } = applyActions('Apply');
      apply.addEventListener('click', (e) => {
        const a = addr.value.trim();
        if (a && !/^\d{1,3}(\.\d{1,3}){3}$/.test(a)) { toast('The address must be an IPv4 address like 192.0.2.1, or empty.', 'error'); return; }
        const body = { vlan };
        if ((on.value === '1') !== !!q.enabled) body.enabled = on.value === '1';
        if ((a || '255.255.255.255') !== (q.address || '255.255.255.255')) body.address = a;
        if (Number(ver.value) !== q.version) body.version = Number(ver.value);
        if ((elect.value === '1') !== !!q.election) body.election = elect.value === '1';
        if (Object.keys(body).length === 1) { toast('Nothing changed.', 'ok'); return; }
        secWrite(e.currentTarget, s, '/api/security/querier', body, 'Apply', done);
      });
      sec.body.appendChild(actions);
      pane.appendChild(sec.sec);
    }

    if (v6) {
      const sec = formSection('MLD snooping (IPv6)');
      const on = onOffSelect(v6.enabled);
      const leave = onOffSelect(v6.immediateLeave);
      sec.body.appendChild(field('Snooping', on));
      sec.body.appendChild(field('Immediate leave', leave));
      const { actions, apply } = applyActions('Apply');
      apply.addEventListener('click', (e) => {
        const body = { family: 'ipv6', vlan };
        if ((on.value === '1') !== !!v6.enabled) body.enabled = on.value === '1';
        if ((leave.value === '1') !== !!v6.immediateLeave) body.immediateLeave = leave.value === '1';
        if (Object.keys(body).length === 2) { toast('Nothing changed.', 'ok'); return; }
        secWrite(e.currentTarget, s, '/api/security/snoop-vlan', body, 'Apply', done);
      });
      sec.body.appendChild(actions);
      pane.appendChild(sec.sec);
    }
  }

  function secLoaded(s, pane, build) {
    const st = s._secSet || {};
    if (st.data && !st.data.error) { build(); return; }
    pane.appendChild(el('div', 'card-sub', 'Loading switching security settings…'));
    secLoad(s).then(() => {
      clear(pane);
      if (s._secSet.data && !s._secSet.data.error) build();
      else pane.appendChild(el('div', 'sw-err', 'Could not read switching security settings: ' + ((s._secSet.data && s._secSet.data.error) || 'no answer')));
    });
  }

  function secVlanTab(s, vlan) {
    return { label: 'Multicast', fill: (pane) => secLoaded(s, pane, () => buildSnoopVlan(s, vlan, pane)) };
  }

  // ---- the port popout's Security tab: trusted for DHCP snooping and ARP inspection ----

  function buildSecPort(s, ifx, pane) {
    const d = (s._secSet && s._secSet.data) || {};
    const dhcpT = ((d.dhcp && d.dhcp.trusted) || []).includes(ifx);
    const arpT = ((d.arp && d.arp.trusted) || []).includes(ifx);
    const sec = formSection('Trusted port');
    const dhcp = selectInput([{ label: 'trusted', value: '1' }, { label: 'not trusted', value: '0' }], dhcpT ? '1' : '0');
    const arp = selectInput([{ label: 'trusted', value: '1' }, { label: 'not trusted', value: '0' }], arpT ? '1' : '0');
    sec.body.appendChild(field('DHCP snooping', dhcp));
    sec.body.appendChild(field('ARP inspection', arp));
    sec.body.appendChild(el('div', 'card-sub', 'Trust the ports toward your DHCP server and your other switches. ' +
      'On a port that is not trusted, the switch drops DHCP server replies and checks ARP packets.'));
    const { actions, apply } = applyActions('Apply');
    apply.addEventListener('click', async (e) => {
      const btn = e.currentTarget;
      const wantD = dhcp.value === '1', wantA = arp.value === '1';
      if (wantD === dhcpT && wantA === arpT) { toast('Nothing changed.', 'ok'); return; }
      if (wantD !== dhcpT && wantA !== arpT) {
        const r = await sidePost('/api/security/dhcp-trust', { target: s.target, ifIndex: ifx, on: wantD });
        if (!r || !r.ok) { toast('DHCP snooping trust failed: ' + ((r && r.error) || 'unknown error'), 'error'); return; }
      }
      if (wantA !== arpT) secWrite(btn, s, '/api/security/arp-trust', { ifIndex: ifx, on: wantA }, 'Apply', closePopoutOf(pane));
      else secWrite(btn, s, '/api/security/dhcp-trust', { ifIndex: ifx, on: wantD }, 'Apply', closePopoutOf(pane));
    });
    sec.body.appendChild(actions);
    pane.appendChild(sec.sec);
    if (d.dhcp && !d.dhcp.enabled && d.arp && !d.arp.enabled) {
      pane.appendChild(el('div', 'card-sub', 'DHCP snooping and ARP inspection are both off, so trust has no effect until one is turned on.'));
    }
  }

  function secPortTab(s, ifx) {
    return { label: 'Security', fill: (pane) => secLoaded(s, pane, () => buildSecPort(s, ifx, pane)) };
  }

  // ---- the panel ----

  function paintSecurityPanel(s, body, p) {
    if (!s._ktReconcile) clear(body);
    if (!s.target) { if (!s._ktReconcile) body.appendChild(el('div', 'card-sub', 'Connect with SNMP to see the switching security settings.')); return; }
    s._secSet = s._secSet || {};
    const st = s._secSet;
    if (!s._ktReconcile) sideEnsure(s, st, secLoad);
    const d = st.data;
    const shape = !d ? 'wait' : (d.error ? 'error' : 'ready');
    if (s._ktReconcile && p._secShape !== shape) { s._ktStructural = true; return; }
    p._secShape = shape;
    if (shape === 'wait') { if (!s._ktReconcile) body.appendChild(el('div', 'card-sub', 'Waiting for data…')); return; }
    if (shape === 'error') { if (!s._ktReconcile) body.appendChild(el('div', 'panel-err', 'Could not read the switching security settings: ' + d.error)); return; }

    const igmp = d.igmp || {}, mld = d.mld || {}, dhcp = d.dhcp || {}, arp = d.arp || {};
    const vlans = d.vlanIds || [];

    // ---- multicast ----
    if (!s._ktReconcile) {
      body.appendChild(el('div', 'section-title', 'Multicast snooping'));
      body.appendChild(el('div', 'card-sub', 'Snooping sends multicast, such as video streams, only to the ports that asked for it. ' +
        'It works on a VLAN when it is on for the switch and for that VLAN.'));
    }
    mountInto(body, s, p, 'sec:mcast', ['Setting', 'Now', ''], [
      secToggleRow(s, 'g:igmp', 'IGMP snooping (IPv4)', igmp.enabled, '/api/security/multicast', 'enabled', 'IGMP snooping'),
      secToggleRow(s, 'g:querier', 'IGMP snooping querier', igmp.querier, '/api/security/multicast', 'querier', 'the querier'),
      secToggleRow(s, 'g:mld', 'MLD snooping (IPv6)', mld.enabled, '/api/security/multicast', 'mld', 'MLD snooping')
    ]);
    const v4By = new Map((igmp.vlans || []).map((r) => [r.vlan, r]));
    const v6By = new Map((mld.vlans || []).map((r) => [r.vlan, r]));
    const qBy = new Map((igmp.queriers || []).map((r) => [r.vlan, r]));
    mountInto(body, s, p, 'sec:mvlans', ['VLAN', 'IGMP snooping', 'Immediate leave', 'Querier', 'MLD snooping', 'Router ports', ''], vlans
      .filter((v) => v4By.has(v) || v6By.has(v) || qBy.has(v))
      .map((v) => {
        const a = v4By.get(v) || {}, b = v6By.get(v) || {}, q = qBy.get(v);
        const qText = !q ? '' : (q.enabled ? (q.active ? 'sending, ' + secQuerierAddr(q.activeAddress) : 'on, not sending') : 'off');
        return {
          key: 'v:' + v,
          cells: [{ v: String(v) }, secPill(a.enabled), { v: secOnOff(a.immediateLeave) },
            { pill: q && q.enabled ? 'good' : true, v: qText }, secPill(b.enabled),
            { v: secPorts(s, (a.routerPorts || []).concat(b.routerPorts || []).filter((x, i, l) => l.indexOf(x) === i)) },
            { cellNode: actGroup([actBtn('Change', () => openTabbedPopout(s, 'VLAN ' + v + ' · multicast', [secVlanTab(s, v)], []))]), sig: 'chg' }]
        };
      }));
    const groups = (igmp.groups || []).concat(mld.groups || []);
    if (groups.length) {
      if (!s._ktReconcile) body.appendChild(el('div', 'card-sub', 'Groups the switch has heard reports for:'));
      mountInto(body, s, p, 'sec:groups', ['VLAN', 'Group', 'Source', 'Ports'], groups.map((g) => ({
        key: 'g:' + g.vlan + ':' + g.group + ':' + g.source,
        cells: [{ v: String(g.vlan) }, { v: g.group }, { v: /^(0\.0\.0\.0|::)$/.test(g.source) ? 'any' : g.source }, { v: secPorts(s, g.ports) }]
      })));
    }

    // ---- DHCP snooping ----
    if (!s._ktReconcile) {
      body.appendChild(el('div', 'section-title', 'DHCP snooping'));
      body.appendChild(el('div', 'card-sub', 'Stops a rogue DHCP server: on a snooped VLAN, only trusted ports may answer DHCP requests. ' +
        'Mark the port toward your DHCP server as trusted first, on that port\'s Security tab.'));
    }
    mountInto(body, s, p, 'sec:dhcp', ['Setting', 'Now', ''], [
      secToggleRow(s, 'd:on', 'DHCP snooping', dhcp.enabled, '/api/security/dhcp', 'enabled', 'DHCP snooping', true),
      secToggleRow(s, 'd:mac', 'Check the client MAC address', dhcp.verifyMac, '/api/security/dhcp', 'verifyMac', 'the MAC check'),
      secToggleRow(s, 'd:file', 'Keep bindings in a file on flash', dhcp.file, '/api/security/dhcp', 'file', 'the bindings file')
    ]);
    const dOn = new Set(dhcp.vlans || []);
    const aBy = new Map((arp.vlans || []).map((r) => [r.vlan, r]));
    mountInto(body, s, p, 'sec:dvlans', ['VLAN', 'DHCP snooping', 'ARP inspection', 'ARP list', ''], vlans.map((v) => {
      const a = aBy.get(v);
      return {
        key: 'v:' + v,
        cells: [{ v: String(v) }, secPill(dOn.has(v)), secPill(!!a), { v: a && a.list ? a.list : '' },
          { cellNode: actGroup([
            dOn.has(v)
              ? actBtnConfirm('DHCP off', (e) => secWrite(e.currentTarget, s, '/api/security/dhcp-vlan', { vlan: v, on: false }, 'DHCP off'), 'danger')
              : actBtnConfirm('DHCP on', (e) => secWrite(e.currentTarget, s, '/api/security/dhcp-vlan', { vlan: v, on: true }, 'DHCP on')),
            a
              ? actBtnConfirm('ARP off', (e) => secWrite(e.currentTarget, s, '/api/security/arp-vlan', { vlan: v, on: false }, 'ARP off'), 'danger')
              : actBtnConfirm('ARP on', (e) => secWrite(e.currentTarget, s, '/api/security/arp-vlan', { vlan: v, on: true }, 'ARP on')),
            a ? actBtn('List', () => openTabbedPopout(s, 'VLAN ' + v + ' · ARP list', [secArpListTab(s, v)], [])) : null
          ]), sig: (dOn.has(v) ? 'd1' : 'd0') + (a ? 'a1' : 'a0') }]
      };
    }));
    const trusted = Array.from(new Set((dhcp.trusted || []).concat(arp.trusted || []))).sort((x, y) => x - y);
    if (!s._ktReconcile) body.appendChild(el('div', 'card-sub', trusted.length ? 'Trusted ports:' : 'No port is trusted yet.'));
    if (trusted.length) {
      mountInto(body, s, p, 'sec:trusted', ['Port', 'DHCP snooping', 'ARP inspection', ''], trusted.map((ifx) => ({
        key: 't:' + ifx,
        cells: [{ v: portNameOf(s, ifx) }, { v: (dhcp.trusted || []).includes(ifx) ? 'trusted' : '' }, { v: (arp.trusted || []).includes(ifx) ? 'trusted' : '' },
          { cellNode: actGroup([actBtn('Change', () => openTabbedPopout(s, portNameOf(s, ifx) + ' · security', [secPortTab(s, ifx)], []))]), sig: 'chg' }]
      })));
    }
    if ((dhcp.bindings || []).length) {
      if (!s._ktReconcile) body.appendChild(el('div', 'card-sub', 'Addresses the switch has seen handed out:'));
      mountInto(body, s, p, 'sec:bind', ['VLAN', 'MAC address', 'IP address', 'Port', 'Kind', 'Lease'], dhcp.bindings.map((b) => ({
        key: 'b:' + b.vlan + ':' + b.mac,
        cells: [{ v: String(b.vlan) }, { v: b.mac }, { v: b.ip || '' }, { v: b.ifIndex ? portNameOf(s, b.ifIndex) : '' }, { v: b.type },
          { v: b.lease == null || b.lease === 4294967295 ? 'never ends' : durWords(b.lease) }]
      })));
    }

    // ---- ARP inspection ----
    if (!s._ktReconcile) {
      body.appendChild(el('div', 'section-title', 'ARP inspection'));
      body.appendChild(el('div', 'card-sub', 'Drops ARP packets that claim an address the device was not given, which stops ARP spoofing. ' +
        'It checks against the DHCP snooping bindings and, for devices with a fixed address, an ARP list.'));
    }
    mountInto(body, s, p, 'sec:arp', ['Setting', 'Now', ''], [
      secToggleRow(s, 'a:on', 'ARP inspection', arp.enabled, '/api/security/arp', 'enabled', 'ARP inspection', true),
      secToggleRow(s, 'a:val', 'Check MAC and IP in each packet', arp.validation, '/api/security/arp', 'validation', 'the packet check'),
      { key: 'a:log', cells: [{ v: 'Seconds between log messages' }, { v: arp.logInterval == null ? 'not reported' : String(arp.logInterval) }, { v: '' }] }
    ]);
    if ((arp.vlans || []).length) {
      mountInto(body, s, p, 'sec:acount', ['VLAN', 'Forwarded', 'Dropped', 'Wrong MAC or IP'], arp.vlans.map((a) => ({
        key: 'c:' + a.vlan, cells: [{ v: String(a.vlan) }, { v: a.forwarded == null ? '' : a.forwarded }, { v: a.dropped == null ? '' : a.dropped }, { v: a.mismatched == null ? '' : a.mismatched }]
      })));
    }
    if (!s._ktReconcile) body.appendChild(el('div', 'card-sub', (arp.lists || []).length ? 'ARP lists:' : 'No ARP list yet.'));
    if ((arp.lists || []).length) {
      mountInto(body, s, p, 'sec:alists', ['List', 'IP address', 'MAC address', ''], arp.lists.map((r) => ({
        key: 'l:' + r.name + ':' + r.ip,
        cells: [{ v: r.name }, { v: r.ip }, { v: r.mac || '' },
          { cellNode: actGroup([actBtnConfirm('Remove', (e) => secWrite(e.currentTarget, s, '/api/security/arp-list/remove', { name: r.name, ip: r.ip }, 'Remove'), 'danger')]), sig: 'rm' }]
      })));
    }
    if (!s._ktReconcile) {
      const row = el('div', 'maint-row');
      const name = textInput('', 'list name'); name.size = 14;
      const ip = textInput('', '192.0.2.10'); ip.size = 14;
      const mac = textInput('', '02:00:5e:10:00:01'); mac.size = 18;
      const add = el('button', 'btn', 'Add to list'); add.type = 'button';
      add.addEventListener('click', (e) => {
        if (!name.value.trim() || !ip.value.trim() || !mac.value.trim()) { toast('Give a list name, an IP address and a MAC address.', 'error'); return; }
        secWrite(e.currentTarget, s, '/api/security/arp-list/add', { name: name.value.trim(), ip: ip.value.trim(), mac: mac.value.trim() }, 'Add to list');
      });
      row.appendChild(field('List', name));
      row.appendChild(field('IP address', ip));
      row.appendChild(field('MAC address', mac));
      row.appendChild(add);
      body.appendChild(row);
    }
  }

  // ---- the VLAN's ARP list popout ----

  function secArpListTab(s, vlan) {
    return { label: 'ARP list', fill: (pane) => secLoaded(s, pane, () => {
      const d = s._secSet.data;
      const a = ((d.arp && d.arp.vlans) || []).find((x) => x.vlan === vlan);
      const names = Array.from(new Set(((d.arp && d.arp.lists) || []).map((r) => r.name)));
      const sec = formSection('ARP list for VLAN ' + vlan);
      const sel = selectInput([{ label: 'none', value: '' }].concat(names.map((n) => ({ label: n, value: n }))), (a && a.list) || '');
      sec.body.appendChild(field('List', sel));
      sec.body.appendChild(el('div', 'card-sub', 'Devices in the list pass ARP inspection on this VLAN without a DHCP snooping binding. ' +
        'Make a list below the ARP inspection table first.'));
      const { actions, apply } = applyActions('Apply');
      apply.addEventListener('click', (e) => {
        if (sel.value === ((a && a.list) || '')) { toast('Nothing changed.', 'ok'); return; }
        secWrite(e.currentTarget, s, '/api/security/arp-vlan', { vlan, list: sel.value }, 'Apply', closePopoutOf(pane));
      });
      sec.body.appendChild(actions);
      pane.appendChild(sec.sec);
    }) };
  }
