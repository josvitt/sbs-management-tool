  // =================================================================
  // 31-ipv6-addressing.js: The IPv6 Addressing panel: IPv6 and stateless
  // autoconfig per interface, global addresses, static routes and DNS
  // servers (switch-ipv6.js).
  // =================================================================

  // A keyed panel with a server-side reader (standard B1 family b2), like
  // Switching security. The data rides the server collection as `ipv6`
  // (module-collection.js).
  //
  // s._v6Set = { data, fetchedAt, loading, liveAt, collected }

  function v6Load(s) {
    s._v6Set = s._v6Set || {};
    const st = s._v6Set;
    if (st.loading) return st.loading;
    st.fetchedAt = Date.now();
    st.liveAt = Date.now();
    st.loading = sidePost('/api/ipv6/status', { target: s.target })
      .then((b) => { st.data = (b && !b.error) ? b : { error: (b && b.error) || 'no answer' }; })
      .finally(() => { st.loading = null; sideRepaint(s, 'ipv6'); });
    return st.loading;
  }

  function v6Write(btn, s, url, payload, failLabel, onApplied) {
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
      settle: () => v6Load(s)
    });
  }

  const v6OnOff = (v) => (v == null ? 'not reported' : (v ? 'on' : 'off'));
  const v6Pill = (v) => ({ pill: v ? 'good' : true, v: v6OnOff(v) });
  const v6Name = (s, ifx) => (ifx ? l3Iface(s, ifx).name : '');
  const v6NoZone = (a) => String(a || '').replace(/%\d+$/, '');
  const V6_DHCP_WORDS = { dhcp: 'DHCPv6', off: 'off', autoconfig: 'off', both: 'DHCPv6' };
  // The address this app reaches the switch at, when that is IPv6: removing
  // it, or turning IPv6 off where it lives, would cut the app off.
  const v6Mgmt = (s) => { const h = String((s.target && s.target.host) || '').replace(/^\[|\]$/g, '').toLowerCase(); return h.includes(':') ? h : ''; };

  // The switch's VLAN interfaces and routed ports, for the IPv6 forms.
  function v6Interfaces(s) {
    const h = s.health || {};
    const cv = (c) => (c == null ? '' : String(c.value !== undefined ? c.value : (c.display !== undefined && c.display !== null ? c.display : c)));
    const out = [];
    for (const r of (h.interfaces || [])) {
      const nm = cv(r.rlifPresentName).trim();
      const ifx = parseInt(r.index, 10);
      if (/^\d+$/.test(nm) && (h.vlans || []).some((v) => String(v.index) === nm)) out.push({ ifIndex: ifx, name: l3Iface(s, ifx).name });
    }
    for (const r of (h.portL2L3 || [])) {
      if (parseInt(cv(r.vlanSwitchPortModeCategory), 10) !== 2) continue;   // 2 = l3 routed
      const ifx = parseInt(r.index, 10);
      if (Number.isFinite(ifx)) out.push({ ifIndex: ifx, name: l3Iface(s, ifx).name });
    }
    return out;
  }

  // ---- the interface popout ----

  function buildV6Iface(s, ifx, pane) {
    const d = (s._v6Set && s._v6Set.data) || {};
    const row = (d.summary || []).find((x) => x.ifIndex === ifx) || { ifIndex: ifx, on: false, global: [] };
    const done = () => { const pop = pane.closest && pane.closest('.port-detail-back'); if (pop) pop.remove(); };
    const mgmt = v6Mgmt(s);

    const sec = formSection('IPv6 on ' + v6Name(s, ifx));
    const on = selectInput([{ label: 'on', value: '1' }, { label: 'off', value: '0' }], row.on ? '1' : '0');
    const auto = selectInput([{ label: 'on', value: '1' }, { label: 'off', value: '0' }], row.autoconfig ? '1' : '0');
    sec.body.appendChild(field('IPv6', on));
    sec.body.appendChild(field('Autoconfig', auto));
    sec.body.appendChild(el('div', 'card-sub', 'With IPv6 on, the interface has a link-local address. ' +
      'Autoconfig also takes an address from the prefix a router announces on this network.'));
    const { actions, apply } = applyActions('Apply');
    apply.addEventListener('click', async (e) => {
      const btn = e.currentTarget;
      const wantOn = on.value === '1', wantAuto = auto.value === '1';
      if (wantOn === !!row.on && wantAuto === !!row.autoconfig) { toast('Nothing changed.', 'ok'); return; }
      if (!wantOn && mgmt && row.global.some((g) => g.address === mgmt)) { toast('This app reaches the switch at ' + mgmt + ' on this interface, so IPv6 stays on here.', 'error'); return; }
      if (wantOn !== !!row.on && wantAuto !== !!row.autoconfig) {
        const r = await sidePost('/api/ipv6/autoconfig', { target: s.target, ifIndex: ifx, on: wantAuto });
        if (!r || !r.ok) { toast('Autoconfig failed: ' + ((r && r.error) || 'unknown error'), 'error'); return; }
      }
      if (wantOn !== !!row.on) v6Write(btn, s, '/api/ipv6/enabled', { ifIndex: ifx, on: wantOn }, 'Apply', done);
      else v6Write(btn, s, '/api/ipv6/autoconfig', { ifIndex: ifx, on: wantAuto }, 'Apply', done);
    });
    sec.body.appendChild(actions);
    pane.appendChild(sec.sec);

    const add = formSection('Add a global address');
    const addr = textInput('', '2001:db8::1'); addr.size = 28;
    const len = textInput('64', '64'); len.size = 4;
    add.body.appendChild(field('Address', addr));
    add.body.appendChild(field('Prefix length', len));
    const a2 = applyActions('Add address');
    a2.apply.addEventListener('click', (e) => {
      if (!addr.value.trim()) { toast('Give an IPv6 address.', 'error'); return; }
      v6Write(e.currentTarget, s, '/api/ipv6/address/add', { ifIndex: ifx, address: addr.value.trim(), prefixLength: Number(len.value) }, 'Add address', done);
    });
    add.body.appendChild(a2.actions);
    pane.appendChild(add.sec);
  }

  function v6Loaded(s, pane, build) {
    const st = s._v6Set || {};
    if (st.data && !st.data.error) { build(); return; }
    pane.appendChild(el('div', 'card-sub', 'Loading IPv6 settings…'));
    v6Load(s).then(() => {
      clear(pane);
      if (s._v6Set.data && !s._v6Set.data.error) build();
      else pane.appendChild(el('div', 'sw-err', 'Could not read IPv6 settings: ' + ((s._v6Set.data && s._v6Set.data.error) || 'no answer')));
    });
  }

  function v6IfaceTab(s, ifx) {
    return { label: 'IPv6', fill: (pane) => v6Loaded(s, pane, () => buildV6Iface(s, ifx, pane)) };
  }

  // ---- the panel ----

  function paintIpv6Panel(s, body, p) {
    if (!s._ktReconcile) clear(body);
    if (!s.target) { if (!s._ktReconcile) body.appendChild(el('div', 'card-sub', 'Connect with SNMP to see the IPv6 settings.')); return; }
    s._v6Set = s._v6Set || {};
    const st = s._v6Set;
    if (!s._ktReconcile) sideEnsure(s, st, v6Load);
    const d = st.data;
    const shape = !d ? 'wait' : (d.error ? 'error' : 'ready');
    if (s._ktReconcile && p._v6Shape !== shape) { s._ktStructural = true; return; }
    p._v6Shape = shape;
    if (shape === 'wait') { if (!s._ktReconcile) body.appendChild(el('div', 'card-sub', 'Waiting for data…')); return; }
    if (shape === 'error') { if (!s._ktReconcile) body.appendChild(el('div', 'panel-err', 'Could not read the IPv6 settings: ' + d.error)); return; }

    const summary = d.summary || [];
    const mgmt = v6Mgmt(s);
    const open = (ifx) => openTabbedPopout(s, v6Name(s, ifx) + ' · IPv6', [v6IfaceTab(s, ifx)], []);

    // ---- interfaces ----
    if (!s._ktReconcile) {
      body.appendChild(el('div', 'section-title', 'IPv6 interfaces'));
      body.appendChild(el('div', 'card-sub', 'The switch answers on IPv6 only on the interfaces where it is turned on. ' +
        (d.forwarding ? 'The switch routes IPv6 between them.' : 'The switch does not route IPv6 between them.')));
    }
    const addrRows = [];
    mountInto(body, s, p, 'v6:ifs', ['Interface', 'IPv6', 'Link-local address', 'Global addresses', 'Autoconfig', 'DHCPv6', ''], summary.map((r) => ({
      key: 'i:' + r.ifIndex,
      cells: [{ v: v6Name(s, r.ifIndex) }, v6Pill(r.on), { v: r.linkLocal ? v6NoZone(r.linkLocal) : '' },
        { v: r.global.map((g) => g.address + '/' + g.prefixLength).join(', ') }, v6Pill(r.autoconfig),
        { v: r.dhcp ? (V6_DHCP_WORDS[r.dhcp] || r.dhcp) : '' },
        { cellNode: actGroup([actBtn('Change', () => open(r.ifIndex))]), sig: 'chg' }]
    })));
    for (const r of summary) for (const g of r.global) addrRows.push(Object.assign({ ifIndex: r.ifIndex }, g));
    if (addrRows.length) {
      if (!s._ktReconcile) body.appendChild(el('div', 'card-sub', 'Global addresses:'));
      mountInto(body, s, p, 'v6:addrs', ['Interface', 'Address', 'Prefix length', 'From', ''], addrRows.map((a) => {
        const locked = mgmt && a.address === mgmt;
        return {
          key: 'a:' + a.address,
          cells: [{ v: v6Name(s, a.ifIndex) }, { v: a.address }, { v: String(a.prefixLength == null ? '' : a.prefixLength) },
            { v: a.origin === 'manual' ? 'set by hand' : 'autoconfig' },
            a.origin !== 'manual' ? { v: '' } : locked ? { v: 'in use by this app' } : {
              cellNode: actGroup([actBtnConfirm('Remove', (e) => v6Write(e.currentTarget, s, '/api/ipv6/address/remove', { address: a.address }, 'Remove'), 'danger')]), sig: 'rm'
            }]
        };
      }));
    }
    if (!s._ktReconcile) {
      const have = new Set(summary.filter((r) => r.on).map((r) => r.ifIndex));
      const cands = v6Interfaces(s).filter((c) => !have.has(c.ifIndex));
      if (cands.length) {
        const row = el('div', 'maint-row');
        const sel = selectInput(cands.map((c) => ({ label: c.name, value: String(c.ifIndex) })), String(cands[0].ifIndex));
        const go = el('button', 'btn', 'Turn on IPv6'); go.type = 'button';
        go.addEventListener('click', (e) => v6Write(e.currentTarget, s, '/api/ipv6/enabled', { ifIndex: Number(sel.value), on: true }, 'Turn on IPv6'));
        row.appendChild(field('Interface', sel));
        row.appendChild(go);
        body.appendChild(row);
      }
    }

    // ---- static routes ----
    const routes = d.staticRoutes || [];
    if (!s._ktReconcile) {
      body.appendChild(el('div', 'section-title', 'IPv6 static routes'));
      body.appendChild(el('div', 'card-sub', routes.length ? 'Routes set by hand. A route is used once its next hop answers.' : 'No IPv6 static route yet.'));
    }
    if (routes.length) {
      mountInto(body, s, p, 'v6:routes', ['Destination', 'Next hop', 'Interface', 'Metric', 'In use', ''], routes.map((r) => ({
        key: 'r:' + r.index,
        cells: [{ v: r.dest === '::/0' ? '::/0 (default route)' : r.dest }, { v: v6NoZone(r.nextHop) }, { v: v6Name(s, r.ifIndex) },
          { v: r.cost == null ? '' : String(r.cost) }, { pill: r.active ? 'good' : true, v: r.active ? 'yes' : 'no' },
          mgmt && r.dest === '::/0' ? { v: 'in use by this app' } : {
            cellNode: actGroup([actBtnConfirm('Remove', (e) => v6Write(e.currentTarget, s, '/api/ipv6/route/remove', { index: r.index }, 'Remove'), 'danger')]), sig: 'rm'
          }]
      })));
    }
    if (!s._ktReconcile) {
      const ifs = summary.filter((r) => r.on).map((r) => ({ label: v6Name(s, r.ifIndex), value: String(r.ifIndex) }));
      if (ifs.length) {
        const row = el('div', 'maint-row');
        const dest = textInput('', '2001:db8:1::/48 or ::/0'); dest.size = 22;
        const nh = textInput('', '2001:db8::fe'); nh.size = 22;
        const via = selectInput(ifs, ifs[0].value);
        const metric = textInput('1', '1'); metric.size = 4;
        const go = el('button', 'btn', 'Add route'); go.type = 'button';
        go.addEventListener('click', (e) => {
          const m = /^(.+)\/(\d+)$/.exec(dest.value.trim());
          if (!m) { toast('Give the destination as a prefix, like 2001:db8:1::/48, or ::/0 for the default route.', 'error'); return; }
          if (!nh.value.trim()) { toast('Give the next hop address.', 'error'); return; }
          v6Write(e.currentTarget, s, '/api/ipv6/route/add', { dest: m[1], prefixLength: Number(m[2]), nextHop: nh.value.trim(), ifIndex: Number(via.value), cost: Number(metric.value) }, 'Add route');
        });
        row.appendChild(field('Destination', dest));
        row.appendChild(field('Next hop', nh));
        row.appendChild(field('Interface', via));
        row.appendChild(field('Metric', metric));
        row.appendChild(go);
        body.appendChild(row);
        body.appendChild(el('div', 'card-sub', 'The interface is the one the next hop is reached through.'));
      } else {
        body.appendChild(el('div', 'card-sub', 'Turn IPv6 on for an interface before adding a route.'));
      }
    }

    // ---- DNS servers ----
    const dns = d.dnsServers || [];
    if (!s._ktReconcile) {
      body.appendChild(el('div', 'section-title', 'IPv6 DNS servers'));
      body.appendChild(el('div', 'card-sub', dns.length ? 'The switch asks these to look up names.' : 'No IPv6 DNS server yet.'));
    }
    if (dns.length) {
      mountInto(body, s, p, 'v6:dns', ['Address', 'From', ''], dns.map((r) => ({
        key: 'd:' + r.index,
        cells: [{ v: r.address }, { v: r.source === 'static' ? 'set by hand' : (r.source === 'dhcpv6' ? 'DHCPv6' : String(r.source || '')) },
          r.source !== 'static' ? { v: '' } : {
            cellNode: actGroup([actBtnConfirm('Remove', (e) => v6Write(e.currentTarget, s, '/api/ipv6/dns/remove', { index: r.index }, 'Remove'), 'danger')]), sig: 'rm'
          }]
      })));
    }
    if (!s._ktReconcile) {
      const row = el('div', 'maint-row');
      const addr = textInput('', '2001:db8::53'); addr.size = 24;
      const go = el('button', 'btn', 'Add DNS server'); go.type = 'button';
      go.addEventListener('click', (e) => {
        if (!addr.value.trim()) { toast('Give the DNS server’s IPv6 address.', 'error'); return; }
        v6Write(e.currentTarget, s, '/api/ipv6/dns/add', { address: addr.value.trim() }, 'Add DNS server');
      });
      row.appendChild(field('Address', addr));
      row.appendChild(go);
      body.appendChild(row);
    }
  }
