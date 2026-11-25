  // =================================================================
  // 15-routing.js: IP routing and DNS panel.
  // =================================================================

  // The VLANs panel: the VLAN list with SVI/IPv4 details, create and edit.
  // Standalone (its own module) so the Interfaces panel stays focused on ports.
  // ===========================================================================
  // IP Routing & DNS panel. Read + write: global L3 status, the forwarding
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
