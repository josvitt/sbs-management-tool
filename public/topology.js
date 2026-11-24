/**
 * Topology.
 *
 * The same picture the show-tech viewer draws, built from what SNMP has
 * already told us rather than from an uploaded capture. Every input it
 * needs is on the dashboard somewhere:
 *
 *   CDP and LLDP neighbours  ->  who is attached to which port
 *   the interface table      ->  speed, admin and operational state
 *   VLAN membership          ->  access or trunk, and on which VLAN
 *   spanning tree            ->  the root bridge, port roles, blocked links
 *   PoE                      ->  which links are powering what
 *   the MAC table            ->  hosts that announce nothing at all
 *
 * A switch open in a tab is a device here; its neighbours become nodes
 * too, drawn dimmer because nothing is polling them.
 */
(function (global) {
  'use strict';

  // ---------------------------------------------------------------
  // Reading the health payload
  // ---------------------------------------------------------------
  const dv = (cell, fallback) => {
    if (cell === undefined || cell === null) return fallback === undefined ? '' : fallback;
    if (typeof cell === 'object') {
      const v = cell.display !== undefined && cell.display !== null ? cell.display : cell.value;
      return v === undefined || v === null ? (fallback === undefined ? '' : fallback) : v;
    }
    return cell;
  };

  /**
   * The numeric half of the same idea. `dv` prefers the display string,
   * which is right for anything shown to a person and wrong for anything
   * measured: a speed displays as "10,000 Mbps" and parses as NaN.
   */
  const nv = (cell) => {
    if (cell === undefined || cell === null) return null;
    const raw = typeof cell === 'object' ? cell.value : cell;
    const n = Number(raw);
    return Number.isFinite(n) ? n : null;
  };

  /**
   * Hex only, and just the address. A bridge identifier is a two-byte
   * priority followed by the MAC, so "32768 00:1e:14:aa:bb:cc" must not
   * be compared against a chassis id of "00:1e:14:aa:bb:cc" -- taking the
   * last six bytes makes both sides the same thing.
   */
  const normMac = (mac) => {
    const hex = String(mac || '').toLowerCase().replace(/[^0-9a-f]/g, '');
    return hex.length > 12 ? hex.slice(-12) : hex;
  };

  /** A stable id for something named rather than addressed. */
  const slug = (s) => String(s || '').toLowerCase().replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '') || 'unknown';

  /**
   * What is on the far end of a port. A neighbour tells us its
   * capabilities and a platform string; between them that is usually
   * enough. Capability letters are checked last because a phone that
   * also bridges reports both, and the platform string is the better
   * evidence when it exists.
   */
  function classifyEndpoint(cap, platform, sysName) {
    const c = String(cap || '').toUpperCase();
    const p = (String(platform || '') + ' ' + String(sysName || '')).toUpperCase();
    if (/AIR-|\bAP\b|AIRONET|MERAKI|WIFI|WLAN|CATALYST 91\d\d/.test(p)) return 'ap';
    if (/CAMERA|IP ?CAM|AXIS|HIKVISION/.test(p)) return 'camera';
    if (/\bSEP\b|PHONE|POLYCOM|YEALINK/.test(p)) return 'phone';
    if (/PRINTER|LASERJET/.test(p)) return 'printer';
    if (/SWITCH|CATALYST|NEXUS|C1300|C1200|SG\d|CBS\d/.test(p)) return 'switch';
    if (/ROUTER|ISR|ASR/.test(p)) return 'router';
    // Capability letters: T and P are telephone, W wireless, R router,
    // S switch, B bridge, H host.
    if (/W/.test(c)) return 'ap';
    if (/[TP]/.test(c)) return 'phone';
    if (/[RS B]/.test(c) && /[SB]/.test(c)) return 'switch';
    if (/R/.test(c)) return 'router';
    if (/H/.test(c)) return 'host';
    return 'host';
  }

  function prettyEndpoint(n, kind) {
    if (n.sysName && !/^0\.0\.0\.0$/.test(n.sysName)) return n.sysName;
    if (kind === 'phone') {
      const m = /Phone\s*([\w-]+)/i.exec(n.platform || '');
      return m ? 'Phone ' + m[1] : (n.platform || n.deviceId || 'IP phone');
    }
    return n.deviceId || n.platform || kind;
  }

  /** Gather one switch's neighbours, merging CDP and LLDP per port. */
  function neighboursOf(health) {
    const byPort = new Map();
    const add = (n) => {
      if (!n.local) return;
      const key = String(n.local);
      const existing = byPort.get(key);
      if (!existing) { byPort.set(key, n); return; }
      // The same neighbour seen twice: keep both protocol names and fill
      // in whichever fields the other protocol did not carry.
      existing.protos = Array.from(new Set((existing.protos || []).concat(n.protos || [])));
      for (const f of ['sysName', 'platform', 'deviceId', 'chassisId', 'remotePort', 'address']) {
        if (!existing[f] && n[f]) existing[f] = n[f];
      }
      existing.cap = ((existing.cap || '') + ' ' + (n.cap || '')).trim();
    };

    for (const r of health.cdp || []) {
      add({
        local: dv(r.localPort, dv(r.index)),
        deviceId: dv(r.cdpCacheDeviceId),
        platform: dv(r.cdpCachePlatform),
        remotePort: dv(r.cdpCacheDevicePort),
        address: dv(r.cdpCacheAddress),
        cap: dv(r.cdpCacheCapabilities),
        protos: ['CDP']
      });
    }
    for (const r of health.lldp || []) {
      add({
        local: dv(r.localPort, dv(r.index)),
        sysName: dv(r.lldpRemSysName),
        platform: dv(r.lldpRemSysDesc),
        remotePort: dv(r.lldpRemPortDesc, dv(r.lldpRemPortId)),
        // A chassis id is an address; CDP's device id is a name. Keeping
        // them apart matters, because one of them has to match a bridge
        // identifier later and the other never will.
        chassisId: dv(r.lldpRemChassisId),
        cap: dv(r.lldpRemSysCapEnabled),
        protos: ['LLDP']
      });
    }
    return byPort;
  }

  /** Port facts, keyed by port name: speed, state, VLANs, PoE, STP. */
  function portFacts(health) {
    const facts = new Map();
    const get = (name) => {
      const key = String(name);
      if (!facts.has(key)) facts.set(key, { name: key });
      return facts.get(key);
    };

    for (const r of health.interfaces || []) {
      const name = dv(r.rlifPresentName, dv(r.index));
      if (!name) continue;
      const f = get(name);
      f.index = r.index;
      f.admin = dv(r.rlifPresentAdminStatus);
      f.oper = dv(r.rlifPresentOperStatus);
      f.speed = nv(r.rlifPresentHighSpeed) || null;
      f.inErrors = nv(r.rlifPresentInErrors) || 0;
      f.outErrors = nv(r.rlifPresentOutErrors) || 0;
    }

    /**
     * The switch stores VLAN membership as a bitmap of ports per VLAN;
     * what a link needs is the other direction. Inverting it also decides
     * access versus trunk more reliably than any single object does: one
     * untagged VLAN and nothing else is an access port, a spread of
     * tagged VLANs is a trunk.
     */
    const byIfIndex = new Map();
    for (const f of facts.values()) if (f.index !== undefined) byIfIndex.set(String(f.index), f);
    const addVlan = (raw, vlan, kind) => {
      for (const n of String(raw || '').split(',')) {
        const port = n.trim();
        if (!port) continue;
        const f = byIfIndex.get(port);
        if (!f) continue;
        (f[kind] = f[kind] || []).push(vlan);
      }
    };
    for (const v of health.vlans || []) {
      const id = String(v.index);
      addVlan(v.untagged && v.untagged.value, id, 'untagged');
      addVlan(v.tagged && v.tagged.value, id, 'tagged');
    }
    for (const f of facts.values()) {
      f.untagged = f.untagged || [];
      f.tagged = f.tagged || [];
      f.mode = f.tagged.length > 1 ? 'trunk' : 'access';
      f.accessVlan = f.untagged.length === 1 ? f.untagged[0] : null;
      f.nativeVlan = f.mode === 'trunk' && f.untagged.length ? f.untagged[0] : null;
    }

    for (const r of health.poePorts || []) {
      const name = dv(r.port, dv(r.portIndex));
      if (!name) continue;
      const f = get(name);
      f.poe = {
        detection: dv(r.pethPsePortDetectionStatus),
        cls: dv(r.pethPsePortPowerClassifications)
      };
    }

    /**
     * Spanning tree is reported per bridge port, and per VLAN or instance
     * on this hardware. The common table is enough for the picture: a
     * link either forwards or it does not.
     */
    const byIndex = byIfIndex;
    for (const r of health.stpPorts || []) {
      const f = byIndex.get(String(dv(r.ifIndex, r.index))) ||
        facts.get(String(dv(r.portName, '')));
      if (!f) continue;
      f.stpState = dv(r.dot1dStpPortState);
      f.stpRole = dv(r.dot1dStpPortRole, dv(r.role));
    }
    // Per-VLAN or per-instance state, where it was collected, is more
    // accurate than the common table and overrides it.
    for (const r of (health.pvstPorts || []).concat(health.mstpPorts || [])) {
      const f = byIndex.get(String(dv(r.ifIndex, dv(r.port))));
      if (!f) continue;
      const role = dv(r.rlBrgPvstOperPortRole, dv(r.rldot1sMstpPortRole, ''));
      const state = dv(r.rlBrgPvstOperPortState, dv(r.rldot1sMstpPortState, ''));
      if (role) f.stpRole = role;
      if (state) f.stpState = state;
    }
    return facts;
  }

  const isBlocked = (role, state) =>
    /block|discard|altern|backup/i.test(String(role || '') + ' ' + String(state || ''));

  // ---------------------------------------------------------------
  // Building the graph
  // ---------------------------------------------------------------
  /**
   * `switches` is an array of { host, health, label } - one per open tab
   * that has been polled.
   */
  function build(switches, options) {
    const opts = options || {};
    const nodes = new Map();
    const links = [];
    const warnings = [];

    // An index so a neighbour can be recognised as a switch we are
    // already polling, rather than drawn twice.
    const index = new Map();
    const reg = (key, id) => { if (key) index.set(String(key).toLowerCase(), id); };
    /**
     * Keyed on the tab rather than the address. Two switches can share an
     * address -- different ports through a jump host, the same address
     * behind NAT -- and keying on the host alone silently merges them into
     * one node, which is worse than drawing them twice.
     */
    const nodeId = (sw) => 'sw:' + (sw.id || sw.host);
    for (const sw of switches) {
      const id = nodeId(sw);
      reg(sw.host, id);
      reg(sw.name, id);
      reg(normMac(sw.bridgeMac), id);
      for (const a of sw.addresses || []) reg(a, id);
    }
    const findSwitch = (...keys) => {
      for (const k of keys) {
        if (!k) continue;
        const s = String(k).toLowerCase();
        if (index.has(s)) return index.get(s);
        const nm = normMac(k);
        if (nm && index.has(nm)) return index.get(nm);
        // "sw-core.example.com" should match a switch called "sw-core".
        const short = s.split('.')[0];
        if (short && index.has(short)) return index.get(short);
      }
      return null;
    };

    for (const sw of switches) {
      nodes.set(nodeId(sw), {
        id: nodeId(sw), kind: 'switch', polled: true,
        // Whether its tab is on screen. A closed switch is still polled
        // and still drawn; the difference is only where you find it.
        tabId: sw.id, open: sw.open !== false,
        label: sw.name || sw.host, sub: sw.model || '', host: sw.host,
        health: sw.health, stack: sw.stackUnits || 1, degSwitch: 0,
        isRoot: !!sw.isRoot, bridgeMac: sw.bridgeMac, rootMac: sw.rootMac,
        rootVlans: sw.rootVlans || [], idleRootVlans: sw.idleRootVlans || []
      });
    }

    for (const sw of switches) {
      const srcId = nodeId(sw);
      // The port the spanning tree uses to reach the root, when the switch
      // reports one for a VLAN that is actually carrying traffic.
      const rootPort = sw.rootPort ? String(sw.rootPort) : null;
      const facts = portFacts(sw.health);
      const neighbours = neighboursOf(sw.health);

      for (const [port, n] of neighbours) {
        const f = facts.get(String(port)) || { name: String(port) };
        const kind = classifyEndpoint(n.cap, n.platform, n.sysName);
        const remoteId = findSwitch(n.deviceId, n.sysName, n.chassisId, n.address);

        let targetId;
        if (remoteId && remoteId !== srcId) {
          targetId = remoteId;
        } else if (kind === 'switch' || kind === 'router') {
          // A switch we are not polling still belongs on the picture --
          // knowing the uplink goes somewhere is most of the value.
          const name = n.sysName || n.deviceId || n.platform || 'switch';
          targetId = 'ext:' + slug(name);
          if (!nodes.has(targetId)) {
            nodes.set(targetId, {
              id: targetId, kind: 'switch', polled: false, degSwitch: 0,
              label: name, sub: shortPlatform(n.platform) || 'not polled', macs: []
            });
          }
          // A chassis id is how this node will be recognised as the root
          // bridge later, so it is kept even though nothing displays it.
          const chassis = normMac(n.chassisId || n.deviceId);
          if (chassis.length === 12 && nodes.get(targetId).macs.indexOf(chassis) < 0) {
            nodes.get(targetId).macs.push(chassis);
          }
        } else {
          targetId = 'ep:' + (sw.id || sw.host) + ':' + port;
          nodes.set(targetId, {
            id: targetId, kind, endpoint: true, parent: srcId, polled: false,
            label: prettyEndpoint(n, kind), sub: shortPlatform(n.platform) || ''
          });
        }

        const link = makeLink(srcId, targetId, port, n, f,
          nodes.get(targetId) && nodes.get(targetId).endpoint ? 'endpoint' : 'switch');
        /**
         * The spanning tree's root port says which way the root is. That
         * is worth marking even when the root bridge itself cannot be
         * identified -- with CDP alone there is a name on the far end but
         * no MAC to match against a bridge id, and "up is that way" is
         * still enough to draw the picture the right way round.
         */
        if (rootPort && String(port) === rootPort && link.kind === 'switch') {
          link.towardRoot = true;
          const target = nodes.get(targetId);
          if (target) target.towardRoot = true;
        }
        links.push(link);
      }

      /**
       * Ports with a MAC learned but no neighbour. A workstation runs
       * neither CDP nor LLDP, so without this an access layer looks
       * empty -- which is exactly the part somebody is usually looking
       * for.
       */
      if (opts.macEndpoints !== false) {
        const seen = new Set(Array.from(neighbours.keys()).map(String));
        const byPort = new Map();
        for (const r of sw.health.macTable || []) {
          const port = String(dv(r.port, ''));
          if (!port || seen.has(port)) continue;
          const mac = dv(r.mac);
          if (!mac) continue;
          if (!byPort.has(port)) byPort.set(port, []);
          byPort.get(port).push({ mac, vlan: dv(r.vlan) });
        }
        for (const [port, macs] of byPort) {
          const f = facts.get(port) || { name: port };
          // A port with many MACs behind it is a link to something that
          // switches, not a host; saying "12 devices" is honest and
          // drawing twelve hosts would not be.
          const many = macs.length > 3;
          const id = 'mac:' + (sw.id || sw.host) + ':' + port;
          nodes.set(id, {
            id, kind: many ? 'segment' : 'host', endpoint: true, parent: srcId,
            polled: false, macs,
            label: many ? macs.length + ' devices' : ouiLabel(macs[0].mac),
            sub: many ? 'learned on ' + port : macs[0].mac
          });
          links.push(makeLink(srcId, id, port, { protos: ['MAC'] }, f, 'endpoint'));
        }
      }
    }

    // Two switches that both report the link produce two links; keep one.
    const merged = collapse(links);

    for (const l of merged) {
      const a = nodes.get(l.source), b = nodes.get(l.target);
      if (a && b && a.kind === 'switch' && b.kind === 'switch') { a.degSwitch++; b.degSwitch++; }
    }
    for (const n of nodes.values()) {
      if (n.kind === 'switch' && n.polled) n.role = inferRole(n);
    }

    // The root bridge, agreed across everything we polled.
    const rootVotes = new Map();
    for (const sw of switches) {
      if (!sw.rootMac) continue;
      const m = normMac(sw.rootMac);
      rootVotes.set(m, (rootVotes.get(m) || 0) + 1);
    }
    /**
     * A switch that is root only for VLANs nothing uses is not the root of
     * anything that matters, and saying so is more useful than quietly
     * dropping it -- somebody comparing this against the CLI will want to
     * know why the two disagree.
     */
    for (const sw of switches) {
      if ((sw.idleRootVlans || []).length && !sw.isRoot) {
        warnings.push({
          sev: 'inf', title: 'Root of a VLAN that is not carrying anything',
          det: (sw.name || sw.host) + ' is the root bridge for VLAN ' +
            sw.idleRootVlans.slice(0, 6).join(', ') +
            (sw.idleRootVlans.length > 6 ? '\u2026' : '') +
            ', which is shut down or has no member ports. That is not counted ' +
            'when placing it, so the diagram may disagree with what the switch ' +
            'reports for the common spanning tree.'
        });
      }
    }

    const elected = Array.from(rootVotes.entries()).sort((a, b) => b[1] - a[1])[0];
    if (elected) {
      const rootId = findSwitch(elected[0]);
      const rootNode = rootId ? nodes.get(rootId)
        : Array.from(nodes.values()).find((n) => n.kind === 'switch' && !n.polled &&
          (n.macs || []).indexOf(elected[0]) >= 0);
      if (rootNode) { rootNode.isRoot = true; rootNode.role = 'Core'; }
      warnings.push({
        sev: 'inf', title: 'Spanning-tree root bridge',
        det: elected[0] + (rootNode ? ' \u00b7 ' + rootNode.label
          : ' \u00b7 not among the switches being polled')
      });
      if (rootVotes.size > 1) {
        warnings.push({
          sev: 'wrn', title: 'Switches disagree on the root bridge',
          det: 'Polled switches report ' + rootVotes.size + ' different root bridges. ' +
            'That is either a partitioned spanning tree or per-VLAN roots being ' +
            'reported at different moments.'
        });
      }
    }

    const blocked = merged.filter((l) => l.blocked).length;
    if (blocked) {
      warnings.push({
        sev: 'inf', title: 'Blocked by spanning tree',
        det: blocked + ' link' + (blocked === 1 ? ' is' : 's are') + ' blocking. That is the ' +
          'tree doing its job where there is a loop, and a fault where there should not be one.'
      });
    }

    const unconfirmed = merged.filter((l) => l.kind === 'switch' && !l.confirmed).length;
    if (unconfirmed) {
      warnings.push({
        sev: 'wrn', title: 'One-sided adjacencies',
        det: unconfirmed + ' switch link' + (unconfirmed === 1 ? ' was' : 's were') +
          ' reported by only one end. Usually the other switch is not being polled; ' +
          'it can also mean CDP or LLDP is off on one side.'
      });
    }

    return { nodes, links: merged, warnings };
  }

  function makeLink(source, target, port, n, f, kind) {
    return {
      source, target, kind,
      aPort: String(port), bPort: n.remotePort || '',
      protos: n.protos || [],
      speed: f.speed || null,
      admin: f.admin, oper: f.oper,
      mode: f.mode, accessVlan: f.accessVlan, nativeVlan: f.nativeVlan,
      untagged: f.untagged || [], tagged: f.tagged || [],
      stpRole: f.stpRole, stpState: f.stpState,
      blocked: isBlocked(f.stpRole, f.stpState),
      down: /down/i.test(String(f.oper || '')),
      poe: f.poe && /deliver/i.test(String(f.poe.detection || '')) ? f.poe : null,
      errors: (f.inErrors || 0) + (f.outErrors || 0),
      confirmed: false
    };
  }

  /** One link per pair of ports, however many switches described it. */
  function collapse(links) {
    const out = new Map();
    for (const l of links) {
      const key = [l.source, l.target].sort().join('|') +
        (l.kind === 'endpoint' ? '|' + l.aPort : '');
      const existing = out.get(key);
      if (!existing) { out.set(key, l); continue; }
      // Seen from both ends: that is the confirmation, and each end knows
      // its own port name.
      existing.confirmed = true;
      if (existing.source === l.target && !existing.bPort) existing.bPort = l.aPort;
      existing.protos = Array.from(new Set(existing.protos.concat(l.protos)));
      existing.blocked = existing.blocked || l.blocked;
      existing.towardRoot = existing.towardRoot || l.towardRoot;
      existing.poe = existing.poe || l.poe;
      if (!existing.speed) existing.speed = l.speed;
      if (!existing.mode) existing.mode = l.mode;
    }
    return Array.from(out.values());
  }

  function inferRole(n) {
    if (n.isRoot) return 'Core';
    if (n.degSwitch >= 3) return 'Core';
    if (n.degSwitch === 2) return 'Distribution';
    return 'Access';
  }

  const shortPlatform = (p) => String(p || '').split(/[,\n]/)[0].replace(/^cisco\s+/i, '').trim();

  /**
   * A MAC is not a name, but its first half is a manufacturer, and
   * "Cisco device" beats "00:1e:..." for someone scanning a diagram.
   */
  const OUI = {
    '000c29': 'VMware', '005056': 'VMware', '001c14': 'VMware',
    '00155d': 'Hyper-V', '080027': 'VirtualBox',
    '001e': 'Cisco', '0026': 'Cisco', '00d0': 'Cisco', '588d': 'Cisco',
    'b4e9b0': 'Cisco', '00219b': 'Dell', 'd4ae52': 'Dell', 'f8bc12': 'Dell',
    '3c07 54': 'Apple', '000393': 'Apple', 'ac87a3': 'Apple',
    '001a11': 'Google', '3c5ab4': 'Google',
    '000f4b': 'Oracle', '0017ab': 'Nintendo', '001d7e': 'Cisco-Linksys',
    '0004f2': 'Polycom', '64167f': 'Polycom', '00907f': 'WatchGuard'
  };
  function ouiLabel(mac) {
    const clean = normMac(mac);
    for (const len of [6, 4]) {
      const v = OUI[clean.slice(0, len)];
      if (v) return v;
    }
    return clean ? clean.replace(/(..)/g, '$1:').slice(0, 8) + '\u2026' : 'host';
  }

  global.Topology = {
    build, classifyEndpoint, portFacts, neighboursOf, ouiLabel, isBlocked, normMac
  };
})(window);

/**
 * The view: a layered layout and an SVG renderer.
 *
 * Kept apart from the model above so the picture can be rebuilt without
 * re-reading any switch, and so the model can be tested on its own.
 */
(function (global) {
  'use strict';

  const NS = 'http://www.w3.org/2000/svg';
  const el = (tag, attrs) => {
    const n = document.createElementNS(NS, tag);
    for (const k in attrs || {}) n.setAttribute(k, attrs[k]);
    return n;
  };
  const trunc = (s, n) => {
    s = String(s || '');
    return s.length > n ? s.slice(0, n - 1) + '\u2026' : s;
  };
  const esc = (s) => String(s === undefined || s === null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

  const KIND_COLOR = {
    switch: 'var(--t-cyan)', router: 'var(--t-blue)', phone: 'var(--t-amber)',
    host: 'var(--t-green)', server: 'var(--t-green)', ap: 'var(--t-violet)',
    camera: 'var(--t-blue)', printer: 'var(--t-dim)', segment: 'var(--t-dim)'
  };
  const KIND_GLYPH = {
    phone: '\u260e', host: '\u25a6', server: '\u25a4', ap: '\u25c7',
    camera: '\u25c9', printer: '\u2399', segment: '\u2317', router: '\u25c6'
  };

  /**
   * Layered by distance from the root bridge, which is the layout a
   * network engineer already has in their head: root at the top, access
   * at the bottom, endpoints fanned beneath the switch they hang off.
   */
  function layout(graph, W, H, focusVlan, opts) {
    const showEndpoints = !(opts && opts.hideEndpoints);
    const nodes = Array.from(graph.nodes.values());
    let switches = nodes.filter((n) => n.kind === 'switch');
    if (!switches.length) {
      nodes.forEach((n, i) => { n.x = W / 2 + (i - nodes.length / 2) * 120; n.y = H / 2; });
      return;
    }

    const endpointsOf = new Map();
    for (const e of nodes.filter((n) => n.endpoint)) {
      // Hidden endpoints must not reserve the space they would have taken:
      // the fan beneath a switch is what pushes the tiers apart and shoves
      // links aside, so leaving it there when nothing is drawn in it puts
      // the whole diagram off centre for no visible reason.
      if (!showEndpoints) { e._hidden = true; continue; }
      if (focusVlan && !endpointInVlan(graph, e, focusVlan)) { e._hidden = true; continue; }
      e._hidden = false;
      if (!endpointsOf.has(e.parent)) endpointsOf.set(e.parent, []);
      endpointsOf.get(e.parent).push(e);
    }

    // Wide enough for the labels underneath: endpoints are named after
    // whatever announced itself, and those names are not short.
    const COL = 96, ROW = 60, DROP = 96, NODE_H = 64;
    const fan = (s) => {
      const eps = endpointsOf.get(s.id) || [];
      if (!eps.length) return { rows: 0, height: 0, perRow: 0 };
      const perRow = Math.min(8, Math.max(3, Math.round(Math.sqrt(eps.length * 1.7))));
      return {
        rows: Math.ceil(eps.length / perRow), perRow,
        height: DROP + (Math.ceil(eps.length / perRow) - 1) * ROW + 30
      };
    };

    // Adjacency, skipping links the tree is blocking: a blocked link is
    // real but it is not how traffic gets anywhere, and letting it decide
    // the tiers draws a picture that contradicts the arrows on it.
    const adj = new Map();
    switches.forEach((s) => adj.set(s.id, new Set()));
    for (const l of graph.links) {
      if (l.kind === 'endpoint' || l.blocked) continue;
      if (adj.has(l.source) && adj.has(l.target)) {
        adj.get(l.source).add(l.target);
        adj.get(l.target).add(l.source);
      }
    }

    switches.forEach((s) => { s._layoutRoot = false; });
    const root = switches.find((n) => n.isRoot) ||
      // Nothing identified as the root bridge: the switch every root port
      // points at is the next best answer, and it is the one an operator
      // would draw at the top.
      switches.find((n) => n.towardRoot) ||
      switches.filter((n) => n.polled).sort((a, b) => (b.degSwitch || 0) - (a.degSwitch || 0))[0] ||
      switches[0];
    root._layoutRoot = true;

    const tier = new Map([[root.id, 0]]);
    const queue = [root.id];
    while (queue.length) {
      const id = queue.shift();
      for (const nb of adj.get(id) || []) {
        if (!tier.has(nb)) { tier.set(nb, tier.get(id) + 1); queue.push(nb); }
      }
    }
    let maxTier = 0;
    tier.forEach((v) => { if (v > maxTier) maxTier = v; });

    /**
     * A switch reached only over a blocked link is not unreachable, it is
     * standing by. Placing it at the bottom as an island draws its blocked
     * link straight through everything in between; a second pass that
     * does count blocked links puts it beside the peer it is blocked
     * against, which is where it belongs.
     */
    const standby = new Map();
    for (const l of graph.links) {
      if (l.kind === 'endpoint') continue;
      if (!standby.has(l.source)) standby.set(l.source, new Set());
      if (!standby.has(l.target)) standby.set(l.target, new Set());
      standby.get(l.source).add(l.target);
      standby.get(l.target).add(l.source);
    }
    let settled = true;
    for (let guard = 0; guard < 8 && settled; guard++) {
      settled = false;
      for (const s of switches) {
        if (tier.has(s.id)) continue;
        for (const nb of standby.get(s.id) || []) {
          if (tier.has(nb)) { tier.set(s.id, tier.get(nb) + 1); settled = true; break; }
        }
      }
    }
    tier.forEach((v) => { if (v > maxTier) maxTier = v; });
    // Genuinely disconnected: its own tier, rather than piled on the root.
    switches.forEach((s) => { if (!tier.has(s.id)) { maxTier++; tier.set(s.id, maxTier); } });

    const rows = [];
    for (let t = 0; t <= maxTier; t++) rows.push([]);
    switches.forEach((s) => rows[tier.get(s.id)].push(s));

    const top = [70];
    for (let t = 1; t <= maxTier; t++) {
      let biggest = 0;
      rows[t - 1].forEach((s) => { biggest = Math.max(biggest, fan(s).height); });
      top[t] = top[t - 1] + Math.max(165, NODE_H + biggest + 55);
    }

    // Order within a tier by the median position of what each node is
    // attached to above it, so links run mostly straight down.
    const order = new Map();
    const reindex = () => rows.forEach((row) => row.forEach((s, i) => order.set(s.id, i)));
    reindex();
    for (let pass = 0; pass < 4; pass++) {
      for (let t = 1; t <= maxTier; t++) {
        rows[t].sort((a, b) => median(a, t - 1) - median(b, t - 1));
        reindex();
      }
      for (let t = maxTier - 1; t >= 0; t--) {
        rows[t].sort((a, b) => median(a, t + 1) - median(b, t + 1));
        reindex();
      }
    }
    function median(s, otherTier) {
      const idx = Array.from(adj.get(s.id) || [])
        .filter((id) => tier.get(id) === otherTier)
        .map((id) => order.get(id)).filter((v) => v != null).sort((a, b) => a - b);
      if (!idx.length) return order.get(s.id) ?? 0;
      const m = idx.length;
      return m % 2 ? idx[(m - 1) / 2] : (idx[m / 2 - 1] + idx[m / 2]) / 2;
    }

    // Place, giving each switch enough width for the endpoints under it.
    for (let t = 0; t <= maxTier; t++) {
      const row = rows[t];
      const widths = row.map((s) => Math.max(200, fan(s).perRow * COL + 40));
      const total = widths.reduce((a, b) => a + b, 0);
      let x = Math.max(60, (W - total) / 2);
      row.forEach((s, i) => {
        s.x = x + widths[i] / 2;
        s.y = top[t];
        x += widths[i];
      });
    }

    /**
     * A switch sitting directly under another has its link drawn straight
     * through whatever is fanned out beneath the parent. Nudging it clear
     * of that corridor costs nothing -- the tier is still right, the line
     * no longer crosses eight endpoints and their labels.
     */
    for (let t = 1; t <= maxTier; t++) {
      for (const s of rows[t]) {
        // The full adjacency, blocked links included: a standby peer got
        // its tier from one of those, so it is exactly the node that
        // needs moving out of the corridor.
        for (const parentId of standby.get(s.id) || []) {
          if (tier.get(parentId) !== t - 1) continue;
          const parent = graph.nodes.get(parentId);
          const f = fan(parent);
          if (!f.rows) continue;
          const half = (Math.min(f.perRow, (endpointsOf.get(parentId) || []).length) * COL) / 2;
          if (Math.abs(s.x - parent.x) < half + 40) {
            // Aside on whichever side has more room on screen.
            const dir = parent.x < W / 2 ? 1 : -1;
            s.x = parent.x + dir * (half + 70);
          }
          break;
        }
      }
    }

    for (const [parentId, eps] of endpointsOf) {
      const parent = graph.nodes.get(parentId);
      if (!parent || parent.x === undefined) continue;
      const f = fan(parent);
      eps.forEach((e, i) => {
        const row = Math.floor(i / f.perRow);
        const inRow = i % f.perRow;
        const count = Math.min(f.perRow, eps.length - row * f.perRow);
        e.x = parent.x + (inRow - (count - 1) / 2) * COL;
        e.y = parent.y + DROP + row * ROW;
      });
    }
  }

  function endpointInVlan(graph, e, vlan) {
    for (const l of graph.links) {
      if (l.target !== e.id && l.source !== e.id) continue;
      if (String(l.accessVlan) === String(vlan)) return true;
      if ((l.untagged || []).map(String).indexOf(String(vlan)) >= 0) return true;
      if ((l.tagged || []).map(String).indexOf(String(vlan)) >= 0) return true;
    }
    return false;
  }

  global.TopologyView = { layout, el, trunc, esc, KIND_COLOR, KIND_GLYPH };
})(window);
