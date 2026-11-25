  // =================================================================
  // 22-topology.js: The Topology view.
  // =================================================================


  // ---------- Topology ----------
  /**
   * Every switch open in a tab is a device on the picture; the neighbours
   * they report become nodes too. Nothing here asks the switches for
   * anything new -- it is the health data already on the dashboard, read
   * the other way round.
   */
  const topoPanel = document.getElementById('topo-panel');

  const topoSvg = document.getElementById('topo-svg');
  const topoViewport = document.getElementById('topo-viewport');
  const topoTip = document.getElementById('topo-tip');
  const TV = window.TopologyView;
  const topoState = { graph: null, sel: null, zoom: 1, tx: 0, ty: 0, vlan: '' };

  /**
   * The topology button appears once there is a switch to draw. An empty
   * diagram is not a feature, and a button that leads to "nothing here"
   * teaches people not to press it.
   */
  /**
   * The button appears once a switch has been collected from, and stays
   * once a picture exists. Offering it on an empty app is offering a
   * blank canvas.
   */
  /**
   * The tab exists once there is a switch to draw, and stays while any
   * switch exists at all -- including ones whose tab has been closed,
   * because the topology is where those are found again.
   */
  function paintTopoButton() {
    const any = allSwitches().some((s) => s.health && s.target);
    topoTab.style.display = (any || topoState.graph || topoTabActive) ? '' : 'none';
  }

  /**
   * Which VLANs are actually carrying traffic, and what the spanning tree
   * says about them.
   *
   * A VLAN counts as live when its switch interface is not administratively
   * down and at least one port is a member. Everything else -- a shut
   * VLAN, a VLAN defined but unused -- is ignored, because a spanning tree
   * with nothing in it is not a spanning tree anybody cares about.
   */
  function liveVlanRoots(h) {
    const result = {
      decided: false, isRoot: false, rootMac: null,
      rootVlans: [], idleRootVlans: [], count: 0
    };
    const perVlan = h.pvstVlans || [];
    if (!perVlan.length) return result;

    // VLAN interfaces are listed among the ports, named after the VLAN id.
    const shut = new Set();
    for (const r of h.interfaces || []) {
      const name = dvOf(r.rlifPresentName);
      if (!/^\d+$/.test(String(name))) continue;
      if (/down|disabled/i.test(String(dvOf(r.rlifPresentAdminStatus)))) shut.add(String(name));
    }

    const hasMembers = new Set();
    for (const v of h.vlans || []) {
      const un = String((v.untagged && v.untagged.value) || '');
      const tg = String((v.tagged && v.tagged.value) || '');
      if (un.trim() || tg.trim()) hasMembers.add(String(v.index));
    }

    const votes = new Map();
    const isRootRow = (row) => Number(dvOf(row.isRoot)) === 1 || /yes/i.test(String(dvOf(row.isRoot)));
    for (const row of perVlan) {
      const vlan = String(dvOf(row.vlan, row.index));
      const idle = shut.has(vlan) || (hasMembers.size && !hasMembers.has(vlan));
      if (idle) {
        // Worth remembering: "root for VLAN 1, which is shut down" is the
        // explanation somebody will be looking for when the diagram does
        // not match what the switch told them.
        if (isRootRow(row)) result.idleRootVlans.push(vlan);
        continue;
      }
      result.count++;
      const root = dvOf(row.rlBrgPvstOperVlanDesignatedRoot);
      if (!root) continue;
      const mac = window.Topology.normMac(root);
      if (!mac) continue;
      votes.set(mac, (votes.get(mac) || 0) + 1);
      if (isRootRow(row)) result.rootVlans.push(vlan);
      // The port this VLAN uses to reach the root. With only CDP for
      // neighbours there is no MAC to match the root bridge against, but
      // the port still says which way it is -- and which way is up.
      const rp = dvOf(row.rootPort);
      if (rp && !/^[\u2014-]$/.test(String(rp).trim())) result.rootPort = String(rp).trim();
    }
    if (!result.count) return result;

    result.decided = true;
    // The root of the most live VLANs is the one the diagram should show.
    const ranked = Array.from(votes.entries()).sort((a, b) => b[1] - a[1])[0];
    result.rootMac = ranked ? ranked[0] : null;
    result.isRoot = result.rootVlans.length > 0;
    return result;
  }

  const dvOf = (cell, fallback) => {
    if (cell === undefined || cell === null) return fallback === undefined ? '' : fallback;
    if (typeof cell === 'object') {
      const v = cell.display !== undefined && cell.display !== null ? cell.display : cell.value;
      return v === undefined || v === null ? (fallback === undefined ? '' : fallback) : v;
    }
    return cell;
  };

  function topoSwitchInputs() {
    const out = [];
    // Closed tabs included: putting a switch away should not remove it
    // from the picture of the network, and the topology is where you go
    // to find it again.
    for (const s of allSwitches()) {
      if (!s.health || !s.target) continue;
      const h = s.health;
      const scalar = (name) => {
        const c = h.scalars && h.scalars[name];
        return c ? (c.display !== undefined && c.display !== null ? c.display : c.value) : null;
      };
      /**
       * Being root only matters for VLANs that carry something. A switch
       * can be root for a VLAN that is shut down, or that no port is in --
       * true, and useless. Drawing it at the top of the diagram on that
       * basis says the network is shaped a way it is not.
       */
      const live = liveVlanRoots(h);

      out.push({
        id: s.id,
        open: switches.has(s.id),
        host: s.host,
        name: scalar('sysName') || s.host,
        model: h.model || '',
        health: h,
        bridgeMac: scalar('dot1dBaseBridgeAddress'),
        rootMac: live.decided ? live.rootMac : scalar('dot1dStpDesignatedRoot'),
        isRoot: live.decided ? live.isRoot : (h.summary && h.summary.stpIsRoot === true),
        rootVlans: live.rootVlans,
        liveVlans: live.count,
        idleRootVlans: live.idleRootVlans,
        rootPort: live.rootPort || null,
        stackUnits: (h.stack && h.stack.length) || 1,
        addresses: [s.host]
      });
    }
    return out;
  }

  function topoRebuild(relayout) {
    const inputs = topoSwitchInputs();
    // Any rebuild with real switches behind it is current by definition.
    if (inputs.length) topoState.stale = false;
    if (!inputs.length) {
      /**
       * Nothing polled. The last picture is kept rather than cleared --
       * closing the switches you were looking at should not delete the
       * diagram you were looking at, and a blank canvas is no use to
       * anybody. It is labelled as a snapshot so it is not mistaken for
       * something still being watched.
       */
      topoState.stale = !!topoState.graph;
      topoPaint();
      return;
    }
    topoState.stale = false;
    // Hosts known only by a learned MAC are endpoints like any other, so
    // they follow the endpoints switch rather than having one of their
    // own. They are always built; showing them is the filter's business.
    topoState.graph = window.Topology.build(inputs, { macEndpoints: true });
    if (relayout !== false) {
      TV.layout(topoState.graph, topoSvg.clientWidth || 900, topoSvg.clientHeight || 600,
        topoState.vlan, { hideEndpoints: !document.getElementById('topo-f-endpoints').checked });
    }
    topoVlanOptions();
    topoPaint();
    if (relayout !== false) topoFit();
  }

  /** Which nodes and links the filters allow on screen. */
  function topoVisible() {
    const g = topoState.graph;
    if (!g) return { nodes: [], links: [] };
    const showEp = document.getElementById('topo-f-endpoints').checked;
    const showExt = document.getElementById('topo-f-external').checked;
    const vlan = topoState.vlan;

    const keep = new Set();
    for (const n of g.nodes.values()) {
      if (n.endpoint && (!showEp || n._hidden)) continue;
      if (n.kind === 'switch' && !n.polled && !showExt) continue;
      if (vlan && n.kind === 'switch' && !topoSwitchInVlan(g, n, vlan)) continue;
      keep.add(n.id);
    }
    const links = g.links.filter((l) => {
      if (!keep.has(l.source) || !keep.has(l.target)) return false;
      // A link to a neighbour the switch still remembers on a port that is
      // not up is always drawn. It is a failed or unplugged uplink, which
      // is exactly the thing worth seeing -- hiding it behind a switch
      // meant the one diagram that would have shown the fault did not.
      if (vlan) {
        const inVlan = String(l.accessVlan) === String(vlan) ||
          (l.untagged || []).map(String).indexOf(String(vlan)) >= 0 ||
          (l.tagged || []).map(String).indexOf(String(vlan)) >= 0;
        if (!inVlan) return false;
      }
      return true;
    });
    return { nodes: Array.from(keep).map((id) => g.nodes.get(id)), links };
  }

  function topoSwitchInVlan(g, n, vlan) {
    for (const l of g.links) {
      if (l.source !== n.id && l.target !== n.id) continue;
      if (String(l.accessVlan) === String(vlan)) return true;
      if ((l.untagged || []).map(String).indexOf(String(vlan)) >= 0) return true;
      if ((l.tagged || []).map(String).indexOf(String(vlan)) >= 0) return true;
    }
    return false;
  }

  function topoVlanOptions() {
    const sel = document.getElementById('topo-vlan');
    const seen = new Set();
    for (const l of (topoState.graph ? topoState.graph.links : [])) {
      for (const v of (l.untagged || []).concat(l.tagged || [])) seen.add(String(v));
      if (l.accessVlan) seen.add(String(l.accessVlan));
    }
    const current = sel.value;
    clear(sel);
    sel.appendChild(new Option('All VLANs', ''));
    for (const v of Array.from(seen).sort((a, b) => Number(a) - Number(b))) {
      sel.appendChild(new Option('VLAN ' + v, v));
    }
    sel.value = current && seen.has(current) ? current : '';
    topoState.vlan = sel.value;
  }

  // ---------- drawing ----------
  function topoPaint() {
    const edges = document.getElementById('topo-edges');
    const labels = document.getElementById('topo-edgelabels');
    const nodesG = document.getElementById('topo-nodes');
    clear(edges); clear(labels); clear(nodesG);

    const g = topoState.graph;
    const stat = (id, v) => { document.getElementById(id).textContent = v; };
    document.getElementById('topo-stale').style.display = topoState.stale ? '' : 'none';
    // Painted here rather than only at the call sites: whatever reason the
    // panel had for repainting, the header should agree with what is on
    // screen, and ordering bugs between the two stop being possible.
    paintTopoButton();
    if (!g) {
      stat('topo-n-sw', 0); stat('topo-n-link', 0); stat('topo-n-ep', 0); stat('topo-n-warn', 0);
      topoWarnings([{ sev: 'inf', title: 'Nothing to draw yet',
        det: 'The picture is built from what a switch reports, so it needs one first.' }]);
      // A view you can be sent to needs a way out of it.
      const host = document.getElementById('topo-warnings');
      const add = el('button', 'btn', 'Add a switch');
      add.type = 'button';
      add.style.marginTop = '10px';
      add.addEventListener('click', () => {
        const ids = Array.from(switches.keys());
        if (ids.length) selectSwitch(ids[ids.length - 1]);
        else createSwitch();
      });
      host.appendChild(add);
      return;
    }

    const vis = topoVisible();
    const byId = new Map(vis.nodes.map((n) => [n.id, n]));
    stat('topo-n-sw', vis.nodes.filter((n) => n.kind === 'switch').length);
    stat('topo-n-link', vis.links.filter((l) => l.kind === 'switch').length);
    stat('topo-n-ep', vis.nodes.filter((n) => n.endpoint).length);
    // The stale notice is a note like any other, so it counts as one.
    stat('topo-n-warn', g.warnings.length + (topoState.stale ? 1 : 0));
    topoWarnings(topoState.stale
      ? [{ sev: 'wrn', title: 'No switches open',
        det: 'This is the last picture that was drawn. Nothing is being polled now, so it ' +
          'will not change until a switch is added again.' }].concat(g.warnings)
      : g.warnings);
    topoLegend();

    for (const l of vis.links) {
      const a = byId.get(l.source), b = byId.get(l.target);
      if (!a || !b || a.x === undefined || b.x === undefined) continue;
      const line = TV.el('line', {
        x1: a.x, y1: a.y, x2: b.x, y2: b.y, 'class': 'topo-edge',
        stroke: topoEdgeColour(l),
        'stroke-width': l.kind === 'endpoint' ? 1 : (l.speed >= 10000 ? 3 : 2),
        'stroke-opacity': l.blocked ? 0.75 : (l.kind === 'endpoint' ? 0.4 : 0.85)
      });
      // A blocked link is drawn, because pretending it is absent hides a
      // loop; dashed, because no traffic takes it.
      if (l.blocked) line.setAttribute('stroke-dasharray', '7 5');
      else if (!l.confirmed && l.kind === 'switch') line.setAttribute('stroke-dasharray', '2 4');
      line.addEventListener('mouseenter', (e) => topoShowTip(e, topoLinkTip(l, a, b)));
      line.addEventListener('mousemove', (e) => topoShowTip(e, topoLinkTip(l, a, b)));
      line.addEventListener('mouseleave', topoHideTip);
      line.addEventListener('click', () => topoSelect({ link: l, a, b }));
      edges.appendChild(line);

      if (l.kind === 'switch') {
        // Two thirds of the way down and pushed off the line: the middle
        // of a vertical uplink is exactly where the endpoint fan is.
        const mx = a.x + (b.x - a.x) * 0.62, my = a.y + (b.y - a.y) * 0.62;
        const bits = [];
        if (l.speed) bits.push(topoSpeed(l.speed));
        if (l.mode === 'trunk') bits.push('trunk');
        else if (l.accessVlan) bits.push('v' + l.accessVlan);
        if (l.blocked) bits.push('blocked');
        // Always drawn now, so it has to be obvious which one it is.
        if (l.down) bits.push('down');
        if (bits.length) {
          const len = Math.hypot(b.x - a.x, b.y - a.y) || 1;
          const offX = (-(b.y - a.y) / len) * 12, offY = ((b.x - a.x) / len) * 12;
          const t = TV.el('text', {
            x: mx + offX, y: my + offY, 'text-anchor': 'middle', 'class': 'nodesub',
            'font-size': 9, fill: l.blocked ? 'var(--t-red)' : 'var(--t-faint)'
          });
          t.textContent = bits.join(' \u00b7 ');
          labels.appendChild(t);
        }
      }
    }

    for (const n of vis.nodes) {
      if (n.x === undefined) continue;
      const grp = TV.el('g', {
        'class': 'topo-node', transform: 'translate(' + n.x + ',' + n.y + ')'
      });
      if (n.kind === 'switch') topoDrawSwitch(grp, n, topoState.sel && topoState.sel.node === n.id);
      else topoDrawEndpoint(grp, n, topoState.sel && topoState.sel.node === n.id);
      grp.addEventListener('mouseenter', (e) => topoShowTip(e, topoNodeTip(n)));
      grp.addEventListener('mousemove', (e) => topoShowTip(e, topoNodeTip(n)));
      grp.addEventListener('mouseleave', topoHideTip);
      grp.addEventListener('mousedown', (e) => topoDragNode(e, n, grp));
      grp.addEventListener('click', (e) => { e.stopPropagation(); topoSelect({ node: n.id }); });
      // Double-click goes straight there, without the inspector step.
      grp.addEventListener('dblclick', (e) => {
        e.stopPropagation();
        if (!n.polled) return;
        if (n.tabId && closedSwitches.has(n.tabId)) { reopenSwitch(n.tabId); return; }
        for (const [id, sw] of switches) if (sw.host === n.host) selectSwitch(id);
      });
      nodesG.appendChild(grp);
    }
    topoApplyTransform();
  }

  function topoEdgeColour(l) {
    if (l.blocked) return 'var(--t-red)';
    if (l.down) return 'var(--t-faint)';
    if (l.kind === 'endpoint') return TV.KIND_COLOR[(topoState.graph.nodes.get(l.target) || {}).kind]
      || 'var(--t-dim)';
    if (l.speed >= 10000) return 'var(--t-cyan)';
    return 'var(--t-blue)';
  }

  const topoSpeed = (mbps) => mbps >= 1000 ? (mbps / 1000) + 'G' : mbps + 'M';

  function topoDrawSwitch(g, n, selected) {
    const w = n.polled ? 172 : 150, h = n.polled ? 64 : 54;
    if (n.isRoot) {
      g.appendChild(TV.el('rect', {
        x: -w / 2 - 6, y: -h / 2 - 6, width: w + 12, height: h + 12, rx: 14,
        fill: 'none', stroke: 'var(--t-cyan)', 'stroke-width': 1.5,
        'stroke-opacity': 0.55, 'stroke-dasharray': '3 4'
      }));
    }
    const box = TV.el('rect', {
      x: -w / 2, y: -h / 2, width: w, height: h, rx: 11,
      fill: n.polled ? 'var(--t-node)' : 'var(--t-node2)',
      stroke: selected ? 'var(--t-cyan)' : (n.isRoot ? 'var(--t-cyan)' : 'var(--t-line2)'),
      'stroke-width': selected ? 2.2 : 1.4
    });
    box.style.filter = selected ? 'drop-shadow(0 0 14px rgba(56,224,207,.5))'
      : (n.polled ? 'drop-shadow(0 6px 14px rgba(0,0,0,.45))' : '');
    g.appendChild(box);

    g.appendChild(TV.el('rect', {
      x: -w / 2, y: -h / 2, width: 5, height: h, rx: 2,
      fill: n.isRoot ? 'var(--t-cyan)'
        : (n.role === 'Distribution' ? 'var(--t-blue)'
          : (n.polled ? 'var(--t-green)' : 'var(--t-faint)'))
    }));

    // One pip per stack unit, up to four: a stack is a different thing to
    // reason about and it should be visible without opening anything.
    for (let i = 0; i < Math.min(n.stack || 1, 4); i++) {
      g.appendChild(TV.el('rect', {
        x: w / 2 - 12 - i * 7, y: -h / 2 + 7, width: 5, height: 5, rx: 1,
        fill: i === 0 ? 'var(--t-green)' : 'var(--t-cyan)'
      }));
    }

    const t1 = TV.el('text', {
      x: -w / 2 + 15, y: n.polled ? -9 : -6, 'class': 'nodelabel',
      fill: '#eaf2f7', 'font-size': n.polled ? 13 : 12
    });
    t1.textContent = TV.trunc(n.label, n.polled ? 17 : 16);
    g.appendChild(t1);

    const t2 = TV.el('text', {
      x: -w / 2 + 15, y: n.polled ? 9 : 10, 'class': 'nodesub',
      fill: 'var(--t-dim)', 'font-size': 9.5
    });
    t2.textContent = TV.trunc((n.polled ? (n.role || '') + ' \u00b7 ' : '') + (n.sub || ''),
      n.polled ? 28 : 20);
    g.appendChild(t2);

    if (n.isRoot) {
      const c = TV.el('text', {
        x: w / 2 - 14, y: h / 2 - 9, 'text-anchor': 'end', 'font-size': 9,
        fill: 'var(--t-cyan)', 'class': 'nodesub'
      });
      c.textContent = '\u25c6 ROOT';
      g.appendChild(c);
    }
    /**
     * Only "not polled" is worth saying on the diagram. Whether a switch's
     * tab happens to be open is a fact about this browser, not about the
     * network, and the topology is a picture of the network.
     */
    if (!n.polled) {
      const c = TV.el('text', {
        x: -w / 2 + 15, y: 21, 'font-size': 8.5, fill: 'var(--t-faint)', 'class': 'nodesub'
      });
      c.textContent = 'not polled';
      g.appendChild(c);
    }
  }

  function topoDrawEndpoint(g, n, selected) {
    const colour = TV.KIND_COLOR[n.kind] || 'var(--t-dim)';
    const ring = TV.el('circle', {
      r: selected ? 17 : 14, fill: '#11161f',
      stroke: selected ? 'var(--t-cyan)' : colour, 'stroke-width': selected ? 2.4 : 1.6
    });
    ring.style.filter = selected ? 'drop-shadow(0 0 10px rgba(56,224,207,.5))' : '';
    g.appendChild(ring);
    const glyph = TV.el('text', {
      x: 0, y: 5, 'text-anchor': 'middle', 'font-size': 14, fill: colour
    });
    glyph.textContent = TV.KIND_GLYPH[n.kind] || '?';
    g.appendChild(glyph);
    const label = TV.el('text', {
      x: 0, y: 30, 'text-anchor': 'middle', 'class': 'nodesub',
      fill: 'var(--t-dim)', 'font-size': 9
    });
    label.textContent = TV.trunc(n.label, 14);
    g.appendChild(label);
  }


  // ---------- tooltips, selection, inspector ----------
  function topoShowTip(e, html) {
    topoTip.innerHTML = html;
    topoTip.style.opacity = 1;
    let x = e.clientX + 14, y = e.clientY + 14;
    if (x > window.innerWidth - 320) x = e.clientX - 300;
    if (y > window.innerHeight - 140) y = e.clientY - 120;
    topoTip.style.left = x + 'px';
    topoTip.style.top = y + 'px';
  }
  const topoHideTip = () => { topoTip.style.opacity = 0; };

  function topoNodeTip(n) {
    const esc = TV.esc;
    if (n.kind === 'switch') {
      return '<div class="h">' + esc(n.label) + '</div><div class="l">' +
        esc(n.sub || '') + (n.polled ? ' \u00b7 ' + esc(n.role || '') : ' \u00b7 not polled') +
        '</div>';
    }
    return '<div class="h">' + esc(n.label) + '</div><div class="l">' +
      esc(n.kind) + (n.sub ? ' \u00b7 ' + esc(n.sub) : '') + '</div>';
  }

  function topoLinkTip(l, a, b) {
    const esc = TV.esc;
    // Whichever end is higher on screen is named first, so the tooltip
    // reads the same way round as the line it describes.
    const top = b.y < a.y ? { n: b, port: l.bPort } : { n: a, port: l.aPort };
    const bottom = b.y < a.y ? { n: a, port: l.aPort } : { n: b, port: l.bPort };
    const bits = [];
    if (l.speed) bits.push(topoSpeed(l.speed));
    if (l.mode === 'trunk') bits.push('trunk' + (l.nativeVlan ? ' native ' + l.nativeVlan : ''));
    else if (l.accessVlan) bits.push('access v' + l.accessVlan);
    if (l.stpRole || l.stpState) bits.push('STP ' + [l.stpRole, l.stpState].filter(Boolean).join('/'));
    if (l.poe) bits.push('PoE');
    if (l.down) bits.push('down');
    if (l.kind === 'switch' && !l.confirmed) bits.push('one side only');
    if (l.protos && l.protos.length) bits.push(l.protos.join(' + '));
    return '<div class="h">' + esc(top.n.label) + ' ' + esc(top.port || '?') +
      ' \u2194 ' + esc(bottom.n.label) + ' ' + esc(bottom.port || '?') + '</div>' +
      '<div class="l">' + esc(bits.join(' \u00b7 ')) + '</div>';
  }

  function topoSelect(sel) {
    topoState.sel = sel;
    document.querySelector('.topo-body').classList.add('insp');
    topoPaint();
    topoInspector();
  }

  function topoInspector() {
    const host = document.getElementById('topo-inspector');
    clear(host);
    const sel = topoState.sel;
    const g = topoState.graph;
    if (!sel || !g) return;

    const row = (table, k, v) => {
      if (v === undefined || v === null || v === '') return;
      const tr = document.createElement('tr');
      const a = document.createElement('td'); a.textContent = k;
      const b = document.createElement('td'); b.textContent = v;
      tr.appendChild(a); tr.appendChild(b); table.appendChild(tr);
    };
    const group = (title) => {
      const box = el('div', 'insp-group');
      box.appendChild(el('div', 'eyebrow', title));
      const t = document.createElement('table');
      t.className = 'data-table';
      box.appendChild(t);
      host.appendChild(box);
      return t;
    };

    if (sel.link) {
      const l = sel.link;
      const h = document.createElement('h4');
      h.textContent = (sel.a.label || '') + ' \u2194 ' + (sel.b.label || '');
      host.appendChild(h);
      host.appendChild(el('div', 'insp-sub',
        (l.protos || []).join(' + ') + (l.confirmed ? ' \u00b7 seen from both ends'
          : ' \u00b7 reported by one end')));
      const t = group('Link');
      row(t, sel.a.label + ' port', l.aPort);
      row(t, sel.b.label + ' port', l.bPort || 'not reported');
      row(t, 'Speed', l.speed ? topoSpeed(l.speed) : null);
      row(t, 'State', [l.admin, l.oper].filter(Boolean).join(' / '));
      row(t, 'Mode', l.mode);
      row(t, 'Access VLAN', l.accessVlan);
      row(t, 'Native VLAN', l.nativeVlan);
      row(t, 'Untagged', (l.untagged || []).join(', '));
      row(t, 'Tagged', rangeOf((l.tagged || []).map(Number)));
      row(t, 'Spanning tree', [l.stpRole, l.stpState].filter(Boolean).join(' / '));
      row(t, 'PoE', l.poe ? l.poe.detection + (l.poe.cls ? ' \u00b7 class ' + l.poe.cls : '') : null);
      row(t, 'Errors', l.errors || null);
      return;
    }

    const n = g.nodes.get(sel.node);
    if (!n) return;
    const h = document.createElement('h4');
    h.textContent = n.label;
    host.appendChild(h);
    host.appendChild(el('div', 'insp-sub',
      n.kind === 'switch'
        ? (n.polled ? (n.role || '') + ' \u00b7 ' + (n.sub || '') : 'seen by a neighbour, not polled')
        : n.kind + (n.sub ? ' \u00b7 ' + n.sub : '')));

    if (n.kind === 'switch' && n.polled && n.health) {
      const s = n.health.summary || {};
      const t = group('Switch');
      row(t, 'Model', n.sub);
      row(t, 'Address', n.host);
      row(t, 'Stack units', n.stack > 1 ? n.stack : null);
      row(t, 'Interfaces up', s.interfacesUp != null ? s.interfacesUp + ' / ' + s.interfacesTotal : null);
      row(t, 'VLANs', s.vlanCount);
      row(t, 'Spanning tree', s.stpMode);
      row(t, 'Root bridge', n.isRoot ? 'this switch' : null);
      row(t, 'MAC entries', s.macCount);
      row(t, 'Neighbours', s.neighbourCount);
    }

    const links = g.links.filter((l) => l.source === n.id || l.target === n.id);
    const sw = links.filter((l) => l.kind === 'switch');
    if (sw.length) {
      const t = group('Links to switches');
      for (const l of sw) {
        const other = g.nodes.get(l.source === n.id ? l.target : l.source);
        const port = l.source === n.id ? l.aPort : l.bPort;
        row(t, port || '?', (other ? other.label : '?') +
          (l.blocked ? ' \u00b7 blocked' : '') + (l.speed ? ' \u00b7 ' + topoSpeed(l.speed) : ''));
      }
    }
    const eps = links.filter((l) => l.kind === 'endpoint');
    if (eps.length) {
      const t = group('Attached');
      for (const l of eps) {
        const other = g.nodes.get(l.source === n.id ? l.target : l.source);
        row(t, l.aPort, (other ? other.label : '?') +
          (other && other.kind ? ' \u00b7 ' + other.kind : ''));
      }
    }
    if (n.macs && n.macs.length) {
      const t = group('Learned MACs');
      for (const m of n.macs.slice(0, 12)) row(t, m.mac, 'VLAN ' + m.vlan);
    }
    if (n.kind === 'switch' && n.polled) {
      // "Open this switch" only when there is no tab for it. When one is
      // already open the action is navigation, not opening, and saying
      // "open" for something already open reads as a mistake.
      const btn = el('button', 'btn', n.open ? 'Go to this switch' : 'Open this switch');
      btn.type = 'button';
      btn.addEventListener('click', () => {
        // Its tab may be on screen or merely put away; either way this is
        // the way back to it, and selecting it leaves the topology tab.
        if (n.tabId && closedSwitches.has(n.tabId)) { reopenSwitch(n.tabId); return; }
        for (const [id, sw] of switches) if (sw.host === n.host) selectSwitch(id);
      });
      host.appendChild(btn);
    }
  }

  function topoWarnings(list) {
    const host = document.getElementById('topo-warnings');
    clear(host);
    if (!list || !list.length) {
      host.appendChild(el('div', 'topo-warn', 'Nothing to flag.'));
      return;
    }
    for (const w of list) {
      const box = el('div', 'topo-warn ' + (w.sev || 'inf'));
      box.appendChild(el('b', '', w.title));
      box.appendChild(document.createTextNode(w.det));
      host.appendChild(box);
    }
  }

  function topoLegend() {
    const host = document.getElementById('topo-legend');
    clear(host);
    const add = (glyph, text, colour) => {
      const s = el('span', '');
      const i = el('i', '', glyph);
      i.style.color = colour;
      s.appendChild(i);
      s.appendChild(document.createTextNode(text));
      host.appendChild(s);
    };
    add('\u25c6', 'Spanning-tree root', 'var(--t-cyan)');
    add('\u2500', '10G link', 'var(--t-cyan)');
    add('\u2500', '1G link', 'var(--t-blue)');
    add('\u254c', 'Blocked by spanning tree', 'var(--t-red)');
    add('\u2500', 'Port down \u2014 neighbour still remembered', 'var(--t-faint)');
    add('\u254c', 'Reported by one end only', 'var(--t-faint)');
    add(TV.KIND_GLYPH.phone, 'Phone', TV.KIND_COLOR.phone);
    add(TV.KIND_GLYPH.ap, 'Access point', TV.KIND_COLOR.ap);
    add(TV.KIND_GLYPH.host, 'Host', TV.KIND_COLOR.host);
    add(TV.KIND_GLYPH.segment, 'Several MACs on a port', TV.KIND_COLOR.segment);
  }

  // ---------- pan, zoom, drag ----------
  function topoApplyTransform() {
    topoViewport.setAttribute('transform',
      'translate(' + topoState.tx + ',' + topoState.ty + ') scale(' + topoState.zoom + ')');
  }

  function topoFit() {
    const vis = topoVisible();
    const pts = vis.nodes.filter((n) => n.x !== undefined);
    if (!pts.length) return;
    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    for (const n of pts) {
      minX = Math.min(minX, n.x - 110); maxX = Math.max(maxX, n.x + 110);
      minY = Math.min(minY, n.y - 60); maxY = Math.max(maxY, n.y + 60);
    }
    const w = topoSvg.clientWidth || 900, h = topoSvg.clientHeight || 600;
    /**
     * Half the size that would fill the pane. A diagram fitted edge to
     * edge leaves no room to see that anything is beyond it, and the first
     * thing anyone does with a topology is drag it about -- starting
     * zoomed out means there is somewhere to drag it to.
     */
    // Exactly half what fitting edge to edge would give, cap included: a
    // diagram filling the pane leaves no sign that anything is beyond it,
    // and the first thing anyone does with a topology is drag it around.
    // Never magnified past natural size either -- a two-node network blown
    // up to fill a screen looks like a mistake.
    const zoom = Math.min(1, Math.max(0.08,
      Math.min(w / (maxX - minX), h / (maxY - minY)) * 0.46));
    topoState.zoom = zoom;
    topoState.tx = (w - (maxX + minX) * zoom) / 2;
    topoState.ty = (h - (maxY + minY) * zoom) / 2;
    topoApplyTransform();
  }

  function topoZoomBy(factor) {
    const w = topoSvg.clientWidth / 2, h = topoSvg.clientHeight / 2;
    const next = Math.min(3, Math.max(0.1, topoState.zoom * factor));
    // Zoom about the middle of the view rather than the origin, so the
    // thing being looked at stays where it is.
    topoState.tx = w - (w - topoState.tx) * (next / topoState.zoom);
    topoState.ty = h - (h - topoState.ty) * (next / topoState.zoom);
    topoState.zoom = next;
    topoApplyTransform();
  }

  function topoDragNode(e, n, grp) {
    if (e.button !== 0) return;
    e.stopPropagation();
    const start = { x: e.clientX, y: e.clientY, nx: n.x, ny: n.y };
    let moved = false;
    const move = (ev) => {
      const dx = (ev.clientX - start.x) / topoState.zoom;
      const dy = (ev.clientY - start.y) / topoState.zoom;
      if (Math.abs(dx) + Math.abs(dy) > 2) moved = true;
      n.x = start.nx + dx;
      n.y = start.ny + dy;
      grp.setAttribute('transform', 'translate(' + n.x + ',' + n.y + ')');
      topoPaintEdgesOnly();
    };
    const up = () => {
      document.removeEventListener('mousemove', move);
      document.removeEventListener('mouseup', up);
      if (moved) topoPaint();
    };
    document.addEventListener('mousemove', move);
    document.addEventListener('mouseup', up);
  }

  /** Redraw just the lines while a node is being dragged. */
  function topoPaintEdgesOnly() {
    const vis = topoVisible();
    const byId = new Map(vis.nodes.map((n) => [n.id, n]));
    const lines = document.getElementById('topo-edges').children;
    let i = 0;
    for (const l of vis.links) {
      const a = byId.get(l.source), b = byId.get(l.target);
      const line = lines[i++];
      if (!line || !a || !b) continue;
      line.setAttribute('x1', a.x); line.setAttribute('y1', a.y);
      line.setAttribute('x2', b.x); line.setAttribute('y2', b.y);
    }
  }

  topoSvg.addEventListener('mousedown', (e) => {
    if (e.button !== 0) return;
    const start = { x: e.clientX, y: e.clientY, tx: topoState.tx, ty: topoState.ty };
    topoSvg.classList.add('panning');
    const move = (ev) => {
      topoState.tx = start.tx + (ev.clientX - start.x);
      topoState.ty = start.ty + (ev.clientY - start.y);
      topoApplyTransform();
    };
    const up = () => {
      topoSvg.classList.remove('panning');
      document.removeEventListener('mousemove', move);
      document.removeEventListener('mouseup', up);
    };
    document.addEventListener('mousemove', move);
    document.addEventListener('mouseup', up);
  });
  topoSvg.addEventListener('wheel', (e) => {
    e.preventDefault();
    topoZoomBy(e.deltaY < 0 ? 1.12 : 1 / 1.12);
  }, { passive: false });
  topoSvg.addEventListener('click', () => {
    if (!topoState.sel) return;
    topoState.sel = null;
    document.querySelector('.topo-body').classList.remove('insp');
    topoPaint();
  });

  document.getElementById('topo-zin').addEventListener('click', () => topoZoomBy(1.2));
  document.getElementById('topo-zout').addEventListener('click', () => topoZoomBy(1 / 1.2));
  document.getElementById('topo-fit').addEventListener('click', topoFit);
  document.getElementById('topo-relayout').addEventListener('click', () => topoRebuild(true));
  document.getElementById('topo-f-endpoints').addEventListener('change', () => {
    // Showing or hiding them changes how much room the diagram needs.
    topoRebuild(true);
  });
  document.getElementById('topo-f-external').addEventListener('change', topoPaint);

  document.getElementById('topo-vlan').addEventListener('change', (e) => {
    topoState.vlan = e.target.value;
    // A VLAN focus changes which switches are on the picture, so the
    // layers are worked out again rather than leaving gaps behind.
    TV.layout(topoState.graph, topoSvg.clientWidth || 900, topoSvg.clientHeight || 600,
      topoState.vlan, { hideEndpoints: !document.getElementById('topo-f-endpoints').checked });
    topoPaint();
    topoFit();
  });

  /** Save the diagram as a PNG, at twice the size so it stays readable. */
  document.getElementById('topo-png').addEventListener('click', () => {
    const w = topoSvg.clientWidth, h = topoSvg.clientHeight;
    const clone = topoSvg.cloneNode(true);
    clone.setAttribute('width', w);
    clone.setAttribute('height', h);
    // The SVG is styled from the page, which a detached copy cannot see,
    // so the variables it uses are written in explicitly.
    const styles = getComputedStyle(topoPanel);
    let vars = '';
    for (const name of ['--t-cyan', '--t-blue', '--t-violet', '--t-amber', '--t-green',
      '--t-red', '--t-line', '--t-line2', '--t-ink', '--t-dim', '--t-faint',
      '--t-node', '--t-node2']) {
      vars += name + ':' + styles.getPropertyValue(name) + ';';
    }
    const style = document.createElementNS('http://www.w3.org/2000/svg', 'style');
    style.textContent = 'svg{' + vars + 'background:' +
      getComputedStyle(document.body).backgroundColor + ';}' +
      '.nodelabel,.nodesub{font-family:ui-monospace,Menlo,Consolas,monospace;}';
    clone.insertBefore(style, clone.firstChild);

    const svgText = new XMLSerializer().serializeToString(clone);
    const img = new Image();
    img.onload = () => {
      const canvas = document.createElement('canvas');
      canvas.width = w * 2; canvas.height = h * 2;
      const ctx = canvas.getContext('2d');
      ctx.fillStyle = getComputedStyle(document.body).backgroundColor;
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
      const a = document.createElement('a');
      a.download = 'topology.png';
      a.href = canvas.toDataURL('image/png');
      a.click();
      appLog('info', 'Topology saved as PNG', {});
    };
    img.onerror = () => appLog('warn', 'Could not render the topology to PNG', {});
    img.src = 'data:image/svg+xml;base64,' + btoa(unescape(encodeURIComponent(svgText)));
  });

  paintTopoButton();
