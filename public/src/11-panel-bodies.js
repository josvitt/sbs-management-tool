  // =================================================================
  // 11-panel-bodies.js: The built-in panel bodies (paintBuiltin) and system identity editing.
  // =================================================================

  function paintPanelBody(s, p) {
    if (p.collapsed) return;
    const body = p._body;
    if (!body) return;
    clear(body);
    if (p.kind === 'oid') { paintOidPanel(s, p, body); return; }
    try {
      paintBuiltin(s, p.key, body, p);
    } catch (e) {
      body.appendChild(el('div', 'panel-err', 'Could not render this panel: ' + e.message));
      appLog('error', 'Panel render failed', { panel: p.title, message: e.message });
    }
  }

  // ---------- built-in panel bodies ----------
  /** Panels can be fed by SNMP or a capture; say which, every time. */
  function sourceNote(src, detail) {
    const d = el('div', 'panel-note');
    d.appendChild(el('span', 'src-tag ' + src, src));
    d.appendChild(document.createTextNode(' ' + detail));
    return d;
  }

  function paintBuiltin(s, key, body, p) {
    // SNMP configuration does not depend on a health collection, so it is
    // handled before the "no data yet" gate the health panels sit behind.
    if (key === 'snmpcfg') { paintSnmpPanel(s, body, p); return; }
    if (key === 'acl') { paintAclPanel(s, body, p); return; }
    if (key === 'routing') { paintRoutingPanel(s, body, p); return; }
    if (key === 'vlans') { paintVlanPanel(s, body, p); return; }
    if (key === 'capture') { paintCapturePanel(s, body, p); return; }
    if (key === 'flash') { paintFlashPanel(s, body, p); return; }
    const h = s.health;
    if (!h) { body.appendChild(el('div', 'card-sub', 'No SNMP data yet.')); return; }
    const sc = (k) => (h.scalars[k] ? h.scalars[k].display : null);
    const scv = (k) => (h.scalars[k] ? h.scalars[k].value : null);

    // A forwarding database can be thousands of rows, and putting all of
    // them in the DOM on every refresh costs more than it informs. Render a
    // first slice and let the user ask for the rest; rows go in through a
    // fragment so the browser lays out once instead of per row.
    const ROW_CAP = 250;
    // `display` is omitted by the server when it would just repeat the
    // value, so every read of a cell has to fall back.
    const dv = (c, fallback) => {
      if (c === null || c === undefined) return fallback === undefined ? '' : fallback;
      if (typeof c !== 'object') return c;
      return c.display !== undefined ? c.display : c.value;
    };
    // `index` is a plain string on the row, not a {value,display} cell.
    // Treating it like one yielded undefined, and the table then rendered
    // the wrapper object itself -- the "[object Object]" in every index
    // column.
    const cellText = (raw) => {
      if (raw === null || raw === undefined) return '';
      if (typeof raw === 'object') return raw.display !== undefined ? raw.display : raw.value;
      return raw;
    };
    const cellsOf = (rows, cols) => rows.map((r) => cols.map((c) => {
      const v = cellText(c.key === 'index' ? r.index : r[c.key]);
      return c.state ? { pill: true, v } : { v };
    }));

    switch (key) {
      case 'summary': {
        const sev = overallSeverity(s);
        const hero = el('div', 'hero sev-' + (sev === 'info' ? 'ok' : sev));
        hero.style.margin = '0';
        const main = el('div', 'hero-main');
        const nameRow = el('div', 'hero-name-row');
        nameRow.appendChild(el('div', 'hero-name', sc('sysName') || s.host));
        if (s.target) {
          const pen = el('button', 'hero-edit-btn', '\u270E');
          pen.title = 'Edit name, location and contact';
          pen.type = 'button';
          pen.addEventListener('click', (e) => { e.stopPropagation(); editSysIdentity(s); });
          nameRow.appendChild(pen);
        }
        main.appendChild(nameRow);
        const bits = [];
        if (sc('sysDescr')) bits.push(sc('sysDescr'));
        const ident = [];
        if (h.summary.model) ident.push(h.summary.model);
        const chassis = h.inventory.find((r) => /chassis/i.test((r.entPhysicalClass && r.entPhysicalClass.display) || ''));
        if (chassis) {
          const cell = (c) => (c ? (c.display !== undefined ? c.display : c.value) : null);
          const sn = cell(chassis.entPhysicalSerialNum);
          const sw = cell(chassis.entPhysicalSoftwareRev);
          if (sn) ident.push('S/N ' + sn);
          if (sw) ident.push('Firmware ' + sw);
        }
        if (ident.length) bits.push(ident.join('  \u00b7  '));
        if (sc('sysUpTime')) bits.push('Uptime: ' + sc('sysUpTime'));
        const place = [sc('sysLocation'), sc('sysContact')].filter((x) => x && x !== '(empty)');
        if (place.length) bits.push(place.join('  \u00b7  '));
        main.appendChild(el('div', 'hero-sub', bits.join('\n')));
        hero.appendChild(main);
        hero.appendChild(el('div', 'hero-badge sev-' + (sev === 'info' ? 'info' : sev),
          sev === 'ok' ? 'Healthy' : (sev === 'critical' ? 'Critical' : (sev === 'warning' ? 'Attention' : 'Info'))));
        body.appendChild(hero);

        // Findings belong with the verdict they produced, not in a panel
        // of their own: the badge above says how the switch is, and these
        // say why.
        // Use the shared live-alert set so the findings shown here are exactly
        // what the Attention badge counts (see liveAlerts).
        const list = liveAlerts(s);
        const real = list.filter((x) => x.severity !== 'ok');
        const shown = real.length ? real : list;
        if (shown.length) {
          const wrap = el('div', 'hero-findings');
          for (const f of shown.sort((a, x) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[x.severity] ?? 9))) {
            const row = el('div', 'alert-row sev-' + f.severity);
            row.appendChild(el('div', 'alert-area', f.area));
            row.appendChild(el('div', 'alert-msg', f.message));
            wrap.appendChild(row);
          }
          body.appendChild(wrap);
        }

        // --- quick actions ---
        // The things you come to a switch to *do*, next to the summary of
        // what it is. Each opens its result rather than a settings page.
        const qa = el('div', 'quick-actions');
        const act = (label, cls, fn, busy, title) => {
          const b = el('button', 'btn ' + (cls || ''), busy || label);
          b.type = 'button';
          if (title) b.title = title;
          if (busy) b.disabled = true; else b.addEventListener('click', fn);
          qa.appendChild(b);
          return b;
        };
        act(s.tech ? 'Recollect tech-support' : 'Collect tech-support', 'btn-amber',
          () => startTechCollect(s), s.techBusy, 'Runs show tech-support over SSH');
        if (s.tech) {
          act('View tech-support', '', () => openOverlay(s, 'techOverlay'));
        }
        // When the two configurations are identical there is only one
        // thing to back up, and offering a choice between two copies of
        // the same file is a decision with no consequence.
        const savedCell = h.scalars && h.scalars['rlRunningCDBequalToStartupCDB'];
        const identical = !!savedCell && (
          (savedCell.value !== undefined && savedCell.value !== null)
            ? (Number(savedCell.value) === 1 || /true|yes|equal/i.test(String(savedCell.value)))
            : /true|yes|equal/i.test(String(savedCell.display)));
        if (identical) {
          act('Download config', 'btn-blue', () => backupConfig(s, 'running'), s.cfgBusy,
            'Running and startup are identical; fetches it over TFTP and saves it');
        } else {
          act('Download running-config', 'btn-blue', () => backupConfig(s, 'running'),
            s.cfgBusy, 'Fetches it over TFTP and saves it');
          act('Download startup-config', 'btn-blue', () => backupConfig(s, 'startup'), s.cfgBusy);
        }
        // CLI access moved to its own tab in the task bar (between Overview and
        // Settings), so it is not a Quick Action anymore.
        body.appendChild(qa);
        return;
      }

      case 'metrics': {
        const grid = el('div', 'card-grid');
        grid.style.margin = '0';
        const card = (label, value, cls, sub, pct, pcls, trend) => {
          if (value === null || value === undefined || value === '') return;
          const c = el('div', 'card');
          c.appendChild(el('div', 'card-label', label));
          c.appendChild(el('div', 'card-value' + (cls ? ' ' + cls : ''), value));
          if (sub) c.appendChild(el('div', 'card-sub', sub));
          if (trend) {
            const spark = sparkline(
              (s.history || []).map((x) => ({ t: x.t, v: x[trend.key] })),
              { cls: pcls || cls, unit: trend.unit });
            if (spark) c.appendChild(spark);
            // The card is the summary; the graph behind it is the record.
            c.classList.add('clickable');
            c.title = 'Open the full history of ' + label.toLowerCase();
            c.addEventListener('click', () => openGraph(s, trend.key));
          }
          if (pct != null) {
            const m = el('div', 'meter'); const i = el('i', pcls || '');
            i.style.width = Math.max(0, Math.min(100, pct)) + '%';
            m.appendChild(i); c.appendChild(m);
          }
          grid.appendChild(c);
          return c;
        };

        const led = sc('rlEnvSystemLed');
        if (led) card('Status LED', led, /green/i.test(led) ? 'good' : (/amber/i.test(led) ? 'crit' : ''));

        // Same reasoning as the input rate: the probe keeps reading these
        // between collections, so the newest sample is the honest value.
        const cpuLatest = latestOf(s.history, 'cpu');
        const cpu5 = cpuLatest === null ? Number(scv('rlCpuUtilDuringLast5Minutes')) : cpuLatest;
        if (Number.isFinite(cpu5)) {
          card('CPU (5 min)', cpu5 + '%', cpu5 >= 80 ? 'crit' : (cpu5 >= 60 ? 'warn' : 'good'),
            '1s ' + (scv('rlCpuUtilDuringLastSecond') ?? '?') + '%  \u00b7  1m ' + (scv('rlCpuUtilDuringLastMinute') ?? '?') + '%',
            cpu5, cpu5 >= 80 ? 'crit' : (cpu5 >= 60 ? 'warn' : ''),
            { key: 'cpu', unit: '%' });
        }
        // Packets per second punted to the CPU, beside utilisation: the two
        // answer different questions.
        if (h.summary.cpuInputPps != null) {
          // The rate now, with the peaks underneath. Bursts are what hurt a
          // control plane and the instant you happen to look is rarely one
          // of them, so the peaks earn their place -- but the current value
          // is what the card is *for*, so it stays the headline, and it
          // comes from the newest reading rather than the last collection.
          const latest = latestOf(s.history, 'cpuPps');
          const now = latest === null ? Number(h.summary.cpuInputPps) : latest;
          const hi5 = peakOf(s.history, 'cpuPps', 5 * 60 * 1000);
          const hi60 = peakOf(s.history, 'cpuPps', 60 * 60 * 1000);
          // Each figure carries its unit: "5 min peak 9" reads as two
          // numbers with no way to tell which is which.
          const peaks = [];
          if (hi5) peaks.push('peak ' + groupNum(hi5.peak) + ' pps over 5 min');
          if (hi60 && (!hi5 || hi60.peak !== hi5.peak)) {
            peaks.push(groupNum(hi60.peak) + ' pps over an hour');
          }
          const level = now >= 20000 ? 'crit' : (now >= 5000 ? 'warn' : 'good');
          card('CPU input rate', groupNum(now) + ' pps', level,
            h.summary.cpuInputEnabled === false
              ? 'SCT rate counting is disabled \u2014 value not measured'
              : (peaks.length ? peaks.join('  \u00b7  ')
                : 'packets per second handled by the CPU'),
            null, level, { key: 'cpuPps', unit: 'pps' });
        }
        if (h.summary.flashFreePct != null) {
          const ff = h.summary.flashFreePct;
          card('Flash free', ff + '%', ff < 10 ? 'crit' : (ff < 25 ? 'warn' : 'good'),
            scv('rlFileTotalSizeOfFlash') ? fmtBytes(scv('rlFileFreeSizeOfFlash')) + ' of ' + fmtBytes(scv('rlFileTotalSizeOfFlash')) : '',
            ff, ff < 10 ? 'crit' : (ff < 25 ? 'warn' : ''));
        }
        if (h.summary.maxTempC != null) {
          const x = h.summary.maxTempC;
          card('Max temp', x + '\u00b0C', x >= 80 ? 'crit' : (x >= 65 ? 'warn' : 'good'), h.sensors.length + ' sensor(s)');
        }
        if (h.summary.poeBudgetW) {
          const poeLatest = latestOf(s.history, 'poeW');
          const poeW = poeLatest === null ? h.summary.poeUsedW : poeLatest;
          const pct = (poeW / h.summary.poeBudgetW) * 100;
          const ds = h.summary.datasheetPoeW;
          card('PoE load', poeW + ' W', pct >= 90 ? 'crit' : (pct >= 75 ? 'warn' : 'good'),
            'of ' + h.summary.poeBudgetW + ' W budget (' + pct.toFixed(0) + '%)' +
            (ds && ds !== h.summary.poeBudgetW ? '  \u00b7  ' + h.summary.model + ' rated ' + ds + ' W' : ''),
            pct, pct >= 90 ? 'crit' : (pct >= 75 ? 'warn' : ''),
            { key: 'poeW', unit: 'W' });
        }
        if (h.summary.interfacesTotal) {
          card('Interfaces up', h.summary.interfacesUp + ' / ' + h.summary.interfacesTotal, 'good',
            h.summary.interfacesAdminDown + ' admin down');
        }
        const cfgCell = h.scalars && h.scalars['rlRunningCDBequalToStartupCDB'];
        if (cfgCell) {
          // The scalar is a TruthValue: true(1) = running equals startup (saved).
          // Read the raw value when present (robust to any display format like
          // "1", "true", or "true(1)"), else fall back to the display text.
          const rawVal = cfgCell.value;
          const isSaved = (rawVal !== undefined && rawVal !== null)
            ? (Number(rawVal) === 1 || /true|yes|equal/i.test(String(rawVal)))
            : /true|yes|equal/i.test(String(cfgCell.display));
          const c = card('Config saved', isSaved ? 'Yes' : 'No',
            isSaved ? 'good' : 'warn', 'running vs startup');
          // Actionable only when it is not saved: comparing two identical
          // files, or offering to save what is already saved, is busywork.
          if (c && !isSaved) {
            c.classList.add('clickable');
            c.title = 'Show what differs, and save the running configuration';
            c.appendChild(el('div', 'card-action', 'Compare and save \u2192'));
            c.addEventListener('click', () => openConfigDiff(s));
          }
        }
        // VLAN, neighbour and MAC counts are inventory, not health: they
        // are the size of a table, and each has a panel that shows the
        // table itself. A number with no threshold is not a key metric.
        body.appendChild(grid);
        return;
      }

      // One panel for the physical box: supplies, fans, sensors, the stack
      // and the identifiable hardware. They are all answers to "what is in
      // this switch and is it healthy", and as five panels they were five
      // mostly-empty boxes.
      case 'hardware': {
        const section = (title, note) => {
          if (s._ktReconcile) return;
          const st = el('div', 'section-title', title);
          if (note) st.appendChild(el('span', 'st-note', note));
          body.appendChild(st);
        };

        // Inventory leads: what the box *is* comes before how it is
        // doing. Only hardware with an identity worth recording -- ports,
        // fans, supplies and sensors are covered by the sections below,
        // and a row with no model, serial or revision identifies
        // nothing.
        const rows = h.inventory.filter((r) => {
          const cls = String((r.entPhysicalClass && r.entPhysicalClass.display) || '');
          if (/port|fan|powerSupply|sensor|container|slot|backplane/i.test(cls)) return false;
          if (!/chassis|module|stack/i.test(cls)) return false;
          const has = (k) => {
            const c = r[k];
            const v = c ? (c.display !== undefined ? c.display : c.value) : '';
            return v !== undefined && v !== null && String(v).trim() !== '' && String(v) !== '(empty)';
          };
          return has('entPhysicalModelName') || has('entPhysicalSerialNum') ||
            has('entPhysicalHardwareRev') || has('entPhysicalSoftwareRev');
        });
        if (rows.length) {
          // entPhysicalName is often just an index ("1" for the chassis),
          // in which case the description is the thing worth showing.
          const label = (r) => {
            const name = dv(r.entPhysicalName);
            const descr = dv(r.entPhysicalDescr);
            if (!name || /^\d+$/.test(String(name).trim())) return descr || name;
            return name;
          };
          section('Inventory');
          mountInto(body, s, p, 'inventory', ['Name', 'Class', 'Model', 'Serial', 'HW', 'SW'],
            keyedRowsFrom(rows.map((r) => [
              { v: label(r) }, { v: dv(r.entPhysicalClass) }, { v: dv(r.entPhysicalModelName) },
              { v: dv(r.entPhysicalSerialNum) }, { v: dv(r.entPhysicalHardwareRev) },
              { v: dv(r.entPhysicalSoftwareRev) }]), rows, (r) => r.index));
        }

        if (h.psus.length) {
          section('Power supplies');
          mountInto(body, s, p, 'psus', ['Supply', 'State', 'Source'],
            keyedRowsFrom(cellsOf(h.psus, [
              { key: 'rlEnvMonSupplyStatusDescr' }, { key: 'rlEnvMonSupplyState', state: true },
              { key: 'rlEnvMonSupplySource' }]), h.psus, (r) => r.index));
        }
        if (h.fans.length) {
          section('Fans');
          mountInto(body, s, p, 'fans', ['Fan', 'State'],
            keyedRowsFrom(cellsOf(h.fans, [
              { key: 'rlEnvMonFanStatusDescr' }, { key: 'rlEnvMonFanState', state: true }]), h.fans, (r) => r.index));
        }
        if (h.sensors.length) {
          section('Sensors');
          mountInto(body, s, p, 'sensors', ['Sensor', 'Type', 'Reading', 'Status'],
            keyedRowsFrom(cellsOf(h.sensors, [
              { key: 'index' }, { key: 'entPhySensorType' }, { key: 'entPhySensorValue' },
              { key: 'entPhySensorOperStatus', state: true }]), h.sensors, (r) => r.index));
        }
        // A single unit is not a stack, and saying so tells nobody
        // anything they cannot see from the model number.
        if (h.stack.length > 1) {
          section('Stack units', h.stack.length + ' units');
          mountInto(body, s, p, 'stack', ['Unit', 'Model', 'Software', 'MAC'],
            keyedRowsFrom(cellsOf(h.stack, [
              { key: 'index' }, { key: 'rlPhdStackProductID' },
              { key: 'rlPhdStackSofrwareVer' }, { key: 'rlPhdStackMacAddr' }]), h.stack, (r) => r.index));
        }

        if (!s._ktReconcile && !body.children.length) {
          body.appendChild(el('div', 'empty-state', 'The switch reported no hardware detail.'));
        }
        return;
      }

      // Interfaces and PoE describe the same physical ports, so they are
      // one table: what the port is doing, and what it is powering. The
      // PoE columns only appear on a switch that has PoE at all.
      case 'interfaces': {
        // In reconcile mode the body is not cleared, so the fixed scaffolding
        // (notes, the PoE budget header, section titles) is already present and
        // must not be re-appended; only the keyed tables reconcile. Each
        // appendChild of fixed chrome is therefore guarded with !s._ktReconcile.
        if (h.interfacesNotPresent && !s._ktReconcile) {
          body.appendChild(el('div', 'panel-note',
            h.interfacesNotPresent + ' interface(s) reporting notPresent(6) are not shown.'));
        }

        // Power budget first: it applies to the whole table below it.
        if (h.poe.length && !s._ktReconcile) {
          // A measured 0 W is valid; only treat a genuinely absent reading as
          // unknown. Never print "null W".
          const used = Number.isFinite(h.summary.poeUsedW) ? h.summary.poeUsedW : 0;
          const budget = Number.isFinite(h.summary.poeBudgetW) ? h.summary.poeBudgetW : 0;
          const pct = budget ? (used / budget) * 100 : 0;
          const head = el('div', 'poe-head');
          const big = el('div', 'poe-figure');
          big.appendChild(el('span', 'poe-used' + (pct >= 90 ? ' crit' : (pct >= 75 ? ' warn' : '')),
            used + ' W'));
          big.appendChild(el('span', 'poe-of', ' drawn of ' + budget + ' W PoE budget'));
          head.appendChild(big);
          const meter = el('div', 'meter');
          const bar = el('i', pct >= 90 ? 'crit' : (pct >= 75 ? 'warn' : ''));
          bar.style.width = Math.max(0, Math.min(100, pct)) + '%';
          meter.appendChild(bar);
          head.appendChild(meter);
          const on = h.poePorts.filter((r) => /deliveringPower/i.test(
            (r.pethPsePortDetectionStatus && r.pethPsePortDetectionStatus.display) || '')).length;
          head.appendChild(el('div', 'card-sub',
            [pct.toFixed(0) + '% used', (budget - used) + ' W free', on + ' port(s) delivering']
              .join('  \u00b7  ')));
          body.appendChild(head);
          if (h.poeIgnored && h.poeIgnored.length) {
            const note = el('div', 'panel-note', h.poeIgnored.length + ' phantom PSE row(s) ignored');
            note.title = h.poeIgnored.map((x) => 'PSE ' + x.index +
              (x.budget != null ? ' (' + x.budget + 'W)' : '')).join(', ');
            body.appendChild(note);
          }
        }

        // Join on the port name: PoE rows carry the same identity the
        // interface list does.
        const poeByPort = new Map();
        for (const r of h.poePorts) {
          const name = dv(r.port);
          if (name) poeByPort.set(String(name), r);
        }
        const hasPoe = h.poePorts.length > 0;

        /**
         * VLAN membership, turned round. The switch reports it per VLAN as
         * a bitmap of ports; what you want when looking at a port is the
         * other direction -- which VLAN it is in, and what it trunks. So
         * the bitmaps are inverted into a per-port index once, here.
         */
        const portVlans = new Map();
        const addVlan = (raw, vlan, kind) => {
          for (const n of String(raw || '').split(',')) {
            const port = n.trim();
            if (!port) continue;
            if (!portVlans.has(port)) portVlans.set(port, { untagged: [], tagged: [] });
            portVlans.get(port)[kind].push(vlan);
          }
        };
        for (const v of h.vlans) {
          const id = String(v.index);
          addVlan(v.untagged && v.untagged.value, id, 'untagged');
          addVlan(v.tagged && v.tagged.value, id, 'tagged');
        }
        const hasVlans = h.vlans.length > 0;

        /**
         * The switch lists its VLAN interfaces in the same table as its
         * ports, named after the VLAN id -- so a VLAN appears twice on
         * screen, once as a "port" called 10 and once as VLAN 10. They are
         * the same thing seen twice, so the interface is folded into the
         * VLAN row it belongs to and dropped from the port list.
         */
        const vlanIds = new Set(h.vlans.map((v) => String(v.index)));
        const sviByVlan = new Map();
        // Port channels are shown in their own section below, not in the ports
        // list - keep them out here to avoid duplicating them.
        const IS_CHANNEL = /^(po|ch|port-?channel|lag|trunk)\s*\d+/i;
        const ports = [];
        for (const r of h.interfaces) {
          const name = String(dv(r.rlifPresentName) || '').trim();
          if (/^\d+$/.test(name) && vlanIds.has(name)) sviByVlan.set(name, r);
          else if (IS_CHANNEL.test(name)) continue;   // shown in Port channels section
          else ports.push(r);
        }

        /**
         * Which ports look like uplinks. Shutting one of these is how you
         * lose contact with the switch you are administering, so they are
         * called out in the confirmation rather than treated like any
         * other port: a neighbour that announced itself over CDP or LLDP,
         * or the port the spanning tree is using to reach the root.
         */
        const uplinks = new Map();
        for (const r of h.cdp) {
          const n = dv(r.localPort, r.index);
          if (n) uplinks.set(String(n), dv(r.cdpCacheDeviceId) || 'a CDP neighbour');
        }
        for (const r of h.lldp) {
          const n = dv(r.localPort, r.index);
          if (n && !uplinks.has(String(n))) {
            uplinks.set(String(n), dv(r.lldpRemSysName) || 'an LLDP neighbour');
          }
        }
        const rootPort = h.scalars.dot1dStpRootPort && h.scalars.dot1dStpRootPort.display;
        if (rootPort && !/none/i.test(String(rootPort))) {
          // Both reasons matter, and a port can have both: knowing it
          // faces core-sw *and* carries the path to the root is more
          // useful than either alone.
          const had = uplinks.get(String(rootPort));
          uplinks.set(String(rootPort),
            had ? had + ', and carries the spanning-tree path to the root'
              : 'the spanning-tree root port');
        }

        // Switchport mode per port, from vlanPortModeState (indexed by ifIndex).
        // Confirmed against this switch's CLI: 11 = access, 12 = trunk. Only
        // those two are labelled; any other code is shown raw ("mode N") rather
        // than guessed, so the column never asserts a mode it can't verify.
        const PORT_MODE = { 11: 'access', 12: 'trunk' };
        const modeByIf = new Map();
        for (const r of (h.portModes || [])) {
          const code = r.vlanPortModeState && (r.vlanPortModeState.value !== undefined
            ? r.vlanPortModeState.value : r.vlanPortModeState.display);
          const n = parseInt(code, 10);
          if (!Number.isNaN(n)) modeByIf.set(String(r.index), PORT_MODE[n] || ('mode ' + n));
        }
        const hasModes = modeByIf.size > 0;

        // Per-port CONFIGURED access VLAN and trunk native VLAN. These reflect
        // the switchport's configured membership even when the port is down,
        // unlike the static egress-port table (which only shows applied
        // membership once the port comes up) - so a VLAN set on a down port is
        // read correctly from here.
        const accessVlanByIf = new Map();
        for (const r of (h.portAccessVlan || [])) {
          const n = parseInt(r.vlanAccessPortModeVlanId && (r.vlanAccessPortModeVlanId.value !== undefined ? r.vlanAccessPortModeVlanId.value : r.vlanAccessPortModeVlanId.display), 10);
          if (Number.isFinite(n) && n > 0) accessVlanByIf.set(String(r.index), n);
        }
        const nativeVlanByIf = new Map();
        for (const r of (h.portNativeVlan || [])) {
          const n = parseInt(r.vlanTrunkPortModeNativeVlanId && (r.vlanTrunkPortModeNativeVlanId.value !== undefined ? r.vlanTrunkPortModeNativeVlanId.value : r.vlanTrunkPortModeNativeVlanId.display), 10);
          if (Number.isFinite(n) && n > 0) nativeVlanByIf.set(String(r.index), n);
        }

        // L2 vs L3 per port, from vlanSwitchPortModeCategory (1 = l2 switchport,
        // 2 = l3 routed). Shown as a compact L2/L3 label; unknown codes raw.
        const L2L3 = { 1: 'L2', 2: 'L3' };
        const l2l3ByIf = new Map();
        for (const r of (h.portL2L3 || [])) {
          const code = r.vlanSwitchPortModeCategory && (r.vlanSwitchPortModeCategory.value !== undefined
            ? r.vlanSwitchPortModeCategory.value : r.vlanSwitchPortModeCategory.display);
          const n = parseInt(code, 10);
          if (!Number.isNaN(n)) l2l3ByIf.set(String(r.index), L2L3[n] || ('cat ' + n));
        }
        const hasL2L3 = l2l3ByIf.size > 0;
        // A routed port's own IPv4 address(es), shown read-only in place of
        // its (empty) VLAN cells; they are set in the IPv4 Addressing panel.
        const ipByIf = new Map();
        for (const a of ipv4Addresses(s)) {
          if (!a.real) continue;
          const ifx = String(a.ifIndex);
          const text = a.ip + (a.pref != null ? '/' + a.pref : '');
          ipByIf.set(ifx, ipByIf.has(ifx) ? ipByIf.get(ifx) + ', ' + text : text);
        }

        // 802.1X per-port config: port-control (force-unauth/auto/force-auth),
        // authorized status, and host-mode (single/multiple/multiple-auth).
        const dvv = (cell) => cell && (cell.value !== undefined ? cell.value : cell.display);
        const PORT_CONTROL = { 1: 'force-unauth', 2: 'auto', 3: 'force-auth' };
        const PORT_STATUS = { 1: 'authorized', 2: 'unauthorized' };
        const HOST_MODE = { 1: 'single', 2: 'multiple', 3: 'multiple-auth' };
        const dot1xByIf = new Map();
        for (const r of (h.dot1xPortCfg || [])) {
          const ctl = parseInt(dvv(r.dot1xAuthAuthControlledPortControl), 10);
          const st = parseInt(dvv(r.dot1xAuthAuthControlledPortStatus), 10);
          dot1xByIf.set(String(r.index), {
            control: PORT_CONTROL[ctl] || (Number.isFinite(ctl) ? 'ctl ' + ctl : ''),
            controlCode: Number.isFinite(ctl) ? ctl : null,
            status: PORT_STATUS[st] || ''
          });
        }
        const hostModeByIf = new Map();
        for (const r of (h.dot1xHostMode || [])) {
          const hm = parseInt(dvv(r.swIfHostMode), 10);
          if (Number.isFinite(hm)) hostModeByIf.set(String(r.index), { mode: HOST_MODE[hm] || ('mode ' + hm), modeCode: hm });
        }
        // Per-port authentication method (for MAB): the enum encodes which
        // methods are enabled on the port (802.1X / MAC / Web combinations).
        const methodByIf = new Map();
        for (const r of (h.dot1xPortMethod || [])) {
          const m = parseInt(dvv(r.rldot1xAuthenticationPortMethod), 10);
          if (Number.isFinite(m)) methodByIf.set(String(r.index), m);
        }
        const hasDot1x = dot1xByIf.size > 0 || hostModeByIf.size > 0;

        // Counters (errors, discards, packet breakdowns, octets) no longer live
        // in the main table — they are fetched on demand into a per-port popout
        // when a row is clicked. The table keeps only identity and state.
        const headers = ['Port', 'Admin', 'Oper', 'Speed']
          .concat(hasL2L3 ? ['L2/L3'] : [])
          .concat(hasModes ? ['Mode'] : [])
          .concat(hasDot1x ? ['802.1X'] : [])
          .concat(hasPoe ? ['PoE'] : [])
          .concat(hasVlans ? ['Untagged', 'Tagged'] : [])
          .concat(['']);

        // The set of VLANs that exist on the switch is the same for every port,
        // so compute it once rather than re-map/filter/sort it per row.
        const allVlans = (h.vlans || []).map((v) => Number(v.index))
          .filter((n) => Number.isFinite(n)).sort((a, b) => a - b);

        // A PoE-capable switch can have ports the interface table does not
        // list; they still belong in the table rather than nowhere.
        const rows = ports.map((r) => {
          const name = dv(r.rlifPresentName);
          const poe = poeByPort.get(String(name));
          if (poe) poeByPort.delete(String(name));
          // detail carries everything the popout shows that we already have from
          // the walk, plus the ifIndex it needs to fetch live counters on click.
          const vlNow = portVlans.get(String(r.index)) || { untagged: [], tagged: [] };
          // 802.1X per-port state (used by both the detail object and the cell).
          const d1x = dot1xByIf.get(String(r.index));
          const hm = hostModeByIf.get(String(r.index));
          const detail = {
            name: String(name || r.index), ifIndex: r.index,
            fields: {
              Description: dv(r.rlifPresentDescr), Alias: dv(r.rlifPresentAlias),
              'MAC address': dv(r.rlifPresentPhysAddress), MTU: dv(r.rlifPresentMtu),
              Speed: dv(r.rlifPresentHighSpeed), Type: dv(r.rlifPresentType),
              'Last change': dv(r.rlifPresentLastChange)
            },
            poe: poe ? {
              Status: dv(poe.pethPsePortDetectionStatus),
              Class: dv(poe.pethPsePortPowerClassifications),
              'Denied count': dv(poe.pethPsePortPowerDeniedCounter)
            } : null,
            // 802.1X per-port config, for display and the editor. control/host
            // carry the current enum codes; present indicates the switch reports
            // dot1x for this port (so the editor only shows for real dot1x ports).
            dot1x: (d1x || hm) ? {
              control: d1x ? d1x.control : '', controlCode: d1x ? d1x.controlCode : null,
              status: d1x ? d1x.status : '',
              hostMode: hm ? hm.mode : '', hostModeCode: hm ? hm.modeCode : null,
              methodCode: methodByIf.has(String(r.index)) ? methodByIf.get(String(r.index)) : null,
              present: !!d1x
            } : null,
            // Physical interface settings (speed/duplex/auto-neg/flow/MDIX) and
            // the port alias are fetched live when the popout opens (not polled
            // in bulk), so only a marker is carried here.
            settings: 'ondemand',
            // Current switchport state and the data the editor needs. mode is
            // 'access'/'trunk' (or '' if the switch didn't report it); l2l3 flags
            // routed ports, which can't take a switchport mode. allVlans is the
            // set of VLANs that exist on the switch (the only ones offered).
            sw: (() => {
              const mode = modeByIf.get(String(r.index)) || '';
              // Prefer the per-port configured VLAN (correct even when the port
              // is down); fall back to the static egress membership.
              let untagged = vlNow.untagged.slice(), tagged = vlNow.tagged.slice();
              const accCfg = accessVlanByIf.get(String(r.index));
              const natCfg = nativeVlanByIf.get(String(r.index));
              if (mode === 'access' && accCfg != null) { untagged = [String(accCfg)]; tagged = []; }
              else if (mode === 'trunk' && natCfg != null) {
                untagged = [String(natCfg)];
                if (tagged.indexOf(String(natCfg)) === -1) tagged = [String(natCfg)].concat(tagged);
              }
              return {
              mode,
              l2l3: l2l3ByIf.get(String(r.index)) || '',
              untagged, tagged,
              allVlans,
              // Spanning-tree uplink / root-path flag, used to warn before a
              // change that could cut the path the app reaches the switch by.
              uplink: uplinks.get(String(name)) || uplinks.get(String(r.index)) || null
            };
            })()
          };
          const base = [
            { click: detail, v: dv(r.rlifPresentName) },
            { pill: true, v: dv(r.rlifPresentAdminStatus) },
            { pill: true, v: dv(r.rlifPresentOperStatus) },
            { v: dv(r.rlifPresentHighSpeed) }
          ];
          const withL2 = hasL2L3 ? base.concat([{ v: l2l3ByIf.get(String(r.index)) || '' }]) : base;
          // A routed (L3) port has no switchport mode; say so rather than show
          // the leftover vlanPortModeState value the switch still reports.
          const modeText = l2l3ByIf.get(String(r.index)) === 'L3' ? 'routed' : (modeByIf.get(String(r.index)) || '');
          const withMode = hasModes ? withL2.concat([{ v: modeText }]) : withL2;
          // 802.1X cell: "control · status", e.g. "auto · authorized".
          let d1xText = '';
          if (d1x || hm) {
            const parts = [];
            if (d1x && d1x.control) parts.push(d1x.control);
            if (d1x && d1x.status) parts.push(d1x.status);
            d1xText = parts.join(' \u00b7 ') || (hm ? hm.mode : '');
          }
          const withDot1x = hasDot1x ? withMode.concat([{ v: d1xText }]) : withMode;
          const withPoe = hasPoe ? withDot1x.concat([
            { pill: true, v: poe ? dv(poe.pethPsePortDetectionStatus) : '' }
          ]) : withDot1x;
          const vl = portVlans.get(String(r.index)) || { untagged: [], tagged: [] };
          const routed = l2l3ByIf.get(String(r.index)) === 'L3';
          const withVlans = hasVlans ? withPoe.concat(routed ? [
            { v: ipByIf.get(String(r.index)) || '' },
            { v: '' }
          ] : [
            { v: vl.untagged.join(', ') },
            { v: rangeOf(vl.tagged) }
          ]) : withPoe;
          const adminUp = !/down|disabled/i.test(String(dv(r.rlifPresentAdminStatus) || ''));
          const poePort = poe ? dv(poe.portIndex, poe.index) : null;
          const uplink = uplinks.get(String(name)) || uplinks.get(String(r.index)) || null;
          const cells = withVlans.concat([{ actions: {
            name: String(name || r.index),
            ifIndex: r.index,
            poePort: poePort,
            adminUp: adminUp,
            uplink: uplink,
            l2l3: l2l3ByIf.get(String(r.index)) || '', hasL2L3Data: hasL2L3
          // The action buttons depend on admin state (Shut/No-shut label), PoE
          // capability and uplink flag; sig changes exactly when they do.
          }, sig: [adminUp ? 'up' : 'down', poePort == null ? '' : poePort, uplink ? 'u' : ''].join('|') }]);
          cells._key = 'if:' + r.index;
          return cells;
        });
        for (const poe of poeByPort.values()) {
          const detail = {
            name: String(dv(poe.port)), ifIndex: null, fields: {},
            poe: {
              Status: dv(poe.pethPsePortDetectionStatus),
              Class: dv(poe.pethPsePortPowerClassifications),
              'Denied count': dv(poe.pethPsePortPowerDeniedCounter)
            }
          };
          const row = [{ click: detail, v: dv(poe.port) }, { v: '' }, { v: '' }, { v: '' }]
            .concat(hasL2L3 ? [{ v: '' }] : [])
            .concat(hasModes ? [{ v: '' }] : [])
            .concat(hasPoe ? [{ pill: true, v: dv(poe.pethPsePortDetectionStatus) }] : []);
          const peCells = (hasVlans ? row.concat([{ v: '' }, { v: '' }]) : row).concat([{ actions: {
            name: String(dv(poe.port)), ifIndex: null,
            poePort: dv(poe.portIndex, poe.index), adminUp: true, uplink: null,
            l2l3: '', hasL2L3Data: hasL2L3
          }, sig: 'poe:' + dv(poe.portIndex, poe.index) }]);
          peCells._key = 'poe:' + String(dv(poe.port));
          rows.push(peCells);
        }

        // Keyed table: reconciles in place on refresh so a single row's change
        // (e.g. a port channel shut) patches only that cell - no teardown, no
        // reflow, no scroll jump.
        mountInto(body, s, p, 'ports', headers,
          rows.map((cells) => ({ key: cells._key || ('row:' + rows.indexOf(cells)), cells: cells })));

        // Port channels (LAGs): all available aggregators, their members and
        // mode, with create/edit/clear.
        buildPortChannels(s, body, h, (title, note) => {
          if (s._ktReconcile) return;   // titles already present on reconcile
          const stt = el('div', 'section-title', title);
          if (note) stt.appendChild(el('span', 'st-note', note));
          body.appendChild(stt);
        }, p);

        return;
      }

      /**
       * Who is on the switch, and who has been let onto the network
       * through it. Three sources answer that: the sessions this app is
       * holding, the switch's own view of its management sessions, and
       * 802.1x.
       */
      case 'auth': {
        const section = (title, note) => {
          if (s._ktReconcile) return;
          const st = el('div', 'section-title', title);
          if (note) st.appendChild(el('span', 'st-note', note));
          body.appendChild(st);
        };

        // --- ours ---
        const mine = (s.appSessions || []).filter((x) =>
          x.target === s.host || String(x.target).indexOf(s.host) >= 0 ||
          (s.consoleTarget && String(x.target).indexOf(s.consoleTarget.path) >= 0));
        if (mine.length) {
          section('This app', mine.length + ' open');
          mountInto(body, s, p, 'appSessions', ['Kind', 'Target', 'Open for', 'State'],
            keyedRowsFrom(mine.map((x) => [
              { pill: true, v: x.kind === 'console' ? 'console' : 'ssh' },
              { v: x.target },
              { v: secs(x.seconds) },
              { v: x.capturing ? 'collecting tech-support' : 'idle' }]), mine, (x, i) => (x.id || x.target || '') + ':' + i));
        }

        // --- the switch's own ---
        if (h.mgmtSessions.length) {
          section('Logged in to the switch', h.mgmtSessions.length + ' session(s)');
          mountInto(body, s, p, 'mgmtSessions', ['Session', 'User', 'Level', 'Channel'],
            keyedRowsFrom(cellsOf(h.mgmtSessions, [
              { key: 'index' }, { key: 'rlSecSdMngSessionUserName' },
              { key: 'rlSecSdMngSessionUserLevel' }, { key: 'rlSecSdMngSessionChannel' }]), h.mgmtSessions, (r) => r.index));
        }
        if (h.sshSessions.length) {
          section('SSH');
          mountInto(body, s, p, 'sshSessions', ['User', 'From', 'Port', 'Cipher', 'Version'],
            keyedRowsFrom(cellsOf(h.sshSessions, [
              { key: 'rlSshServerSessionInetUsername' }, { key: 'rlSshServerSessionInetPeerAddress' },
              { key: 'rlSshServerSessionInetPeerPort' }, { key: 'rlSshServerSessionInetCipher' },
              { key: 'rlSshServerSessionInetPeerVersion' }]), h.sshSessions, (r) => r.index));
        }
        if (h.telnetSessions.length) {
          section('Telnet', 'unencrypted');
          mountInto(body, s, p, 'telnetSessions', ['Session', 'From', 'Logged in', 'Status'],
            keyedRowsFrom(cellsOf(h.telnetSessions, [
              { key: 'index' }, { key: 'rlTelnetSessionClientAddress' },
              { key: 'rlTelnetSessionLoginTime' }, { key: 'rlTelnetSessionStatus', state: true }]), h.telnetSessions, (r) => r.index));
        }

        // --- 802.1x ---
        const hosts = h.dot1xHosts.filter((r) => dv(r.rldot1xAuthMultiSessionUserName) ||
          dv(r.rldot1xAuthMultiSessionId));
        if (hosts.length) {
          // Index the per-host counter tables by the row's own index (port+MAC)
          // so a host row can show its EAPOL/auth/session counters on click.
          const byIdx = (arr) => { const m = new Map(); for (const r of (arr || [])) m.set(String(r.index), r); return m; };
          const stats = byIdx(h.dot1xHostStats), diag = byIdx(h.dot1xHostDiag), sess = byIdx(h.dot1xHostSession);
          const dc = (cell) => (cell && (cell.display !== undefined && cell.display !== null && cell.display !== '') ? cell.display : (cell && cell.value !== undefined ? cell.value : ''));
          const hostDetail = (r) => {
            const idx = String(r.index);
            const st = stats.get(idx) || {}, dg = diag.get(idx) || {}, ss = sess.get(idx) || {};
            openDetailDialog(s, '802.1X host \u00b7 ' + (dv(r.rldot1xAuthMultiSessionUserName) || dv(r.mac) || dv(r.port)), [
              ['Port', dv(r.port)], ['MAC', dv(r.mac)], ['User', dv(r.rldot1xAuthMultiSessionUserName)],
              ['Method', dv(r.rlDot1xAuthMultiSessionMethodType)], ['Session time', dv(r.rldot1xAuthMultiSessionTime)]
            ], {
              'Session': [
                ['Session ID', dv(ss.rldot1xAuthMultiSessionId)],
                ['Accounting session ID', dv(ss.rldot1xAuthMultiSessionAcctSessionId)],
                ['Source IP', dv(ss.rldot1xAuthMultiSessionSourceIpAddress)],
                ['Assigned VLAN', dv(r.rldot1xAuthMultiSessionRadiusAttrVlan) || dv(ss.rldot1xAuthMultiSessionRadiusAttrVlan)],
                ['Filter ID', dv(ss.rldot1xAuthMultiSessionRadiusAttrFilterId)],
                ['Reauth in', dv(ss.rldot1xAuthMultiSessionReauthTimeRemain)]
              ],
              'EAPOL frames': [
                ['Rx', dc(st.rldot1xAuthMultiEapolFramesRx)], ['Tx', dc(st.rldot1xAuthMultiEapolFramesTx)],
                ['Start Rx', dc(st.rldot1xAuthMultiEapolStartFramesRx)], ['Logoff Rx', dc(st.rldot1xAuthMultiEapolLogoffFramesRx)],
                ['Invalid Rx', dc(st.rldot1xAuthMultiInvalidEapolFramesRx)]
              ],
              'Authentication': [
                ['Auth successes', dc(dg.rldot1xAuthMultiAuthSuccessWhileAuthenticating)],
                ['Auth failures', dc(dg.rldot1xAuthMultiAuthFailWhileAuthenticating)],
                ['Backend successes', dc(dg.rldot1xAuthMultiBackendAuthSuccesses)],
                ['Backend challenges', dc(dg.rldot1xAuthMultiBackendAccessChallenges)]
              ],
              'Session traffic': [
                ['Octets Rx', dc(ss.rldot1xAuthMultiSessionOctetsRx)], ['Octets Tx', dc(ss.rldot1xAuthMultiSessionOctetsTx)],
                ['Frames Rx', dc(ss.rldot1xAuthMultiSessionFramesRx)], ['Frames Tx', dc(ss.rldot1xAuthMultiSessionFramesTx)]
              ]
            });
          };
          section('802.1x authenticated hosts', hosts.length + ' host(s)');
          // Map a host's port NAME to its ifIndex so re-auth can target the
          // right port. Re-auth is per-port on this firmware
          // (dot1xPaePortReauthenticate, a write-true trigger), so the button
          // reauthenticates the supplicant(s) on that host's port.
          const ifxByName = new Map();
          for (const ir of (h.interfaces || [])) ifxByName.set(String(dv(ir.rlifPresentName)), ir.index);
          const reauthHost = (r) => {
            const portName = String(dv(r.port));
            const ifx = ifxByName.get(portName);
            if (ifx === undefined || ifx === null) { appLog('warn', 'Re-auth: no ifIndex for port', { port: portName }); return; }
            return snmpSetResult(s, { oid: '1.0.8802.1.1.1.1.1.2.1.5.' + ifx, type: 'Integer', value: 1 })
              .then((res) => ({ ok: res.ok, b: res.body }));
          };
          mountInto(body, s, p, 'dot1xHosts', ['Port', 'User', 'MAC', 'Method', 'VLAN', 'Session', ''],
            keyedRowsFrom(hosts.map((r) => {
              const reBtn = actBtn('Re-auth', (e) => {
                const pr = reauthHost(r);
                if (!pr) return;
                runButtonAction(e.currentTarget, {
                  failLabel: 'Re-auth',
                  run: () => pr.then(({ ok, b }) => ({ ok: ok, body: b })),   // normalise to {ok, body}
                  error: (res) => (res && res.body && res.body.error) || 'error'
                  // No table to settle - re-auth has no visible row change; the
                  // Done confirmation on the button is the feedback.
                });
              }, '', 'Reauthenticate the supplicant(s) on this port');
              return [
                { click: { open: () => hostDetail(r) }, v: dv(r.port) },
                { v: dv(r.rldot1xAuthMultiSessionUserName) },
                { v: dv(r.mac) },
                { v: dv(r.rlDot1xAuthMultiSessionMethodType) },
                { v: dv(r.rldot1xAuthMultiSessionRadiusAttrVlan) },
                { v: dv(r.rldot1xAuthMultiSessionTime) },
                { cellNode: actGroup([reBtn]), sig: 'reauth' }
              ];
            }), hosts, (r) => String(dv(r.port)) + '|' + String(dv(r.mac))));
        }
        if (h.dot1xLocked.length) {
          section('Locked out', h.dot1xLocked.length);
          mountInto(body, s, p, 'dot1xLocked', ['Port', 'MAC'],
            keyedRowsFrom(h.dot1xLocked.map((r) => [
              { v: dv(r.port) }, { v: dv(r.mac) }]), h.dot1xLocked, (r) => String(dv(r.port)) + '|' + String(dv(r.mac))));
        }

        // --- 802.1X global settings (an editor: built on a full paint only;
        // a change to the scalars it shows repaints the panel) and the AAA
        // servers (keyed tables, reconciled in place) ---
        if (!s._ktReconcile) buildDot1xGlobal(s, body, h, section);
        buildAaaServers(s, body, h, section, p);

        if (!s._ktReconcile && !body.children.length) {
          body.appendChild(el('div', 'empty-state',
            'No sessions open, and the switch reported no 802.1x activity.'));
        }
        return;
      }

      /**
       * Everything reachable through a port, in one place: who announced
       * themselves (CDP and LLDP), and what has simply been seen (the
       * forwarding database).
       *
       * CDP and LLDP are two protocols describing the same neighbours, so
       * they are one table with a column saying which spoke. A device
       * running both would otherwise appear twice, in two panels, and
       * leave you to work out it was one device.
       */
      case 'connected': {
        // The MAC forwarding table is large and only shown here, so it is not
        // in the regular poll. Fetch it on demand - but at most once every 30s,
        // and never twice concurrently. Without the time guard, a switch that
        // returns an empty (or merely small) MAC result would leave
        // s.health.macTable falsy and the panel would re-fetch on every repaint,
        // thrashing the switch. The timestamp makes this fire once per visit.
        // Since v1.6.0 a full collection carries the MAC table (h.complete), so
        // this fetch only runs against an older snapshot that lacks it.
        if (!(s.health && s.health.complete) && !s._macFetching && (Date.now() - (s._macFetchedAt || 0) > 30000)) {
          s._macFetching = true;
          fetch('/api/health', { method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target: s.target, only: ['macTable'] }) })
            .then((r) => r.json()).then((body) => {
              s._macFetching = false; s._macFetchedAt = Date.now();
              if (body && !body.error) {
                for (const k of body.keys || []) s.health[k] = body[k];
                // Repaint with the loaded rows, then reflow so the panel grows
                // to fit the now-populated table (the MAC data arrives after the
                // first paint, so without this the panel keeps its empty height
                // and the table scrolls until the module is reopened).
                const cp = s.panels && s.panels.find((x) => x.kind === 'builtin' && x.key === 'connected');
                if (!cp || !reconcilePanelInPlace(s, cp)) repaintPanel(s, 'connected');
                reflowTallPanels(s);
              }
            }).catch(() => { s._macFetching = false; s._macFetchedAt = Date.now(); });
        }
        const neighbours = new Map();
        const keyFor = (port, id) => String(port) + '\u0000' + String(id || '').toLowerCase();

        const addNeighbour = (port, id, via, extra) => {
          // Same port and same identity is the same neighbour. Identities
          // differ between the protocols (CDP gives a device-id, LLDP a
          // system name), so a port with one of each and no contradiction
          // is treated as one device rather than two.
          let hit = null;
          for (const [k, n] of neighbours) {
            if (n.port !== port) continue;
            const a = String(n.id || '').toLowerCase();
            const bb = String(id || '').toLowerCase();
            if (!a || !bb || a === bb || a.indexOf(bb) >= 0 || bb.indexOf(a) >= 0) { hit = n; break; }
            if (k) { /* different device on the same port: keep both */ }
          }
          if (!hit) {
            hit = { port, id, via: [], remotePort: '', descr: '', address: '' };
            neighbours.set(keyFor(port, id) + ':' + neighbours.size, hit);
          }
          if (!hit.id) hit.id = id;
          if (hit.via.indexOf(via) < 0) hit.via.push(via);
          for (const k of ['remotePort', 'descr', 'address']) {
            if (!hit[k] && extra[k]) hit[k] = extra[k];
          }
        };

        for (const r of h.cdp) {
          addNeighbour(dv(r.localPort, r.index), dv(r.cdpCacheDeviceId), 'CDP', {
            remotePort: dv(r.cdpCacheDevicePort),
            descr: dv(r.cdpCachePlatform),
            address: dv(r.cdpCacheAddress)
          });
        }
        for (const r of h.lldp) {
          addNeighbour(dv(r.localPort, r.index), dv(r.lldpRemSysName) || dv(r.lldpRemChassisId), 'LLDP', {
            remotePort: dv(r.lldpRemPortId),
            descr: dv(r.lldpRemPortDesc),
            address: dv(r.lldpRemChassisId)
          });
        }

        if (neighbours.size) {
          if (!s._ktReconcile) {
            const st = el('div', 'section-title', 'Neighbours');
            st.appendChild(el('span', 'st-note', neighbours.size + ' device(s)'));
            body.appendChild(st);
          }
          const nbr = Array.from(neighbours.values());
          mountInto(body, s, p, 'neighbours', ['Local port', 'Device', 'Via', 'Remote port', 'Details'],
            nbr.map((n, i) => ({ key: 'nbr:' + (n.port || '') + '|' + (n.id || '') + '|' + i, cells: [
              { v: n.port }, { v: n.id }, { v: n.via.join(' + ') }, { v: n.remotePort }, { v: n.descr || n.address }] })));
        }

        if (h.macTable.length || s.target) {
          if (!s._ktReconcile) {
            const st = el('div', 'section-title', 'MAC address table');
            // Count + note are stable containers refreshed on every pass (incl.
            // the reconcile after the on-demand fetch finishes), so a "loading"
            // hint can turn into the real count/empty-state without a rebuild.
            p._macCount = el('span', 'st-note', '');
            st.appendChild(p._macCount);
            body.appendChild(st);
            if (s.target) {
              const macCtlRow = el('div', 'tbl-add');
              const addBtn = el('button', 'tbl-add-btn', '+ Add static MAC'); addBtn.type = 'button';
              addBtn.addEventListener('click', () => openStaticMacForm(s, h));
              macCtlRow.appendChild(addBtn);
              body.appendChild(macCtlRow);
            }
            p._macNote = el('div', 'card-sub', '');
            body.appendChild(p._macNote);
          }
          // The table is on-demand (fetched on first open), so an empty table is
          // ambiguous: still loading, or genuinely empty? Say which, so the user
          // doesn't read "loading" as "no devices".
          if (p._macCount) {
            p._macCount.textContent = (s._macFetching && !h.macTable.length)
              ? 'loading…' : h.macTable.length.toLocaleString() + ' entries';
          }
          if (p._macNote) {
            p._macNote.textContent = h.macTable.length ? ''
              : (s._macFetching ? 'Loading MAC address table…' : 'No MAC entries learned yet.');
          }
          if (h.macTable.length) {
            const cols = ['VLAN', 'MAC', 'Port', 'Status'].concat(s.target ? [''] : []);
            const krows = h.macTable.map((r) => {
              const statusNum = parseInt((r.dot1qTpFdbStatus && (r.dot1qTpFdbStatus.value !== undefined ? r.dot1qTpFdbStatus.value : r.dot1qTpFdbStatus.display)), 10);
              const isStatic = statusNum === 1 || statusNum === 5;
              const macStr = String(dv(r.mac) || '');
              const vlanStr = String(dv(r.vlan) || '');
              const base = [{ v: dv(r.vlan) }, { v: dv(r.mac) }, { v: dv(r.port) }, { v: dv(r.dot1qTpFdbStatus) }];
              let cells = base;
              if (s.target) {
                const bpNum = parseInt((r.dot1qTpFdbPort && (r.dot1qTpFdbPort.value !== undefined ? r.dot1qTpFdbPort.value : r.dot1qTpFdbPort.display)), 10) || 0;
                const delCell = isStatic
                  ? { cellNode: actGroup([actBtnConfirm('Delete', (e) => {
                      runButtonAction(e.currentTarget, {
                        failLabel: 'Delete MAC',
                        run: () => deleteStaticMac(s, vlanStr, macStr, bpNum).then(() => ({ ok: true, body: {} })),
                        onApplied: () => { markConfigDirty(s); s._macFetchedAt = 0; },
                        settle: () => refreshTables(s, ['macTable'])
                      });
                    }, 'danger', 'Delete this static MAC entry')]), sig: 'del' }
                  : { v: '' };
                cells = base.concat([delCell]);
              }
              return { key: 'mac:' + vlanStr + '|' + macStr, cells: cells };
            });
            // The FDB can be thousands of entries - paginate at 50 via the engine.
            mountInto(body, s, p, 'macTable', cols, krows, { pageSize: 50 });
          }
          // (empty / loading text handled by p._macNote above)
        }

        // Don't claim "nothing here" while the MAC table is still being fetched.
        if (!s._ktReconcile && !neighbours.size && !h.macTable.length && !s._macFetching) {
          body.appendChild(el('div', 'empty-state', 'No neighbours or learned addresses.'));
        }
        return;
      }

      // A complete view of spanning tree: which mode is running, who the
      // root is, how stable the topology is, and what every port is doing
      // -- plus the per-instance or per-VLAN detail for MSTP and PVST.
      // Laid out the way `show spanning-tree` reads, because that is the
      // shape the information actually has. Under PVST or MSTP the real
      // state is per VLAN or per instance -- the common dot1dStpPortTable
      // reports every port disabled and is worse than useless on its own.
      // Syslog and traps are the same question -- what has this switch
      // been telling me -- asked over two transports, so they are one
      // list, merged by time and labelled by where each line came from.
      case 'events': paintEventsPanel(s, body); return;

      case 'stp': {
        const mode = h.summary.stpMode || 'unknown';
        const MODE_LABEL = {
          stp: 'STP (802.1D)', rstp: 'RSTP (802.1w)', mstp: 'MSTP (802.1s)',
          pvst: 'Rapid-PVST / PVST', unknown: 'not reported'
        };
        const perInstance = mode === 'pvst' || mode === 'mstp';
        const isDisabled = (v) => !v || /^(dsbl|disabled|unknown|broken)/i.test(String(v));
        const detect = h.stpDetect || {};
        const instances = mode === 'pvst' ? h.pvstVlans : (mode === 'mstp' ? h.mstpInstances : []);
        const pv = mode === 'pvst';
        const instId = (inst) => String(dv(pv ? inst.rlBrgPvstOperVlanId : inst.rldot1sMstpInstanceId, inst.index));
        const showCommon = !(perInstance && instances.length);

        // Ports per instance, and which of them are participating. A port is
        // participating only if its *state* says so: switches report
        // "designated" against disabled ports and even against slots that do
        // not exist, and the CLI lists a port as active only on its Sts column.
        // Ports that did not resolve to a real interface are slots in the
        // switch's ifIndex space, not ports, and never belong in a table.
        const roleOf = (r) => dv(pv ? r.rlBrgPvstOperPortRole : r.rldot1sMStpInstancePortRole);
        const stateOf = (r) => dv(pv ? r.rlBrgPvstOperPortState : r.rldot1sMstpInstancePortState);
        const portsByKey = new Map();
        if (perInstance) {
          for (const r of (pv ? h.pvstPorts : h.mstpPorts)) {
            const k = String(dv(pv ? r.vlan : r.instance));
            if (!portsByKey.has(k)) portsByKey.set(k, []);
            portsByKey.get(k).push(r);
          }
        }
        const instPorts = (id) => {
          const everything = portsByKey.get(id) || [];
          const all = everything.filter((r) => r.realPort !== false);
          return { all, active: all.filter((r) => !isDisabled(stateOf(r))), phantom: everything.length - all.length };
        };
        const commonActive = h.stpPorts.filter((r) => !isDisabled(dv(r.dot1dStpPortState)));
        const commonHidden = showCommon && h.stpPorts.length > commonActive.length && !s._stpShowDisabled;
        const omitted = showCommon ? (h.stpPortsOmitted || 0) : 0;

        // Keyed paint (B2): the layout is built on a full paint only. Its
        // shape - the mode, the instances, which of them have a table, and
        // which notes exist - is the signature; when a refresh changes it the
        // pass is structural and the panel repaints. Otherwise tables
        // reconcile row by row and the text blocks update in their own nodes.
        const sig = JSON.stringify([mode, perInstance, showCommon, !!s._stpShowDisabled,
          instances.map((i) => instId(i) + ':' + (instPorts(instId(i)).active.length ? 't' : 'n')),
          h.pvstInconsistencies.length > 0, h.stpPorts.length > 0, commonHidden, omitted > 0]);
        if (s._ktReconcile && p._stpSig !== sig) { s._ktStructural = true; return; }
        if (!s._ktReconcile) { p._stpSig = sig; p._stpLive = {}; }
        // A block whose text changes with each refresh: built once, then
        // refilled in place only when its content differs.
        const live = (key, parent, cls, fill) => {
          const fresh = el('div', cls);
          fill(fresh);
          // An empty block (a note with nothing to say this time) is hidden.
          if (!s._ktReconcile) { fresh.hidden = !fresh.firstChild; p._stpLive[key] = fresh; parent.appendChild(fresh); return fresh; }
          const node = p._stpLive[key];
          if (node && node.innerHTML !== fresh.innerHTML) {
            clear(node);
            while (fresh.firstChild) node.appendChild(fresh.firstChild);
            node.hidden = !node.firstChild;
          }
          return node || fresh;
        };
        const kvRows = (box, pairs) => {
          for (const [k, v] of pairs) {
            if (v === undefined || v === null || v === '') continue;
            const row = el('div', 'kv-row');
            row.appendChild(el('div', 'k', k));
            row.appendChild(el('div', 'v', v));
            box.appendChild(row);
          }
        };
        const sectionTitle = (key, title, note) => {
          if (!s._ktReconcile) {
            const st = el('div', 'section-title', title);
            const n = el('span', 'st-note', note);
            p._stpLive[key] = n;
            st.appendChild(n);
            body.appendChild(st);
          } else if (p._stpLive[key] && p._stpLive[key].textContent !== note) {
            p._stpLive[key].textContent = note;
          }
        };

        // --- what mode, and the global picture ---
        live('head', body, 'stp-head', (head) => {
          if (!perInstance) {
            head.appendChild(el('div', 'hero-badge sev-' + (h.summary.stpIsRoot ? 'info' : 'ok'),
              h.summary.stpIsRoot ? 'This switch is root' : 'Non-root bridge'));
          }
          const facts = el('div', 'stp-facts');
          const pairs = [
            ['Mode', (MODE_LABEL[mode] || mode) + (detect.disagrees && detect.reportedVersion
              ? '  ·  the switch reports "' + detect.reportedVersion + '"' : '')],
            ['This bridge', (sc('dot1dStpPriority') ? sc('dot1dStpPriority') + '  ' : '') + (sc('dot1dBaseBridgeAddress') || '')]
          ];
          if (mode === 'mstp') {
            pairs.push(['MST region', sc('rldot1sMstpConfigurationName')],
              ['Region digest', sc('rldot1sMstpConfigurationDigest')],
              ['Max hops', sc('rldot1sMstpDesignatedMaxHopes')]);
          }
          if (!perInstance) {
            pairs.push(['Root bridge', sc('dot1dStpDesignatedRoot')], ['Root port', sc('dot1dStpRootPort')],
              ['Cost to root', sc('dot1dStpRootCost')], ['Topology changes', sc('dot1dStpTopChanges')],
              ['Last change', sc('dot1dStpTimeSinceTopologyChange')],
              ['Timers in force', [sc('dot1dStpHelloTime') && 'hello ' + sc('dot1dStpHelloTime'),
                sc('dot1dStpMaxAge') && 'max age ' + sc('dot1dStpMaxAge'),
                sc('dot1dStpForwardDelay') && 'forward delay ' + sc('dot1dStpForwardDelay')].filter(Boolean).join('  ·  ')]);
          }
          if (detect.disagrees) {
            // Worth stating plainly: the mode shown was worked out from the
            // tables the switch populates, not from what it says it runs.
            pairs.push(['Detected from', (detect.pvstVlanRows ? detect.pvstVlanRows + ' per-VLAN row(s)' : '') +
              (detect.mstpInstanceRows ? (detect.pvstVlanRows ? ', ' : '') + detect.mstpInstanceRows + ' MST instance row(s)' : '') +
              ' returned by the switch']);
          }
          if (perInstance) {
            const rooted = instances.filter((r) => String(dv(r.isRoot)) === 'yes').length;
            pairs.push(['Instances', instances.length + (pv ? ' VLAN(s)' : ' MST instance(s)') +
              (rooted ? '  ·  root for ' + rooted : '')]);
          }
          kvRows(facts, pairs);
          head.appendChild(facts);
        });

        // --- per VLAN / per instance, the way the CLI prints it ---
        // Only ports doing something: a 24-port switch times five VLANs is
        // 120 rows of "Dsbl" that say nothing.
        if (perInstance) {
          for (const inst of instances) {
            const id = instId(inst);
            const k = 'inst:' + id;
            let wrap = p._stpLive[k + ':wrap'];
            if (!s._ktReconcile) { wrap = el('div', 'stp-instance'); p._stpLive[k + ':wrap'] = wrap; body.appendChild(wrap); }
            const amRoot = String(dv(inst.isRoot)) === 'yes';
            live(k + ':head', wrap, 'stp-instance-head', (head) => {
              head.appendChild(el('span', 'stp-instance-name', (pv ? 'VLAN ' : 'Instance ') + id));
              head.appendChild(el('span', 'stp-instance-badge' + (amRoot ? ' root' : ''),
                amRoot ? 'this switch is the root' : 'root elsewhere'));
            });
            const pick = (pvstCol, mstpCol) => dv(pv ? inst[pvstCol] : inst[mstpCol]);
            const hello = pick('rlBrgPvstOperVlanHelloTime', 'rldot1sMstpInstanceHelloTime');
            const maxAge = pick('rlBrgPvstOperVlanMaxAge', 'rldot1sMstpInstanceMaxAge');
            const fwd = pick('rlBrgPvstOperVlanForwardDelay', 'rldot1sMstpInstanceForwardDelay');
            const tc = pick('rlBrgPvstOperVlanTopChanges', 'rldot1sMstpInstanceTopChanges');
            const ts = pick('rlBrgPvstOperVlanTimeSinceTopologyChange', 'rldot1sMstpInstanceTimeSinceTopologyChange');
            live(k + ':facts', wrap, 'stp-instance-facts', (kv) => kvRows(kv, [
              ['Root ID', pick('rlBrgPvstOperVlanDesignatedRoot', 'rldot1sMstpInstanceDesignatedRoot')],
              ['Root port', amRoot ? '' : dv(inst.rootPort)],
              ['Path cost', amRoot ? '' : pick('rlBrgPvstOperVlanRootCost', 'rldot1sMstpInstanceRootCost')],
              ['Bridge priority', pick('rlBrgPvstOperVlanPriority', 'rldot1sMstpInstancePriority')],
              ['Timers', [hello && 'hello ' + hello, maxAge && 'max age ' + maxAge, fwd && 'forward delay ' + fwd].filter(Boolean).join('  ·  ')],
              ['Topology changes', tc !== '' && tc !== undefined ? tc + (ts ? '  ·  last ' + ts : '') : undefined]
            ]));
            const { all, active, phantom } = instPorts(id);
            if (active.length) {
              mountInto(wrap, s, p, 'stp:' + k, ['Port', 'Role', 'State', 'Cost', 'Priority', 'Edge', 'BPDUs in', 'BPDUs out'],
                active.map((r) => ({ key: 'port:' + dv(r.port), cells: [
                  { v: dv(r.port) },
                  { pill: true, v: roleOf(r) },
                  { pill: true, v: stateOf(r) },
                  { v: dv(pv ? r.rlBrgPvstOperPortPathCost : r.rldot1sMstpInstancePortPathCost) },
                  { v: dv(pv ? r.rlBrgPvstOperPortPriority : r.rldot1sMstpInstancePortPriority) },
                  { v: dv(pv ? r.rlBrgPvstOperPortEdgePort : '') },
                  { v: dv(pv ? r.rlBrgPvstOperPortBpduReceived : r.rldot1sMStpInstancePortBpduReceived) },
                  { v: dv(pv ? r.rlBrgPvstOperPortBpduSent : r.rldot1sMStpInstancePortBpduSent) }] })));
              live(k + ':note', wrap, 'panel-note', (n) => {
                if (all.length > active.length || phantom) {
                  n.textContent = (all.length - active.length) + ' disabled port(s) not shown' +
                    (phantom ? ', and ' + phantom + ' entr(y/ies) for interfaces this switch does not have' : '') + '.';
                }
              });
            } else {
              live(k + ':note', wrap, 'panel-note', (n) => {
                n.textContent = 'No ports are participating in this instance' +
                  (all.length ? ' (' + all.length + ' disabled' + (phantom ? ', ' + phantom + ' non-existent' : '') + ').' : '.');
              });
            }
          }
          if (!instances.length && !s._ktReconcile) {
            body.appendChild(el('div', 'panel-note',
              'No per-VLAN or per-instance spanning-tree rows were returned, so only the common ' +
              'instance is shown below.'));
          }
        } else {
          const probed = [];
          if (detect.pvstVlanRows !== undefined) probed.push('rlBrgPvstOperVlanTable: ' + detect.pvstVlanRows + ' rows');
          if (detect.mstpInstanceRows !== undefined) probed.push('rldot1sMstpInstanceTable: ' + detect.mstpInstanceRows + ' rows');
          live('probed', body, 'panel-note', (n) => {
            if (probed.length) {
              n.textContent = 'No per-VLAN or per-instance tables are populated on this switch (' +
                probed.join(', ') + '), so the common instance below is the whole picture.';
            }
          });
        }

        // --- inconsistencies always matter ---
        if (h.pvstInconsistencies.length) {
          sectionTitle('incons', 'Spanning-tree inconsistencies', 'ports blocked by a protection feature');
          mountInto(body, s, p, 'pvstInconsistencies', ['Port', 'VLAN', 'State'],
            h.pvstInconsistencies.map((r, i) => ({ key: 'pvst:' + (dv(r.port) || '') + '|' + (dv(r.vlan) || '') + '|' + i, cells: [
              { v: dv(r.port) }, { v: dv(r.vlan) }, { pill: true, v: dv(r.state) }] })));
        }

        // --- the common instance ---
        // Only shown when it is the answer. Under PVST or MSTP the real
        // state is per VLAN or per instance and this table reports every
        // port disabled, so it is left out entirely rather than displayed
        // with a caveat -- a table of misleading values plus an
        // explanation is still a table of misleading values.
        if (showCommon && h.stpPorts.length) {
          sectionTitle('ports', 'Ports', commonActive.length
            ? commonActive.length + ' active of ' + h.stpPorts.length
            : 'all ' + h.stpPorts.length + ' ports report disabled');
          const showList = s._stpShowDisabled ? h.stpPorts : commonActive;
          mountInto(body, s, p, 'stpPorts', ['Port', 'State', 'Enabled', 'Cost', 'Priority', 'Edge', 'P2P',
            'Designated bridge', 'Transitions'], showList.map((r) => ({ key: 'stp:' + (dv(r.port) || r.index), cells: [
            { v: dv(r.port) },
            { pill: true, v: dv(r.dot1dStpPortState) },
            { v: dv(r.dot1dStpPortEnable) },
            { v: dv(r.dot1dStpPortPathCost) },
            { v: dv(r.dot1dStpPortPriority) },
            { v: dv(r.edge) },
            { v: dv(r.p2p) },
            { v: dv(r.dot1dStpPortDesignatedBridge) },
            { v: dv(r.dot1dStpPortForwardTransitions) }] })));
          if (commonHidden) {
            live('hidden', body, 'panel-note', (n) => {
              n.appendChild(document.createTextNode((h.stpPorts.length - commonActive.length) + ' disabled port(s) hidden.  '));
              const show = el('button', 'raw-toggle', 'Show disabled ports');
              show.type = 'button';
              show.addEventListener('click', () => { s._stpShowDisabled = true; repaintPanel(s, 'stp'); });
              n.appendChild(show);
            });
          }
        } else if (showCommon && !s._ktReconcile) {
          body.appendChild(el('div', 'panel-note',
            'The switch did not return a spanning-tree port table. Either spanning tree is ' +
            'disabled, or this model does not implement dot1dStpPortTable.'));
        }

        if (omitted) {
          live('omitted', body, 'panel-note', (n) => {
            n.textContent = omitted.toLocaleString() + ' row(s) hidden: the switch answers for every slot in its ' +
              'ifIndex space, including stack members that are not fitted and port-channels that do ' +
              'not exist. Only interfaces present in rlifPresentTable are shown.';
          });
        }
        return;
      }

      default:
        body.appendChild(el('div', 'card-sub', 'Unknown panel: ' + key));
    }
  }

  /**
   * A session came up but SNMP was never configured, so the dashboard has
   * nothing to read. Dropping straight into a terminal assumes that is
   * what was wanted; often the reason for connecting at all is to *make*
   * the switch pollable. So ask, and offer to do it.
   */
  /**
   * A session came up but SNMP was never configured, so the dashboard has
   * nothing to read. Say so, offer the terminal, and show the commands
   * that would make the switch pollable -- driving a CLI blind proved too
   * fragile to do on the operator's behalf, but the commands themselves
   * are still the useful part.
   */
  /**
   * Build the commands from what the operator has typed, so what gets
   * pasted is theirs rather than a template with placeholders left in it.
   * Placeholders are the reason copied examples get pasted wrong.
   */
  // Edit the switch's identity (sysName / sysLocation / sysContact) from the
  // Details panel. These three fields are the only writable ones in the
  // system group; they live in Details (not the SNMP panel) so the info is
  // shown once, and this is the edit path for them. Writing needs a
  // DefaultSuper credential — if the connected one is read-only the switch
  // returns authorizationError, which is surfaced plainly.
  const SYS_EDIT_OIDS = {
    name: '1.3.6.1.2.1.1.5.0', location: '1.3.6.1.2.1.1.6.0', contact: '1.3.6.1.2.1.1.4.0'
  };
  // Edit the system name, location and contact in the standard pop-out (A5):
  // one tap to save (B8), the failure as the red line under the button.
  function editSysIdentity(s) {
    if (!s.target) return;
    const h = s.health;
    const cur = (k) => {
      const v = h && h.scalars && h.scalars[k] ? h.scalars[k].display : '';
      return (v && v !== '(empty)') ? v : '';
    };
    openTabbedPopout(s, 'Switch identity', [{ label: 'Identity', fill: (pane, close) => {
      const form = el('div', 'snmp-form acl-form');
      const sec = formSection('Identity');
      sec.body.classList.add('acl-stack');
      const defs = [
        ['name', 'System name', SYS_EDIT_OIDS.name, cur('sysName')],
        ['location', 'Location', SYS_EDIT_OIDS.location, cur('sysLocation')],
        ['contact', 'Contact', SYS_EDIT_OIDS.contact, cur('sysContact')]
      ];
      const inputs = {};
      for (const [key, label, oid, value] of defs) {
        const inp = textInput(value);
        inputs[key] = { inp, oid, current: value, label };
        sec.body.appendChild(field(label, inp));
      }
      form.appendChild(sec.sec);
      const { actions, apply, msg } = applyActions('Save');
      apply.addEventListener('click', (ev) => {
        clear(msg);
        const changes = Object.values(inputs).filter((f) => f.inp.value !== f.current)
          .map((f) => ({ label: f.label, oid: f.oid, value: f.inp.value }));
        if (!changes.length) { close(); return; }
        runButtonAction(ev.currentTarget, {
          failLabel: 'Save identity', spinLabel: 'Saving\u2026',
          run: async () => {
            s.writeBusy = true;
            try {
              for (const ch of changes) {
                const { body: j } = await apiPost('/api/snmp-config/status-set-apply', { target: s.target, cfg: { oid: ch.oid, value: ch.value } });
                if (!j || !j.ok) return { ok: false, error: ch.label + ': ' + ((j && j.error) || 'failed') };
                if (!j.applied.ok) { const d = (j.applied.log && j.applied.log[0] && j.applied.log[0].detail) || 'change failed'; return { ok: false, error: ch.label + ' could not be changed: ' + d }; }
              }
              return { ok: true };
            } catch (e) { return { ok: false, error: 'lost contact with the local server: ' + e.message }; }
            finally { s.writeBusy = false; }
          },
          ok: (r) => r && r.ok,
          error: (r) => { const e = (r && r.error) || 'failed'; msg.appendChild(el('div', 'sw-err', 'Save identity failed: ' + e)); return e; },
          onApplied: () => markConfigDirty(s),
          settle: () => {
            const panel = s.panels && s.panels.find((p) => p.kind === 'builtin' && p.key === 'summary');
            return Promise.resolve(panel ? refreshPanel(s, panel) : startHealth(s)).then(() => close());
          }
        });
      });
      form.appendChild(actions); form.appendChild(msg);
      pane.appendChild(form);
      inputs.name.inp.focus();
    } }], []);
  }

