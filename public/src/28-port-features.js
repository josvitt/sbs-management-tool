  // =================================================================
  // 28-port-features.js: The Port features panel and the port popout's
  // Features tab (PoE, port security, storm control, LLDP/CDP/EEE, cable
  // test), plus port mirroring and errdisable recovery.
  // =================================================================

  // A keyed panel with a server-side reader (standard B1 family b2), like
  // System. The data rides the server collection as `ports`
  // (module-collection.js, switch-ports.js).
  //
  // s._ports = { data, fetchedAt, loading, liveAt, collected }
  // data is /api/ports/status's reply; data.error is set when it failed.

  function portsLoad(s) {
    s._ports = s._ports || {};
    const st = s._ports;
    if (st.loading) return st.loading;
    st.fetchedAt = Date.now();
    st.liveAt = Date.now();
    st.loading = sidePost('/api/ports/status', { target: s.target })
      .then((b) => { st.data = (b && !b.error) ? b : { error: (b && b.error) || 'no answer' }; })
      .finally(() => { st.loading = null; sideRepaint(s, 'portfeatures'); });
    return st.loading;
  }

  // One write: post, reload when it lands, toast a failure.
  function portsWrite(btn, s, url, payload, failLabel, onApplied) {
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
      settle: () => portsLoad(s)
    });
  }

  function portNameOf(s, ifx) {
    const r = ((s.health && s.health.interfaces) || []).find((x) => String(x.index) === String(ifx));
    const c = r && r.rlifPresentName;
    const nm = c == null ? '' : String(c.display != null ? c.display : (c.value != null ? c.value : c)).trim();
    return nm || ('ifIndex ' + ifx);
  }

  const POE_WORDS = { deliveringPower: 'delivering power', searching: 'searching', disabled: 'off', fault: 'fault', otherFault: 'fault', test: 'testing' };
  const LOCK_WORDS = { disabled: 'classic lock (no new addresses)', dynamic: 'learn up to the limit',
    'secure-permanent': 'learn up to the limit, keep them', 'secure-delete-on-reset': 'learn up to the limit, forget on reboot' };
  const LLDP_WORDS = { txAndRx: 'send and receive', txOnly: 'send only', rxOnly: 'receive only', disabled: 'off' };
  const CAUSE_WORDS = {
    'loopback-detection': 'Loopback detected', 'port-security': 'Port security violation', 'dot1x-src-address': '802.1X source address',
    'acl-deny': 'ACL deny', 'stp-bpdu-guard': 'STP BPDU guard', 'stp-loopback-guard': 'STP loop guard', 'pcb-overheat': 'Board overheat',
    udld: 'UDLD', 'storm-control': 'Storm control', 'link-flapping': 'Link flapping', 'link-state-group': 'Link state group'
  };
  const watts = (mw) => (mw == null ? '' : (Math.round(mw / 100) / 10) + ' W');
  const rowFor = (list, key, v) => (list || []).find((x) => x[key] === v);
  const boolSel = (on, yes, no) => selectInput([{ label: yes || 'on', value: '1' }, { label: no || 'off', value: '0' }], on ? '1' : '0');

  // VCT cable length buckets (rlPhyTestGetUnits alaskaPhyLength).
  const LENGTH_WORDS = { 0: 'under 50 m', 1: '50 to 80 m', 2: '80 to 110 m', 3: '110 to 140 m', 4: 'over 140 m' };
  function cableWords(r) {
    if (r.status !== 'success') return r.status === 'failed' ? 'could not measure' : (r.status || '');
    if (r.test === 'cableLength' && r.units === 13) return LENGTH_WORDS[r.result] || String(r.result);
    if (r.units === 6) return r.result + ' m';
    if (r.units === 14) return ({ 0: 'OK', 1: 'open', 2: 'short', 3: 'impedance mismatch' })[r.result] || String(r.result);
    return String(r.result);
  }

  // ---- the port popout's Features tab ----

  function buildPortFeatures(s, ifx, pane) {
    const d = (s._ports && s._ports.data) || {};
    const msg = el('div', 'port-detail-msg');
    const done = () => { const pop = pane.closest && pane.closest('.port-detail-back'); if (pop) pop.remove(); };

    // PoE (pethPsePortTable is indexed group.port, where port is the ifIndex).
    const poe = rowFor(d.poe, 'port', ifx);
    if (poe) {
      const sec = formSection('Power over Ethernet');
      sec.body.appendChild(el('div', 'card-sub', (POE_WORDS[poe.detection] || poe.detection || 'unknown') +
        (poe.powerMw ? ', drawing ' + watts(poe.powerMw) : '') + (poe.powerClass != null ? ', class ' + poe.powerClass : '') +
        (poe.operLimitMw ? ', allowed ' + watts(poe.operLimitMw) : '')));
      const adm = boolSel(poe.admin, 'on', 'off');
      const pri = selectInput([{ label: 'critical', value: 'critical' }, { label: 'high', value: 'high' }, { label: 'low', value: 'low' }], poe.priority || 'low');
      const lim = textInput(poe.limitMw == null ? '' : String(poe.limitMw / 1000), '30'); lim.size = 6;
      sec.body.appendChild(field('Power', adm));
      sec.body.appendChild(field('Priority', pri));
      sec.body.appendChild(field('Power limit (W)', lim));
      const { actions, apply } = applyActions('Apply PoE');
      apply.addEventListener('click', (e) => {
        const w = Number(lim.value);
        if (!Number.isFinite(w) || w < 0) { toast('The power limit is a number of watts.', 'error'); return; }
        portsWrite(e.currentTarget, s, '/api/ports/poe', { group: poe.group, port: poe.port, admin: adm.value === '1',
          priority: pri.value, limitMw: Math.round(w * 1000) }, 'Apply PoE', done);
      });
      sec.body.appendChild(actions);
      pane.appendChild(sec.sec);
    }

    // Port security (swIfLock).
    const sec0 = rowFor(d.security, 'ifIndex', ifx);
    if (sec0) {
      const sec = formSection('Port security');
      sec.body.appendChild(el('div', 'card-sub', (sec0.operLocked ? 'Locked' : 'Not locked') +
        (sec0.macCount != null ? ', ' + sec0.macCount + ' address' + (sec0.macCount === 1 ? '' : 'es') + ' learned' : '')));
      const lock = boolSel(sec0.locked, 'locked', 'not locked');
      const mode = selectInput(Object.keys(LOCK_WORDS).map((k) => ({ label: LOCK_WORDS[k], value: k })), sec0.mode || 'disabled');
      const max = textInput(sec0.maxMacs == null ? '' : String(sec0.maxMacs), '1'); max.size = 4;
      sec.body.appendChild(field('Lock', lock));
      sec.body.appendChild(field('Learning', mode));
      sec.body.appendChild(field('Address limit', max));
      sec.body.appendChild(el('div', 'card-sub', 'A locked port drops traffic from any device it has not learned. ' +
        'Do not lock the port this computer reaches the switch through.'));
      const { actions, apply } = applyActions('Apply port security');
      apply.addEventListener('click', (e) => portsWrite(e.currentTarget, s, '/api/ports/security',
        { ifIndex: ifx, locked: lock.value === '1', mode: mode.value, maxMacs: Number(max.value) }, 'Apply port security', done));
      sec.body.appendChild(actions);
      pane.appendChild(sec.sec);
    }

    // Storm control (rlStormCtrlRateLimCfgTable): only the rate is written.
    const storm = rowFor(d.storm, 'ifIndex', ifx);
    if (storm) {
      const sec = formSection('Storm control');
      const kinds = [['broadcast', 'Broadcast'], ['multicastAll', 'Multicast'], ['unknownUnicast', 'Unknown unicast']];
      const inputs = {};
      for (const [k, label] of kinds) {
        const t = storm.traffic[k] || {};
        inputs[k] = textInput(t.rate == null ? '' : String(t.rate), '0'); inputs[k].size = 8;
        sec.body.appendChild(field(label + ' (kb/s, 0 = off)', inputs[k]));
      }
      const { actions, apply } = applyActions('Apply storm control');
      apply.addEventListener('click', (e) => {
        const changed = kinds.map(([k]) => k).filter((k) => String((storm.traffic[k] || {}).rate) !== inputs[k].value.trim());
        if (!changed.length) { toast('Nothing changed.', 'ok'); return; }
        runButtonAction(e.currentTarget, {
          failLabel: 'Apply storm control',
          run: async () => {
            for (const k of changed) {
              const r = await sidePost('/api/ports/storm', { target: s.target, ifIndex: ifx, traffic: k, rate: Number(inputs[k].value) });
              if (!r || !r.ok) return r;
            }
            return { ok: true };
          },
          ok: (r) => r && r.ok, error: (r) => (r && r.error) || 'unknown error',
          onApplied: () => { markConfigDirty(s); done(); }, settle: () => portsLoad(s)
        });
      });
      sec.body.appendChild(actions);
      pane.appendChild(sec.sec);
    }

    // LLDP, CDP and EEE.
    const lldp = rowFor(d.lldp && d.lldp.ports, 'port', ifx);
    const cdp = rowFor(d.cdp && d.cdp.ports, 'ifIndex', ifx);
    const eee = rowFor(d.eee && d.eee.ports, 'ifIndex', ifx);
    if (lldp || cdp || eee) {
      const sec = formSection('Discovery and power saving');
      const lldpSel = lldp ? selectInput(Object.keys(LLDP_WORDS).map((k) => ({ label: LLDP_WORDS[k], value: k })), lldp.admin || 'txAndRx') : null;
      const cdpSel = cdp ? boolSel(cdp.on) : null;
      const eeeSel = eee ? boolSel(eee.admin) : null;
      if (lldpSel) sec.body.appendChild(field('LLDP', lldpSel));
      if (cdpSel) sec.body.appendChild(field('CDP', cdpSel));
      if (eeeSel) sec.body.appendChild(field('Energy Efficient Ethernet', eeeSel));
      if (eee) sec.body.appendChild(el('div', 'card-sub', 'EEE is ' + (eee.oper ? 'running' : 'not running') + ' on this link' +
        (eee.remote == null ? '.' : (eee.remote ? '; the other end supports it.' : '; the other end does not use it.'))));
      const { actions, apply } = applyActions('Apply');
      apply.addEventListener('click', (e) => {
        const body = { ifIndex: ifx };
        if (lldpSel && lldpSel.value !== lldp.admin) body.lldp = lldpSel.value;
        if (cdpSel && (cdpSel.value === '1') !== !!cdp.on) body.cdp = cdpSel.value === '1';
        if (eeeSel && (eeeSel.value === '1') !== !!eee.admin) body.eee = eeeSel.value === '1';
        if (Object.keys(body).length === 1) { toast('Nothing changed.', 'ok'); return; }
        portsWrite(e.currentTarget, s, '/api/ports/discovery', body, 'Apply', done);
      });
      sec.body.appendChild(actions);
      pane.appendChild(sec.sec);
    }

    // Cable test.
    if (d.ports && d.ports.indexOf(ifx) >= 0) {
      const sec = formSection('Cable test');
      const out = el('div');
      const TEST_WORDS = { cableStatus: 'Cable', cableFault: 'Fault', cableLength: 'Length',
        pair1: 'Pair 1', pair2: 'Pair 2', pair3: 'Pair 3', pair4: 'Pair 4' };
      const show = (rows) => {
        clear(out);
        if (!rows.length) { out.appendChild(el('div', 'card-sub', 'No test has been run on this port.')); return; }
        // Polarity and skew only mean something to a cable tester; a pair
        // result the switch could not measure is summed up in one line.
        const shown = rows.filter((r) => TEST_WORDS[r.test] && r.status === 'success');
        const missed = rows.filter((r) => TEST_WORDS[r.test] && r.status !== 'success');
        const dl = el('dl', 'port-detail-grid');
        for (const r of shown) { dl.appendChild(el('dt', '', TEST_WORDS[r.test])); dl.appendChild(el('dd', '', cableWords(r))); }
        if (shown.length) out.appendChild(dl);
        if (missed.length) out.appendChild(el('div', 'card-sub', missed.map((r) => TEST_WORDS[r.test]).join(', ') +
          ': the switch could not measure ' + (missed.length === 1 ? 'it' : 'these') + '. A pair test needs the full test, which takes the link down.'));
        if (rows[0].at) out.appendChild(el('div', 'card-sub', 'Measured ' + rows[0].at + '.'));
      };
      show((d.cableTests || []).filter((r) => r.ifIndex === ifx));
      const run = (kind, label) => (e) => runButtonAction(e.currentTarget, {
        failLabel: label, spinLabel: 'Testing…',
        run: () => sidePost('/api/ports/cable-test', { target: s.target, ifIndex: ifx, kind }),
        ok: (r) => r && r.ok, error: (r) => (r && r.error) || 'unknown error',
        onApplied: (r) => show(r.results || []), settle: () => portsLoad(s)
      });
      const len = el('button', 'btn btn-small', 'Measure length'); len.type = 'button';
      len.title = 'Estimates the cable length on a link that is up at 1 Gb/s. The link stays up.';
      len.addEventListener('click', run('length', 'Measure length'));
      const full = el('button', 'btn btn-small btn-danger', 'Full cable test'); full.type = 'button';
      full.title = 'Checks each pair for opens and shorts. The link goes down for a few seconds.';
      withConfirm(full, run('full', 'Full cable test'), { label: 'Full cable test', danger: true });
      const row = el('div', 'snmp-form-actions'); row.appendChild(len); row.appendChild(full);
      sec.body.appendChild(out);
      sec.body.appendChild(row);
      sec.body.appendChild(el('div', 'card-sub', 'The full test takes the link down for a few seconds, so a device on this port loses its connection briefly.'));
      pane.appendChild(sec.sec);
    }

    if (!pane.children.length) pane.appendChild(el('div', 'card-sub', 'The switch reports none of these features for this port.'));
    pane.appendChild(msg);
  }

  // The Features tab, for openPortDetail. Loads the data first when needed.
  function portFeaturesTab(s, ifx) {
    return { label: 'Features', fill: (pane) => {
      const st = s._ports || {};
      if (st.data && !st.data.error) { buildPortFeatures(s, ifx, pane); return; }
      pane.appendChild(el('div', 'card-sub', 'Loading port features…'));
      portsLoad(s).then(() => {
        clear(pane);
        if (s._ports.data && !s._ports.data.error) buildPortFeatures(s, ifx, pane);
        else pane.appendChild(el('div', 'sw-err', 'Could not read port features: ' + ((s._ports.data && s._ports.data.error) || 'no answer')));
      });
    } };
  }

  // ---- the panel ----

  function portOptions(s, ports) {
    return ports.map((i) => ({ label: portNameOf(s, i), value: String(i) }));
  }

  function paintPortFeaturesPanel(s, body, p) {
    if (!s._ktReconcile) clear(body);
    if (!s.target) { if (!s._ktReconcile) body.appendChild(el('div', 'card-sub', 'Connect with SNMP to see the port features.')); return; }
    s._ports = s._ports || {};
    const st = s._ports;
    if (!s._ktReconcile) sideEnsure(s, st, portsLoad);
    const d = st.data;
    const shape = !d ? 'wait' : (d.error ? 'error' : 'ready');
    if (s._ktReconcile && p._portsShape !== shape) { s._ktStructural = true; return; }
    p._portsShape = shape;
    if (shape === 'wait') { if (!s._ktReconcile) body.appendChild(el('div', 'card-sub', 'Waiting for data…')); return; }
    if (shape === 'error') { if (!s._ktReconcile) body.appendChild(el('div', 'panel-err', 'Could not read the port features: ' + d.error)); return; }

    const ports = d.ports || [];
    const ed = d.errdisable || { causes: [], ports: [] };
    const mirror = d.mirror || { destinations: [], sources: [] };
    const toggleCell = (on, label, url, payload) => {
      if (on == null) return { v: '' };
      const b = on
        ? actBtnConfirm('Turn off', (e) => portsWrite(e.currentTarget, s, url, Object.assign({}, payload, { on: false }), 'Turn off ' + label), 'danger')
        : actBtn('Turn on', (e) => portsWrite(e.currentTarget, s, url, Object.assign({}, payload, { on: true }), 'Turn on ' + label));
      return { cellNode: actGroup([b]), sig: on ? 'off' : 'on' };
    };
    const onPill = (v) => (v == null ? true : (v ? 'good' : true));
    const onWord = (v) => (v == null ? 'not reported' : (v ? 'on' : 'off'));

    // ---- switch-wide ----
    if (!s._ktReconcile) body.appendChild(el('div', 'section-title', 'Switch-wide'));
    const g = (key, label, v) => ({ key: 'global:' + key, cells: [{ v: label }, { pill: onPill(v), v: onWord(v) }, toggleCell(v, label, '/api/ports/global', { feature: key })] });
    mountInto(body, s, p, 'ports:global', ['Feature', 'State', ''], [
      g('lldp', 'LLDP', d.lldp && d.lldp.enabled),
      g('cdp', 'CDP', d.cdp && d.cdp.enabled),
      g('eee', 'Energy Efficient Ethernet', d.eee && d.eee.enabled)
    ]);

    // ---- errdisable recovery ----
    if (!s._ktReconcile) body.appendChild(el('div', 'section-title', 'Shut-down ports'));
    if (ed.ports.length) {
      mountInto(body, s, p, 'ports:errdis', ['Port', 'Reason', 'Comes back'], ed.ports.map((x) => ({
        key: 'ed:' + x.ifIndex,
        cells: [{ v: portNameOf(s, x.ifIndex) }, { pill: 'crit', v: CAUSE_WORDS[x.reason] || x.reason || '' },
          { v: x.recover ? (x.secondsLeft == null ? 'yes' : 'in ' + x.secondsLeft + ' s') : 'no, turn it back on by hand' }]
      })));
    } else if (!s._ktReconcile) body.appendChild(el('div', 'card-sub', 'No port is shut down by errdisable.'));
    if (!s._ktReconcile) body.appendChild(el('div', 'section-title', 'Automatic recovery'));
    mountInto(body, s, p, 'ports:causes', ['Cause', 'Recovers by itself', ''], ed.causes.map((c) => ({
      key: 'cause:' + c.id,
      cells: [{ v: CAUSE_WORDS[c.cause] || c.cause }, { pill: onPill(c.recover), v: onWord(c.recover) },
        toggleCell(c.recover, 'recovery', '/api/ports/errdisable/cause', { cause: c.cause })]
    })));
    if (!s._ktReconcile) {
      const row = el('div', 'maint-row');
      p._edInt = textInput(ed.intervalSec == null ? '' : String(ed.intervalSec), '300'); p._edInt.size = 6;
      const b = el('button', 'btn', 'Set interval'); b.type = 'button';
      b.addEventListener('click', (e) => portsWrite(e.currentTarget, s, '/api/ports/errdisable/interval', { seconds: Number(p._edInt.value) }, 'Set interval'));
      row.appendChild(field('Wait before recovery (seconds)', p._edInt));
      row.appendChild(b);
      body.appendChild(row);
    }
    if (document.activeElement !== p._edInt && ed.intervalSec != null && p._edSeen !== ed.intervalSec) { p._edSeen = ed.intervalSec; p._edInt.value = String(ed.intervalSec); }

    // ---- port mirroring ----
    if (!s._ktReconcile) body.appendChild(el('div', 'section-title', 'Port mirroring'));
    const sessions = mirror.destinations.map((x) => x.session)
      .concat(mirror.sources.map((x) => x.session)).filter((v, i, a) => a.indexOf(v) === i).sort((a, b) => a - b);
    if (sessions.length) {
      mountInto(body, s, p, 'ports:mirror', ['Session', 'Copied ports', 'To port', ''], sessions.map((id) => {
        const dst = mirror.destinations.find((x) => x.session === id);
        const src = mirror.sources.filter((x) => x.session === id);
        return {
          key: 'mirror:' + id,
          cells: [{ v: String(id) },
            { v: src.map((x) => (x.type === 'port' ? portNameOf(s, x.index) : x.type + ' ' + x.index) + ' (' + (x.direction || '') + ')').join(', ') },
            { v: dst ? portNameOf(s, dst.ifIndex) : 'none' },
            { cellNode: actGroup([actBtnConfirm('Remove', (e) => portsWrite(e.currentTarget, s, '/api/ports/mirror/remove', { session: id }, 'Remove mirroring'), 'danger')]), sig: 'rm' }]
        };
      }));
    } else if (!s._ktReconcile) body.appendChild(el('div', 'card-sub', 'No port is being mirrored.'));
    if (!s._ktReconcile) {
      const row = el('div', 'maint-row');
      p._mSrc = el('select'); p._mSrc.multiple = true; p._mSrc.size = 4;
      p._mDir = selectInput([{ label: 'both ways', value: 'both' }, { label: 'received', value: 'rx' }, { label: 'sent', value: 'tx' }], 'both');
      p._mDst = selectInput([], '');
      const add = el('button', 'btn', 'Start mirroring'); add.type = 'button';
      add.addEventListener('click', (e) => {
        const m = (s._ports.data && s._ports.data.mirror) || { destinations: [], sources: [] };
        const dest = Number(p._mDst.value);
        const src = Array.from(p._mSrc.selectedOptions).map((o) => ({ ifIndex: Number(o.value), direction: p._mDir.value }));
        if (!src.length) { toast('Choose at least one port to copy.'); return; }
        // To a port that already receives copies: add the ports to its session.
        const existing = m.destinations.find((x) => x.ifIndex === dest);
        if (existing) {
          runButtonAction(e.currentTarget, {
            failLabel: 'Start mirroring',
            run: async () => {
              for (const x of src) {
                const r = await sidePost('/api/ports/mirror/source/add', Object.assign({ target: s.target, session: existing.session }, x));
                if (!r || !r.ok) return r;
              }
              return { ok: true };
            },
            ok: (r) => r && r.ok, error: (r) => (r && r.error) || 'unknown error',
            onApplied: () => markConfigDirty(s), settle: () => portsLoad(s)
          });
          return;
        }
        const used = m.destinations.map((x) => x.session).concat(m.sources.map((x) => x.session));
        const id = [1, 2, 3, 4].find((n) => used.indexOf(n) < 0);
        if (!id) { toast('All four mirroring sessions are in use.'); return; }
        portsWrite(e.currentTarget, s, '/api/ports/mirror/add', { session: id, dest, sources: src }, 'Start mirroring');
      });
      row.appendChild(field('Copy these ports', p._mSrc));
      row.appendChild(field('Traffic', p._mDir));
      row.appendChild(field('To port', p._mDst));
      row.appendChild(add);
      body.appendChild(row);
      body.appendChild(el('div', 'card-sub', 'The port the copies go to carries only the copies while mirroring is on: plug a computer running a packet capture into it.'));
    }
    const optsKey = ports.join(',');
    if (p._mOpts !== optsKey) {
      p._mOpts = optsKey;
      for (const sel of [p._mSrc, p._mDst]) {
        const keep = Array.from(sel.selectedOptions || []).map((o) => o.value);
        clear(sel);
        for (const o of portOptions(s, ports)) { const op = el('option', '', o.label); op.value = o.value; if (keep.indexOf(o.value) >= 0) op.selected = true; sel.appendChild(op); }
      }
    }

    // ---- per port ----
    if (!s._ktReconcile) body.appendChild(el('div', 'section-title', 'Ports'));
    mountInto(body, s, p, 'ports:list', ['Port', 'PoE', 'Port security', 'Storm control', 'LLDP', 'EEE', ''], ports.map((ifx) => {
      const poe = rowFor(d.poe, 'port', ifx);
      const sec = rowFor(d.security, 'ifIndex', ifx);
      const storm = rowFor(d.storm, 'ifIndex', ifx);
      const lldp = rowFor(d.lldp && d.lldp.ports, 'port', ifx);
      const eee = rowFor(d.eee && d.eee.ports, 'ifIndex', ifx);
      const stormOn = storm && Object.keys(storm.traffic).filter((k) => storm.traffic[k].rate > 0);
      return {
        key: 'port:' + ifx,
        cells: [{ v: portNameOf(s, ifx) },
          poe ? { pill: poe.admin ? (poe.detection === 'fault' || poe.detection === 'otherFault' ? 'crit' : 'good') : true,
            v: poe.admin ? (POE_WORDS[poe.detection] || poe.detection || 'on') + (poe.powerMw ? ', ' + watts(poe.powerMw) : '') : 'off' } : { v: '' },
          sec ? { pill: sec.locked ? 'warn' : true, v: sec.locked ? 'locked' : 'off' } : { v: '' },
          storm ? { v: stormOn.length ? stormOn.join(', ') : 'off' } : { v: '' },
          lldp ? { v: LLDP_WORDS[lldp.admin] || lldp.admin || '' } : { v: '' },
          eee ? { v: eee.admin ? (eee.oper ? 'running' : 'on') : 'off' } : { v: '' },
          { cellNode: actGroup([actBtn('Change', () => openTabbedPopout(s, portNameOf(s, ifx) + ' · features', [portFeaturesTab(s, ifx)], []))]), sig: 'chg' }]
      };
    }));
  }
