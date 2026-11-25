  // =================================================================
  // 29-stp-settings.js: The Spanning tree settings panel and the port
  // popout's Spanning tree tab: on or off, the mode, the bridge priority
  // (switch, VLAN or MSTP instance) and per port the cost, priority,
  // PortFast and BPDU guard. The Spanning tree panel (11-panel-bodies.js)
  // shows the running tree; this one changes it.
  // =================================================================

  // A keyed panel with a server-side reader (standard B1 family b2), like
  // Port features. The data rides the server collection as `stp`
  // (module-collection.js, switch-stp.js).
  //
  // s._stpSet = { data, fetchedAt, loading, liveAt, collected }

  function stpSetLoad(s) {
    s._stpSet = s._stpSet || {};
    const st = s._stpSet;
    if (st.loading) return st.loading;
    st.fetchedAt = Date.now();
    st.liveAt = Date.now();
    st.loading = sidePost('/api/stp/status', { target: s.target })
      .then((b) => { st.data = (b && !b.error) ? b : { error: (b && b.error) || 'no answer' }; })
      .finally(() => { st.loading = null; sideRepaint(s, 'stpsettings'); });
    return st.loading;
  }

  function stpWrite(btn, s, url, payload, failLabel, onApplied) {
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
      settle: () => stpSetLoad(s)
    });
  }

  const STP_MODE_WORDS = { stp: 'STP (802.1D)', rstp: 'RSTP (802.1w)', mstp: 'MSTP (802.1s)', pvst: 'PVST+', 'rapid-pvst': 'Rapid PVST+' };
  const STP_ROLE_WORDS = { root: 'root', designated: 'designated', alternate: 'alternate', backup: 'backup', disabled: 'disabled', master: 'master' };
  const bridgePriorityOptions = () => Array.from({ length: 16 }, (_, k) => ({ label: String(k * 4096), value: String(k * 4096) }));
  const portPriorityOptions = () => Array.from({ length: 16 }, (_, k) => ({ label: String(k * 16), value: String(k * 16) }));
  const stpPerVlan = (mode) => mode === 'pvst' || mode === 'rapid-pvst';
  const stpOnOff = (v) => (v == null ? 'not reported' : (v ? 'on' : 'off'));
  const edgeWord = (r) => (r.edge ? 'on' : (r.autoEdge ? 'auto' : 'off'));

  // ---- the port popout's Spanning tree tab ----

  function buildStpPort(s, ifx, pane) {
    const d = (s._stpSet && s._stpSet.data) || {};
    const r = (d.ports || []).find((x) => x.ifIndex === ifx);
    if (!r) { pane.appendChild(el('div', 'card-sub', 'The switch reports no spanning tree settings for this port.')); return; }
    const done = () => { const pop = pane.closest && pane.closest('.port-detail-back'); if (pop) pop.remove(); };

    const sec = formSection('This port');
    sec.body.appendChild(el('div', 'card-sub', 'Role ' + (STP_ROLE_WORDS[r.role] || r.role || 'not reported') +
      ', cost in use ' + (r.cost == null ? 'not reported' : r.cost) + (r.operEdge ? ', running as an edge port' : '') + '.'));
    const on = selectInput([{ label: 'on', value: '1' }, { label: 'off', value: '0' }], r.enabled === false ? '0' : '1');
    const pri = selectInput(portPriorityOptions(), String(r.priority == null ? 128 : r.priority));
    const cost = textInput(r.adminCost == null ? '0' : String(r.adminCost), '0'); cost.size = 10;
    const edge = selectInput([{ label: 'on', value: 'on' }, { label: 'automatic', value: 'auto' }, { label: 'off', value: 'off' }], edgeWord(r));
    const guard = selectInput([{ label: 'on', value: '1' }, { label: 'off', value: '0' }], r.bpduGuard ? '1' : '0');
    sec.body.appendChild(field('Spanning tree', on));
    sec.body.appendChild(field('Port priority', pri));
    sec.body.appendChild(field('Cost (0 = automatic)', cost));
    sec.body.appendChild(field('PortFast (edge port)', edge));
    sec.body.appendChild(field('BPDU guard', guard));
    sec.body.appendChild(el('div', 'card-sub', 'PortFast is for ports with a computer, phone or printer on them. ' +
      'BPDU guard shuts the port down if a switch is plugged into it.'));
    const { actions, apply } = applyActions('Apply');
    apply.addEventListener('click', (e) => {
      const c = Number(cost.value);
      if (!Number.isInteger(c) || c < 0) { toast('The cost is a whole number; 0 means automatic.', 'error'); return; }
      const body = { port: r.port };
      if ((on.value === '1') !== (r.enabled !== false)) body.enabled = on.value === '1';
      if (Number(pri.value) !== r.priority) body.priority = Number(pri.value);
      if (c !== (r.adminCost == null ? 0 : r.adminCost)) body.cost = c;
      if (edge.value !== edgeWord(r)) { body.edge = edge.value === 'on'; body.autoEdge = edge.value === 'auto'; }
      if ((guard.value === '1') !== !!r.bpduGuard) body.bpduGuard = guard.value === '1';
      if (Object.keys(body).length === 1) { toast('Nothing changed.', 'ok'); return; }
      stpWrite(e.currentTarget, s, '/api/stp/port', body, 'Apply', done);
    });
    sec.body.appendChild(actions);
    pane.appendChild(sec.sec);

    // Under PVST or MSTP: the port's cost and priority in one VLAN or instance.
    const per = stpPerVlan(d.mode) ? (d.vlans || []).map((v) => ({ id: v.vlan, rows: v.ports, key: 'vlan' }))
      : (d.mode === 'mstp' ? (d.instances || []).map((i) => ({ id: i.instance, rows: i.ports, key: 'instance' })) : []);
    if (per.length) {
      const word = per[0].key === 'vlan' ? 'VLAN' : 'Instance';
      const sec2 = formSection('In one ' + word.toLowerCase());
      const which = selectInput(per.map((x) => ({ label: word + ' ' + x.id, value: String(x.id) })), String(per[0].id));
      const pri2 = selectInput(portPriorityOptions(), '128');
      const cost2 = textInput('0', '0'); cost2.size = 10;
      const fill = () => {
        const x = per.find((y) => String(y.id) === which.value);
        const row = x && (x.rows || []).find((y) => y.port === r.port);
        pri2.value = String(row && row.priority != null ? row.priority : 128);
        cost2.value = String(row ? (row.cost != null ? row.cost : (row.adminCost || 0)) : 0);
      };
      which.addEventListener('change', fill); fill();
      sec2.body.appendChild(field(word, which));
      sec2.body.appendChild(field('Port priority', pri2));
      sec2.body.appendChild(field('Cost (0 = automatic)', cost2));
      const a2 = applyActions('Apply to this ' + word.toLowerCase());
      a2.apply.addEventListener('click', (e) => {
        const c = Number(cost2.value);
        if (!Number.isInteger(c) || c < 0) { toast('The cost is a whole number; 0 means automatic.', 'error'); return; }
        const body = { port: r.port, priority: Number(pri2.value), cost: c };
        body[per[0].key] = Number(which.value);
        stpWrite(e.currentTarget, s, '/api/stp/port-in', body, 'Apply', done);
      });
      sec2.body.appendChild(a2.actions);
      pane.appendChild(sec2.sec);
    }
  }

  function stpPortTab(s, ifx) {
    return { label: 'Spanning tree', fill: (pane) => {
      const st = s._stpSet || {};
      if (st.data && !st.data.error) { buildStpPort(s, ifx, pane); return; }
      pane.appendChild(el('div', 'card-sub', 'Loading spanning tree settings…'));
      stpSetLoad(s).then(() => {
        clear(pane);
        if (s._stpSet.data && !s._stpSet.data.error) buildStpPort(s, ifx, pane);
        else pane.appendChild(el('div', 'sw-err', 'Could not read spanning tree settings: ' + ((s._stpSet.data && s._stpSet.data.error) || 'no answer')));
      });
    } };
  }

  // ---- the panel ----

  function paintStpSettingsPanel(s, body, p) {
    if (!s._ktReconcile) clear(body);
    if (!s.target) { if (!s._ktReconcile) body.appendChild(el('div', 'card-sub', 'Connect with SNMP to see the spanning tree settings.')); return; }
    s._stpSet = s._stpSet || {};
    const st = s._stpSet;
    if (!s._ktReconcile) sideEnsure(s, st, stpSetLoad);
    const d = st.data;
    const per = d && !d.error ? (stpPerVlan(d.mode) ? 'vlan' : (d.mode === 'mstp' ? 'instance' : 'none')) : '';
    const shape = !d ? 'wait' : (d.error ? 'error' : 'ready:' + per);
    if (s._ktReconcile && p._stpSetShape !== shape) { s._ktStructural = true; return; }
    p._stpSetShape = shape;
    if (shape === 'wait') { if (!s._ktReconcile) body.appendChild(el('div', 'card-sub', 'Waiting for data…')); return; }
    if (shape === 'error') { if (!s._ktReconcile) body.appendChild(el('div', 'panel-err', 'Could not read the spanning tree settings: ' + d.error)); return; }

    // ---- switch-wide ----
    if (!s._ktReconcile) body.appendChild(el('div', 'section-title', 'Switch-wide'));
    const onBtn = d.enabled == null ? { v: '' } : {
      cellNode: actGroup([d.enabled
        ? actBtnConfirm('Turn off', (e) => stpWrite(e.currentTarget, s, '/api/stp/enabled', { on: false }, 'Turn off spanning tree'), 'danger')
        : actBtn('Turn on', (e) => stpWrite(e.currentTarget, s, '/api/stp/enabled', { on: true }, 'Turn on spanning tree'))]),
      sig: d.enabled ? 'off' : 'on'
    };
    mountInto(body, s, p, 'stp:global', ['Setting', 'Now', ''], [
      { key: 'g:on', cells: [{ v: 'Spanning tree' }, { pill: d.enabled ? 'good' : 'warn', v: stpOnOff(d.enabled) }, onBtn] },
      { key: 'g:mode', cells: [{ v: 'Mode' }, { v: STP_MODE_WORDS[d.mode] || d.mode || 'not reported' }, { v: '' }] },
      { key: 'g:pri', cells: [{ v: per === 'none' ? 'Bridge priority' : 'Bridge priority (common)' }, { v: d.priority == null ? '' : String(d.priority) }, { v: '' }] }
    ]);
    if (!s._ktReconcile) {
      const row = el('div', 'maint-row');
      p._stpMode = selectInput(Object.keys(STP_MODE_WORDS).map((k) => ({ label: STP_MODE_WORDS[k], value: k })), d.mode || 'rstp');
      const setMode = el('button', 'btn', 'Set mode'); setMode.type = 'button';
      withConfirm(setMode, (e) => stpWrite(e.currentTarget, s, '/api/stp/mode', { mode: p._stpMode.value }, 'Set mode'),
        { label: 'Set mode', danger: true });
      row.appendChild(field('Mode', p._stpMode));
      row.appendChild(setMode);
      p._stpPri = selectInput(bridgePriorityOptions(), String(d.priority == null ? 32768 : d.priority));
      const setPri = el('button', 'btn', 'Set priority'); setPri.type = 'button';
      setPri.addEventListener('click', (e) => stpWrite(e.currentTarget, s, '/api/stp/priority', { priority: Number(p._stpPri.value) }, 'Set priority'));
      row.appendChild(field('Bridge priority', p._stpPri));
      row.appendChild(setPri);
      body.appendChild(row);
      body.appendChild(el('div', 'card-sub', 'The lowest priority becomes the root bridge. Changing the mode makes every switch ' +
        'rebuild its tree, which stops traffic for a few seconds.'));
    }

    // ---- per VLAN or per instance ----
    if (per !== 'none') {
      const word = per === 'vlan' ? 'VLAN' : 'Instance';
      const list = per === 'vlan' ? (d.vlans || []).map((v) => ({ id: v.vlan, priority: v.priority }))
        : (d.instances || []).map((i) => ({ id: i.instance, priority: i.priority }));
      if (!s._ktReconcile) body.appendChild(el('div', 'section-title', 'Bridge priority per ' + word.toLowerCase()));
      mountInto(body, s, p, 'stp:per', [word, 'Bridge priority', ''], list.map((x) => {
        const sel = selectInput(bridgePriorityOptions(), String(x.priority == null ? 32768 : x.priority));
        const b = actBtn('Set', (e) => {
          const payload = { priority: Number(sel.value) };
          payload[per] = x.id;
          stpWrite(e.currentTarget, s, '/api/stp/priority', payload, 'Set ' + word.toLowerCase() + ' priority');
        });
        return { key: per + ':' + x.id, cells: [{ v: String(x.id) }, { v: x.priority == null ? '' : String(x.priority) },
          { cellNode: actGroup([sel, b]), sig: 'set:' + x.priority }] };
      }));
      if (!list.length && !s._ktReconcile) body.appendChild(el('div', 'card-sub', 'The switch lists no ' + word.toLowerCase() + ' settings.'));
    }

    // ---- per port ----
    if (!s._ktReconcile) body.appendChild(el('div', 'section-title', 'Ports'));
    const ports = d.ports || [];
    mountInto(body, s, p, 'stp:ports', ['Port', 'Spanning tree', 'Priority', 'Cost', 'PortFast', 'BPDU guard', ''], ports.map((r) => {
      const name = r.ifIndex == null ? 'port ' + r.port : portNameOf(s, r.ifIndex);
      return {
        key: 'p:' + r.port,
        cells: [{ v: name }, { v: stpOnOff(r.enabled) }, { v: r.priority == null ? '' : String(r.priority) },
          { v: r.adminCost ? String(r.adminCost) : (r.cost == null ? 'automatic' : 'automatic: ' + r.cost) },
          { pill: r.edge || r.autoEdge ? 'good' : true, v: edgeWord(r) },
          { pill: r.bpduGuard ? 'good' : true, v: stpOnOff(r.bpduGuard) },
          r.ifIndex == null ? { v: '' } : { cellNode: actGroup([actBtn('Change', () => openTabbedPopout(s, name + ' · spanning tree', [stpPortTab(s, r.ifIndex)], []))]), sig: 'chg' }]
      };
    }));
  }
