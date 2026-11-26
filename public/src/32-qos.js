  // =================================================================
  // 32-qos.js: The QoS panel: the QoS mode and trust, trust, rate limit
  // and shapers per port, and the CoS and DSCP queue maps (switch-qos.js).
  // =================================================================

  // A keyed panel with a server-side reader (standard B1 family b2), like
  // IPv6 addressing. The data rides the server collection as `qos`
  // (module-collection.js).
  //
  // s._qosSet = { data, fetchedAt, loading, liveAt, collected }

  function qosLoad(s) {
    s._qosSet = s._qosSet || {};
    const st = s._qosSet;
    if (st.loading) return st.loading;
    st.fetchedAt = Date.now();
    st.liveAt = Date.now();
    st.loading = sidePost('/api/qos/status', { target: s.target })
      .then((b) => { st.data = (b && !b.error) ? b : { error: (b && b.error) || 'no answer' }; })
      .finally(() => { st.loading = null; sideRepaint(s, 'qos'); });
    return st.loading;
  }

  function qosWrite(btn, s, url, payload, failLabel, onApplied) {
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
      settle: () => qosLoad(s)
    });
  }

  // Several writes from one Apply, one after another; the first refusal stops them.
  function qosWriteAll(btn, s, steps, failLabel, onApplied) {
    return runButtonAction(btn, {
      failLabel,
      run: async () => {
        s.writeBusy = true;
        try {
          for (const [url, payload] of steps) {
            const r = await sidePost(url, Object.assign({ target: s.target }, payload));
            if (!r || !r.ok) return r;
          }
          return { ok: true };
        } finally { s.writeBusy = false; }
      },
      ok: (r) => r && r.ok,
      error: (r) => (r && r.error) || 'unknown error',
      onApplied: () => { markConfigDirty(s); if (onApplied) onApplied(); },
      settle: () => qosLoad(s)
    });
  }

  const QOS_MODE_WORDS = { disable: 'off', basic: 'basic', advanced: 'advanced' };
  const QOS_TRUST_WORDS = { cos: 'CoS (802.1p)', dscp: 'DSCP', 'cos-dscp': 'CoS and DSCP' };
  const qosRate = (n) => (n ? n.toLocaleString() + ' kb/s' : 'off');
  const QUEUE_OPTS = [1, 2, 3, 4, 5, 6, 7, 8].map((q) => ({ label: 'queue ' + q, value: String(q) }));

  function qosNumOk(input, what, allowEmpty) {
    const t = input.value.trim();
    if (t === '' && allowEmpty) return true;
    if (!/^\d+$/.test(t)) { toast(what + ' must be a whole number.', 'error'); return false; }
    return true;
  }

  // ---- the port popout ----

  function buildQosPort(s, ifx, pane) {
    const d = (s._qosSet && s._qosSet.data) || {};
    const row = (d.ports || []).find((x) => x.ifIndex === ifx);
    if (!row) { pane.appendChild(el('div', 'card-sub', 'The switch reported no QoS settings for this port.')); return; }
    const done = () => { const pop = pane.closest && pane.closest('.port-detail-back'); if (pop) pop.remove(); };

    const sec = formSection('Trust and rates');
    const trust = selectInput([{ label: 'on', value: '1' }, { label: 'off', value: '0' }], row.trust ? '1' : '0');
    const limit = textInput(String(row.rateLimit || 0), '0'); limit.size = 10;
    const shape = textInput(String(row.shaper.on ? row.shaper.cir : 0), '0'); shape.size = 10;
    const burst = textInput(String(row.shaper.cbs || 128000), '128000'); burst.size = 10;
    sec.body.appendChild(field('Trust', trust));
    sec.body.appendChild(field('Rate limit in (kb/s, 0 = off)', limit));
    sec.body.appendChild(field('Shaper out (kb/s, 0 = off)', shape));
    sec.body.appendChild(field('Shaper burst (bytes)', burst));
    sec.body.appendChild(el('div', 'card-sub', 'Trust lets the port use the priority marked in each frame (basic mode). ' +
      'The rate limit drops what comes in above the rate. The shaper holds what goes out to the rate. Rates are 64 kb/s or more.'));
    const { actions, apply } = applyActions('Apply');
    apply.addEventListener('click', (e) => {
      if (!qosNumOk(limit, 'The rate limit') || !qosNumOk(shape, 'The shaper rate') || !qosNumOk(burst, 'The burst size')) return;
      const steps = [];
      if ((trust.value === '1') !== !!row.trust) steps.push(['/api/qos/port-trust', { ifIndex: ifx, on: trust.value === '1' }]);
      if (Number(limit.value) !== (row.rateLimit || 0)) steps.push(['/api/qos/rate-limit', { ifIndex: ifx, rate: Number(limit.value) }]);
      const cir = Number(shape.value), was = row.shaper.on ? row.shaper.cir : 0;
      if (cir !== was || (cir && Number(burst.value) !== row.shaper.cbs)) steps.push(['/api/qos/port-shaper', { ifIndex: ifx, cir, cbs: Number(burst.value) }]);
      if (!steps.length) { toast('Nothing changed.', 'ok'); return; }
      qosWriteAll(e.currentTarget, s, steps, 'Apply', done);
    });
    sec.body.appendChild(actions);
    pane.appendChild(sec.sec);

    const q = formSection('Queue shapers');
    const shaped = (row.queueShaper && row.queueShaper.queues) || [];
    q.body.appendChild(el('div', 'card-sub', shaped.length
      ? 'Shaped now: ' + shaped.map((x) => 'queue ' + x.queue + ' at ' + qosRate(x.cir)).join(', ') + '.'
      : 'No queue on this port is shaped.'));
    const qSel = selectInput(QUEUE_OPTS, String(shaped.length ? shaped[0].queue : 1));
    const qRate = textInput('', '0 = off'); qRate.size = 10;
    const qBurst = textInput('128000', '128000'); qBurst.size = 10;
    const fill = () => { const x = shaped.find((y) => String(y.queue) === qSel.value); qRate.value = x ? String(x.cir) : ''; if (x) qBurst.value = String(x.cbs); };
    qSel.addEventListener('change', fill); fill();
    q.body.appendChild(field('Queue', qSel));
    q.body.appendChild(field('Rate (kb/s, 0 = off)', qRate));
    q.body.appendChild(field('Burst (bytes)', qBurst));
    const a2 = applyActions('Set queue shaper');
    a2.apply.addEventListener('click', (e) => {
      if (!qosNumOk(qRate, 'The queue rate') || !qosNumOk(qBurst, 'The burst size')) return;
      qosWrite(e.currentTarget, s, '/api/qos/queue-shaper', { ifIndex: ifx, queue: Number(qSel.value), cir: Number(qRate.value), cbs: Number(qBurst.value) }, 'Set queue shaper', done);
    });
    q.body.appendChild(a2.actions);
    pane.appendChild(q.sec);
  }

  function qosPortTab(s, ifx) {
    return {
      label: 'QoS',
      fill: (pane) => {
        const st = s._qosSet || {};
        if (st.data && !st.data.error) { buildQosPort(s, ifx, pane); return; }
        pane.appendChild(el('div', 'card-sub', 'Loading QoS settings…'));
        qosLoad(s).then(() => {
          clear(pane);
          if (s._qosSet.data && !s._qosSet.data.error) buildQosPort(s, ifx, pane);
          else pane.appendChild(el('div', 'sw-err', 'Could not read QoS settings: ' + ((s._qosSet.data && s._qosSet.data.error) || 'no answer')));
        });
      }
    };
  }

  // A "value to queue" row: pick the value and the queue, then Set; and a
  // button that puts the whole map back to the switch's defaults.
  function qosMapForm(s, body, which, values, label) {
    const row = el('div', 'maint-row');
    const val = selectInput(values.map((v) => ({ label: label + ' ' + v, value: String(v) })), String(values[0]));
    const queue = selectInput(QUEUE_OPTS, '1');
    const map = (s._qosSet.data[which === 'cos' ? 'cosMap' : 'dscpMap'] || []);
    const fill = () => { const m = map.find((x) => String(x[which]) === val.value); if (m && m.queue) queue.value = String(m.queue); };
    val.addEventListener('change', fill); fill();
    const go = el('button', 'btn', 'Set'); go.type = 'button';
    go.addEventListener('click', (e) => qosWrite(e.currentTarget, s, '/api/qos/' + which + '-map', { [which]: Number(val.value), queue: Number(queue.value) }, 'Set'));
    row.appendChild(field(label, val));
    row.appendChild(field('Goes to', queue));
    row.appendChild(go);
    row.appendChild(actGroup([actBtnConfirm('Put back the defaults', (e) => qosWrite(e.currentTarget, s, '/api/qos/restore-map', { map: which }, 'Put back the defaults'), 'danger')]));
    body.appendChild(row);
  }

  // ---- the panel ----

  function paintQosPanel(s, body, p) {
    if (!s._ktReconcile) clear(body);
    if (!s.target) { if (!s._ktReconcile) body.appendChild(el('div', 'card-sub', 'Connect with SNMP to see the QoS settings.')); return; }
    s._qosSet = s._qosSet || {};
    const st = s._qosSet;
    if (!s._ktReconcile) sideEnsure(s, st, qosLoad);
    const d = st.data;
    const shape = !d ? 'wait' : (d.error ? 'error' : 'ready');
    if (s._ktReconcile && p._qosShape !== shape) { s._ktStructural = true; return; }
    p._qosShape = shape;
    if (shape === 'wait') { if (!s._ktReconcile) body.appendChild(el('div', 'card-sub', 'Waiting for data…')); return; }
    if (shape === 'error') { if (!s._ktReconcile) body.appendChild(el('div', 'panel-err', 'Could not read the QoS settings: ' + d.error)); return; }

    // ---- mode and trust ----
    if (!s._ktReconcile) {
      body.appendChild(el('div', 'section-title', 'QoS mode'));
      const sched = (d.scheduling || [])[0];
      const allEf = sched && sched.queues.every((q) => q.type === 'ef');
      body.appendChild(el('div', 'card-sub', 'Each frame goes to one of 8 egress queues by its CoS or DSCP value. ' +
        (allEf ? 'The queues are served by strict priority: queue 8 first.' : 'Some queues share the line by weight.')));
      if (d.mode == null) {
        body.appendChild(el('div', 'card-sub', 'The switch did not report its QoS mode.'));
      } else {
        const row = el('div', 'maint-row');
        const mode = selectInput(Object.keys(QOS_MODE_WORDS).map((k) => ({ label: QOS_MODE_WORDS[k], value: k })), d.mode);
        const nowTrust = d.mode === 'advanced' ? d.advancedTrust : d.basicTrust;
        const trust = selectInput(Object.keys(QOS_TRUST_WORDS).map((k) => ({ label: QOS_TRUST_WORDS[k], value: k })), nowTrust || 'cos');
        const go = el('button', 'btn', 'Apply'); go.type = 'button';
        go.addEventListener('click', (e) => {
          const steps = [];
          if (mode.value !== d.mode) steps.push(['/api/qos/mode', { mode: mode.value }]);
          // The trust belongs to the mode, so it is written after the mode changes.
          const trustNow = mode.value === 'advanced' ? d.advancedTrust : d.basicTrust;
          if (mode.value !== 'disable' && trust.value !== trustNow) steps.push(['/api/qos/trust', { trust: trust.value }]);
          if (!steps.length) { toast('Nothing changed.', 'ok'); return; }
          qosWriteAll(e.currentTarget, s, steps, 'Apply');
        });
        row.appendChild(field('Mode', mode));
        row.appendChild(field('Trust', trust));
        row.appendChild(go);
        body.appendChild(row);
        body.appendChild(el('div', 'card-sub', 'Off sends everything to one queue. Basic sorts by the trusted value. ' +
          'Advanced also uses policy maps, which this app does not change.'));
      }
    }

    // ---- ports ----
    if (!s._ktReconcile) body.appendChild(el('div', 'section-title', 'Ports'));
    const ports = d.ports || [];
    mountInto(body, s, p, 'qos:ports', ['Port', 'Trust', 'Rate limit in', 'Shaper out', 'Queue shapers', ''], ports.map((r) => {
      const qs = (r.queueShaper && r.queueShaper.queues) || [];
      return {
        key: 'p:' + r.ifIndex,
        cells: [{ v: portNameOf(s, r.ifIndex) },
          { pill: r.trust ? 'good' : true, v: r.trust ? 'on' : 'off' },
          { v: r.rateLimit == null ? '' : qosRate(r.rateLimit) },
          { v: r.shaper.on ? qosRate(r.shaper.cir) : 'off' },
          { v: qs.length ? qs.map((x) => 'q' + x.queue + ' ' + qosRate(x.cir)).join(', ') : 'none' },
          { cellNode: actGroup([actBtn('Change', () => openTabbedPopout(s, portNameOf(s, r.ifIndex) + ' · QoS', [qosPortTab(s, r.ifIndex)], []))]), sig: 'chg' }]
      };
    }));

    // ---- CoS map ----
    const cos = d.cosMap || [];
    if (!s._ktReconcile) {
      body.appendChild(el('div', 'section-title', 'CoS to queue'));
      body.appendChild(el('div', 'card-sub', 'Which queue a frame goes to by its 802.1p priority (CoS 0 to 7).'));
    }
    mountInto(body, s, p, 'qos:cos', ['CoS', 'Queue', 'Default'], cos.map((m) => ({
      key: 'c:' + m.cos,
      cells: [{ v: String(m.cos) }, (m.queue !== m.default ? { pill: 'warn', v: String(m.queue) } : { v: String(m.queue) }), { v: m.default == null ? '' : String(m.default) }]
    })));
    if (!s._ktReconcile && cos.length) qosMapForm(s, body, 'cos', cos.map((m) => m.cos), 'CoS');

    // ---- DSCP map ----
    const dscp = d.dscpMap || [];
    const moved = dscp.filter((m) => m.default != null && m.queue !== m.default);
    if (!s._ktReconcile) {
      body.appendChild(el('div', 'section-title', 'DSCP to queue'));
      body.appendChild(el('div', 'card-sub', !dscp.length ? 'The switch did not report its DSCP map.'
        : moved.length ? 'The DSCP values sent to a queue other than the default. Every other value uses its default queue.'
          : 'Every DSCP value uses its default queue.'));
    }
    if (moved.length) {
      mountInto(body, s, p, 'qos:dscp', ['DSCP', 'Queue', 'Default'], moved.map((m) => ({
        key: 'd:' + m.dscp,
        cells: [{ v: String(m.dscp) }, { pill: 'warn', v: String(m.queue) }, { v: String(m.default) }]
      })));
    }
    if (!s._ktReconcile && dscp.length) qosMapForm(s, body, 'dscp', dscp.map((m) => m.dscp), 'DSCP');
  }
