  // =================================================================
  // 27-system.js: The System panel (clock, users, management access).
  // =================================================================

  // A keyed panel with a server-side reader (standard B1 family b2), like
  // Reboot and firmware. The data rides the server collection as `system`
  // (module-collection.js, switch-system.js).
  //
  // s._system = { data, fetchedAt, loading, liveAt, collected }
  // data is /api/system/status's reply; data.error is set when it failed.

  function systemLoad(s) {
    s._system = s._system || {};
    const st = s._system;
    if (st.loading) return st.loading;
    st.fetchedAt = Date.now();
    st.liveAt = Date.now();
    st.loading = sidePost('/api/system/status', { target: s.target })
      .then((b) => { st.data = (b && !b.error) ? b : { error: (b && b.error) || 'no answer' }; })
      .finally(() => { st.loading = null; sideRepaint(s, 'system'); });
    return st.loading;
  }

  const CLOCK_WORDS = {
    invalid: 'not set', manuallySet: 'set by hand', synchronizedBySntp: 'synchronized by SNTP',
    setByRtc: 'from the built-in clock', setByPnP: 'set by Plug and Play'
  };
  const SERVER_PILL = { up: 'good', down: 'bad', inProcess: 'warn' };

  const onOff = (v) => (v == null ? 'not reported' : (v ? 'on' : 'off'));
  const onOffPill = (v) => (v == null ? true : (v ? 'good' : true));

  function utcOffsetWords(t) {
    if (!t.zoneOffset) return 'not reported';
    return 'UTC' + t.zoneOffset + (t.zoneCode ? ' (' + t.zoneCode + ')' : '');
  }

  function dstWords(d) {
    if (!d || !d.mode) return 'not reported';
    if (d.mode === 'none') return 'off';
    const how = d.mode === 'recurring' ? 'every year' : 'on set dates';
    return 'on, ' + how + (d.offsetMin ? ', ' + d.offsetMin + ' min' : '') + (d.code ? ' (' + d.code + ')' : '');
  }

  // Key/value rows for a two-column settings table.
  function settingRows(prefix, pairs) {
    return pairs.map(([label, value, pill]) => ({
      key: prefix + ':' + label,
      cells: [{ v: label }, pill === undefined ? { v: value } : { pill, v: value }]
    }));
  }

  function paintSystemPanel(s, body, p) {
    if (!s._ktReconcile) clear(body);
    if (!s.target) { if (!s._ktReconcile) body.appendChild(el('div', 'card-sub', 'Connect with SNMP to see the system settings.')); return; }
    s._system = s._system || {};
    const st = s._system;
    if (!s._ktReconcile) sideEnsure(s, st, systemLoad);
    const d = st.data;
    const shape = !d ? 'wait' : (d.error ? 'error' : 'ready');
    if (s._ktReconcile && p._systemShape !== shape) { s._ktStructural = true; return; }
    p._systemShape = shape;
    if (shape === 'wait') { if (!s._ktReconcile) body.appendChild(el('div', 'card-sub', 'Waiting for data…')); return; }
    if (shape === 'error') { if (!s._ktReconcile) body.appendChild(el('div', 'panel-err', 'Could not read the system settings: ' + d.error)); return; }

    const t = d.time || {};
    const sntp = t.sntp || {};
    const users = (d.users && d.users.list) || [];
    const a = d.access || {};
    const acl = a.mgmtAcl || {};

    // ---- Clock ----
    if (!s._ktReconcile) body.appendChild(el('div', 'section-title', 'Clock'));
    mountInto(body, s, p, 'system:clock', ['Setting', 'Value'], settingRows('clock', [
      ['Switch time', t.now || 'not reported'],
      ['Clock source', CLOCK_WORDS[t.clock] || 'not reported', t.clock === 'invalid' ? 'bad' : (t.clock === 'synchronizedBySntp' ? 'good' : true)],
      ['Time zone', utcOffsetWords(t)],
      ['Summer time', dstWords(t.dst)],
      ['SNTP', sntp.unicast == null ? 'not reported' : (sntp.unicast ? 'on' : 'off'), onOffPill(sntp.unicast)],
      ['SNTP authentication', onOff(sntp.auth)]
    ]));

    if (!s._ktReconcile) body.appendChild(el('div', 'section-title', 'SNTP servers'));
    const servers = t.servers || [];
    if (servers.length) {
      mountInto(body, s, p, 'system:sntp', ['Server', 'Polled', 'Stratum', 'Status'], servers.map((x) => ({
        key: 'sntp:' + x.address,
        cells: [{ v: x.address }, { v: x.polled == null ? '' : (x.polled ? 'yes' : 'no') },
          { v: x.stratum == null ? '' : String(x.stratum) },
          { pill: SERVER_PILL[x.status] || true, v: x.status || 'unknown' }]
      })));
    } else if (!s._ktReconcile) body.appendChild(el('div', 'card-sub', 'No SNTP servers are set.'));

    // ---- Users ----
    if (!s._ktReconcile) body.appendChild(el('div', 'section-title', 'Local users'));
    if (users.length) {
      mountInto(body, s, p, 'system:users', ['User', 'Privilege', 'Failed logins', 'Status'], users.map((u) => ({
        key: 'user:' + u.name,
        cells: [{ v: u.name }, { v: u.privilege == null ? '' : String(u.privilege) + (u.privilege === 15 ? ' (admin)' : '') },
          { v: u.failedLogins == null ? '' : String(u.failedLogins) },
          { pill: u.locked ? 'bad' : 'good', v: u.locked ? 'locked' : 'usable' }]
      })));
    } else if (!s._ktReconcile) body.appendChild(el('div', 'card-sub', 'The switch did not list any local users.'));

    // ---- Management access ----
    if (!s._ktReconcile) body.appendChild(el('div', 'section-title', 'Management access'));
    const port = (on, n) => (on && n ? 'on, port ' + n : onOff(on));
    mountInto(body, s, p, 'system:access', ['Service', 'State'], settingRows('access', [
      ['SSH', port(a.ssh, a.sshPort), onOffPill(a.ssh)],
      ['Telnet', onOff(a.telnet), a.telnet ? 'warn' : true],
      ['HTTPS', port(a.https, a.httpsPort), onOffPill(a.https)],
      ['HTTP', port(a.http, a.httpPort), a.http ? 'warn' : true],
      ['Management access list', acl.enabled == null ? 'not reported' : (acl.enabled ? 'on' + (acl.active ? ', ' + acl.active : '') : 'off'), onOffPill(acl.enabled)]
    ]));
    if (!s._ktReconcile) {
      body.appendChild(el('div', 'card-sub', 'Telnet and HTTP send passwords unencrypted, so they show in yellow when they are on.'));
    }
  }
