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
  const SERVER_PILL = { up: 'good', down: 'crit', inProcess: 'warn' };

  const onOff = (v) => (v == null ? 'not reported' : (v ? 'on' : 'off'));
  const onOffPill = (v) => (v == null ? true : (v ? 'good' : true));

  function utcOffsetWords(t) {
    if (!t.zoneOffset) return 'not reported';
    return 'UTC' + (/^[+-]/.test(t.zoneOffset) ? '' : '+') + t.zoneOffset + (t.zoneCode ? ' (' + t.zoneCode + ')' : '');
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

  // One write: post, refresh the panel when it lands, toast a failure.
  function systemWrite(btn, s, url, payload, failLabel, onApplied) {
    return runButtonAction(btn, {
      failLabel,
      run: async () => {
        s.writeBusy = true;
        try { return await sidePost(url, Object.assign({ target: s.target }, payload)); }
        finally { s.writeBusy = false; }
      },
      ok: (r) => r && r.ok,
      error: (r) => (r && r.error) || 'unknown error',
      onApplied,
      settle: () => systemLoad(s)
    });
  }

  // The switch's local time now, from this computer's clock and the
  // switch's total UTC offset, as "YYYY-MM-DD hh:mm:ss".
  function switchLocalNow(offsetSec) {
    const d = new Date(Date.now() + (Number(offsetSec) || 0) * 1000);
    const p2 = (n) => String(n).padStart(2, '0');
    return d.getUTCFullYear() + '-' + p2(d.getUTCMonth() + 1) + '-' + p2(d.getUTCDate()) + ' ' +
      p2(d.getUTCHours()) + ':' + p2(d.getUTCMinutes()) + ':' + p2(d.getUTCSeconds());
  }

  // A length of time in words: "90 seconds", "5 minutes", "3 hours", "2 days".
  function durWords(secs) {
    if (secs == null) return '';
    if (secs < 120) return secs + ' seconds';
    if (secs < 7200) return Math.round(secs / 60) + ' minutes';
    if (secs < 172800) return Math.round(secs / 3600) + ' hours';
    return Math.round(secs / 86400) + ' days';
  }
  function agoWords(secs) {
    return secs == null ? '' : durWords(secs) + ' ago';
  }

  const PRIVILEGES = [
    { label: '15: admin', value: '15' },
    { label: '7: limited', value: '7' },
    { label: '1: read-only', value: '1' }
  ];

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
      ['Clock source', CLOCK_WORDS[t.clock] || 'not reported', t.clock === 'invalid' ? 'crit' : (t.clock === 'synchronizedBySntp' ? 'good' : true)],
      ['Time zone', utcOffsetWords(t)],
      ['Summer time', dstWords(t.dst)],
      ['SNTP', sntp.unicast == null ? 'not reported' : (sntp.unicast ? 'on' : 'off'), onOffPill(sntp.unicast)],
      ['Last SNTP sync', sntp.sinceSyncSec == null ? 'not reported' : agoWords(sntp.sinceSyncSec), sntp.sinceSyncSec > 86400 ? 'warn' : undefined],
      ['SNTP authentication', onOff(sntp.auth)]
    ]));

    if (!s._ktReconcile) {
      const row = el('div', 'maint-row');
      const off = textInput(t.zoneOffset ? ((/^[+-]/.test(t.zoneOffset) ? '' : '+') + t.zoneOffset) : '', '-07:00');
      off.size = 7;
      const code = textInput(t.zoneCode || '', 'MST'); code.size = 5;
      const apply = el('button', 'btn', 'Set time zone'); apply.type = 'button';
      apply.addEventListener('click', (e) => systemWrite(e.currentTarget, s, '/api/system/timezone',
        { offset: off.value.trim(), code: code.value.trim() }, 'Set time zone'));
      p._sysOff = off; p._sysCode = code; p._sysZoneSeen = (t.zoneOffset || '') + '|' + (t.zoneCode || '');
      row.appendChild(field('UTC offset', off));
      row.appendChild(field('Name', code));
      row.appendChild(apply);
      const clockBtn = el('button', 'btn btn-blue', 'Set clock from this computer'); clockBtn.type = 'button';
      clockBtn.title = 'Sets the switch clock to this computer\'s time, in the switch\'s time zone';
      clockBtn.addEventListener('click', (e) => systemWrite(e.currentTarget, s, '/api/system/clock',
        { local: switchLocalNow((s._system.data.time || {}).totalOffsetSec) }, 'Set clock'));
      row.appendChild(clockBtn);
      p._sysSntpBtn = el('button', 'btn btn-blue', ''); p._sysSntpBtn.type = 'button';
      p._sysSntpBtn.addEventListener('click', (e) => {
        const on = !(((s._system.data || {}).time || {}).sntp || {}).unicast;
        systemWrite(e.currentTarget, s, '/api/system/sntp', { on }, on ? 'Turn SNTP on' : 'Turn SNTP off');
      });
      row.appendChild(p._sysSntpBtn);
      body.appendChild(row);
    }
    p._sysSntpBtn.textContent = sntp.unicast ? 'Turn SNTP off' : 'Turn SNTP on';
    // Follow the switch's time zone into the inputs when it changes, unless
    // the user is typing in them.
    const zoneNow = (t.zoneOffset || '') + '|' + (t.zoneCode || '');
    if (zoneNow !== p._sysZoneSeen && document.activeElement !== p._sysOff && document.activeElement !== p._sysCode) {
      p._sysZoneSeen = zoneNow;
      p._sysOff.value = t.zoneOffset ? ((/^[+-]/.test(t.zoneOffset) ? '' : '+') + t.zoneOffset) : '';
      p._sysCode.value = t.zoneCode || '';
    }

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
    if (!s._ktReconcile) {
      body.appendChild(el('div', 'card-sub', 'The switch does not accept new SNTP servers over SNMP, so the list is read-only here. ' +
        'Change it on the switch\'s web page under Administration > Time Settings > SNTP Unicast.'));
    }

    // ---- Users ----
    if (!s._ktReconcile) body.appendChild(el('div', 'section-title', 'Local users'));
    if (users.length) {
      const admins = users.filter((u) => u.privilege === 15).length;
      mountInto(body, s, p, 'system:users', ['User', 'Privilege', 'Failed logins', 'Status', ''], users.map((u) => {
        const last = u.privilege === 15 && admins === 1;
        return {
          key: 'user:' + u.name,
          cells: [{ v: u.name }, { v: u.privilege == null ? '' : String(u.privilege) + (u.privilege === 15 ? ' (admin)' : '') },
            { v: u.failedLogins == null ? '' : String(u.failedLogins) },
            { pill: u.locked ? 'crit' : 'good', v: u.locked ? 'locked' : 'usable' },
            { cellNode: actGroup([last ? null : actBtnConfirm('Delete', (e) => systemWrite(e.currentTarget, s,
              '/api/system/user/delete', { name: u.name }, 'Delete user'), 'danger', 'Delete this account')]), sig: last ? 'last' : 'del' }]
        };
      }));
    } else if (!s._ktReconcile) body.appendChild(el('div', 'card-sub', 'The switch did not list any local users.'));
    if (!s._ktReconcile) {
      const row = el('div', 'maint-row');
      p._sysUser = selectInput([], '');
      const priv = selectInput(PRIVILEGES, '15');
      const setPriv = el('button', 'btn', 'Change privilege'); setPriv.type = 'button';
      setPriv.addEventListener('click', (e) => systemWrite(e.currentTarget, s, '/api/system/user/privilege',
        { name: p._sysUser.value, privilege: Number(priv.value) }, 'Change privilege'));
      row.appendChild(field('User', p._sysUser));
      row.appendChild(field('Privilege', priv));
      row.appendChild(setPriv);
      body.appendChild(row);
      body.appendChild(el('div', 'card-sub', 'The switch does not accept new users or passwords over SNMP. ' +
        'Add a user or change a password on the switch\'s web page under Administration > User Accounts.'));
    }
    // Keep the user picker in step with the list, keeping the choice.
    const names = users.map((u) => u.name);
    if (p._sysUserNames !== names.join('\n')) {
      p._sysUserNames = names.join('\n');
      const keep = p._sysUser.value;
      clear(p._sysUser);
      for (const n of names) { const o = el('option', '', n); o.value = n; p._sysUser.appendChild(o); }
      if (names.includes(keep)) p._sysUser.value = keep;
    }

    // ---- Management access ----
    if (!s._ktReconcile) body.appendChild(el('div', 'section-title', 'Management access'));
    const port = (on, n) => (on && n ? 'on, port ' + n : onOff(on));
    const svcOn = { ssh: a.ssh, telnet: a.telnet, https: a.https, http: a.http };
    const onCount = Object.values(svcOn).filter(Boolean).length;
    const toggle = (svc, label) => {
      const on = svcOn[svc];
      if (on == null) return { v: '' };
      if (on && onCount === 1) return { v: 'the only one on', sig: 'only' };
      const b = on
        ? actBtnConfirm('Turn off', (e) => systemWrite(e.currentTarget, s, '/api/system/service', { service: svc, on: false }, 'Turn off ' + label), 'danger')
        : actBtn('Turn on', (e) => systemWrite(e.currentTarget, s, '/api/system/service', { service: svc, on: true }, 'Turn on ' + label));
      return { cellNode: actGroup([b]), sig: on ? 'off' : 'on' };
    };
    const svcRow = (svc, label, value, pill) => ({ key: 'access:' + svc, cells: [{ v: label }, { pill, v: value }, toggle(svc, label)] });
    mountInto(body, s, p, 'system:access', ['Service', 'State', ''], [
      svcRow('ssh', 'SSH', port(a.ssh, a.sshPort), onOffPill(a.ssh)),
      svcRow('telnet', 'Telnet', onOff(a.telnet), a.telnet ? 'warn' : true),
      svcRow('https', 'HTTPS', port(a.https, a.httpsPort), onOffPill(a.https)),
      svcRow('http', 'HTTP', port(a.http, a.httpPort), a.http ? 'warn' : true),
      { key: 'access:acl', cells: [{ v: 'Management access list' },
        { pill: onOffPill(acl.enabled), v: acl.enabled == null ? 'not reported' : (acl.enabled ? 'on' + (acl.active ? ', ' + acl.active : '') : 'off') }, { v: '' }] }
    ]);
    if (!s._ktReconcile) {
      body.appendChild(el('div', 'card-sub', 'Telnet and HTTP send passwords unencrypted, so they show in yellow when they are on. ' +
        'The app itself uses SNMP, so turning these off does not disconnect it.'));
    }
  }
