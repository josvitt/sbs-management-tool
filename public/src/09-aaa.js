  // =================================================================
  // 09-aaa.js: 802.1X global settings and AAA (RADIUS/TACACS+) servers.
  // =================================================================

  // Global 802.1X settings for the Sessions & authentication panel: port-based
  // auth enable, guest VLAN id/timeout, and the notification (trap) toggles -
  // all scalar read-write objects. Shown always; editable controls write via
  // SNMP SET and the switch enforces access.
  const DOT1X_G = {
    sysAuth:   { oid: '1.0.8802.1.1.1.1.1.1', kind: 'enable' },        // enabled(1)/disabled(2)
    guestVid:  { oid: '1.3.6.1.4.1.9.6.1.101.95.4', kind: 'int' },     // 0 = none
    guestTime: { oid: '1.3.6.1.4.1.9.6.1.101.95.19', kind: 'int' },    // 0..180
    macSucc:   { oid: '1.3.6.1.4.1.9.6.1.101.95.20', kind: 'truth' },
    macFail:   { oid: '1.3.6.1.4.1.9.6.1.101.95.21', kind: 'truth' },
    suppSucc:  { oid: '1.3.6.1.4.1.9.6.1.101.95.29', kind: 'truth' },
    suppFail:  { oid: '1.3.6.1.4.1.9.6.1.101.95.30', kind: 'truth' },
    webQuiet:  { oid: '1.3.6.1.4.1.9.6.1.101.95.25', kind: 'truth' }
  };
  const D1XG_SCALAR = {
    sysAuth: 'dot1xPaeSystemAuthControl', guestVid: 'rldot1xGuestVlanVID', guestTime: 'rldot1xGuestVlanTimeInterval',
    macSucc: 'rldot1xMacAuthSuccessTrapEnabled', macFail: 'rldot1xMacAuthFailureTrapEnabled',
    suppSucc: 'rldot1xSupplicantSuccessTrapEnabled', suppFail: 'rldot1xSupplicantFailureTrapEnabled',
    webQuiet: 'rldot1xWebQuietFailureTrapEnabled'
  };

  function buildDot1xGlobal(s, body, h, section) {
    const sc = (name) => (h.scalars && h.scalars[name]);
    const dvS = (name) => { const c = sc(name); return c ? (c.display !== undefined && c.display !== '' ? c.display : c.value) : undefined; };
    // Only show if the switch reports at least the global control (i.e. it
    // supports 802.1X).
    if (dvS('dot1xPaeSystemAuthControl') === undefined && dvS('rldot1xGuestVlanVID') === undefined) return;
    section('802.1X global settings', '');

    const wrap = el('div', 'd1xg');
    // TruthValue is true(1)/false(2); enable objects use enabled(1)/disabled(2).
    // Decide by the leading numeric value (1 = on) when present, else by text -
    // the old /1/ substring test could misfire on any string containing a 1.
    const truthy = (v) => {
      const str = String(v == null ? '' : v).trim();
      const m = str.match(/\((\d+)\)\s*$/) || str.match(/^(\d+)$/);   // "true (1)" or "1"
      if (m) return parseInt(m[1], 10) === 1;
      return /^(true|enabled|on|yes)$/i.test(str);
    };
    const isOn = truthy(dvS('dot1xPaeSystemAuthControl'));

    const field = (grid, label, node, narrow) => { const f = el('div', 'd1xg-field' + (narrow ? ' narrow' : '')); f.appendChild(el('label', '', label)); f.appendChild(node); grid.appendChild(f); return node; };

    // Port-based auth enable — on its own line.
    const authGrid = el('div', 'd1xg-grid');
    const sysSel = el('select'); for (const o of [['on', 'Enabled'], ['off', 'Disabled']]) { const op = el('option', '', o[1]); op.value = o[0]; sysSel.appendChild(op); }
    sysSel.value = isOn ? 'on' : 'off';
    field(authGrid, 'Port-based authentication', sysSel);
    wrap.appendChild(authGrid);

    // Guest VLAN — its own row group, separated by spacing (no heading, to
    // avoid doubling with the field label below).
    const gvGrid = el('div', 'd1xg-grid'); gvGrid.style.marginTop = '12px';
    const curGuest = dvS('rldot1xGuestVlanVID') != null ? String(dvS('rldot1xGuestVlanVID')) : '0';
    const voiceVid = String(dvS('vlanVoiceOperVid') || '').replace(/[^\d]/g, '');
    const gvid = el('select');
    const noneOpt = el('option', '', 'None'); noneOpt.value = '0'; gvid.appendChild(noneOpt);
    const vlanList = ((s.health && s.health.vlans) || []).map((v) => Number(v.index)).filter((n) => Number.isFinite(n) && n > 1 && String(n) !== voiceVid).sort((a, b) => a - b);
    for (const v of vlanList) { const o = el('option', '', 'VLAN ' + v); o.value = String(v); gvid.appendChild(o); }
    // Keep the current value visible even if it's VLAN 1/voice (so state is honest).
    if (curGuest !== '0' && !vlanList.some((v) => String(v) === curGuest)) { const o = el('option', '', 'VLAN ' + curGuest + (curGuest === voiceVid ? ' (voice)' : (curGuest === '1' ? ' (default)' : ''))); o.value = curGuest; gvid.appendChild(o); }
    gvid.value = curGuest;
    field(gvGrid, 'Guest VLAN', gvid);
    const gtime = el('input'); gtime.type = 'number'; gtime.min = '0'; gtime.max = '180'; gtime.value = dvS('rldot1xGuestVlanTimeInterval') != null ? String(dvS('rldot1xGuestVlanTimeInterval')) : '';
    field(gvGrid, 'Guest VLAN timeout (s)', gtime, true);
    wrap.appendChild(gvGrid);

    // MAB (MAC Authentication Bypass) global settings: the format of the
    // username the switch builds from a client's MAC when doing MAC auth.
    wrap.appendChild(el('div', 'aaa-sub', 'MAC authentication (MAB)'));
    const mabGrid = el('div', 'd1xg-grid');
    // RADIUS attribute format: EAP (true) vs PAP/Call-Check (false).
    const eapSel = el('select'); for (const o of [['on', 'EAP'], ['off', 'PAP (Call-Check)']]) { const op = el('option', '', o[1]); op.value = o[0]; eapSel.appendChild(op); }
    eapSel.value = truthy(dvS('rldot1xMacAuthEapEnabled')) ? 'on' : 'off';
    field(mabGrid, 'RADIUS format', eapSel);
    // Username group size (how MAC octets are grouped): 1 / 2 / 4 / 12.
    const gsCur = String(dvS('rldot1xMacAuthUserGroupsize') || '').replace(/[^\d]/g, '') || '2';
    const gsSel = el('select'); for (const g of ['1', '2', '4', '12']) { const o = el('option', '', g); o.value = g; gsSel.appendChild(o); }
    gsSel.value = ['1', '2', '4', '12'].indexOf(gsCur) >= 0 ? gsCur : '2';
    field(mabGrid, 'Group size', gsSel, true);
    // Separator: hyphen(1) / colon(2) / dot(3).
    const sepMap = { '1': 'hyphen', '2': 'colon', '3': 'dot' };
    const sepCur = String(dvS('rldot1xMacAuthUserSeparator') || '').match(/\((\d)\)/);
    const sepVal = sepCur ? sepCur[1] : (/hyphen/i.test(String(dvS('rldot1xMacAuthUserSeparator'))) ? '1' : /colon/i.test(String(dvS('rldot1xMacAuthUserSeparator'))) ? '2' : /dot/i.test(String(dvS('rldot1xMacAuthUserSeparator'))) ? '3' : '1');
    const sepSel = el('select'); for (const [v, label] of [['1', 'hyphen (-)'], ['2', 'colon (:)'], ['3', 'dot (.)']]) { const o = el('option', '', label); o.value = v; sepSel.appendChild(o); }
    sepSel.value = sepVal;
    field(mabGrid, 'Separator', sepSel);
    // Lowercase MAC in username.
    const lcSel = el('select'); for (const o of [['on', 'Lowercase'], ['off', 'Uppercase']]) { const op = el('option', '', o[1]); op.value = o[0]; lcSel.appendChild(op); }
    lcSel.value = truthy(dvS('rldot1xMacAuthUserLowercase')) ? 'on' : 'off';
    field(mabGrid, 'MAC case', lcSel);
    wrap.appendChild(mabGrid);

    // Trap toggles.
    wrap.appendChild(el('div', 'aaa-sub', 'Trap settings'));
    const trapGrid = el('div', 'd1xg-traps');
    // The success/failure traps are controlled by a PER-METHOD enum (one scalar
    // for success, one for failure): the value encodes which auth methods send
    // a trap. Confirmed from the switch/MIB:
    //   0 none | 1 eapol(802.1x) | 2 mac+eapol | 3 mac | 4 web
    //   5 web+eapol | 6 web+mac | 7 web+mac+eapol
    // So the GUI's four 802.1x/MAC success/failure checkboxes are really two
    // enums. We present 802.1x, MAC and Web checkboxes for each of success and
    // failure, and encode/decode the enum from them.
    const ENUM_METHODS = { 0: [], 1: ['eapol'], 2: ['mac', 'eapol'], 3: ['mac'], 4: ['web'], 5: ['web', 'eapol'], 6: ['web', 'mac'], 7: ['web', 'mac', 'eapol'] };
    const methodsToEnum = (set) => {
      const has = (m) => set.has(m);
      for (const v of Object.keys(ENUM_METHODS)) {
        const ms = ENUM_METHODS[v];
        if (ms.length === set.size && ms.every((m) => has(m))) return Number(v);
      }
      return 0;
    };
    const enumOf = (name) => { const raw = dvS(name); const m = String(raw == null ? '' : raw).match(/\((\d+)\)/) || String(raw).match(/^(\d+)$/); return m ? parseInt(m[1], 10) : 0; };
    const succEnum = enumOf('rldot1xMacWebAuthSuccessTrapEnabled');
    const failEnum = enumOf('rldot1xMacWebAuthFailureTrapEnabled');
    const succSet = new Set(ENUM_METHODS[succEnum] || []);
    const failSet = new Set(ENUM_METHODS[failEnum] || []);

    // A compact matrix: columns are the auth methods (802.1X / MAC / Web),
    // rows are Success and Failure. Checkboxes line up under their column at any
    // width, which reads far better than a wrapping row of labels.
    const methodCbs = { succ: {}, fail: {} };
    const methods = [['eapol', '802.1X'], ['mac', 'MAC'], ['web', 'Web']];
    const matrix = el('table', 'd1xg-trap-matrix');
    const mhead = el('tr');
    mhead.appendChild(el('th', 'd1xg-trap-rowhead', ''));
    for (const [, label] of methods) mhead.appendChild(el('th', '', label));
    matrix.appendChild(mhead);
    for (const [which, rowLabel, set] of [['succ', 'Success', succSet], ['fail', 'Failure', failSet]]) {
      const tr = el('tr');
      tr.appendChild(el('td', 'd1xg-trap-rowhead', rowLabel));
      for (const [m] of methods) {
        const cell = el('td', 'd1xg-trap-cell');
        const cb = el('input'); cb.type = 'checkbox'; cb.checked = set.has(m);
        methodCbs[which][m] = cb;
        cell.appendChild(cb);
        tr.appendChild(cell);
      }
      matrix.appendChild(tr);
    }
    trapGrid.appendChild(matrix);

    // The remaining genuine TruthValue toggles (supplicant, web quiet) as a
    // clean checkbox list below the matrix.
    const trapDefs = [
      ['suppSucc', 'Supplicant auth success'], ['suppFail', 'Supplicant auth failure'],
      ['webQuiet', 'Web quiet failure']
    ];
    const trapCbs = {};
    const extraList = el('div', 'd1xg-trap-extra');
    for (const [key, label] of trapDefs) {
      const lab = el('label', 'check-label');
      const cb = el('input'); cb.type = 'checkbox'; cb.checked = truthy(dvS(D1XG_SCALAR[key]));
      trapCbs[key] = cb;
      lab.appendChild(cb); lab.appendChild(el('span', '', label));
      extraList.appendChild(lab);
    }
    trapGrid.appendChild(extraList);
    wrap.appendChild(trapGrid);

    // Apply.
    const { actions, apply, msg } = applyActions('Apply 802.1X settings');
    withConfirm(apply, (ev) => {
      clear(msg);
      const vbs = [];
      const curTruth = (key) => truthy(dvS(D1XG_SCALAR[key]));
      // sysAuth: enabled(1)/disabled(2)
      // Collect the controls the user actually changed, to highlight on success.
      const changedCtls = [];
      const newSys = sysSel.value === 'on' ? 1 : 2;
      if ((newSys === 1) !== isOn) { vbs.push({ oid: DOT1X_G.sysAuth.oid + '.0', type: 'Integer', value: newSys }); changedCtls.push(sysSel); }
      // guest vid / timeout
      // rldot1xGuestVlanVID is a VlanIndex - this firmware wants it as Gauge,
      // not Integer (Integer gave WrongType), matching the switchport VLAN writes.
      const nvid = parseInt(gvid.value, 10); if (Number.isFinite(nvid) && String(nvid) !== String(dvS('rldot1xGuestVlanVID'))) { vbs.push({ oid: DOT1X_G.guestVid.oid + '.0', type: 'Gauge', value: nvid }); changedCtls.push(gvid); }
      const ntime = parseInt(gtime.value, 10); if (Number.isFinite(ntime) && String(ntime) !== String(dvS('rldot1xGuestVlanTimeInterval'))) { vbs.push({ oid: DOT1X_G.guestTime.oid + '.0', type: 'Integer', value: ntime }); changedCtls.push(gtime); }
      // Success/failure method-trap enums (encode the checked methods).
      const newSucc = methodsToEnum(new Set(['eapol', 'mac', 'web'].filter((m) => methodCbs.succ[m].checked)));
      const newFail = methodsToEnum(new Set(['eapol', 'mac', 'web'].filter((m) => methodCbs.fail[m].checked)));
      if (newSucc !== succEnum) { vbs.push({ oid: '1.3.6.1.4.1.9.6.1.101.95.26.0', type: 'Integer', value: newSucc }); for (const m of ['eapol', 'mac', 'web']) changedCtls.push(methodCbs.succ[m]); }
      if (newFail !== failEnum) { vbs.push({ oid: '1.3.6.1.4.1.9.6.1.101.95.27.0', type: 'Integer', value: newFail }); for (const m of ['eapol', 'mac', 'web']) changedCtls.push(methodCbs.fail[m]); }
      // Remaining TruthValue toggles: true(1)/false(2)
      for (const [key] of trapDefs) {
        const want = trapCbs[key].checked;
        if (want !== curTruth(key)) { vbs.push({ oid: DOT1X_G[key].oid + '.0', type: 'Integer', value: want ? 1 : 2 }); changedCtls.push(trapCbs[key]); }
      }
      // MAB global settings.
      const numOf = (name) => { const m = String(dvS(name) || '').match(/\((\d+)\)/) || String(dvS(name)).match(/^(\d+)$/); return m ? parseInt(m[1], 10) : null; };
      if ((eapSel.value === 'on') !== truthy(dvS('rldot1xMacAuthEapEnabled'))) { vbs.push({ oid: '1.3.6.1.4.1.9.6.1.101.95.35.0', type: 'Integer', value: eapSel.value === 'on' ? 1 : 2 }); changedCtls.push(eapSel); }
      if (parseInt(gsSel.value, 10) !== numOf('rldot1xMacAuthUserGroupsize')) { vbs.push({ oid: '1.3.6.1.4.1.9.6.1.101.95.36.0', type: 'Integer', value: parseInt(gsSel.value, 10) }); changedCtls.push(gsSel); }
      if (parseInt(sepSel.value, 10) !== numOf('rldot1xMacAuthUserSeparator')) { vbs.push({ oid: '1.3.6.1.4.1.9.6.1.101.95.37.0', type: 'Integer', value: parseInt(sepSel.value, 10) }); changedCtls.push(sepSel); }
      if ((lcSel.value === 'on') !== truthy(dvS('rldot1xMacAuthUserLowercase'))) { vbs.push({ oid: '1.3.6.1.4.1.9.6.1.101.95.38.0', type: 'Integer', value: lcSel.value === 'on' ? 1 : 2 }); changedCtls.push(lcSel); }
      if (!vbs.length) { msg.appendChild(el('div', 'card-sub', 'No changes.')); return; }
      runButtonAction(ev.currentTarget, {
        failLabel: 'Apply 802.1X settings',
        run: () => snmpSetResult(s, vbs),
        ok: (res) => res && res.ok && !(res.body && res.body.error),
        error: (res) => { msg.appendChild(el('div', 'sw-err', 'Change failed: ' + ((res && res.body && res.body.error) || 'error'))); return (res && res.body && res.body.error) || 'error'; },
        onApplied: () => markConfigDirty(s, changedCtls),
        settle: () => {
          // These settings ARE scalars, so re-read just the scalar OIDs we wrote
          // and update h.scalars in place. The auth-panel repaint is scheduled
          // AFTER runButtonAction's Done flash finishes - repainting during the
          // flash recreates the panel and destroys the button mid-flash.
          const changedScalars = {};
          for (const key of Object.keys(DOT1X_G)) changedScalars[D1XG_SCALAR[key]] = DOT1X_G[key].oid;
          changedScalars['rldot1xMacWebAuthSuccessTrapEnabled'] = '1.3.6.1.4.1.9.6.1.101.95.26';
          changedScalars['rldot1xMacWebAuthFailureTrapEnabled'] = '1.3.6.1.4.1.9.6.1.101.95.27';
          changedScalars['rldot1xMacAuthEapEnabled'] = '1.3.6.1.4.1.9.6.1.101.95.35';
          changedScalars['rldot1xMacAuthUserGroupsize'] = '1.3.6.1.4.1.9.6.1.101.95.36';
          changedScalars['rldot1xMacAuthUserSeparator'] = '1.3.6.1.4.1.9.6.1.101.95.37';
          changedScalars['rldot1xMacAuthUserLowercase'] = '1.3.6.1.4.1.9.6.1.101.95.38';
          return refreshScalars(s, changedScalars).then(() => { setTimeout(() => repaintPanel(s, 'auth'), 1900); });
        }
      });
    // Switching port-based authentication on or off changes access on every
    // 802.1X port, so that one change asks for a second tap; the rest apply
    // on the first (B8).
    }, { when: () => (sysSel.value === 'on') !== isOn, confirmText: () => (sysSel.value === 'on' ? 'Enable 802.1X?' : 'Disable 802.1X?') });
    wrap.appendChild(actions); wrap.appendChild(msg);
    body.appendChild(wrap);
  }

  // ---- AAA servers (RADIUS + TACACS+) ----
  // Keyed tables (B2/B3) in the Sessions & authentication panel, reconciled in
  // place like the rest of it. A row opens the server in the standard pop-out:
  // its settings (an editor, or read-only without write access) and, for
  // RADIUS, its RFC 4668 counters. The shared key is write-only on the switch,
  // so only whether one is set is ever shown.
  const RADIUS_USAGE = { 1: 'login', 2: '802.1X', 3: 'all', 4: 'wireless' };
  const AAA_TABLES = ['radiusServers', 'radiusStats', 'tacacsServers'];
  function aaaDv(cell) {
    return (cell && (cell.display !== undefined && cell.display !== null && cell.display !== ''))
      ? cell.display : (cell && cell.value !== undefined ? cell.value : '');
  }
  // InetAddress columns arrive as raw bytes (hex). Decode to a readable IP.
  function aaaInetAddr(cell) {
    const raw = (cell && cell.value !== undefined && cell.value !== null && cell.value !== '') ? cell.value : aaaDv(cell);
    if (raw === '' || raw === null || raw === undefined) return '';
    const str = String(raw).replace(/\s*\(hex\)\s*$/i, '');
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(str) || str.indexOf(':') >= 0) return str;
    const hex = str.replace(/0x/gi, '').replace(/[^0-9a-fA-F]/g, '');
    if (hex.length === 8) return [0, 2, 4, 6].map((i) => parseInt(hex.substr(i, 2), 16)).join('.');
    if (hex.length === 32) return (hex.match(/.{4}/g) || []).join(':').replace(/\b0+(\w)/g, '$1');
    return str;
  }
  function aaaKeyStatus(useGlobalCell, keyCell) {
    if (/true|1|yes/i.test(String(aaaDv(useGlobalCell)))) return 'global default';
    const k = aaaDv(keyCell);
    const hex = String(k).replace(/[^0-9a-fA-F]/g, '');
    return (k !== '' && k !== null && k !== undefined && !/^0+$/.test(hex)) ? 'set' : 'none';
  }
  // The servers as the table, the pop-out and the writes read them.
  function aaaModel(h) {
    h = h || {};
    const stats = new Map();
    for (const r of (h.radiusStats || [])) { const a = aaaInetAddr(r.radiusAuthServerAddress); if (a) stats.set(String(a), r); }
    const radius = (h.radiusServers || []).map((r) => {
      const addr = aaaInetAddr(r.rlRadiusServerInetAddress);
      return { addr, authPort: aaaDv(r.rlRadiusServerInetAuthPortNumber), acctPort: aaaDv(r.rlRadiusServerInetAcctPortNumber),
        priority: aaaDv(r.rlRadiusServerInetPriority),
        usage: RADIUS_USAGE[Number(aaaDv(r.rlRadiusServerInetUsage))] || aaaDv(r.rlRadiusServerInetUsage),
        timeout: aaaDv(r.rlRadiusServerInetTimeout), retries: aaaDv(r.rlRadiusServerInetRetries),
        deadtime: aaaDv(r.rlRadiusServerInetDeadtime), source: aaaDv(r.rlRadiusServerInetSource),
        key: aaaKeyStatus(r.rlRadiusServerInetUseGlobalDefaultKey, r.rlRadiusServerInetKey),
        useGlobalKey: /true|1|yes/i.test(String(aaaDv(r.rlRadiusServerInetUseGlobalDefaultKey))),
        stats: stats.get(String(addr)) || null };
    });
    const tacacs = (h.tacacsServers || []).map((r) => {
      const statusRaw = String(aaaDv(r.rlTacacsServerInetConnectionStatus));
      return { addr: aaaInetAddr(r.rlTacacsServerInetAddress), port: aaaDv(r.rlTacacsServerInetPortNumber),
        status: statusRaw, connected: /connected\(0\)|^0$|^connected$/i.test(statusRaw) && !/not/i.test(statusRaw),
        type: aaaDv(r.rlTacacsServerInetConnectionType), priority: aaaDv(r.rlTacacsServerInetPriority),
        timeout: aaaDv(r.rlTacacsServerInetTimeout),
        key: aaaKeyStatus(r.rlTacacsServerInetUseGlobalDefaultKey, r.rlTacacsServerInetKey),
        useGlobalKey: /true|1|yes/i.test(String(aaaDv(r.rlTacacsServerInetUseGlobalDefaultKey))) };
    });
    return { radius, tacacs };
  }
  // Whether this credential may change the switch's config (a full SNMP Admin).
  // Learned from the SNMP configuration panel when it has loaded; otherwise
  // asked once here, and the panel repainted when the answer arrives.
  function aaaEditable(s) {
    const known = (s._snmp && s._snmp.editable) || s._aaaEditable;
    if (known === undefined && !s._aaaAccessPending && s.target) {
      s._aaaAccessPending = true;
      snmpCfgPost(s, 'access').then((access) => {
        s._aaaEditable = !!(access && access.ok && access.level === 'full');
        s._aaaAccessPending = false;
        repaintPanel(s, 'auth');
      }).catch(() => { s._aaaAccessPending = false; });
    }
    return !!known;
  }
  // The session negotiates privacy, so a shared key typed here is encrypted.
  function aaaIsV3Priv(s) {
    const t = s.target || {};
    return String(t.version) === '3' && !!t.v3 && String(t.v3.level) === 'authPriv';
  }
  function aaaRefresh(s) { return refreshTables(s, AAA_TABLES); }
  // One add/edit/delete. A 409 carries the server's warning that the shared key
  // would cross the network in cleartext; the caller asks before resending.
  async function aaaWrite(s, url, payload) {
    s.writeBusy = true;
    try {
      const { status, body } = await apiPost(url, Object.assign({ target: s.target }, payload));
      if (status === 409 && body && body.warning) return { ok: false, warning: body.warning, error: body.warning };
      if (body && body.ok) return { ok: true };
      return { ok: false, error: (body && body.error) || 'the switch rejected it' };
    } catch (e) {
      return { ok: false, error: 'lost contact with the local server: ' + e.message };
    } finally { s.writeBusy = false; }
  }

  function buildAaaServers(s, body, h, section, p) {
    const editable = aaaEditable(s);
    const model = aaaModel(h);
    const sc = (k) => (h.scalars && h.scalars[k]);
    const isOn = (k) => sc(k) && /true|enable|1|yes/i.test(String(sc(k).display || sc(k).value));
    if (!s._ktReconcile) p._aaaNotes = {};
    // A section with its count note kept in a stable node, so a reconcile
    // refreshes it in place (B2).
    const head = (name, title, note, addLabel, onAdd) => {
      if (!s._ktReconcile) {
        section(title, ' ');
        const st = body.lastChild;
        const n = st && st.querySelector && st.querySelector('.st-note');
        if (n) p._aaaNotes[name] = n;
        if (addLabel && editable) body.appendChild(addControl(addLabel, onAdd));
      }
      const n = p._aaaNotes && p._aaaNotes[name];
      if (n) n.textContent = note;
    };
    const delCell = (kind, url, payload, addr) => ({ cellNode: actGroup([actBtnConfirm('Delete', (e) => {
      runButtonAction(e.currentTarget, {
        failLabel: 'Delete ' + (kind === 'radius' ? 'RADIUS' : 'TACACS+') + ' server',
        run: () => aaaWrite(s, url, payload),
        ok: (r) => r && r.ok,
        error: (r) => (r && r.error) || 'the switch rejected it',
        onApplied: () => markConfigDirty(s),
        settle: () => aaaRefresh(s)
      });
    }, 'danger', 'Delete server ' + addr)]), sig: 'del' });

    // Shown when there are servers, or when the operator can add one.
    if (model.radius.length || editable) {
      head('radius', 'RADIUS servers', model.radius.length + (isOn('rlAAARadiusEnabled') ? ' \u00b7 enabled' : ' \u00b7 disabled'),
        'Add RADIUS server', () => openAaaServer(s, 'radius', null));
      if (model.radius.length) mountInto(body, s, p, 'radius',
        ['Address', 'Auth port', 'Acct port', 'Priority', 'Usage', 'Timeout', 'Retries', 'Key'].concat(editable ? [''] : []),
        model.radius.map((r) => ({ key: 'radius:' + r.addr, cells: [
          { v: r.addr, click: { open: () => openAaaServer(s, 'radius', r.addr) } },
          { v: r.authPort }, { v: r.acctPort }, { v: r.priority }, { v: r.usage }, { v: r.timeout }, { v: r.retries }, { v: r.key }]
          .concat(editable ? [delCell('radius', '/api/aaa/radius/delete', { address: r.addr, authPort: r.authPort, acctPort: r.acctPort }, r.addr)] : []) })));
      else if (!s._ktReconcile) body.appendChild(el('div', 'card-sub', 'No RADIUS servers configured.'));
    }
    if (model.tacacs.length || editable) {
      head('tacacs', 'TACACS+ servers', model.tacacs.length + (isOn('rlAAATacacsEnabled') ? ' \u00b7 enabled' : ' \u00b7 disabled'),
        'Add TACACS+ server', () => openAaaServer(s, 'tacacs', null));
      if (model.tacacs.length) mountInto(body, s, p, 'tacacs',
        ['Address', 'Port', 'State', 'Priority', 'Timeout', 'Key'].concat(editable ? [''] : []),
        model.tacacs.map((r) => ({ key: 'tacacs:' + r.addr, cells: [
          { v: r.addr, click: { open: () => openAaaServer(s, 'tacacs', r.addr) } },
          { v: r.port }, { pill: true, v: r.connected ? 'connected' : 'not connected' },
          { v: r.priority }, { v: r.timeout }, { v: r.key }]
          .concat(editable ? [delCell('tacacs', '/api/aaa/tacacs/delete', { address: r.addr }, r.addr)] : []) })));
      else if (!s._ktReconcile) body.appendChild(el('div', 'card-sub', 'No TACACS+ servers configured.'));
    }
  }

  // Open a server (addr) or the add form (addr null) in the standard pop-out,
  // read from the current tables so it always shows what the switch holds now.
  function openAaaServer(s, kind, addr) {
    const model = aaaModel(s.health);
    const list = kind === 'radius' ? model.radius : model.tacacs;
    const cur = addr ? list.find((x) => x.addr === addr) : null;
    if (addr && !cur) return;
    const label = kind === 'radius' ? 'RADIUS' : 'TACACS+';
    const title = cur ? label + ' \u00b7 ' + cur.addr : 'Add ' + label + ' server';
    const tabs = [];
    if (aaaEditable(s)) tabs.push({ label: 'Server', fill: (pane, close) => aaaServerForm(s, kind, cur, pane, close) });
    else {
      tabs.push({ label: 'Server', fill: (pane) => {
        const dl = el('dl', 'port-detail-grid');
        const pairs = kind === 'radius'
          ? [['Address', cur.addr], ['Auth port', cur.authPort], ['Acct port', cur.acctPort], ['Priority', cur.priority],
            ['Usage', cur.usage], ['Timeout (s)', cur.timeout], ['Retries', cur.retries], ['Deadtime (min)', cur.deadtime],
            ['Source', cur.source], ['Shared key', cur.key]]
          : [['Address', cur.addr], ['Port', cur.port], ['Connection', cur.status], ['Type', cur.type],
            ['Priority', cur.priority], ['Timeout (s)', cur.timeout], ['Shared key', cur.key]];
        for (const [k, v] of pairs) { if (v === undefined || v === null || v === '') continue; dl.appendChild(el('dt', '', k)); dl.appendChild(el('dd', '', String(v))); }
        pane.appendChild(dl);
      } });
    }
    if (cur && cur.stats) {
      tabs.push({ label: 'Counters', fill: (pane) => {
        const dl = el('dl', 'port-detail-grid');
        for (const [k, v] of Object.entries(cur.stats)) {
          if (k === 'index') continue;
          const val = (v && typeof v === 'object') ? (v.display !== undefined ? v.display : v.value) : v;
          if (val === undefined || val === null || val === '') continue;
          dl.appendChild(el('dt', '', k.replace(/^radiusAuthClient/, '').replace(/^radiusAuthServer/, 'Server ').replace(/([A-Z])/g, ' $1').trim()));
          dl.appendChild(el('dd', '', String(val)));
        }
        pane.appendChild(dl);
      } });
    }
    openTabbedPopout(s, title, tabs, []);
  }

  // The add/edit form (A5/B6/B8): one tap to save, except that a shared key
  // which would travel in cleartext asks for a second tap first.
  function aaaServerForm(s, kind, cur, pane, close) {
    const form = el('div', 'snmp-form acl-form');
    const v3Priv = aaaIsV3Priv(s);
    // A number input rejects a value it can't parse ("1,812"), so keep only
    // the numeric part of what the switch displays.
    const num = (v, ph) => {
      const i = el('input'); i.type = 'number'; if (ph) i.placeholder = ph;
      const m = v != null && v !== '' ? String(v).replace(/,/g, '').match(/-?\d+(\.\d+)?/) : null;
      if (m) i.value = m[0];
      return i;
    };
    const sec = formSection('Server');
    const addr = textInput(cur ? cur.addr : '', 'e.g. 192.168.1.3');
    if (cur) addr.disabled = true;   // the address is the row's identity
    sec.body.appendChild(field('Server IP', addr));
    let authPort, acctPort, port, usageSel;
    if (kind === 'radius') {
      authPort = num(cur ? cur.authPort : 1812); sec.body.appendChild(field('Auth port', authPort));
      acctPort = num(cur ? cur.acctPort : 1813); sec.body.appendChild(field('Acct port', acctPort));
      const want = String((cur && cur.usage) || 'all').toLowerCase();
      usageSel = selectInput(['all', 'login', '802.1X', 'wireless'].map((u) => ({ label: u, value: u })), '');
      for (const o of usageSel.options) if (o.value.toLowerCase() === want) usageSel.value = o.value;
      sec.body.appendChild(field('Usage', usageSel));
    } else {
      port = num(cur ? cur.port : 49); sec.body.appendChild(field('Port', port));
    }
    const prio = num(cur ? cur.priority : 0); sec.body.appendChild(field('Priority', prio));
    const timeout = num(cur ? cur.timeout : '', 'optional'); sec.body.appendChild(field('Timeout (s)', timeout));
    form.appendChild(sec.sec);

    const keySec = formSection('Shared key');
    if (!v3Priv) keySec.body.appendChild(el('div', 'sw-warn', 'This session is not SNMPv3 with privacy, so a shared key entered here is sent in cleartext.'));
    const gk = el('input'); gk.type = 'checkbox'; gk.checked = !!(cur && cur.useGlobalKey);
    const gkWrap = el('label', 'snmp-field-check'); gkWrap.appendChild(gk); gkWrap.appendChild(el('span', '', 'Use global default key'));
    keySec.body.appendChild(gkWrap);
    const key = el('input'); key.type = 'password'; key.placeholder = cur ? '(unchanged)' : 'shared secret';
    const keyRow = el('div', 'key-row');
    const show = el('button', 'btn btn-small', 'Show'); show.type = 'button';
    show.addEventListener('click', () => { const shown = key.type === 'text'; key.type = shown ? 'password' : 'text'; show.textContent = shown ? 'Show' : 'Hide'; });
    keyRow.appendChild(key); keyRow.appendChild(show);
    const keyField = field('Key', keyRow);
    keySec.body.appendChild(keyField);
    const syncKey = () => { keyField.style.display = gk.checked ? 'none' : ''; };
    gk.addEventListener('change', syncKey); syncKey();
    form.appendChild(keySec.sec);

    const keyTyped = () => !gk.checked && !!key.value;
    let warned = false;   // the server said the key would go in cleartext
    const { actions, apply, msg } = applyActions(cur ? 'Save' : 'Add server');
    withConfirm(apply, (ev) => {
      clear(msg);
      const a = (addr.value || '').trim();
      if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(a)) { msg.appendChild(el('div', 'sw-err', 'Enter a valid IPv4 address.')); return; }
      const payload = { address: a, edit: !!cur, priority: parseInt(prio.value, 10),
        timeout: timeout.value === '' ? undefined : parseInt(timeout.value, 10),
        useGlobalKey: gk.checked, key: gk.checked ? undefined : (key.value || undefined),
        confirm: warned || (keyTyped() && !v3Priv) };
      if (kind === 'radius') Object.assign(payload, { authPort: parseInt(authPort.value, 10) || 1812, acctPort: parseInt(acctPort.value, 10) || 1813, usage: usageSel.value });
      else payload.port = parseInt(port.value, 10) || 49;
      const label = (cur ? 'Save ' : 'Add ') + (kind === 'radius' ? 'RADIUS' : 'TACACS+') + ' server';
      runButtonAction(ev.currentTarget, {
        failLabel: label, spinLabel: cur ? 'Saving\u2026' : 'Adding\u2026',
        run: () => aaaWrite(s, '/api/aaa/' + kind, payload),
        ok: (r) => r && r.ok,
        error: (r) => {
          if (r && r.warning) { warned = true; msg.appendChild(el('div', 'sw-warn', r.warning + ' Tap ' + apply.dataset.restLabel + ' again to send it anyway.')); return 'the key would be sent in cleartext'; }
          const e = (r && r.error) || 'the switch rejected it';
          msg.appendChild(el('div', 'sw-err', label + ' failed: ' + e));
          return e;
        },
        onApplied: () => markConfigDirty(s),
        settle: () => aaaRefresh(s).then(() => close())
      });
    }, { when: () => keyTyped() && !v3Priv && !warned, confirmText: 'Send key in cleartext?' });
    apply.dataset.restLabel = cur ? 'Save' : 'Add server';
    form.appendChild(actions); form.appendChild(msg);
    pane.appendChild(form);
    if (!cur) addr.focus();
  }
