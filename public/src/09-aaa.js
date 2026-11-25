  // =================================================================
  // 09-aaa.js: 802.1X global settings and AAA (RADIUS/TACACS+) servers.
  // =================================================================

  // AAA server inventory (RADIUS + TACACS+) for the Authentication panel. Each
  // server is one summary row with an expander revealing the deep detail:
  // timeouts/retries/deadtime, shared-key status, and (RADIUS) the full RFC
  // 4668 statistics. The shared key itself is write-only on the switch, so we
  // show whether a key is set, not its value.
  // AAA server inventory (RADIUS + TACACS+) for the Authentication panel,
  // rendered as standard tables with column headers. Each server row is
  // clickable to open a detail popout with the deep data (timeouts, deadtime,
  // shared-key status, and the full RADIUS statistics). The shared key is
  // write-only on the switch, so only whether one is set is ever shown.
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
    });
    wrap.appendChild(actions); wrap.appendChild(msg);
    body.appendChild(wrap);
  }

  function buildAaaServers(s, body, h, section, p) {
    const dv2 = (cell) => (cell && (cell.display !== undefined && cell.display !== null && cell.display !== '')
      ? cell.display : (cell && cell.value !== undefined ? cell.value : ''));
    const RADIUS_USAGE = { 1: 'login', 2: '802.1X', 3: 'all', 4: 'wireless' };

    // InetAddress columns arrive as raw bytes (hex). Decode to a readable IP.
    const inetAddr = (cell) => {
      let raw = (cell && cell.value !== undefined && cell.value !== null && cell.value !== '')
        ? cell.value : dv2(cell);
      if (raw === '' || raw === null || raw === undefined) return '';
      let str = String(raw).replace(/\s*\(hex\)\s*$/i, '');
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(str) || str.indexOf(':') >= 0) return str;
      const hex = str.replace(/0x/gi, '').replace(/[^0-9a-fA-F]/g, '');
      if (hex.length === 8) return [0, 2, 4, 6].map((i) => parseInt(hex.substr(i, 2), 16)).join('.');
      if (hex.length === 32) return (hex.match(/.{4}/g) || []).join(':').replace(/\b0+(\w)/g, '$1');
      return str;
    };
    const keyStatus = (useGlobalCell, keyCell) => {
      if (/true|1|yes/i.test(String(dv2(useGlobalCell)))) return 'global default';
      const k = dv2(keyCell);
      const hex = String(k).replace(/[^0-9a-fA-F]/g, '');
      return (k !== '' && k !== null && k !== undefined && !/^0+$/.test(hex)) ? 'set' : 'none';
    };

    const statsByAddr = new Map();
    for (const r of (h.radiusStats || [])) {
      const addr = inetAddr(r.radiusAuthServerAddress);
      if (addr) statsByAddr.set(String(addr), r);
    }

    const radius = h.radiusServers || [];
    const tacacs = h.tacacsServers || [];
    // Show the section when there are servers, or when the operator can add one.
    const editableEarly = (s._snmp && s._snmp.editable) || s._aaaEditable;
    if (!radius.length && !tacacs.length && !editableEarly) return;

    const sc = (k) => (h.scalars && h.scalars[k]);
    const isOn = (k) => sc(k) && /true|enable|1|yes/i.test(String(sc(k).display || sc(k).value));

    // A detail popout, reusing the generic key/value dialog look.
    const openDetail = (title, pairs, statsRow) => {
      const prev = document.querySelector('.port-detail-back');
      if (prev) prev.remove();
      const back = el('div', 'port-detail-back');
      const pop = el('div', 'port-detail');
      const close = () => back.remove();
      back.addEventListener('click', (e) => { if (e.target === back) close(); });
      const head = el('div', 'port-detail-head');
      head.appendChild(el('h3', '', title));
      const x = el('button', 'port-detail-x', '\u00d7'); x.type = 'button';
      x.addEventListener('click', close); head.appendChild(x);
      pop.appendChild(head);
      const grid = (ps) => {
        const dl = el('dl', 'port-detail-grid');
        for (const [k, v] of ps) {
          if (v === undefined || v === null || v === '') continue;
          dl.appendChild(el('dt', '', k)); dl.appendChild(el('dd', '', String(v)));
        }
        return dl;
      };
      pop.appendChild(grid(pairs));
      if (statsRow) {
        pop.appendChild(el('div', 'port-detail-sub', 'RADIUS statistics'));
        pop.appendChild(grid([
          ['Round-trip (ms)', dv2(statsRow.radiusAuthClientRoundTripTime)],
          ['Access-Requests', dv2(statsRow.radiusAuthClientAccessRequests)],
          ['Accepts', dv2(statsRow.radiusAuthClientAccessAccepts)],
          ['Rejects', dv2(statsRow.radiusAuthClientAccessRejects)],
          ['Challenges', dv2(statsRow.radiusAuthClientAccessChallenges)],
          ['Retransmissions', dv2(statsRow.radiusAuthClientAccessRetransmissions)],
          ['Timeouts', dv2(statsRow.radiusAuthClientTimeouts)],
          ['Pending', dv2(statsRow.radiusAuthClientPendingRequests)],
          ['Bad authenticators', dv2(statsRow.radiusAuthClientBadAuthenticators)],
          ['Malformed responses', dv2(statsRow.radiusAuthClientMalformedAccessResponses)],
          ['Unknown types', dv2(statsRow.radiusAuthClientUnknownTypes)],
          ['Packets dropped', dv2(statsRow.radiusAuthClientPacketsDropped)]
        ]));
      }
      back.appendChild(pop);
      document.body.appendChild(back);
    };

    // --- write support: add / edit / delete ---
    // Write access is "full DefaultSuper" credential. The SNMP config panel
    // learns this when it loads; if it hasn't, fetch it here (once, cached) and
    // repaint when it arrives, so the add/edit/delete controls appear without
    // needing to visit the SNMP panel first.
    let editable = (s._snmp && s._snmp.editable) || s._aaaEditable;
    if (editable === undefined && !s._aaaAccessPending) {
      s._aaaAccessPending = true;
      snmpCfgPost(s, 'access').then((access) => {
        s._aaaEditable = !!(access && access.ok && access.level === 'full');
        s._aaaAccessPending = false;
        const p = s.panels.find((x) => x.key === 'auth');
        if (p && p._body) paintPanelBody(s, p);
      }).catch(() => { s._aaaAccessPending = false; });
    }
    editable = editable || false;
    // Pre-emptive cleartext-key note: is this session SNMPv3 authPriv?
    const t = s.target || {};
    const isV3Priv = String(t.version) === '3' && t.v3 && String(t.v3.level) === 'authPriv';

    // A field row helper for the add/edit forms.
    const inp = (type, val, ph) => { const i = el('input'); i.type = type; if (val != null) i.value = val; if (ph) i.placeholder = ph; return i; };

    // In-app confirm: renders a message with Confirm / Cancel buttons into a
    // host element and resolves true/false. No browser dialog.
    const inAppConfirm = (host, message, confirmLabel) => new Promise((resolve) => {
      for (const old of Array.from(host.querySelectorAll('.inapp-confirm'))) old.remove();
      const box = el('div', 'inapp-confirm');
      box.appendChild(el('div', 'sw-warn', message));
      const row = el('div', 'snmp-form-actions');
      const yes = el('button', 'btn btn-small btn-danger', confirmLabel || 'Confirm'); yes.type = 'button';
      const no = el('button', 'btn btn-small', 'Cancel'); no.type = 'button';
      yes.addEventListener('click', () => { box.remove(); resolve(true); });
      no.addEventListener('click', () => { box.remove(); resolve(false); });
      row.appendChild(yes); row.appendChild(no); box.appendChild(row);
      host.appendChild(box);
    });

    // Submit an add/edit. If the server replies that the key would be sent in
    // cleartext (409 + warning), show an in-app confirm rather than a browser
    // prompt, then resend with confirm=true.
    const submit = (url, payload, host, onOk) => {
      const go = (confirmed) => fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(Object.assign({ target: s.target, confirm: confirmed }, payload)) })
        .then((r) => r.json().then((b) => ({ status: r.status, b })))
        .then(({ status, b }) => {
          if (status === 409 && b.warning && !confirmed) {
            return inAppConfirm(host, b.warning + ' Send the key anyway?', 'Send anyway')
              .then((ok) => { if (ok) return go(true); });
          }
          if (b && b.ok) { onOk(); markConfigDirty(s); refreshPanel(s, s.panels.find((p) => p.key === 'auth')); }
          else { clearErr(host); host.appendChild(el('div', 'sw-err', (b && b.error) || 'Failed.')); }
        })
        .catch((e) => { clearErr(host); host.appendChild(el('div', 'sw-err', e.message)); });
      s.writeBusy = true;
      Promise.resolve(go(false)).finally(() => { s.writeBusy = false; });
    };

    // Delete with an in-app confirm rendered next to the row's action cell.
    // The Delete button confirms itself (two-tap), so this deletes directly and
    // refreshes just the auth panel.
    const delDirect = (url, payload) => {
      s.writeBusy = true;
      fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(Object.assign({ target: s.target }, payload)) })
        .then((r) => r.json()).then((b) => {
          s.writeBusy = false;
          if (b && b.ok) { markConfigDirty(s); refreshPanel(s, s.panels.find((p) => p.key === 'auth')); }
          else { appLog('error', 'Delete failed', { message: (b && b.error) || 'unknown' }); toast('Delete failed: ' + ((b && b.error) || 'the switch rejected it'), 'error'); }
        }).catch((e) => { s.writeBusy = false; appLog('error', 'Delete error', { message: e.message }); toast('Delete failed: ' + e.message, 'error'); });
    };

    // Build an add/edit form for RADIUS or TACACS.
    const serverForm = (kind, host, existing) => {
      const wrap = el('div', 'aaa-form');
      if (!isV3Priv) wrap.appendChild(el('div', 'sw-warn',
        'This session is not SNMPv3 with privacy — a shared key entered here is sent in cleartext.'));
      const grid = el('div', 'snmp-form-grid');
      const addr = inp('text', existing ? existing.address : '', 'e.g. 192.168.1.3');
      if (existing) addr.disabled = true;   // address is the key; edit keeps it fixed
      grid.appendChild(field('Server IP', addr));
      let authPort, acctPort, port, usageSel;
      if (kind === 'radius') {
        authPort = inp('number', existing ? existing.authPort : 1812); grid.appendChild(field('Auth port', authPort));
        acctPort = inp('number', existing ? existing.acctPort : 1813); grid.appendChild(field('Acct port', acctPort));
        usageSel = el('select'); for (const u of ['all', 'login', '802.1x', 'wireless']) { const o = el('option', '', u); o.value = u; usageSel.appendChild(o); }
        if (existing && existing.usage) usageSel.value = existing.usage;
        grid.appendChild(field('Usage', usageSel));
      } else {
        port = inp('number', existing ? existing.port : 49); grid.appendChild(field('Port', port));
      }
      const prio = inp('number', existing ? existing.priority : 0); grid.appendChild(field('Priority', prio));
      const timeout = inp('number', existing ? existing.timeout : '', 'optional'); grid.appendChild(field('Timeout (s)', timeout));
      const globalKey = el('input'); globalKey.type = 'checkbox'; globalKey.checked = existing ? !!existing.useGlobalKey : false;
      const gkWrap = el('label', 'snmp-field-check'); gkWrap.appendChild(globalKey); gkWrap.appendChild(el('span', '', 'Use global default key'));
      const key = inp('password', '', existing ? '(unchanged)' : 'shared secret');
      // Key field with a show/hide toggle so the operator can verify what they
      // typed without re-entering it.
      const keyField = el('div', 'snmp-field');
      keyField.appendChild(el('label', '', 'Shared key'));
      const keyRow = el('div', 'key-row');
      const showToggle = el('button', 'btn btn-small key-show', 'Show'); showToggle.type = 'button';
      showToggle.addEventListener('click', () => {
        const shown = key.type === 'text';
        key.type = shown ? 'password' : 'text';
        showToggle.textContent = shown ? 'Show' : 'Hide';
      });
      keyRow.appendChild(key); keyRow.appendChild(showToggle);
      keyField.appendChild(keyRow);
      const syncKey = () => { keyField.style.display = globalKey.checked ? 'none' : ''; };
      globalKey.addEventListener('change', syncKey); syncKey();
      grid.appendChild(gkWrap);
      grid.appendChild(keyField);
      wrap.appendChild(grid);

      const cancel = el('button', 'btn btn-small', 'Cancel'); cancel.type = 'button';
      cancel.addEventListener('click', () => wrap.remove());
      const { actions, apply: save } = applyActions(existing ? 'Save' : 'Add', { extra: [cancel] });
      save.addEventListener('click', () => {
        const a = (addr.value || '').trim();
        if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(a)) { clearErr(wrap); wrap.appendChild(el('div', 'sw-err', 'Enter a valid IPv4 address.')); return; }
        const common = { address: a, edit: !!existing, priority: parseInt(prio.value, 10),
          timeout: timeout.value === '' ? undefined : parseInt(timeout.value, 10),
          useGlobalKey: globalKey.checked, key: globalKey.checked ? undefined : (key.value || undefined) };
        if (kind === 'radius') {
          submit('/api/aaa/radius', Object.assign(common, {
            authPort: parseInt(authPort.value, 10) || 1812, acctPort: parseInt(acctPort.value, 10) || 1813,
            usage: usageSel.value }), wrap, () => wrap.remove());
        } else {
          submit('/api/aaa/tacacs', Object.assign(common, { port: parseInt(port.value, 10) || 49 }), wrap, () => wrap.remove());
        }
      });
      wrap.appendChild(actions);
      host.appendChild(wrap);
    };
    const clearErr = (node) => { for (const e of Array.from(node.querySelectorAll('.sw-err'))) e.remove(); };

    // Remove any open inline AAA editor/add-form/confirm anywhere in the panel,
    // so only one is ever shown.
    const closeAaaEditors = () => {
      for (const n of Array.from(body.querySelectorAll('.aaa-inline-row'))) n.remove();
      for (const n of Array.from(body.querySelectorAll('.aaa-form'))) n.remove();
      for (const n of Array.from(body.querySelectorAll('.inapp-confirm'))) n.remove();
      // Mark any in-place editing rows as no longer editing (a repaint, if one
      // follows, rebuilds them clean).
      for (const tr of Array.from(body.querySelectorAll('tr.aaa-editing'))) {
        tr._editing = false; tr.classList.remove('aaa-editing');
      }
    };
    s._aaaCloseEditors = closeAaaEditors;


    // Build an edit form into a row-editor host (the proven SNMP-groups pattern:
    // openRowEditor inserts a <tr> after the row and returns a div to fill).
    // Edit form rendered into a row-editor host (openRowEditor inserts a <tr>
    // after the row and returns a div to fill).
    const editForm = (kind, host, cur, tr, onCancel) => {
      const form = el('div', 'snmp-form');
      form.appendChild(el('h5', '', 'Edit ' + (kind === 'radius' ? 'RADIUS' : 'TACACS+') + ' server ' + cur.address));
      if (!isV3Priv) form.appendChild(el('div', 'sw-warn',
        'This session is not SNMPv3 with privacy — a shared key entered here is sent in cleartext.'));
      const grid = el('div', 'snmp-form-grid');
      // A number input rejects a value it can't parse (e.g. "1,812" or
      // "1812 (auth)"), silently showing empty - so pull the numeric part out
      // of whatever the display string is before assigning it.
      const num = (v) => {
        const i = el('input'); i.type = 'number';
        if (v != null && v !== '') {
          const m = String(v).replace(/,/g, '').match(/-?\d+(\.\d+)?/);
          if (m) i.value = m[0];
        }
        return i;
      };
      let authPort, acctPort, port, usageSel;
      if (kind === 'radius') {
        authPort = num(cur.authPort); grid.appendChild(field('Auth port', authPort));
        acctPort = num(cur.acctPort); grid.appendChild(field('Acct port', acctPort));
        usageSel = el('select'); for (const u of ['all', 'login', '802.1X', 'wireless']) { const o = el('option', '', u); o.value = u; usageSel.appendChild(o); }
        // Pre-select the current usage, matching case-insensitively so "802.1X"
        // from the switch lines up with the option regardless of letter case.
        if (cur.usage) {
          const want = String(cur.usage).toLowerCase();
          for (const o of usageSel.options) { if (o.value.toLowerCase() === want) { usageSel.value = o.value; break; } }
        }
        grid.appendChild(field('Usage', usageSel));
      } else {
        port = num(cur.port); grid.appendChild(field('Port', port));
      }
      const prio = num(cur.priority); grid.appendChild(field('Priority', prio));
      const timeout = num(cur.timeout); grid.appendChild(field('Timeout (s)', timeout));
      const gk = el('input'); gk.type = 'checkbox'; gk.checked = !!cur.useGlobalKey;
      const gkWrap = el('label', 'snmp-field-check'); gkWrap.appendChild(gk); gkWrap.appendChild(el('span', '', 'Use global default key'));
      const key = el('input'); key.type = 'password'; key.placeholder = '(unchanged)';
      const keyField = el('div', 'snmp-field'); keyField.appendChild(el('label', '', 'Shared key'));
      const keyRow = el('div', 'key-row');
      const showBtn = el('button', 'btn btn-small', 'Show'); showBtn.type = 'button';
      showBtn.addEventListener('click', () => { const sh = key.type === 'text'; key.type = sh ? 'password' : 'text'; showBtn.textContent = sh ? 'Show' : 'Hide'; });
      keyRow.appendChild(key); keyRow.appendChild(showBtn); keyField.appendChild(keyRow);
      const syncKey = () => { keyField.style.display = gk.checked ? 'none' : ''; };
      gk.addEventListener('change', syncKey); syncKey();
      grid.appendChild(gkWrap); grid.appendChild(keyField);
      form.appendChild(grid);
      const cancel = el('button', 'btn btn-small secondary', 'Cancel'); cancel.type = 'button';
      cancel.addEventListener('click', () => { if (onCancel) onCancel(); else if (tr) closeRowEditors(tr.closest('table')); });
      const { actions, apply: save } = applyActions('Save', { extra: [cancel] });
      save.addEventListener('click', () => {
        const common = { address: cur.address, edit: true, priority: parseInt(prio.value, 10),
          timeout: timeout.value === '' ? undefined : parseInt(timeout.value, 10),
          useGlobalKey: gk.checked, key: gk.checked ? undefined : (key.value || undefined) };
        if (kind === 'radius') submit('/api/aaa/radius', Object.assign(common, {
          authPort: parseInt(authPort.value, 10) || 1812, acctPort: parseInt(acctPort.value, 10) || 1813, usage: usageSel.value }), host, () => {});
        else submit('/api/aaa/tacacs', Object.assign(common, { port: parseInt(port.value, 10) || 49 }), host, () => {});
      });
      form.appendChild(actions);
      host.appendChild(form);
    };

    // Edit/Delete buttons for a row, using the row-editor host (the detail popout
    // stays available via the clickable address cell).
    const rowActionsCell = (kind, addr, extra) => {
      const btns = [];
      // Editing is via row-click (opens the edit popout); the row action is
      // delete only, unless a caller explicitly wants the inline Edit too.
      if (!extra.deleteOnly) btns.push(actBtn('Edit', (e) => { const tr = e.target.closest('tr');
        editForm(kind, openRowEditor(tr, tr.children.length), Object.assign({ address: addr }, extra.cur), tr); }, '', 'Edit this server'));
      btns.push(actBtnConfirm('Delete', (e) => { const tr = e.target.closest('tr');
        delDirect(extra.delUrl, extra.delPayload); }, 'danger', 'Delete this server'));
      return actGroup(btns);
    };
    // Read-only key/value grid for a server popout when the session can't edit.
    const aaaReadonly = (pairs) => {
      const dl = el('dl', 'port-detail-grid');
      for (const [k, v] of pairs) { if (v === undefined || v === null || v === '') continue; dl.appendChild(el('dt', '', k)); dl.appendChild(el('dd', '', String(v))); }
      return dl;
    };
    // RADIUS live-stats grid (RFC 4668 counters) for the Counters tab.
    const radiusStatsGrid = (stats) => {
      const wrap = el('div');
      wrap.appendChild(el('div', 'port-detail-sub', 'RADIUS statistics'));
      const dl = el('dl', 'port-detail-grid');
      for (const [k, v] of Object.entries(stats || {})) {
        if (k === 'index') continue;
        const val = (v && typeof v === 'object') ? (v.display !== undefined ? v.display : v.value) : v;
        if (val === undefined || val === null || val === '') continue;
        dl.appendChild(el('dt', '', k.replace(/^radiusAuthClient/, '').replace(/([A-Z])/g, ' $1').trim())); dl.appendChild(el('dd', '', String(val)));
      }
      wrap.appendChild(dl);
      return wrap;
    };

    if (radius.length || editable) {
      section('RADIUS servers', radius.length + (isOn('rlAAARadiusEnabled') ? ' \u00b7 enabled' : ' \u00b7 disabled'));
      if (radius.length) mountInto(body, s, p, 'radius',
        ['Address', 'Auth port', 'Acct port', 'Priority', 'Usage', 'Timeout', 'Retries', 'Key'].concat(editable ? [''] : []),
        radius.map((r) => {
          const addr = inetAddr(r.rlRadiusServerInetAddress);
          const authPort = dv2(r.rlRadiusServerInetAuthPortNumber);
          const acctPort = dv2(r.rlRadiusServerInetAcctPortNumber);
          const usage = RADIUS_USAGE[Number(dv2(r.rlRadiusServerInetUsage))] || dv2(r.rlRadiusServerInetUsage);
          const key = keyStatus(r.rlRadiusServerInetUseGlobalDefaultKey, r.rlRadiusServerInetKey);
          const stats = statsByAddr.get(String(addr));
          const cur = { address: addr, authPort, acctPort, priority: dv2(r.rlRadiusServerInetPriority), usage,
            timeout: dv2(r.rlRadiusServerInetTimeout),
            useGlobalKey: /true|1|yes/i.test(String(dv2(r.rlRadiusServerInetUseGlobalDefaultKey))) };
          // Row-click opens the standard edit popout: Config tab = the edit form
          // (when editable, else a read-only view), Counters tab = RADIUS stats.
          const openIt = () => openEditPopout(s, 'RADIUS \u00b7 ' + addr,
            (pane, close) => { if (editable) editForm('radius', pane, cur, null, close); else pane.appendChild(aaaReadonly([
              ['Address', addr], ['Auth port', authPort], ['Acct port', acctPort],
              ['Priority', dv2(r.rlRadiusServerInetPriority)], ['Usage', usage],
              ['Timeout (s)', dv2(r.rlRadiusServerInetTimeout)], ['Retries', dv2(r.rlRadiusServerInetRetries)],
              ['Deadtime (min)', dv2(r.rlRadiusServerInetDeadtime)], ['Source', dv2(r.rlRadiusServerInetSource)],
              ['Shared key', key]])); },
            stats ? (pane) => pane.appendChild(radiusStatsGrid(stats)) : null);
          const row = [
            { click: { open: openIt }, v: addr },
            { v: authPort }, { v: acctPort }, { v: dv2(r.rlRadiusServerInetPriority) }, { v: usage },
            { v: dv2(r.rlRadiusServerInetTimeout) }, { v: dv2(r.rlRadiusServerInetRetries) }, { v: key }
          ];
          if (editable) row.push({ cellNode: rowActionsCell('radius', addr, { cur, deleteOnly: true,
            delUrl: '/api/aaa/radius/delete', delPayload: { address: addr, authPort, acctPort } }), sig: 'ra' });
          return { key: 'radius:' + addr, cells: row };
        }));
      if (editable) {
        body.appendChild(addControl('Add RADIUS server', (host) => {
          const open = host.querySelector('.aaa-form'); if (s._aaaCloseEditors) s._aaaCloseEditors();
          if (!open) serverForm('radius', host, null); else host.querySelector('.aaa-form').remove();
        }));
      }
    }

    if (tacacs.length || editable) {
      section('TACACS+ servers', tacacs.length + (isOn('rlAAATacacsEnabled') ? ' \u00b7 enabled' : ' \u00b7 disabled'));
      if (tacacs.length) mountInto(body, s, p, 'tacacs',
        ['Address', 'Port', 'State', 'Priority', 'Timeout', 'Key'].concat(editable ? [''] : []),
        tacacs.map((r) => {
          const addr = inetAddr(r.rlTacacsServerInetAddress);
          const port = dv2(r.rlTacacsServerInetPortNumber);
          const statusRaw = String(dv2(r.rlTacacsServerInetConnectionStatus));
          const connected = /connected\(0\)|^0$|^connected$/i.test(statusRaw) && !/not/i.test(statusRaw);
          const key = keyStatus(r.rlTacacsServerInetUseGlobalDefaultKey, r.rlTacacsServerInetKey);
          const cur = { address: addr, port, priority: dv2(r.rlTacacsServerInetPriority), timeout: dv2(r.rlTacacsServerInetTimeout),
            useGlobalKey: /true|1|yes/i.test(String(dv2(r.rlTacacsServerInetUseGlobalDefaultKey))) };
          const openIt = () => openEditPopout(s, 'TACACS+ \u00b7 ' + addr,
            (pane, close) => { if (editable) editForm('tacacs', pane, cur, null, close); else pane.appendChild(aaaReadonly([
              ['Address', addr], ['Port', port], ['Connection', dv2(r.rlTacacsServerInetConnectionStatus)],
              ['Type', dv2(r.rlTacacsServerInetConnectionType)], ['Priority', dv2(r.rlTacacsServerInetPriority)],
              ['Timeout (s)', dv2(r.rlTacacsServerInetTimeout)], ['Shared key', key]])); },
            null);
          const row = [
            { click: { open: openIt }, v: addr },
            { v: port }, { pill: true, v: connected ? 'connected' : 'not connected' },
            { v: dv2(r.rlTacacsServerInetPriority) }, { v: dv2(r.rlTacacsServerInetTimeout) }, { v: key }
          ];
          if (editable) row.push({ cellNode: rowActionsCell('tacacs', addr, { cur, deleteOnly: true,
            delUrl: '/api/aaa/tacacs/delete', delPayload: { address: addr } }), sig: 'ta' });
          return { key: 'tacacs:' + addr, cells: row };
        }));
      if (editable) {
        body.appendChild(addControl('Add TACACS+ server', (host) => {
          const open = host.querySelector('.aaa-form'); if (s._aaaCloseEditors) s._aaaCloseEditors();
          if (!open) serverForm('tacacs', host, null); else host.querySelector('.aaa-form').remove();
        }));
      }
    }

  }
