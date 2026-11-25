  // =================================================================
  // 07-ports.js: Per-port editors: interface settings, voice VLAN, switchport, 802.1X per port, counters and port actions; static MAC entries.
  // =================================================================

  // ---- static MAC entries (dot1qStaticUnicastTable) ----
  // Index: { dot1qFdbId (VLAN), MAC (6 bytes), ReceivePort (0 = any) }.
  // Create: Status = permanent(3) + AllowedToGoTo (bridge-port bitmap).
  // Delete: Status = invalid(2). The standard learned FDB (dot1qTpFdbStatus)
  // is read-only, so only static entries can be removed via SNMP; a learned
  // entry is cleared by bouncing its port or letting it age out.
  const STATIC_MAC = {
    allowedToGoTo: '1.3.6.1.2.1.17.7.1.3.1.1.3',  // dot1qStaticUnicastAllowedToGoTo (PortList)
    status:        '1.3.6.1.2.1.17.7.1.3.1.1.4'   // dot1qStaticUnicastStatus (INTEGER)
  };
  // "AA:BB:CC:DD:EE:FF" -> "170.187.204.221.238.255" (dotted decimal, for the OID index).
  function macToOidBytes(mac) {
    const parts = String(mac).trim().split(/[:\-.]/).map((h) => parseInt(h, 16));
    if (parts.length !== 6 || parts.some((n) => !Number.isFinite(n) || n < 0 || n > 255)) return null;
    return parts.join('.');
  }
  // Validate a MAC address string.
  function isValidMac(mac) { return /^([0-9a-f]{2}[:\-]){5}[0-9a-f]{2}$/i.test(String(mac).trim()); }

  // Voice VLAN Telephony OUI prefix = OCTET STRING(SIZE 3). On this firmware the
  // index is the 3 raw bytes with NO length prefix (e.g. OUI AA-BB-CC indexes as
  // "170.187.204", not "3.170.187.204" - verified against a switch-created row).
  // Encode "AA-BB-CC" (3 hex octets) to "b1.b2.b3", or null if invalid; decode back.
  function ouiToOidIndex(oui) {
    const parts = String(oui || '').trim().split(/[:\-.\s]+/).map((h) => parseInt(h, 16));
    if (parts.length !== 3 || parts.some((n) => !Number.isFinite(n) || n < 0 || n > 255)) return null;
    return parts.join('.');
  }
  function ouiIndexToStr(idx) {
    const p = String(idx || '').split('.').map((n) => parseInt(n, 10));
    if (p.length !== 3 || p.some((n) => !Number.isFinite(n) || n < 0 || n > 255)) return String(idx || '');
    return p.map((n) => n.toString(16).padStart(2, '0')).join('-');
  }

  // Build the static-table index suffix: <vlan>.<mac bytes>.<receivePort>.
  function staticMacSuffix(vlan, mac, receivePort) {
    const mb = macToOidBytes(mac);
    if (mb === null) return null;
    return vlan + '.' + mb + '.' + (receivePort || 0);
  }

  // Create a static MAC entry. Verified against a real entry the switch made:
  // the PORT is encoded in the index as the ReceivePort (last arc), and the only
  // thing written is Status = permanent(3). dot1qStaticUnicastAllowedToGoTo is
  // NOT set (writing it was the WrongValue). Index: <vlan>.<mac bytes>.<port>.
  async function addStaticMac(s, vlan, mac, bridgePort, status) {
    const suffix = staticMacSuffix(vlan, mac, parseInt(bridgePort, 10));
    if (!suffix) throw new Error('invalid MAC address');
    // status: permanent(3) default, deleteOnReset(4), deleteOnTimeout(5),
    // secure(1). Any of these creates the entry; writing invalid(2) deletes.
    const st = [1, 3, 4, 5].indexOf(parseInt(status, 10)) !== -1 ? parseInt(status, 10) : 3;
    await snmpSet(s, { oid: STATIC_MAC.status + '.' + suffix, type: 'Integer', value: st });
  }
  // Delete a static MAC entry: Status = invalid(2) at the same index (the port
  // is part of the index, so the caller passes the entry's receive port).
  async function deleteStaticMac(s, vlan, mac, bridgePort) {
    const suffix = staticMacSuffix(vlan, mac, parseInt(bridgePort, 10) || 0);
    if (!suffix) throw new Error('invalid MAC address');
    await snmpSet(s, { oid: STATIC_MAC.status + '.' + suffix, type: 'Integer', value: 2 }); // invalid = delete
  }

  // The add-static-MAC form (popout): MAC, VLAN, and the port to map it to.
  function openStaticMacForm(s, h) {
    // Port options: each bridge port -> its interface name. AllowedToGoTo is a
    // bridge-port bitmap, so we offer bridge-port numbers labelled by name.
    const cv = (c) => (c == null ? '' : (c.value !== undefined ? c.value : c.display));
    const nameByIfx = new Map();
    for (const r of (h.interfaces || [])) { const nm = String(cv(r.rlifPresentName) || '').trim(); if (nm) nameByIfx.set(String(r.index), nm); }
    const portOpts = [];
    for (const r of (h.bridgePorts || [])) {
      const bp = String(r.index);
      const ifx = String(cv(r.dot1dBasePortIfIndex) || '');
      const nm = nameByIfx.get(ifx);
      if (nm && !/^\d+$/.test(nm)) portOpts.push({ label: nm + ' (bridge ' + bp + ')', value: bp, sort: nm });
    }
    portOpts.sort((a, b) => String(a.sort).localeCompare(String(b.sort), undefined, { numeric: true }));
    const vlanOpts = (h.vlans || []).map((v) => ({ label: 'VLAN ' + v.index, value: String(v.index) }));

    const tabs = [{ label: 'Add static MAC', fill: (pane, close) => {
      const form = el('div', 'snmp-form acl-form');
      const sec = formSection('Static MAC entry');
      const macIn = el('input'); macIn.type = 'text'; macIn.placeholder = 'AA:BB:CC:DD:EE:FF'; macIn.maxLength = 17;
      sec.body.appendChild(field('MAC address', macIn));
      const vlanSel = vlanOpts.length ? selectInput(vlanOpts, vlanOpts[0].value) : (() => { const i = el('input'); i.type = 'number'; i.min = '1'; i.max = '4094'; i.value = '1'; return i; })();
      sec.body.appendChild(field('VLAN', vlanSel));
      const portSel = portOpts.length ? selectInput(portOpts, portOpts[0].value) : (() => { const i = el('input'); i.type = 'number'; i.min = '1'; i.placeholder = 'bridge port #'; return i; })();
      sec.body.appendChild(field('Port', portSel));
      // Status matches the switch's own dialog (dot1qStaticUnicastStatus):
      // Permanent(3), Delete on reset(4), Delete on timeout(5), Secure(1=other).
      const statusSel = selectInput([
        { label: 'Permanent', value: '3' },
        { label: 'Delete on reset', value: '4' },
        { label: 'Delete on timeout', value: '5' },
        { label: 'Secure', value: '1' }
      ], '3');
      sec.body.appendChild(field('Status', statusSel));
      form.appendChild(sec.sec);
      const { actions, apply } = applyActions('Add static MAC');
      const msg = el('div', 'port-detail-msg');
      apply.addEventListener('click', (ev) => {
        clear(msg);
        const mac = (macIn.value || '').trim();
        if (!isValidMac(mac)) { msg.appendChild(el('div', 'sw-err', 'Enter a MAC like AA:BB:CC:DD:EE:FF.')); return; }
        const vlan = parseInt(vlanSel.value, 10);
        const bp = parseInt(portSel.value, 10);
        if (!Number.isFinite(vlan) || !Number.isFinite(bp)) { msg.appendChild(el('div', 'sw-err', 'Choose a VLAN and port.')); return; }
        const status = parseInt(statusSel.value, 10) || 3;
        runButtonAction(ev.currentTarget, {
          failLabel: 'Add static MAC', spinLabel: 'Adding\u2026',
          run: () => addStaticMac(s, vlan, mac, bp, status).then(() => ({ ok: true }), (e) => ({ ok: false, error: e.message })),
          ok: (r) => r && r.ok,
          error: (r) => { msg.appendChild(el('div', 'sw-err', 'Could not add static MAC \u2014 ' + ((r && r.error) || 'failed'))); return (r && r.error) || 'failed'; },
          onApplied: () => { const pop = pane.closest && pane.closest('.port-detail-back'); if (pop) pop.remove(); markConfigDirty(s); s._macFetchedAt = 0; },
          settle: () => new Promise((res) => setTimeout(() => refreshTables(s, ['macTable']).then(res, res), 800))
        });
      });
      form.appendChild(actions); form.appendChild(msg);
      pane.appendChild(form);
    } }];
    openTabbedPopout(s, 'Add static MAC', tabs, []);
  }

  // Physical interface settings editor: speed, duplex, auto-negotiation, flow
  // control, MDI/MDIX, and the port description (ifAlias). All are SNMP SETs to
  // swIfTable columns (and ifAlias). Speed/duplex only take effect when auto-neg
  // is disabled, so those two are disabled in the UI while auto-neg is on.
  const IFSET = {
    speed:  { oid: '1.3.6.1.4.1.9.6.1.101.43.1.1.15' },
    duplex: { oid: '1.3.6.1.4.1.9.6.1.101.43.1.1.3' },
    autoneg:{ oid: '1.3.6.1.4.1.9.6.1.101.43.1.1.16' },
    flow:   { oid: '1.3.6.1.4.1.9.6.1.101.43.1.1.14' },
    mdix:   { oid: '1.3.6.1.4.1.9.6.1.101.43.1.1.28' },
    alias:  { oid: '1.3.6.1.2.1.31.1.1.1.18' },
    caps:   { oid: '1.3.6.1.4.1.9.6.1.101.43.1.1.46' },  // swIfPortCapabilities (BITS)
    // Per-port Voice VLAN table. The diagnostic showed the GUI-added port lives in
    // vlanVoiceOUIBasedPortTable (.12.5) - the .4 table is empty on this firmware.
    // A working port has VlanIndex (.2) set to the voice VLAN BEFORE Enable (.1);
    // VlanIndex is Unsigned32 ('Gauge'), not Integer.
    voiceEnable: { oid: '1.3.6.1.4.1.9.6.1.101.48.54.12.5.1.1' },  // Enable (TruthValue)
    voiceVlanIdx: { oid: '1.3.6.1.4.1.9.6.1.101.48.54.12.5.1.2' }, // VlanIndex (Unsigned32)
    voiceSecure: { oid: '1.3.6.1.4.1.9.6.1.101.48.54.12.5.1.3' },  // Secure (TruthValue)
    voiceMembership: { oid: '1.3.6.1.4.1.9.6.1.101.48.54.12.5.1.4' }, // CurrentMembership (ro)
    voiceQos: { oid: '1.3.6.1.4.1.9.6.1.101.48.54.12.5.1.5' }      // QosMode (src(1)/all(2))
  };
  // AutoNegCapabilitiesBits positions -> the speeds they imply.
  const CAP_BITS = {
    2: 10, 3: 10,          // tenHalf / tenFull -> 10 Mb/s
    4: 100, 5: 100,        // fastHalf / fastFull -> 100 Mb/s
    6: 1000, 7: 1000,      // gigaHalf / gigaFull -> 1 Gb/s
    8: '10g',              // tenGigaFull -> 10 Gb/s (admin value 10)
    9: 5000,               // fiveGigaFull
    10: 2500,              // twoPointFiveGigaFull
    11: 25000, 12: 40000, 13: 50000, 14: 100000, 15: 200000
  };
  // swIfSpeedAdminMode values. The MIB says "bits per second" but the switch
  // rejects bps values with WrongValue, and notes "A value of 10 is returned
  // for 10G" - so the encoding is Mb/s, with 10G special-cased as the literal
  // 10. (10 Mb/s is not offered: these switches are GE/2.5GE/10GE, and 10 is
  // claimed by 10G.)
  const SPEED_OPTS = [{ label: 'auto/unset', value: 0 },
    { label: '100 Mb/s', value: 100 }, { label: '1 Gb/s', value: 1000 },
    { label: '2.5 Gb/s', value: 2500 }, { label: '5 Gb/s', value: 5000 }, { label: '10 Gb/s', value: 10 }];
  const DUPLEX_OPTS = [{ label: 'full', value: 3 }, { label: 'half', value: 2 }, { label: 'none', value: 1 }];
  const AUTONEG_OPTS = [{ label: 'enabled', value: 1 }, { label: 'disabled', value: 2 }];
  const FLOW_OPTS = [{ label: 'on', value: 1 }, { label: 'off', value: 2 }, { label: 'auto-negotiation', value: 3 }];
  const MDIX_OPTS = [{ label: 'auto', value: 3 }, { label: 'normal', value: 2 }, { label: 'cross', value: 1 }];

  // Fetch this one port's physical settings + alias on demand (not polled in
  // bulk). Returns { speed, duplex, autoneg, flow, mdix, alias }.
  // Decode a swIfPortCapabilities BITS varbind into a Set of supported speed
  // values (matching the SPEED_OPTS values: 100, 1000, 2500, 5000, and '10' for
  // 10G). BITS are MSB-first: byte 0 bit 7 is bit position 0. Returns null if
  // the value can't be decoded (so the caller offers all speeds rather than
  // wrongly hiding them).
  function decodeCapsToSpeeds(vb) {
    let bytes = null;
    const raw = vb && (vb.value !== undefined ? vb.value : vb.display);
    if (raw == null) return null;
    if (Array.isArray(raw)) bytes = raw;
    else if (typeof raw === 'string') {
      const hex = raw.replace(/0x/gi, '').replace(/[^0-9a-fA-F]/g, '');
      if (hex.length >= 2 && hex.length % 2 === 0) {
        bytes = []; for (let i = 0; i < hex.length; i += 2) bytes.push(parseInt(hex.substr(i, 2), 16));
      } else {
        // Maybe a plain integer rendered as a string.
        const n = parseInt(raw, 10);
        if (Number.isFinite(n)) bytes = [(n >> 8) & 0xff, n & 0xff];
      }
    } else if (typeof raw === 'number') {
      bytes = [(raw >> 8) & 0xff, raw & 0xff];
    }
    if (!bytes || !bytes.length) return null;
    const speeds = new Set();
    for (let byteIdx = 0; byteIdx < bytes.length; byteIdx++) {
      for (let bit = 0; bit < 8; bit++) {
        const pos = byteIdx * 8 + bit;                 // BITS position
        const set = (bytes[byteIdx] >> (7 - bit)) & 1; // MSB-first
        if (set && CAP_BITS[pos] !== undefined) {
          const sp = CAP_BITS[pos];
          speeds.add(sp === '10g' ? 10 : sp);          // 10G admin value is 10
        }
      }
    }
    return speeds.size ? speeds : null;
  }

  async function fetchIfSettings(s, ifx, fields) {
    // fields: optional list of keys to read (speed/duplex/autoneg/flow/mdix/
    // alias). Omitted = all. Keeping the GET to only the fields that matter
    // keeps the control-plane load minimal after a targeted edit.
    const want = fields && fields.length ? new Set(fields) : null;
    const all = { speed: IFSET.speed.oid, duplex: IFSET.duplex.oid, autoneg: IFSET.autoneg.oid,
      flow: IFSET.flow.oid, mdix: IFSET.mdix.oid, alias: IFSET.alias.oid, caps: IFSET.caps.oid,
      voiceEnable: IFSET.voiceEnable.oid, voiceSecure: IFSET.voiceSecure.oid,
      voiceMembership: IFSET.voiceMembership.oid, voiceQos: IFSET.voiceQos.oid };
    const oids = Object.entries(all).filter(([k]) => !want || want.has(k)).map(([, oid]) => oid + '.' + ifx);
    const { body: b } = await apiPost('/api/snmp/get', { target: s.target, oids });
    const out = { speed: null, duplex: null, autoneg: null, flow: null, mdix: null, alias: '', speeds: null,
      voiceEnable: null, voiceSecure: null, voiceMembership: null, voiceQos: null };
    const col = (oid) => oid.split('.').slice(0, -1).join('.');
    const map = { [IFSET.speed.oid]: 'speed', [IFSET.duplex.oid]: 'duplex', [IFSET.autoneg.oid]: 'autoneg',
      [IFSET.flow.oid]: 'flow', [IFSET.mdix.oid]: 'mdix', [IFSET.alias.oid]: 'alias', [IFSET.caps.oid]: 'caps',
      [IFSET.voiceEnable.oid]: 'voiceEnable', [IFSET.voiceSecure.oid]: 'voiceSecure',
      [IFSET.voiceMembership.oid]: 'voiceMembership', [IFSET.voiceQos.oid]: 'voiceQos' };
    for (const vb of ((b && b.results) || [])) {
      if (vb.error) continue;
      const k = map[col(String(vb.oid || ''))];
      if (!k) continue;
      if (k === 'alias') out.alias = vb.value != null ? String(vb.value) : '';
      else if (k === 'caps') {
        // Decode the BITS value into the set of supported speeds. The value may
        // arrive as a hex string, a byte array, or a number; handle each.
        out.speeds = decodeCapsToSpeeds(vb);
      } else { const n = parseInt(vb.value, 10); out[k] = Number.isFinite(n) ? n : null; }
    }
    return out;
  }

  function buildInterfaceSettings(s, detail, st) {
    const box = el('div', 'port-detail-settings');
    detail.alias = st.alias;   // used by the Apply diff
    const sel = (opts, cur) => { const e = el('select'); for (const o of opts) { const op = el('option', '', o.label); op.value = String(o.value); if (o.value === cur) op.selected = true; e.appendChild(op); } return e; };
    const grid = el('div', 'snmp-form-grid');

    const aliasIn = el('input'); aliasIn.type = 'text'; aliasIn.maxLength = 64;
    aliasIn.value = detail.alias != null ? detail.alias : '';
    aliasIn.placeholder = 'port description';
    grid.appendChild(field('Description', aliasIn));

    const autoSel = sel(AUTONEG_OPTS, st.autoneg);
    grid.appendChild(field('Auto-negotiation', autoSel));
    // Offer only speeds the port actually supports (from swIfPortCapabilities).
    // Always keep 'auto/unset' (0) and the current value, even if the caps read
    // failed or didn't include it, so the dropdown never hides the real state.
    const supported = st.speeds instanceof Set ? st.speeds : null;
    const speedOpts = SPEED_OPTS.filter((o) => o.value === 0 || o.value === st.speed ||
      !supported || supported.has(o.value));
    const speedSel = sel(speedOpts, st.speed);
    const speedField = field('Speed', speedSel); grid.appendChild(speedField);
    const duplexSel = sel(DUPLEX_OPTS, st.duplex);
    const duplexField = field('Duplex', duplexSel); grid.appendChild(duplexField);
    // Speed/duplex only apply when auto-neg is disabled.
    const syncAuto = () => {
      const on = parseInt(autoSel.value, 10) === 1;
      speedSel.disabled = on; duplexSel.disabled = on;
      speedField.title = on ? 'Disable auto-negotiation to set a fixed speed' : '';
      duplexField.title = on ? 'Disable auto-negotiation to set a fixed duplex' : '';
    };
    autoSel.addEventListener('change', syncAuto); syncAuto();

    const flowSel = sel(FLOW_OPTS, st.flow);
    grid.appendChild(field('Flow control', flowSel));
    const mdixSel = sel(MDIX_OPTS, st.mdix);
    grid.appendChild(field('MDI/MDIX', mdixSel));
    box.appendChild(grid);

    const { actions, apply, msg } = applyActions('Apply');
    const setOne = (oid, type, value) => snmpSet(s, { oid, type, value });
    // Build the ordered diff of changed fields -> SET steps. Returns [] when
    // nothing changed. Kept as a function so the no-changes case can short-circuit
    // before the action runs.
    const buildSteps = (ix) => {
      const newAuto = parseInt(autoSel.value, 10);
      const newSpeed = parseInt(speedSel.value, 10);
      const newDuplex = parseInt(duplexSel.value, 10);
      const newFlow = parseInt(flowSel.value, 10);
      const newMdix = parseInt(mdixSel.value, 10);
      const newAlias = aliasIn.value;
      const steps = [];
      // Order: set auto-neg first (it gates speed/duplex), then the rest.
      if (newAuto !== st.autoneg) steps.push(['autoneg', IFSET.autoneg.oid + '.' + ix, 'Integer', newAuto, newAuto]);
      if (newAuto === 2) {   // only meaningful when auto-neg disabled
        if (newSpeed !== st.speed) steps.push(['speed', IFSET.speed.oid + '.' + ix, 'Integer', newSpeed, newSpeed]);
        if (newDuplex !== st.duplex) steps.push(['duplex', IFSET.duplex.oid + '.' + ix, 'Integer', newDuplex, newDuplex]);
      }
      if (newFlow !== st.flow) steps.push(['flow', IFSET.flow.oid + '.' + ix, 'Integer', newFlow, newFlow]);
      if (newMdix !== st.mdix) steps.push(['mdix', IFSET.mdix.oid + '.' + ix, 'Integer', newMdix, newMdix]);
      if (newAlias !== (detail.alias != null ? detail.alias : '')) steps.push(['alias', IFSET.alias.oid + '.' + ix, 'OctetString', newAlias, newAlias]);
      return steps;
    };
    const ctlByName = { autoneg: autoSel, speed: speedSel, duplex: duplexSel, flow: flowSel, mdix: mdixSel, alias: aliasIn };
    // The write button: two-tap confirm (a speed/duplex change bounces the link),
    // then runButtonAction owns the spinner->done/revert lifecycle (standard B6).
    // run() performs the ordered batch; settle() does the computed re-read and the
    // delayed row refreshes. The detailed per-field failure list still goes to the
    // inline msg div (more useful than a generic toast for a multi-field apply).
    withConfirm(apply, (ev) => {
      const ix = detail.ifIndex;
      clear(msg);
      const steps = buildSteps(ix);
      if (!steps.length) { msg.appendChild(el('div', 'card-sub', 'No changes.')); return; }
      runButtonAction(ev.currentTarget, {
        failLabel: 'Apply',
        run: async () => {
          s.writeBusy = true;
          // Suppress the reactive link-trap refresh for a short window - we
          // re-read what we need ourselves after the port bounces.
          s._ifWriteUntil = Date.now() + 12000;
          const failures = [];
          for (const [name, oid, type, value] of steps) {
            try { await setOne(oid, type, value); }
            catch (e) { failures.push(name + ': ' + e.message); }
          }
          s.writeBusy = false;
          const changed = new Set(steps.map((x) => x[0]));
          // A successful SET tells us the new value, so local state is taken from
          // what we set; we only RE-READ fields the switch may have coerced as a
          // side effect (toggling auto-neg can change effective speed/duplex, a
          // speed the port can't do may be rounded).
          if (changed.has('autoneg')) st.autoneg = steps.find((x) => x[0] === 'autoneg')[4];
          if (changed.has('speed')) st.speed = steps.find((x) => x[0] === 'speed')[4];
          if (changed.has('duplex')) st.duplex = steps.find((x) => x[0] === 'duplex')[4];
          if (changed.has('flow')) st.flow = steps.find((x) => x[0] === 'flow')[4];
          if (changed.has('mdix')) st.mdix = steps.find((x) => x[0] === 'mdix')[4];
          if (changed.has('alias')) { const a = steps.find((x) => x[0] === 'alias')[4]; st.alias = a; detail.alias = a; }

          const reread = new Set();
          if (changed.has('autoneg')) { reread.add('speed'); reread.add('duplex'); }
          if (changed.has('speed')) reread.add('speed');
          if (changed.has('duplex')) reread.add('duplex');
          return { ok: failures.length === 0, failures: failures,
            changedControls: steps.map((x) => ctlByName[x[0]]).filter(Boolean),
            reread: Array.from(reread), ix: ix };
        },
        ok: (res) => res && res.ok,
        error: (res) => {
          const list = (res && res.failures) || [];
          const text = 'Some changes were rejected \u2014 ' + list.join('; ');
          msg.appendChild(el('div', 'sw-err', text));
          return text;
        },
        onApplied: (res) => markConfigDirty(s, res.changedControls),
        settle: async (res) => {
          if (res.reread.length) {
            try {
              const fresh = await fetchIfSettings(s, res.ix, res.reread);
              for (const k of res.reread) if (fresh[k] !== null && fresh[k] !== undefined) st[k] = fresh[k];
            } catch (e) { /* non-fatal */ }
          }
          // Reflect local state in the controls (no further reads).
          autoSel.value = String(st.autoneg); speedSel.value = String(st.speed);
          duplexSel.value = String(st.duplex); flowSel.value = String(st.flow);
          mdixSel.value = String(st.mdix); aliasIn.value = st.alias || '';

          syncAuto();
          // Update just this port's row in the main table. A short delay lets the
          // link settle; a second read a few seconds later catches the final
          // negotiated speed after renegotiation.
          setTimeout(() => refreshOnePort(s, res.ix), 2500);
          setTimeout(() => refreshOnePort(s, res.ix), 6000);
        }
      });
    });
    box.appendChild(actions); box.appendChild(msg);
    return box;
  }

  // Per-port Voice VLAN editor (vlanVoicePortTable .4), on its own tab. Secure
  // mode is a REQUIRED choice when enabling a port (the switch needs it set), so
  // it has no silent default - the user picks Off/Secure. QoS mode is a dropdown.
  // Enabling also sets the companion VlanIndex (Unsigned32) to the current Voice
  // VLAN. One Apply diffs all the voice columns, via runButtonAction.
  function buildVoiceVlanEditor(s, detail, st) {
    const box = el('div', 'port-detail-settings');
    const ix = detail.ifIndex;
    const grid = el('div', 'snmp-form-grid');
    const voiceSel = selectInput([{ label: 'Disabled', value: 2 }, { label: 'Enabled', value: 1 }], (st.voiceEnable === 1 ? 1 : 2));
    const memb = (st.voiceMembership === 1) ? ' (active)' : '';
    grid.appendChild(field('Voice VLAN' + memb, voiceSel));
    // Secure mode is not exposed; a port is always added in standard (off) mode.
    // It is still set (to off) as part of the atomic row write when enabling.
    const voiceQosSel = selectInput([{ label: 'Telephony source MAC', value: 1 }, { label: 'All', value: 2 }], (st.voiceQos === 2 ? 2 : 1));
    grid.appendChild(field('QoS mode', voiceQosSel));
    box.appendChild(grid);

    const { actions, apply, msg } = applyActions('Apply');
    const voiceVid = () => parseInt((s.health && s.health.scalars && (s.health.scalars.vlanVoiceAdminVid || {}).value), 10);
    apply.addEventListener('click', (ev) => {
      clear(msg);
      const newVoice = parseInt(voiceSel.value, 10);
      const newQos = parseInt(voiceQosSel.value, 10);
      const newSecure = 2;   // always standard (off); secure mode is not exposed
      // Build the ordered diff. When enabling: VlanIndex (Gauge) -> Secure -> QoS
      // -> Enable. Secure/QoS also apply on their own when already enabled.
      const steps = [];
      const curSecure = (st.voiceSecure === 1 ? 1 : (st.voiceSecure === 2 ? 2 : null));
      const curQos = (st.voiceQos === 2 ? 2 : 1);
      const curVoice = (st.voiceEnable === 1 ? 1 : 2);
      const enabling = (newVoice === 1 && curVoice !== 1);
      if (enabling) {
        const vid = voiceVid();
        if (Number.isFinite(vid) && vid >= 1 && vid <= 4094) steps.push(['vlan', IFSET.voiceVlanIdx.oid + '.' + ix, 'Gauge', vid]);
      }
      if (Number.isFinite(newSecure) && (newSecure !== curSecure || enabling)) steps.push(['secure', IFSET.voiceSecure.oid + '.' + ix, 'Integer', newSecure]);
      if (Number.isFinite(newQos) && (newQos !== curQos || enabling)) steps.push(['qos', IFSET.voiceQos.oid + '.' + ix, 'Integer', newQos]);
      if (newVoice !== curVoice) steps.push(['enable', IFSET.voiceEnable.oid + '.' + ix, 'Integer', newVoice]);
      if (!steps.length) { msg.appendChild(el('div', 'card-sub', 'No changes.')); return; }
      runButtonAction(ev.currentTarget, {
        failLabel: 'Apply',
        run: async () => {
          // Send the whole row in ONE PDU. Setting Enable in its own PDU returns
          // WrongValue even when the companion columns already hold a working
          // port's exact values - the firmware validates the row atomically, the
          // way the GUI sets it. One multi-varbind SET matches that.
          const vb = steps.map(([, oid, type, value]) => ({ oid, type, value }));
          try {
            const res = await snmpSetResult(s, vb);
            const err = res && res.body && res.body.error;
            return { ok: res && res.ok && !err, failures: err ? [err] : [] };
          } catch (e) { return { ok: false, failures: [e.message] }; }
        },
        ok: (res) => res && res.ok,
        error: (res) => { const t = 'Some changes were rejected \u2014 ' + ((res && res.failures) || []).join('; '); msg.appendChild(el('div', 'sw-err', t)); return t; },
        onApplied: () => markConfigDirty(s),
        settle: () => fetchIfSettings(s, ix, ['voiceEnable', 'voiceSecure', 'voiceQos', 'voiceMembership']).then((fresh) => {
          for (const k of ['voiceEnable', 'voiceSecure', 'voiceQos', 'voiceMembership']) if (fresh[k] !== null && fresh[k] !== undefined) st[k] = fresh[k];
          voiceSel.value = String(st.voiceEnable === 1 ? 1 : 2);
          voiceQosSel.value = String(st.voiceQos === 2 ? 2 : 1);
        }).catch(() => {})
      });
    });
    box.appendChild(actions); box.appendChild(msg);
    return box;
  }

  // The port as it is now, for the undo of a switchport change: its mode and
  // VLANs, and (for a routed port) its IPv4 addresses.
  function switchportBefore(s, detail) {
    const sw = detail.sw;
    const ifx = parseInt(detail.ifIndex, 10);
    return {
      mode: sw.mode,
      access: sw.mode === 'access' ? sw.untagged[0] : undefined,
      native: sw.mode === 'trunk' ? sw.untagged[0] : undefined,
      tagged: sw.mode === 'trunk' ? (sw.tagged || []).slice() : [],
      addrs: sw.l2l3 === 'L3' ? ipv4Addresses(s).filter((a) => a.ifIndex === ifx).map((a) => ({ ip: a.ip, mask: a.mask, owner: a.owner })) : []
    };
  }

  // The switchport mode/VLAN editor inside the port dialog. Shows the current
  // configuration and an inline form: mode (access / trunk / routed), the
  // access VLAN, or the trunk native + tagged VLANs — all chosen from VLANs
  // that already exist on the switch. Writes use the SNMP SET sequence proven
  // against this firmware (VlanIndex objects as Gauge, native folded into the
  // allowed bitmap, mode flipped last).
  //
  // "routed" is the port's L2/L3 category, not a switchport mode: CISCOSB-vlan
  // vlanSwitchPortModeCategory (read-write, 1 = l2 "switchport", 2 = l3 "no
  // switchport"). It is offered only where the switch reports that category
  // for the port. A routed port has no VLANs; its IPv4 address is set in the
  // IPv4 Addressing panel, like every other interface address.
  function buildSwitchportEditor(s, detail) {
    const sw = detail.sw;
    const box = el('div', 'sw-editor');
    const knowsCategory = sw.l2l3 === 'L2' || sw.l2l3 === 'L3';
    const wasRouted = sw.l2l3 === 'L3';

    // Management protection (MODULE-STANDARD B6): a routed port that holds the
    // address this app talks to the switch on cannot go back to a switchport
    // (that removes the address), and a port flagged as the uplink cannot be
    // made routed (that takes it out of the VLAN the app reaches the switch
    // through). Both are locked with the reason, not just cautioned.
    const holdsMgmtIp = wasRouted && isManagementIf(s, detail.ifIndex);
    const lockReason = holdsMgmtIp
      ? 'This routed port holds ' + s.target.host + ', the address this app uses to reach the switch. Turning it back into a switchport would remove that address and cut off access, so it is locked.'
      : (!wasRouted && sw.uplink)
        ? 'Routed is locked: this port is ' + sw.uplink + ', so it likely carries this app’s connection to the switch. Making it routed would take it out of that VLAN.'
        : '';

    const vlans = sw.allVlans.length ? sw.allVlans : [1];
    const grid = el('div', 'snmp-form-grid');

    // Mode selector — shown immediately, no edit button.
    const modeSel = el('select');
    const MODES = [['access', 'access'], ['trunk', 'trunk']].concat(knowsCategory ? [['routed', 'routed (no switchport)']] : []);
    const curMode = wasRouted ? 'routed' : sw.mode;
    for (const [v, label] of MODES) {
      const o = el('option', '', label); o.value = v;
      if (v === curMode) o.selected = true;
      // Lock whichever direction would cut the management path.
      if (lockReason && (holdsMgmtIp ? v !== 'routed' : v === 'routed')) o.disabled = true;
      modeSel.appendChild(o);
    }
    grid.appendChild(field('Mode', modeSel));

    // Access VLAN (single).
    const accSel = el('select');
    for (const v of vlans) { const o = el('option', '', String(v)); o.value = String(v); accSel.appendChild(o); }
    if (sw.mode === 'access' && sw.untagged[0]) accSel.value = String(sw.untagged[0]);
    const accField = field('Access VLAN', accSel);
    grid.appendChild(accField);

    // Trunk native (single).
    const natSel = el('select');
    for (const v of vlans) { const o = el('option', '', String(v)); o.value = String(v); natSel.appendChild(o); }
    if (sw.mode === 'trunk' && sw.untagged[0]) natSel.value = String(sw.untagged[0]);
    const natField = field('Native (untagged)', natSel);
    grid.appendChild(natField);

    // Trunk tagged (multi).
    const tagSel = el('select'); tagSel.multiple = true; tagSel.size = Math.min(6, Math.max(2, vlans.length));
    for (const v of vlans) {
      const o = el('option', '', String(v)); o.value = String(v);
      if (sw.mode === 'trunk' && sw.tagged.indexOf(v) !== -1) o.selected = true;
      tagSel.appendChild(o);
    }
    const tagField = field('Tagged VLANs (ctrl/cmd-click)', tagSel);
    grid.appendChild(tagField);

    box.appendChild(grid);

    // What the chosen mode means, in one line, shown under the fields.
    const modeNote = el('div', 'card-sub');
    box.appendChild(modeNote);

    const syncMode = () => {
      const m = modeSel.value;
      accField.style.display = m === 'access' ? '' : 'none';
      natField.style.display = m === 'trunk' ? '' : 'none';
      tagField.style.display = m === 'trunk' ? '' : 'none';
      modeNote.textContent = m === 'routed'
        ? (wasRouted ? 'Routed port: it has no VLANs. Set its address in IPv4 Addressing.'
          : 'Applying makes this a routed port (no switchport): it leaves its VLANs, and its address is then set in IPv4 Addressing.')
        : (wasRouted ? 'Applying makes this a switchport again and removes the port’s IPv4 address.' : '');
      modeNote.style.display = modeNote.textContent ? '' : 'none';
    };
    modeSel.addEventListener('change', syncMode); syncMode();

    if (lockReason) box.appendChild(el('div', 'sw-warn', lockReason));
    // Inline, non-blocking uplink caution (no browser prompt).
    else if (sw.uplink) {
      box.appendChild(el('div', 'sw-warn',
        'Caution: this port is ' + sw.uplink + '. Changing its mode or VLANs may cut your management connection to the switch.'));
    }

    const { actions, apply: save, msg } = applyActions('Apply', { msgClass: 'sw-msg' });
    box.appendChild(actions);
    box.appendChild(msg);

    // A change of category (switchport <-> routed) takes something away, so
    // Apply asks first and names what goes; an ordinary mode/VLAN change
    // applies on the first tap, as before.
    const categoryChanges = () => (modeSel.value === 'routed') !== (sw.l2l3 === 'L3');
    const confirmText = () => {
      if (modeSel.value !== 'routed') return 'Make switchport: removes its IPv4 address';
      const vl = Array.from(new Set([].concat(sw.untagged || [], sw.tagged || []).map(String))).filter(Boolean);
      return 'Make routed: removes ' + detail.name + (vl.length ? ' from VLAN ' + vl.join(', ') : ' from its VLANs');
    };
    withConfirm(save, (ev) => {
      const cfg = { ifIndex: detail.ifIndex, mode: modeSel.value, wasRouted: sw.l2l3 === 'L3', before: switchportBefore(s, detail) };
      clear(msg);
      if (cfg.mode === 'routed' && cfg.wasRouted) { msg.appendChild(el('div', 'card-sub', 'No changes.')); return; }
      if (cfg.mode === 'trunk') {
        cfg.native = parseInt(natSel.value, 10);
        cfg.tagged = Array.from(tagSel.selectedOptions).map((o) => parseInt(o.value, 10)).filter(Number.isFinite);
      } else if (cfg.mode === 'access') {
        cfg.access = parseInt(accSel.value, 10);
      }
      runButtonAction(ev.currentTarget, {
        failLabel: 'Save switchport', spinLabel: 'Saving…',
        run: () => applySwitchportConfig(s, cfg),
        ok: (res) => res && res.ok,
        error: (res) => {
          const box2 = el('div', 'sw-err');
          box2.appendChild(el('div', '', res && res.restored === true
            ? 'The switch refused the change, so the port was put back as it was:'
            : res && res.restored === false
              ? 'The switch refused the change, and putting the port back failed too. Check this port:'
              : 'Some steps failed:'));
          const pre = el('pre'); pre.className = 'diff'; pre.textContent = (res && res.log ? res.log.join('\n') : 'unknown error');
          box2.appendChild(pre); msg.appendChild(box2);
          return 'some steps failed';
        },
        onApplied: () => {
          markConfigDirty(s, [modeSel].concat(cfg.mode === 'access' ? [accSel] : cfg.mode === 'trunk' ? [natSel] : []));
          const nowRouted = cfg.mode === 'routed';
          if (nowRouted !== cfg.wasRouted) {
            sw.l2l3 = nowRouted ? 'L3' : 'L2';
            syncMode();
          }
          if (nowRouted) return;
          sw.mode = cfg.mode;
          if (cfg.mode === 'access') { sw.untagged = [cfg.access]; sw.tagged = []; }
          else {
            sw.untagged = [cfg.native];
            sw.tagged = Array.from(new Set([cfg.native].concat(cfg.tagged))).sort((a, b) => a - b);
          }
          s._vlanFlashSet = new Set();
          if (cfg.mode === 'access') { if (cfg.access) s._vlanFlashSet.add(Number(cfg.access)); }
          else { if (cfg.native) s._vlanFlashSet.add(Number(cfg.native)); for (const t of (cfg.tagged || [])) s._vlanFlashSet.add(Number(t)); }
        },
        settle: () => new Promise((res) => setTimeout(() => refreshTables(s, ['interfaces', 'portModes', 'portL2L3', 'vlansCurrent', 'vlans', 'sviAddrs', 'portAccessVlan', 'portNativeVlan']).then(res, res), 1200))
      });
    }, { when: categoryChanges, confirmText, danger: true });

    return box;
  }

  // The SET steps that put a port into one switchport state. VlanIndex as
  // Gauge, native always in the allowed bitmap (all four blocks, so the list is
  // exact), mode flipped last so a rejected VLAN write can't leave a port in a
  // new mode with no membership. state: { mode: 'access'|'trunk', access,
  // native, tagged }. Each step is [title, varbinds], with an optional { waitBefore: ms }.
  function switchportSteps(if_, st) {
    const steps = [];
    if (st.mode === 'trunk') {
      steps.push(['native', [{ oid: 'vlanTrunkPortModeNativeVlanId.' + if_, type: 'Gauge', value: st.native }]]);
      const allowed = Array.from(new Set([st.native].concat(st.tagged || []))).filter(Number.isFinite).sort((a, b) => a - b);
      for (const [name, hex] of vlanListBlocks(allowed)) {
        steps.push([name, [{ oid: name + '.' + if_, type: 'OctetString', valueHex: hex }]]);
      }
      steps.push(['mode=trunk', [{ oid: 'vlanPortModeState.' + if_, type: 'Integer', value: 12 }]]);
    } else if (st.mode === 'access') {
      steps.push(['access-vlan', [{ oid: 'vlanAccessPortModeVlanId.' + if_, type: 'Gauge', value: st.access }]]);
      steps.push(['mode=access', [{ oid: 'vlanPortModeState.' + if_, type: 'Integer', value: 11 }]]);
    }
    return steps;
  }

  // The SET steps that give a routed port back the addresses it had: a static
  // row (address, ifIndex, mask, active) or the DHCP client (createAndGo).
  function addressRestoreSteps(if_, addrs) {
    const steps = [];
    for (const a of (addrs || [])) {
      if (a.owner === 2) steps.push(['DHCP client', [{ oid: DHCP_CL.status + '.' + if_, type: 'Integer', value: 4 }]]);
      else if (a.owner === 1 && a.ip && a.mask) {
        steps.push(['address ' + a.ip, ifAddressVarbinds(a.ip, a.mask, if_)]);
      }
    }
    // One DHCP step is enough however many rows the lease shows.
    return steps.filter((st, i) => st[0] !== 'DHCP client' || steps.findIndex((x) => x[0] === 'DHCP client') === i);
  }

  // The whole change as two lists of steps: the change itself, and the undo
  // that puts the port back as it was (cfg.before), run when a step fails.
  //   cfg: { ifIndex, mode: 'access'|'trunk'|'routed', access, native, tagged,
  //          wasRouted, before: { mode, access, native, tagged, addrs } }
  // Category changes go through vlanSwitchPortModeCategory: routed = 2 ("no
  // switchport"); back to a switchport = the port's IPv4 address and DHCP
  // client come off first (teardown, run by the caller), then 1
  // ("switchport"), then the usual access/trunk steps.
  const ROUTED_SETTLE_MS = 2500;
  function planSwitchportChange(cfg) {
    const if_ = cfg.ifIndex;
    const CATEGORY = 'vlanSwitchPortModeCategory.' + if_;
    const before = cfg.before || {};
    const forward = [];
    const undo = [];
    if (cfg.mode === 'routed') {
      forward.push(['no switchport', [{ oid: CATEGORY, type: 'Integer', value: 2 }]]);
      undo.push(['switchport', [{ oid: CATEGORY, type: 'Integer', value: 1 }]]);
      undo.push(...switchportSteps(if_, before));
    } else {
      if (cfg.wasRouted) {
        forward.push(['switchport', [{ oid: CATEGORY, type: 'Integer', value: 1 }]]);
        undo.push(['no switchport', [{ oid: CATEGORY, type: 'Integer', value: 2 }]]);
        // The switch refuses an address for about 2 s after the category
        // changes, so the first address step waits.
        const back = addressRestoreSteps(if_, before.addrs);
        if (back.length) back[0] = [back[0][0], back[0][1], { waitBefore: ROUTED_SETTLE_MS }];
        undo.push(...back);
      } else {
        undo.push(...switchportSteps(if_, before));
      }
      forward.push(...switchportSteps(if_, cfg));
    }
    // The undo can only put back a state it knows: an access port with its
    // VLAN, or a trunk with its native VLAN. Anything else (a mode this
    // editor doesn't offer) is reported as not restorable.
    const knownBefore = cfg.wasRouted ||
      (before.mode === 'access' && Number.isFinite(before.access)) ||
      (before.mode === 'trunk' && Number.isFinite(before.native));
    return { forward, undo, undoComplete: knownBefore, teardownFirst: !!cfg.wasRouted && cfg.mode !== 'routed' };
  }

  // Send steps in order through snmpSetResult. stopOnFail: the first failure
  // ends the run. Returns { ok, sent, log }; `sent` counts the steps that
  // reached the switch and succeeded.
  async function runSetSteps(s, steps, log, prefix, stopOnFail) {
    let ok = true, sent = 0;
    for (const [title, vbs, opt] of steps) {
      if (opt && opt.waitBefore) await new Promise((r) => setTimeout(r, opt.waitBefore));
      let stepOk = true;
      try {
        const { ok: rOk, status, body } = await snmpSetResult(s, vbs);
        if (!rOk || (body && body.error)) { stepOk = false; log.push(prefix + title + ': ERROR ' + ((body && body.error) || ('HTTP ' + status))); }
        else {
          const bad = (body.results || []).find((v) => v.error);
          if (bad) { stepOk = false; log.push(prefix + title + ': ' + bad.oid + ' ' + bad.error); }
          else log.push(prefix + title + ': ok');
        }
      } catch (e) { stepOk = false; log.push(prefix + title + ': ' + e.message); }
      if (stepOk) sent++;
      else { ok = false; if (stopOnFail) break; }
    }
    return { ok, sent };
  }

  // The production write. Returns { ok, restored, log:[] }. It stops at the
  // first rejected step and then puts the port back the way it was (the undo
  // of planSwitchportChange), so a change is either whole or undone, never
  // left half-applied. `restored` is true when the undo went through, false
  // when it failed (the port needs checking), undefined when nothing failed.
  async function applySwitchportConfig(s, cfg) {
    const log = [];
    if (!s.target) return { ok: false, log: ['Not connected.'] };
    // Hold the browser's own refreshes during the write: this firmware has
    // crashed when a full multi-table walk lands on top of a config-touching
    // SNMP write. (The server holds its collection too: write-hold.js.)
    const ownsBusy = !s.writeBusy;
    if (ownsBusy) s.writeBusy = true;
    const plan = planSwitchportChange(cfg);
    let res, restored;
    try {
      if (plan.teardownFirst) {
        // teardownSvi is best-effort per row and never throws; if an address
        // survives it, the category step below is the one that reports it.
        await teardownSvi(s, cfg.ifIndex);
        log.push('remove IPv4 address: sent');
      }
      res = await runSetSteps(s, plan.forward, log, '', true);
      if (!res.ok && (res.sent > 0 || plan.teardownFirst)) {
        log.push('Putting the port back as it was:');
        const back = await runSetSteps(s, plan.undo, log, '  undo ', false);
        restored = back.ok && plan.undoComplete;
        if (!plan.undoComplete) log.push('  The port was in a mode this editor cannot put back.');
        log.push(restored ? 'The port is back as it was.' : 'The undo failed too. Check this port on the switch.');
      } else if (!res.ok) {
        restored = true;   // the first step was refused: nothing changed
      }
    } finally {
      if (ownsBusy) s.writeBusy = false;
    }
    appLog(res && res.ok ? 'info' : 'error', 'Switchport config applied', { host: s.host, ifIndex: cfg.ifIndex, mode: cfg.mode, ok: !!(res && res.ok), restored });
    return { ok: !!(res && res.ok), restored, log };
  }

  // 802.1X per-port editor: shows current port-control, status, and host-mode,
  // and lets a write-capable session change port-control and host-mode. These
  // are SNMP SETs to dot1xAuthAuthControlledPortControl and swIfHostMode.
  const DOT1X_CONTROL_OID = '1.0.8802.1.1.1.1.2.1.1.6';   // dot1xAuthAuthControlledPortControl
  const SWIF_HOSTMODE_OID = '1.3.6.1.4.1.9.6.1.101.43.1.1.30'; // swIfHostMode
  const GUEST_VLAN_PORTS_OID = '1.3.6.1.4.1.9.6.1.101.95.5';   // rldot1xGuestVlanPorts (PortList scalar)
  const PORT_METHOD_OID = '1.3.6.1.4.1.9.6.1.101.95.10.1.1';   // rldot1xAuthenticationPortMethod (per-port)
  const CONTROL_OPTS = [{ label: 'force-unauthorized', value: 1 }, { label: 'auto', value: 2 }, { label: 'force-authorized', value: 3 }];
  const HOSTMODE_OPTS = [{ label: 'single', value: 1 }, { label: 'multiple', value: 2 }, { label: 'multiple-auth', value: 3 }];

  function buildDot1xEditor(s, detail) {
    const box = el('div', 'port-detail-dot1x');
    const d = detail.dot1x;
    // Current state, always shown.
    const dl = el('dl', 'port-detail-grid');
    const row = (k, v) => { if (v) { dl.appendChild(el('dt', '', k)); dl.appendChild(el('dd', '', enumWord(v))); } };
    row('Port-control', d.control || '(not set)');
    row('Status', d.status || '(unknown)');
    row('Host-mode', d.hostMode || '(not set)');
    box.appendChild(dl);

    // The editor is always shown (like the switchport editor in this same
    // popout); a write without sufficient access fails with a clear error from
    // the switch rather than being hidden. Only shown for ports the switch
    // actually reports 802.1X config for.
    const grid = el('div', 'snmp-form-grid');
    const ctlSel = el('select');
    for (const o of CONTROL_OPTS) { const op = el('option', '', o.label); op.value = String(o.value); if (o.value === d.controlCode) op.selected = true; ctlSel.appendChild(op); }
    grid.appendChild(field('Port-control', ctlSel));
    const hmSel = el('select');
    for (const o of HOSTMODE_OPTS) { const op = el('option', '', o.label); op.value = String(o.value); if (o.value === d.hostModeCode) op.selected = true; hmSel.appendChild(op); }
    grid.appendChild(field('Host-mode', hmSel));

    // Authentication methods on this port (802.1X / MAC / Web). MAC = MAB (MAC
    // Authentication Bypass). The switch stores this as one enum encoding the
    // combination (rldot1xAuthenticationPortMethod), same scheme as the global
    // trap matrix. Decode it into three checkboxes; re-encode on apply.
    const PORT_METHOD_ENUM = { 1: ['eapol'], 2: ['mac', 'eapol'], 3: ['mac'], 4: ['web'], 5: ['web', 'eapol'], 6: ['web', 'mac'], 7: ['web', 'mac', 'eapol'] };
    const methodToEnum = (set) => {
      for (const v of Object.keys(PORT_METHOD_ENUM)) { const ms = PORT_METHOD_ENUM[v]; if (ms.length === set.size && ms.every((m) => set.has(m))) return Number(v); }
      return null;
    };
    const curMethodSet = new Set(PORT_METHOD_ENUM[d.methodCode] || (d.methodCode == null ? ['eapol'] : []));
    const methodCbs = {};
    const methodBox = el('div', 'dot1x-method-row');
    for (const [m, label] of [['eapol', '802.1X'], ['mac', 'MAC (MAB)'], ['web', 'Web']]) {
      const lab = el('label', 'check-label');
      const cb = el('input'); cb.type = 'checkbox'; cb.checked = curMethodSet.has(m);
      methodCbs[m] = cb;
      lab.appendChild(cb); lab.appendChild(el('span', '', label));
      methodBox.appendChild(lab);
    }
    grid.appendChild(field('Auth methods', methodBox));

    // Guest VLAN enable for this port. Driven by the rldot1xGuestVlanPorts
    // PortList bitmap (a scalar): this port's bit set = guest VLAN enabled.
    const gvBitmap = (s.health && s.health.scalars && s.health.scalars.rldot1xGuestVlanPorts) || null;
    const gvHex = gvBitmap ? String(gvBitmap.value !== undefined ? gvBitmap.value : gvBitmap.display || '').replace(/0x|\s|\(hex\)|"/gi, '') : '';
    const portNum = Number(detail.ifIndex);
    const gvWasOn = portBitSet(gvHex, portNum);
    const gvCb = el('input'); gvCb.type = 'checkbox'; gvCb.checked = gvWasOn;
    const gvWrap = el('label', 'snmp-field-check'); gvWrap.appendChild(gvCb); gvWrap.appendChild(el('span', '', 'Guest VLAN enabled'));
    grid.appendChild(gvWrap);
    box.appendChild(grid);

    const { actions, apply, msg } = applyActions('Apply');
    const ctlOid = DOT1X_CONTROL_OID + '.' + detail.ifIndex;
    const hmOid = SWIF_HOSTMODE_OID + '.' + detail.ifIndex;
    const setOne = (oid, value) => snmpSet(s, { oid, type: 'Integer', value });
    // Re-read the live port-control and host-mode for this port and refresh the
    // popout's display, so it reflects what the switch actually holds now.
    const reread = async () => {
      try {
        const { ok, body } = await apiPost('/api/snmp/get', { target: s.target, oids: [ctlOid, hmOid] });
        if (ok && body && !body.error) {
          const CTL = { 1: 'force-unauth', 2: 'auto', 3: 'force-auth' };
          const HM = { 1: 'single', 2: 'multiple', 3: 'multiple-auth' };
          for (const vb of (body.results || [])) {
            if (vb.error) continue;
            const n = parseInt(vb.value, 10);
            if (!Number.isFinite(n)) continue;
            // Distinguish by the OID: the port-control OID is the IEEE arc
            // (1.0.8802…); host-mode is the Cisco arc. Match on the oid field,
            // which carries the numeric OID (the name field does not).
            const oidStr = String(vb.oid || vb.name || '');
            if (oidStr.indexOf('1.0.8802') >= 0) { d.controlCode = n; d.control = CTL[n] || d.control; }
            else { d.hostModeCode = n; d.hostMode = HM[n] || d.hostMode; }
          }
          // Reflect the re-read values in the dropdowns and the display grid.
          ctlSel.value = String(d.controlCode); hmSel.value = String(d.hostModeCode);
          const dds = dl.querySelectorAll('dd');
          if (dds[0]) dds[0].textContent = d.control || '(not set)';
          if (dds[2]) dds[2].textContent = d.hostMode || '(not set)';
        }
      } catch (e) { /* non-fatal: the table refresh still runs */ }
    };

    withConfirm(apply, (ev) => {
      clear(msg);
      const newCtl = parseInt(ctlSel.value, 10);
      const newHm = parseInt(hmSel.value, 10);
      const ctlChanged = newCtl !== d.controlCode;
      const hmChanged = newHm !== d.hostModeCode;
      const gvChanged = gvCb.checked !== gvWasOn;
      const newMethodSet = new Set(['eapol', 'mac', 'web'].filter((m) => methodCbs[m].checked));
      const newMethod = methodToEnum(newMethodSet);
      const methodChanged = newMethod != null && newMethod !== d.methodCode;
      if (!ctlChanged && !hmChanged && !gvChanged && !methodChanged) { msg.appendChild(el('div', 'card-sub', 'No changes.')); return; }
      runButtonAction(ev.currentTarget, {
        failLabel: '802.1X change',
        run: async () => {
          s.writeBusy = true;
          try {
            if (hmChanged) {
              if (d.controlCode !== 3) await setOne(ctlOid, 3);
              await setOne(hmOid, newHm);
              if (newCtl !== 3) await setOne(ctlOid, newCtl);
            } else if (ctlChanged) {
              await setOne(ctlOid, newCtl);
            }
            if (methodChanged) await setOne(PORT_METHOD_OID + '.' + detail.ifIndex, newMethod);
            if (gvChanged) {
              const newHex = setPortBit(gvHex, portNum, gvCb.checked);
              try { await snmpSet(s, { oid: GUEST_VLAN_PORTS_OID + '.0', type: 'OctetString', valueHex: newHex }); }
              catch (e) { throw new Error('guest VLAN: ' + e.message); }
            }
            s.writeBusy = false;
            const changedControls = [];
            if (ctlChanged) changedControls.push(ctlSel);
            if (hmChanged) changedControls.push(hmSel);
            if (methodChanged) for (const m of ['eapol', 'mac', 'web']) changedControls.push(methodCbs[m]);
            if (gvChanged) changedControls.push(gvCb);
            return { ok: true, changedControls: changedControls, gvChanged: gvChanged };
          } catch (e) { s.writeBusy = false; return { ok: false, error: e.message }; }
        },
        ok: (r) => r && r.ok,
        error: (r) => { msg.appendChild(el('div', 'sw-err', '802.1X change failed: ' + ((r && r.error) || 'failed'))); reread(); return (r && r.error) || 'failed'; },
        onApplied: (r) => markConfigDirty(s, r.changedControls),
        settle: async (r) => {
          await reread();
          if (r.gvChanged) { await refreshScalars(s, { rldot1xGuestVlanPorts: GUEST_VLAN_PORTS_OID }); }
          return refreshTables(s, ['dot1xPortCfg', 'dot1xHostMode', 'dot1xPortMethod']);
        }
      });
    });

    box.appendChild(actions); box.appendChild(msg);
    return box;
  }

  // Build a minimal q-bridge PortList octet string with a single port's bit
  // set. Encoding (same MSB-first scheme as the VLAN-list bitmaps): octet 0
  // covers ports 1-8, MSB = lowest port. Only as many octets as needed to reach
  // the port are emitted; the agent treats missing trailing octets as zero.
  function buildPortListBit(portNum) {
    const byteCount = Math.floor((portNum - 1) / 8) + 1;
    const buf = new Uint8Array(byteCount);
    const bit = portNum - 1;
    buf[Math.floor(bit / 8)] |= (0x80 >> (bit % 8));
    let hex = '';
    for (const b of buf) hex += b.toString(16).padStart(2, '0');
    return hex;
  }

  // Reset one port's MIB counters via rlIfClearPortMibCounters (a read-write
  // PortList scalar: each set bit = a port whose counters are cleared). A
  // PortList bit is a bridge port number. On the C1200/C1300 a physical port's
  // bridge port equals its ifIndex (the recorded C1300-24MGP-4X: gi1/0/1-24 =
  // 1-24, te1/0/1-4 = 49-52 in both dot1dBasePortTable and rlifPresentTable),
  // so the ifIndex is the bit position, as in the port-channel member lists.
  async function clearPortCounters(s, ifIndex) {
    if (!s.target) return { ok: false, error: 'Not connected.' };
    const ownsBusy = !s.writeBusy;
    if (ownsBusy) s.writeBusy = true;
    let out;
    try {
      const { ok, status, body } = await snmpSetResult(s, { oid: 'rlIfClearPortMibCounters.0', type: 'OctetString', valueHex: buildPortListBit(ifIndex) });
      if (!ok || (body && body.error)) out = { ok: false, error: (body && body.error) || ('HTTP ' + status) };
      else {
        const bad = (body.results || []).find((v) => v.error);
        out = bad ? { ok: false, error: bad.error } : { ok: true };
      }
    } catch (e) { out = { ok: false, error: e.message }; }
    if (ownsBusy) s.writeBusy = false;
    appLog(out.ok ? 'info' : 'error', 'Clear port counters', { host: s.host, ifIndex, ok: out.ok });
    return out;
  }

  async function fetchPortCounters(s, ifIndex, wrap) {
    if (!s.target) { clear(wrap); wrap.appendChild(el('div', 'card-sub', 'Not connected.')); return; }
    // Build the full OID list (preferred 64-bit plus 32-bit fallback), then
    // fetch in small batches. A single 22-OID GET can produce a reply the SNMP
    // library fails to parse, which never resolves — small PDUs avoid that and
    // also let partial data show if one batch fails.
    const oids = [];
    for (const row of PORT_COUNTERS) for (let i = 1; i < row.length; i++) oids.push(row[i] + '.' + ifIndex);
    const BATCH = 6;
    const byName = new Map();
    let anyError = null;
    for (let i = 0; i < oids.length; i += BATCH) {
      const slice = oids.slice(i, i + BATCH);
      try {
        const { ok, status, body } = await apiPost('/api/snmp/get', { target: s.target, oids: slice });
        if (!ok || (body && body.error)) { anyError = (body && body.error) || ('HTTP ' + status); continue; }
        for (const vb of ((body && body.results) || [])) {
          if (vb.error) continue;
          const col = vb.column || (vb.name ? String(vb.name).split('.')[0] : '');
          if (col && !byName.has(col)) byName.set(col, vb);
        }
      } catch (e) { anyError = e.message; }
    }
    clear(wrap);
    const dlg = el('dl', 'port-detail-grid');
    for (const row of PORT_COUNTERS) {
      let vb = null;
      for (let i = 1; i < row.length; i++) { vb = byName.get(row[i]); if (vb) break; }
      if (!vb) continue;
      const val = vb.display !== undefined && vb.display !== null && vb.display !== String(vb.value)
        ? vb.display : vb.value;
      dlg.appendChild(el('dt', '', row[0]));
      dlg.appendChild(el('dd', '', enumWord(String(val === undefined || val === null ? '' : val))));
    }
    if (dlg.children.length) {
      wrap.appendChild(dlg);
      wrap.appendChild(el('div', 'card-sub', 'Read live at ' + new Date().toLocaleTimeString() + '.'));
    } else {
      wrap.appendChild(el('div', 'card-sub',
        anyError ? ('Could not read counters: ' + anyError) : 'No counter values returned.'));
    }
  }

  function portActionsCell(s, info) {
    const td = document.createElement('td');
    td.className = 'tbl-act';

    const done = (message) => {
      clear(td);
      td.appendChild(el('span', 'card-sub', message));
      setTimeout(paint, 4000);
    };

    const post = (url, body, describe, btn) => {
      // Port actions (PoE bounce, admin up/down) bounce the port; suppress the
      // reactive link-trap refresh while we do our own targeted update.
      s._ifWriteUntil = Date.now() + 12000;
      const hasIf = info.ifIndex !== null && info.ifIndex !== undefined;
      runButtonAction(btn, {
        failLabel: info.name,
        run: () => apiPost(url, Object.assign({ target: s.target }, body)),
        ok: (res) => res && res.ok && !(res.body && res.body.error),
        error: (res) => (res && res.body && res.body.error) || 'unknown',
        onApplied: (res) => { appLog('info', 'Port action complete', Object.assign({ host: s.host, port: info.name }, res.body || {})); markConfigDirty(s); },
        settle: () => hasIf ? refreshOnePort(s, info.ifIndex).then(() => { setTimeout(() => refreshOnePort(s, info.ifIndex), 3000); }) : Promise.resolve(),
        // When there is no button to flash (shouldn't happen here) or the action
        // wasn't on the keyed table, fall back to the inline text summary.
        onDone: (res) => { if (!btn) done(describe(res.body || {})); }
      }).catch(() => { /* toast already shown by the helper */ });
    };

    function paint() {
      clear(td);
      const group = [];
      // Bounce PoE and shut/no-shut only make sense for a port that has an L2 or
      // L3 mode defined. A port whose L2/L3 mode is blank (unconfigured /
      // non-switching) does not get these controls. If the switch reports no
      // L2/L3 data at all (hasL2L3Data false), the controls are allowed since we
      // cannot tell - we only withhold them when we positively know the mode is
      // absent for that port.
      const showControls = (info.l2l3 === 'L2' || info.l2l3 === 'L3') ||
        (info.hasL2L3Data === false);
      if (info.poePort && showControls) {
        // Two-tap confirm (like every other action); the uplink warning, when
        // relevant, rides in the button title.
        const b = actBtnConfirm('Bounce PoE',
          (e) => post('/api/port/poe', { port: info.poePort, action: 'bounce' },
            (out) => (out.enabled ? 'power restored' : 'still off') +
              (out.configRestored === false ? ' \u00b7 config left unsaved' : ''), e.currentTarget),
          'danger',
          'Power-cycle ' + info.name + (info.uplink ? ' \u2014 faces ' + info.uplink : '') + ' to reboot whatever it powers');
        group.push(b);
      }
      if (info.ifIndex && showControls) {
        const down = info.adminUp;
        const b = actBtnConfirm(down ? 'Shut' : 'No shut',
          (e) => post('/api/port/admin', { ifIndex: info.ifIndex, action: down ? 'down' : 'up' },
            (out) => 'admin ' + (out.admin === 1 ? 'up' : 'down'), e.currentTarget),
          down ? 'danger' : '',
          (down ? 'Administratively disable ' : 'Re-enable ') + info.name +
            (down && info.uplink ? ' \u2014 faces ' + info.uplink + ', shutting it may cut off this switch' : ''));
        group.push(b);
      }
      if (group.length) td.appendChild(actGroup(group));
      else td.appendChild(el('span', 'card-sub', '\u2014'));
    }

    paint();
    return td;
  }

  /** Collapse a list of numbers into ranges: 1,2,3,7 -> "1-3, 7". */
  function rangeOf(list) {
    const nums = list.map(Number).filter((n) => Number.isFinite(n)).sort((a, b) => a - b);
    if (!nums.length) return '';
    const out = [];
    let start = nums[0], prev = nums[0];
    for (let i = 1; i <= nums.length; i++) {
      const n = nums[i];
      if (n === prev + 1) { prev = n; continue; }
      out.push(start === prev ? String(start) : start + '-' + prev);
      start = prev = n;
    }
    return out.join(', ');
  }
