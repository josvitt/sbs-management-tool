  // =================================================================
  // 17-snmp-config.js: SNMP configuration (communities, groups, users,
  // notification recipients); first-run SNMP setup.
  // =================================================================

  // SNMP configuration is a keyed panel (standard B1b) whose rows come from its
  // own loader instead of health.js. Its data is a computed view on the server
  // (/api/snmp-config joins the community, VACM and target tables and probes
  // what this credential may do), and a load is ~35 walks, about the whole pps
  // budget (B5a), so it is read on demand once per visit, never on the health
  // cycle. Everything else is the keyed-panel pattern: a B2 skeleton, mountInto
  // tables with stable keys, counts refreshed in place, and a write that
  // re-reads only its own section and reconciles.
  //
  // s._snmp = { data, fetchedAt, loading, editable }. data holds one reply per
  // action below; data.error is set when the local server could not be reached.
  // editable (a full SNMP Admin credential) is also read by the AAA panel.

  // The section reads, in load order, and where each lands in s._snmp.data.
  const SNMP_LISTS = [['recipients', 'recips'], ['communities', 'comms'], ['groups', 'groups'],
    ['users', 'users'], ['target-check', 'tcheck'], ['views', 'views']];

  async function snmpCfgPost(s, action, extra) {
    const { body } = await apiPost('/api/snmp-config/' + action, Object.assign({ target: s.target }, extra || {}));
    return body || { ok: false, error: 'no reply from the local server' };
  }

  // Load everything. The reads go ONE AT A TIME, not in parallel: each opens
  // its own SNMP session on the server and walks several tables, and a C1300's
  // agent handles concurrent sessions badly, especially right after a VACM or
  // community change. Returns the in-flight promise if a load is running.
  function snmpLoad(s) {
    s._snmp = s._snmp || {};
    const st = s._snmp;
    if (st.loading) return st.loading;
    st.fetchedAt = Date.now();
    st.liveAt = Date.now();
    st.loading = (async () => {
      const d = {};
      try { d.access = await snmpCfgPost(s, 'access'); }
      catch (e) { st.data = { error: 'Lost contact with the local server: ' + e.message }; st.editable = false; return; }
      st.editable = !!(d.access.ok && d.access.level === 'full');
      // A credential that cannot read the config tables gets only the banner.
      if (!(d.access.ok && d.access.level === 'limited')) {
        for (const [action, k] of SNMP_LISTS) d[k] = await snmpCfgPost(s, action).catch(() => null);
      }
      st.data = d;
    })().finally(() => { st.loading = null; snmpRepaint(s); });
    return st.loading;
  }
  // Once per visit: on open, unless a load is running or ran in the last 30 s.
  function ensureSnmpLoaded(s) {
    if (!s.target) return;
    const st = s._snmp || {};
    if (st.data && st.collected) return;            // the snapshot carries it (adoptCollectedModules)
    if (st.loading || Date.now() - (st.fetchedAt || 0) < 30000) return;
    snmpLoad(s);
  }
  // After a write: re-read only the sections it touched (plus the target
  // integrity check when recipients or communities changed, since those own
  // target rows), then reconcile. Returns a promise for a write's settle.
  async function snmpRefresh(s, names) {
    const st = s._snmp;
    if (!st || !st.data || st.data.error) return snmpLoad(s);
    st.liveAt = Date.now();      // newer than any snapshot taken before this write
    const want = names.slice();
    if (want.some((n) => n === 'recipients' || n === 'communities')) want.push('target-check');
    for (const [action, k] of SNMP_LISTS) {
      if (want.indexOf(action) !== -1) st.data[k] = await snmpCfgPost(s, action).catch(() => null);
    }
    snmpRepaint(s);
  }
  function snmpRepaint(s) {
    const p = s.panels && s.panels.find((x) => x.kind === 'builtin' && x.key === 'snmpcfg');
    if (!p || !p._body || p.collapsed) return;
    if (!reconcilePanelInPlace(s, p)) repaintPanel(s, 'snmpcfg');
  }

  // One write: POST the apply action and normalise the reply for
  // runButtonAction. s.writeBusy holds health refreshes off the switch while
  // the write runs.
  async function snmpWrite(s, action, payload) {
    s.writeBusy = true;
    try {
      const j = await snmpCfgPost(s, action, payload);
      if (!j.ok) return { ok: false, error: j.error || 'the switch rejected it' };
      const r = j.applied;
      if (r && !r.ok) {
        const bad = (r.log || []).find((x) => !x.ok);
        return { ok: false, error: (bad && bad.detail) || 'the switch rejected it' };
      }
      return { ok: true };
    } catch (e) {
      return { ok: false, error: 'lost contact with the local server: ' + e.message };
    } finally { s.writeBusy = false; }
  }

  // A two-tap Delete for a table row (B6): spins until the section is re-read.
  function snmpDeleteCell(s, label, action, payload, sections, title) {
    return { cellNode: actGroup([actBtnConfirm(label === 'Remove row' ? 'Remove' : 'Delete', (e) => {
      runButtonAction(e.currentTarget, {
        failLabel: label,
        run: () => snmpWrite(s, action, payload),
        ok: (r) => r && r.ok,
        error: (r) => (r && r.error) || 'the switch rejected it',
        onApplied: () => markConfigDirty(s),
        settle: () => snmpRefresh(s, sections)
      });
    }, 'danger', title)]), sig: 'del' };
  }

  // The panel (standard B2): scaffolding on a full paint only; keyed tables
  // through mountInto on every pass; counts and notes in stable nodes.
  function paintSnmpPanel(s, body, p) {
    if (!s._ktReconcile) clear(body);
    if (!s.target) { if (!s._ktReconcile) body.appendChild(el('div', 'card-sub', 'Add SNMP credentials for this switch first.')); return; }
    if (!s._ktReconcile) ensureSnmpLoaded(s);
    const d = s._snmp && s._snmp.data;
    if (!d) {
      if (!s._ktReconcile) { body.appendChild(el('div', 'card-sub', 'Waiting for data\u2026')); p._snmpWaiting = true; }
      return;
    }
    // What this credential may do decides the whole layout, so a change of it
    // (or the first data arriving) is structural.
    const access = d.access || {};
    const mode = d.error ? 'error' : (access.ok ? access.level : 'unknown');
    if (s._ktReconcile && (p._snmpWaiting || p._snmpMode !== mode)) { s._ktStructural = true; return; }
    p._snmpWaiting = false;
    p._snmpMode = mode;
    if (!s._ktReconcile) { p._snmpNotes = {}; p._snmpSubs = {}; }

    if (mode === 'error') { if (!s._ktReconcile) body.appendChild(el('div', 'panel-err', d.error)); return; }
    // Access banner: shown unless the credential is a full SNMP Admin.
    if (!s._ktReconcile) {
      if (mode === 'unknown') {
        body.appendChild(el('div', 'sw-err', 'Could not check what this credential may change: ' + (access.error || 'no answer') + '.'));
      } else if (mode !== 'full') {
        const banner = el('div', 'snmp-access-banner ' + (mode === 'limited' ? 'warn' : 'info'));
        banner.appendChild(el('span', 'snmp-access-icon', mode === 'limited' ? '\u26a0' : '\u2139'));
        p._snmpBanner = el('span', '', '');
        banner.appendChild(p._snmpBanner);
        body.appendChild(banner);
      }
    }
    if (p._snmpBanner) p._snmpBanner.textContent = access.summary || '';
    if (mode === 'limited') return;
    const editable = mode === 'full';

    const section = (name, title, addLabel, onAdd) => {
      if (s._ktReconcile) return;
      const st = el('div', 'section-title', title);
      p._snmpNotes[name] = el('span', 'st-note', '');
      st.appendChild(p._snmpNotes[name]);
      body.appendChild(st);
      if (addLabel && editable) body.appendChild(addControl(addLabel, onAdd));
    };
    const note = (name, text) => { const n = p._snmpNotes[name]; if (n) n.textContent = text; };
    // A muted line under a heading, kept in a stable node.
    const sub = (name, text) => {
      if (!s._ktReconcile) { p._snmpSubs[name] = el('div', 'card-sub', ''); body.appendChild(p._snmpSubs[name]); }
      const n = p._snmpSubs[name]; if (n) { n.textContent = text || ''; n.style.display = text ? '' : 'none'; }
    };
    const emptyNote = (msg) => { if (!s._ktReconcile) body.appendChild(el('div', 'card-sub', msg)); };
    const count = (n, one, many) => n + ' ' + (n === 1 ? one : many);
    const act = editable ? [''] : [];

    // ---- Malformed target rows (only when there are any) ----
    const bad = (d.tcheck && d.tcheck.ok && d.tcheck.bad) || [];
    if (bad.length) {
      section('bad', 'Malformed target rows');
      note('bad', count(bad.length, 'row', 'rows'));
      if (!s._ktReconcile) {
        const warn = el('div', 'snmp-access-banner warn');
        warn.appendChild(el('span', 'snmp-access-icon', '\u26a0'));
        warn.appendChild(el('span', '', 'These notification target rows have an address the switch cannot read. ' +
          'They cause the switch\u2019s %SNMP-F-BADTDOMAIN fault and can crash configuration saves. ' +
          'They are usually left behind by an interrupted write, and removing them is safe.'));
        body.appendChild(warn);
      }
      mountInto(body, s, p, 'snmp:bad', ['Row', 'Transport domain', 'Address bytes', 'Problem'].concat(act),
        bad.map((b) => ({ key: 'bad:' + b.index, cells: [{ v: b.name }, { v: b.domain || '(none)' }, { v: String(b.taddrLen) }, { v: b.reason }]
          .concat(editable ? [snmpDeleteCell(s, 'Remove row', 'target-row-delete-apply', { key: { destroyOid: b.destroyOid } }, ['target-check'], 'Remove this malformed row')] : []) })));
    }

    // ---- Notification recipients ----
    const rd = d.recips;
    section('rcp', 'Notification recipients', 'Add recipient', () => openSnmpRecipientForm(s));
    if (!rd || !rd.ok) { note('rcp', ''); emptyNote('Recipients unavailable.'); }
    else {
      const recips = rd.recipients || [];
      note('rcp', count(recips.length, 'recipient', 'recipients'));
      sub('rcp', rd.auth_failure_traps && rd.auth_failure_traps !== 'unknown' ? 'Authentication-failure traps: ' + rd.auth_failure_traps : '');
      if (!recips.length) emptyNote('No notification recipients configured.');
      else mountInto(body, s, p, 'snmp:rcp', ['Address', 'Port', 'Type', 'Version', 'Community / user', 'Status'].concat(act),
        recips.map((r) => ({ key: 'rcp:' + (r.key ? r.key.source + ':' + r.key.index : r.name), cells: [
          { v: r.address }, { v: r.port }, { v: r.type }, { v: r.version }, { v: r.security_name }, { v: r.status }]
          .concat(editable ? [r.key ? snmpDeleteCell(s, 'Delete recipient', 'recipient-delete-apply', { key: r.key }, ['recipients'], 'Delete this recipient') : { v: '' }] : []) })));
    }

    // The credential this app connects with cannot be deleted (the switch
    // refuses, and it would cut the app off), so its row shows the standard
    // lock with the reason instead of offering Delete (B6).
    const inUseCell = (row) => {
      if (!row.inUse) return null;
      const locked = el('span', 'card-sub', '\uD83D\uDD12 in use');
      locked.title = 'This app connects to the switch with this credential, so it cannot be deleted here.';
      return { cellNode: locked, sig: 'locked' };
    };

    // ---- Communities ----
    // Traps and Status are not shown: Traps is only filled for the legacy
    // station-restricted community table (unused here), and a community is
    // either present or deleted.
    const cd = d.comms;
    section('comm', 'SNMP communities', 'Add community', () => openSnmpCommunityForm(s, null));
    if (!cd || !cd.ok) { note('comm', ''); emptyNote('Communities unavailable.'); }
    else {
      const comms = cd.communities || [];
      note('comm', count(comms.length, 'community', 'communities'));
      if (!comms.length) emptyNote('No communities found.');
      else mountInto(body, s, p, 'snmp:comm', ['Community', 'Station', 'Access', 'View'].concat(act),
        comms.map((c) => {
          const key = 'comm:' + (c.key ? c.key.source + ':' + c.key.index : c.community);
          const first = (editable && c.key) ? { v: c.community, click: { open: () => openSnmpCommunityForm(s, key) } } : { v: c.community };
          return { key, cells: [first, { v: c.station || 'any' }, { v: c.access || '' }, { v: c.view || '\u2014' }]
            .concat(editable ? [inUseCell(c) || (c.key ? snmpDeleteCell(s, 'Delete community', 'community-delete-apply', { key: c.key }, ['communities'], 'Delete this community') : { v: '' })] : []) };
        }));
    }

    // ---- SNMPv3 groups ----
    const gd = d.groups;
    section('grp', 'SNMPv3 groups', 'Add group', () => openSnmpGroupForm(s, null));
    if (!gd || !gd.ok) { note('grp', ''); emptyNote('Groups unavailable.'); }
    else {
      const groups = gd.groups || [];
      note('grp', count(groups.length, 'group', 'groups'));
      const vcell = (views, lvl) => { const v = (views || {})[lvl]; if (!v) return '\u2014'; return [v.read, v.write, v.notify].map((x) => x || '\u2014').join(' / '); };
      if (!groups.length) emptyNote('No SNMPv3 groups found.');
      else mountInto(body, s, p, 'snmp:grp', ['Group', 'No Auth (R/W/N)', 'Auth (R/W/N)', 'Privacy (R/W/N)', 'Members'],
        groups.map((g) => ({ key: 'grp:' + g.group, cells: [
          editable ? { v: g.group, click: { open: () => openSnmpGroupForm(s, g.group) } } : { v: g.group },
          { v: vcell(g.views, 'noAuthNoPriv') }, { v: vcell(g.views, 'authNoPriv') }, { v: vcell(g.views, 'authPriv') }, { v: g.members }] })));
    }

    // ---- SNMPv3 users ----
    const ud = d.users;
    section('usr', 'SNMPv3 users');
    if (!ud || !ud.ok) { note('usr', ''); emptyNote('Users unavailable.'); }
    else {
      const users = ud.users || [];
      note('usr', count(users.length, 'user', 'users'));
      sub('usr', 'Users are created in the switch\u2019s web interface. This panel lists them and can delete them.');
      if (!users.length) emptyNote('No SNMPv3 users found.');
      else mountInto(body, s, p, 'snmp:usr', ['User', 'Auth', 'Privacy', 'Group', 'Status'].concat(act),
        users.map((u) => ({ key: 'usr:' + (u.key ? u.key.index : u.name), cells: [
          { v: u.name }, { v: u.auth }, { v: u.priv }, { v: u.group }, { v: u.status }]
          .concat(editable ? [inUseCell(u) || (u.key ? snmpDeleteCell(s, 'Delete user', 'user-delete-apply', { key: u.key }, ['users'], 'Delete this user') : { v: '' })] : []) })));
    }
  }

  // ---- Forms (standard A5/B6/B8) ----
  // Each opens in the tabbed pop-out (Esc closes), lays its fields out with
  // formSection + field, applies on one tap through runButtonAction, shows a
  // failure as the red line under the button, and closes once the section has
  // been re-read. Lists they offer (communities, views) come from the load.
  function snmpForm(s, title, tab, build) {
    openTabbedPopout(s, title, [{ label: tab, fill: (pane, close) => build(pane, close) }], []);
  }
  function snmpSubmit(s, ev, msg, failLabel, spinLabel, action, payload, sections, close) {
    runButtonAction(ev.currentTarget, {
      failLabel, spinLabel,
      run: () => snmpWrite(s, action, payload),
      ok: (r) => r && r.ok,
      error: (r) => { const e = (r && r.error) || 'the switch rejected it'; clear(msg); msg.appendChild(el('div', 'sw-err', failLabel + ' failed: ' + e)); return e; },
      onApplied: () => markConfigDirty(s),
      settle: () => snmpRefresh(s, sections).then(() => close())
    });
  }
  const snmpView = (s) => ((s._snmp && s._snmp.data && s._snmp.data.views && s._snmp.data.views.views) || []);
  const SNMP_ACCESS = [{ label: 'Read Only', value: 'read-only' }, { label: 'Read Write', value: 'read-write' }, { label: 'SNMP Admin', value: 'snmp-admin' }];

  // ---- Add recipient ----
  function openSnmpRecipientForm(s) {
    snmpForm(s, 'Add notification recipient', 'Recipient', (pane, close) => {
      const form = el('div', 'snmp-form acl-form');
      const comms = ((s._snmp.data.comms && s._snmp.data.comms.communities) || []).map((c) => c.community).filter(Boolean);
      const ip = textInput('', '192.168.1.50');
      const port = textInput('162');
      const ntype = selectInput([{ label: 'Trap', value: 'trap' }, { label: 'Inform (acknowledged)', value: 'inform' }], 'trap');
      const version = selectInput([{ label: 'SNMPv2c', value: '2c' }, { label: 'SNMPv1', value: '1' }, { label: 'SNMPv3', value: '3' }], '2c');
      const community = selectInput(comms.length ? comms.map((c) => ({ label: c, value: c })) : [{ label: '(no communities found)', value: '' }], comms[0] || '');
      const user = textInput('', 'existing SNMPv3 user');
      const level = selectInput([{ label: 'authPriv', value: 'authPriv' }, { label: 'authNoPriv', value: 'authNoPriv' }, { label: 'noAuthNoPriv', value: 'noAuthNoPriv' }], 'authPriv');
      const timeout = textInput('15'); const retries = textInput('3');

      const where = formSection('Recipient');
      where.body.appendChild(field('IPv4 address', ip));
      where.body.appendChild(field('UDP port', port));
      where.body.appendChild(field('Notification type', ntype));
      where.body.appendChild(field('Version', version));
      const sec = formSection('Security');
      const commField = field('Community sent in notifications', community);
      const userField = field('SNMPv3 user (must exist on the switch)', user);
      const levelField = field('Security level', level);
      sec.body.appendChild(commField); sec.body.appendChild(userField); sec.body.appendChild(levelField);
      const inform = formSection('Inform');
      inform.body.appendChild(field('Timeout (s)', timeout));
      inform.body.appendChild(field('Retries', retries));
      form.appendChild(where.sec); form.appendChild(sec.sec); form.appendChild(inform.sec);
      const sync = () => {
        const v3 = version.value === '3';
        commField.style.display = v3 ? 'none' : '';
        userField.style.display = v3 ? '' : 'none';
        levelField.style.display = v3 ? '' : 'none';
        inform.sec.style.display = ntype.value === 'inform' ? '' : 'none';
      };
      version.addEventListener('change', sync); ntype.addEventListener('change', sync); sync();

      const { actions, apply, msg } = applyActions('Add recipient');
      apply.addEventListener('click', (ev) => {
        clear(msg);
        const cfg = { ip: ip.value.trim(), port: port.value.trim(), ntype: ntype.value, version: version.value };
        if (!ipv4ToHex(cfg.ip)) { msg.appendChild(el('div', 'sw-err', 'Enter a valid IPv4 address.')); return; }
        if (version.value === '3') {
          cfg.user = user.value.trim(); cfg.level = level.value;
          if (!cfg.user) { msg.appendChild(el('div', 'sw-err', 'Enter the SNMPv3 user.')); return; }
        } else {
          cfg.community = community.value;
          if (!cfg.community) { msg.appendChild(el('div', 'sw-err', 'Add a community first.')); return; }
        }
        if (ntype.value === 'inform') { cfg.timeout = timeout.value; cfg.retries = retries.value; }
        snmpSubmit(s, ev, msg, 'Add recipient', 'Adding\u2026', 'recipient-add-apply', { cfg }, ['recipients'], close);
      });
      form.appendChild(actions); form.appendChild(msg);
      pane.appendChild(form);
      ip.focus();
    });
  }

  // ---- Add / edit community ----
  // Editing changes only the access mode and view: the community string and
  // station are part of the row's identity, so they are shown but fixed.
  function openSnmpCommunityForm(s, rowKey) {
    const comms = (s._snmp.data.comms && s._snmp.data.comms.communities) || [];
    const c = rowKey ? comms.find((x) => 'comm:' + (x.key ? x.key.source + ':' + x.key.index : x.community) === rowKey) : null;
    if (rowKey && !c) return;
    snmpForm(s, c ? 'Community \u00b7 ' + c.community : 'Add SNMP community', 'Community', (pane, close) => {
      const form = el('div', 'snmp-form acl-form');
      const views = snmpView(s);
      const sec = formSection('Community');
      const name = textInput(c ? c.community : '', 'community string');
      sec.body.appendChild(field('Community string', name));
      if (c) {
        name.disabled = true;
        const station = textInput(c.station || 'any'); station.disabled = true;
        sec.body.appendChild(field('Station', station));
      }
      const cur = c ? (/admin/i.test(c.access || '') ? 'snmp-admin' : (/write/i.test(c.access || '') ? 'read-write' : 'read-only')) : 'read-only';
      const access = selectInput(SNMP_ACCESS, cur);
      const curView = c && c.view && c.view !== '\u2014' ? c.view : '';
      const viewOpts = [{ label: '(default for the mode)', value: '' }].concat(views.map((v) => ({ label: v, value: v })));
      if (curView && views.indexOf(curView) === -1) viewOpts.push({ label: curView + ' (current)', value: curView });
      const view = selectInput(viewOpts, curView);
      sec.body.appendChild(field('Access mode', access));
      sec.body.appendChild(field('View', view));
      if (c) sec.body.appendChild(el('div', 'card-sub', 'To change the community string or station, delete the community and add it again.'));
      form.appendChild(sec.sec);

      const { actions, apply, msg } = applyActions(c ? 'Save' : 'Add community');
      apply.addEventListener('click', (ev) => {
        clear(msg);
        const community = c ? c.community : name.value.trim();
        if (!community) { msg.appendChild(el('div', 'sw-err', 'Enter a community string.')); return; }
        if (!c && comms.some((x) => x.community === community)) { msg.appendChild(el('div', 'sw-err', 'A community named \u201c' + community + '\u201d already exists.')); return; }
        const cfg = { community, access: access.value, view: view.value };
        if (c) snmpSubmit(s, ev, msg, 'Save community', 'Saving\u2026', 'community-modify-apply', { cfg }, ['communities'], close);
        else snmpSubmit(s, ev, msg, 'Add community', 'Adding\u2026', 'community-add-apply', { cfg }, ['communities'], close);
      });
      form.appendChild(actions); form.appendChild(msg);
      pane.appendChild(form);
      if (!c) name.focus();
    });
  }

  // ---- Add / edit group ----
  // A group sets the Read / Write / Notify view for each security level: one
  // row of three view pickers per level.
  function snmpViewSelect(views, current) {
    const opts = [{ label: '(none)', value: '' }].concat(views.map((v) => ({ label: v, value: v })));
    if (current && views.indexOf(current) === -1) opts.push({ label: current + ' (current)', value: current });
    return selectInput(opts, current || '');
  }
  function snmpLevelGrid(views, existing) {
    const wrap = el('div', 'snmp-levels');
    const cells = {};
    for (const [key, label] of [['noAuthNoPriv', 'No authentication'], ['authNoPriv', 'Authentication'], ['authPriv', 'Authentication and privacy']]) {
      const lv = (existing || {})[key] || {};
      wrap.appendChild(el('div', 'snmp-lvl-label', label));
      const row = el('div', 'snmp-lvl-row');
      const sels = { read: snmpViewSelect(views, lv.read), write: snmpViewSelect(views, lv.write), notify: snmpViewSelect(views, lv.notify) };
      row.appendChild(field('Read', sels.read));
      row.appendChild(field('Write', sels.write));
      row.appendChild(field('Notify', sels.notify));
      wrap.appendChild(row);
      cells[key] = sels;
    }
    const levels = () => {
      const out = {};
      for (const k of Object.keys(cells)) out[k] = { read: cells[k].read.value, write: cells[k].write.value, notify: cells[k].notify.value };
      return out;
    };
    return { node: wrap, levels };
  }
  function openSnmpGroupForm(s, groupName) {
    const groups = (s._snmp.data.groups && s._snmp.data.groups.groups) || [];
    const g = groupName ? groups.find((x) => x.group === groupName) : null;
    if (groupName && !g) return;
    snmpForm(s, g ? 'Group \u00b7 ' + g.group : 'Add SNMPv3 group', 'Group', (pane, close) => {
      const form = el('div', 'snmp-form acl-form');
      let name = null;
      if (!g) {
        const id = formSection('Group');
        name = textInput('', 'group name');
        id.body.appendChild(field('Group name', name));
        form.appendChild(id.sec);
      }
      const vs = formSection('Views by security level');
      vs.body.classList.add('acl-stack');
      vs.body.appendChild(el('div', 'card-sub', g
        ? 'Setting all three views of a level to (none) removes that level from the group.'
        : 'Leave a level\u2019s views as (none) to leave that level out of the group.'));
      const grid = snmpLevelGrid(snmpView(s), g ? (g.views || {}) : { authPriv: { read: 'DefaultSuper', notify: 'DefaultSuper' } });
      vs.body.appendChild(grid.node);
      form.appendChild(vs.sec);

      const { actions, apply, msg } = applyActions(g ? 'Save' : 'Add group');
      apply.addEventListener('click', (ev) => {
        clear(msg);
        const group = g ? (g.key && g.key.display) || g.group : name.value.trim();
        if (!group) { msg.appendChild(el('div', 'sw-err', 'Enter a group name.')); return; }
        if (!g && groups.some((x) => x.group === group)) { msg.appendChild(el('div', 'sw-err', 'A group named \u201c' + group + '\u201d already exists.')); return; }
        const cfg = { group, levels: grid.levels() };
        if (g) snmpSubmit(s, ev, msg, 'Save group', 'Saving\u2026', 'group-modify-apply', { cfg }, ['groups'], close);
        else snmpSubmit(s, ev, msg, 'Add group', 'Adding\u2026', 'group-add-apply', { cfg }, ['groups'], close);
      });
      form.appendChild(actions); form.appendChild(msg);
      pane.appendChild(form);
      if (name) name.focus();
    });
  }

  function offerSetup(s) {
    s.setupIntro.textContent = 'Connected to ' + (s.host || 'the switch') +
      '. There are no SNMP credentials for it yet. Enter SNMP credentials to use the ' +
      'dashboard, or go to the CLI.';
    showView(s, 'setup');
  }

  function initSetup(s) {
    q2(s, '.f-setup-cli').addEventListener('click', () => {
      s.wantTerminal = true;
      openOverlay(s, 'termOverlay');
    });
    q2(s, '.f-setup-snmp').addEventListener('click', () => {
      if (s.subMode !== 'ready') selectCredCard(s, 'snmp');
      showView(s, 'creds');
      s.hostInput.focus();
    });
  }
