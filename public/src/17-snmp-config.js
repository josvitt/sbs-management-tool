  // =================================================================
  // 17-snmp-config.js: SNMP configuration module (the write side): communities, groups, users, recipients; first-run SNMP setup.
  // =================================================================

  // ===================================================================
  // SNMP configuration module (the write side).
  // ===================================================================
  //
  // A self-contained interactive panel: it loads on expand and on its own
  // refresh, never on the health poll. The first thing it does is ask the
  // switch whether this credential is an SNMP Admin (DefaultSuper); if it
  // is not, a banner says so and the add/edit/delete controls are disabled,
  // because the switch would refuse them anyway.

  function snmpCfgPost(s, action, extra) {
    return fetch('/api/snmp-config/' + action, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(Object.assign({ target: s.target }, extra || {}))
    }).then((r) => r.json());
  }

  function paintSnmpPanel(s, body) {
    if (!s.target) {
      body.appendChild(el('div', 'card-sub', 'Add SNMP credentials for this switch first.'));
      return;
    }
    s._snmp = s._snmp || {};
    const root = el('div', 'snmp-cfg');
    body.appendChild(root);

    const banner = el('div', 'snmp-access-banner'); banner.style.display = 'none';
    root.appendChild(banner);
    const sections = el('div', 'snmp-sections');
    root.appendChild(sections);

    // Fresh DOM nodes each paint, but the fetched DATA is cached: the section
    // node handles are tied to this root, so drop the stale handles.
    s._snmp.root = root; s._snmp.banner = banner; s._snmp.sections = sections;
    s._snmp.secNodes = {};
    // Behave like a keyed panel on open: if we have ANY cached data, render it
    // immediately (no blocking "Reading…" reload), regardless of age - a keyed
    // panel always shows its last-known state instantly. Then, if the cache is
    // stale (>30s) or absent, refresh in the BACKGROUND so the panel never
    // blocks on open. Only a true cold start (never loaded) shows the loading
    // state, exactly as a keyed panel shows "waiting for data" before its first
    // walk. The 30s guard prevents re-fetching on rapid open/close.
    if (s._snmp.lastData) {
      paintSnmpBanner(s);
      if (s._snmp.access && s._snmp.access.ok && s._snmp.access.level === 'limited') { clear(sections); }
      else renderSnmpSections(s);
      if (Date.now() - (s._snmp.fetchedAt || 0) >= 30000 && !s._snmp.loading) {
        s._snmp.loading = true;
        loadSnmpPanel(s, root, false).then(() => { s._snmp.loading = false; }, () => { s._snmp.loading = false; });
      }
    } else if (!s._snmp.loading) {
      s._snmp.loading = true;
      loadSnmpPanel(s, root, false).then(() => { s._snmp.loading = false; }, () => { s._snmp.loading = false; });
    }
  }

  // Paint the access banner from the cached access result (shared by the fresh
  // re-open path and loadSnmpPanel).
  function paintSnmpBanner(s) {
    const access = s._snmp.access, banner = s._snmp.banner;
    if (access && access.ok && access.level !== 'full') {
      banner.style.display = '';
      banner.className = 'snmp-access-banner ' + (access.level === 'limited' ? 'warn' : 'info');
      clear(banner);
      banner.appendChild(el('span', 'snmp-access-icon', access.level === 'limited' ? '\u26A0' : '\u2139'));
      banner.appendChild(el('span', '', access.summary));
    } else {
      banner.style.display = 'none';
    }
  }

  async function loadSnmpPanel(s, root, force) {
    const sections = s._snmp.sections;
    // Only show the blocking "Reading…" placeholder on a cold start (no cached
    // data yet). A background refresh over already-rendered sections must NOT
    // clear them - that would be the "reloads on every open" flash. The fetched
    // data lands via renderSnmpSections at the end, updating in place.
    if (!s._snmp.lastData) {
      clear(sections);
      sections.appendChild(el('div', 'card-sub', 'Reading SNMP configuration\u2026'));
    }
    let access;
    try { access = await snmpCfgPost(s, 'access'); }
    catch (e) { clear(sections); sections.appendChild(el('div', 'panel-err', 'Lost contact with the local server: ' + e.message)); return; }
    s._snmp.access = access;

    // Access banner. editable is true only for a full DefaultSuper credential.
    const editable = access.ok && access.level === 'full';
    s._snmp.editable = editable;
    paintSnmpBanner(s);

    // If the credential can't even read the config tables, there is nothing
    // to list — show only the banner and stop.
    if (access.ok && access.level === 'limited') {
      clear(sections);
      return;
    }

    // Load the four lists ONE AT A TIME, not in parallel. Each request opens
    // its own SNMP session on the server and walks several tables; firing all
    // four at once meant four concurrent sessions doing ~15 table walks
    // simultaneously, which a C1300's SNMP agent handles badly — especially
    // right after a VACM/community change or alongside a config save. Serial
    // keeps the switch under the load of a single session at a time.
    // System identity (name/location/contact) lives in the Details panel.
    const recips = await snmpCfgPost(s, 'recipients').catch(() => null);
    const comms = await snmpCfgPost(s, 'communities').catch(() => null);
    const groups = await snmpCfgPost(s, 'groups').catch(() => null);
    const users = await snmpCfgPost(s, 'users').catch(() => null);
    // Integrity check: malformed snmpTargetAddrTable rows cause the switch's
    // %SNMP-F-BADTDOMAIN fault and can crash config processing. If any are
    // found, show them first with one-click removal — this is the usual debris
    // of a write interrupted by an earlier crash.
    const tcheck = await snmpCfgPost(s, 'target-check').catch(() => null);
    // Preserve scroll across the rebuild (standard A7). A self-managed module's
    // reload clears and repopulates its sections, which would otherwise jump the
    // page after an edit.
    // Render with scroll preserved around the rebuild (standard B5). Each section
    // lives in its own stable wrapper node kept on s._snmp.secNodes, so a single
    // create/delete can refresh just that section's data and re-render only its
    // wrapper (reloadSnmpSection) instead of reloading the whole module.
    s._snmp.lastData = { recips: recips, comms: comms, groups: groups, users: users, tcheck: tcheck };
    s._snmp.editable = editable;
    s._snmp.fetchedAt = Date.now();   // for the on-open freshness check (§B4)
    renderSnmpSections(s);
  }

  // Render all SNMP sections from cached data (s._snmp.lastData) into the stable
  // wrapper nodes. Called by loadSnmpPanel after a fetch, and by paintSnmpPanel
  // on a re-open when the cache is still fresh (no re-fetch). Each section lives
  // in its own wrapper on s._snmp.secNodes, so reloadSnmpSection can refresh one.
  function renderSnmpSections(s) {
    const sections = s._snmp.sections;
    const d = s._snmp.lastData || {};
    const editable = s._snmp.editable;
    s._snmp.secNodes = s._snmp.secNodes || {};
    const mount = (name, node) => {
      const wrap = s._snmp.secNodes[name] || el('div', 'snmp-sec-wrap');
      s._snmp.secNodes[name] = wrap;
      clear(wrap);
      // An empty placeholder (no real section content) collapses the wrapper so
      // the flex gap doesn't leave a phantom blank where e.g. bad-rows would be.
      if (node && node.childNodes.length) { wrap.appendChild(node); wrap.style.display = ''; }
      else { wrap.style.display = 'none'; }
      return wrap;
    };
    selfManagedRender(s, () => {
      clear(sections);
      sections.appendChild(mount('badRows',
        (d.tcheck && d.tcheck.ok && d.tcheck.bad && d.tcheck.bad.length) ? snmpBadRowsSection(s, d.tcheck.bad, editable) : el('div')));
      sections.appendChild(mount('recipients', snmpRecipientsSection(s, d.recips, editable)));
      sections.appendChild(mount('communities', snmpCommunitiesSection(s, d.comms, editable)));
      sections.appendChild(mount('groups', snmpGroupsSection(s, d.groups, editable)));
      sections.appendChild(mount('users', snmpUsersSection(s, d.users, editable)));
    });
  }

  // Refresh ONE SNMP-config section in place: re-fetch only that section's data
  // and re-render only its wrapper node, instead of reloading the whole module
  // (6 serial fetches). `which` is one or more of recipients/communities/groups/
  // users; 'target-check' is refreshed alongside recipient/community changes
  // because those affect target bindings and the bad-rows banner. Returns a
  // promise so a write's runButtonAction settle can hold the spinner until the
  // section updates (standard B5). Falls back to a full reload if the panel
  // hasn't been rendered yet (no stable wrappers).
  async function reloadSnmpSection(s, which) {
    const names = Array.isArray(which) ? which : [which];
    if (!s._snmp || !s._snmp.secNodes || !s._snmp.editable) { return loadSnmpPanel(s, s._snmp && s._snmp.root, true); }
    const editable = s._snmp.editable;
    const touchesTargets = names.some((n) => n === 'recipients' || n === 'communities');
    const render = (name, node) => {
      const wrap = s._snmp.secNodes[name];
      if (!wrap) return;
      selfManagedRender(s, () => {
        clear(wrap);
        if (node && node.childNodes.length) { wrap.appendChild(node); wrap.style.display = ''; }
        else { wrap.style.display = 'none'; }
      });
    };
    for (const name of names) {
      if (name === 'recipients') { const d = await snmpCfgPost(s, 'recipients').catch(() => null); s._snmp.lastData.recips = d; render('recipients', snmpRecipientsSection(s, d, editable)); }
      else if (name === 'communities') { const d = await snmpCfgPost(s, 'communities').catch(() => null); s._snmp.lastData.comms = d; render('communities', snmpCommunitiesSection(s, d, editable)); }
      else if (name === 'groups') { const d = await snmpCfgPost(s, 'groups').catch(() => null); s._snmp.lastData.groups = d; render('groups', snmpGroupsSection(s, d, editable)); }
      else if (name === 'users') { const d = await snmpCfgPost(s, 'users').catch(() => null); s._snmp.lastData.users = d; render('users', snmpUsersSection(s, d, editable)); }
    }
    if (touchesTargets) {
      const tcheck = await snmpCfgPost(s, 'target-check').catch(() => null);
      s._snmp.lastData.tcheck = tcheck;
      render('badRows', (tcheck && tcheck.ok && tcheck.bad && tcheck.bad.length) ? snmpBadRowsSection(s, tcheck.bad, editable) : el('div'));
    }
  }

  function snmpSection(title, actionBtn) {
    const sec = el('div', 'snmp-section');
    const head = el('div', 'snmp-section-head');
    head.appendChild(el('h4', 'snmp-section-title', title));
    if (actionBtn) head.appendChild(actionBtn);
    sec.appendChild(head);
    return sec;
  }

  // Build a table. If rowKey(rowData,i) is given, each <tr> is tagged so an
  // inline editor row can be opened directly beneath it with openRowEditor().

  // Open an inline editor directly under a table row. Returns the host <div>
  // inside a full-width cell. Any existing inline editor is closed first.
  function openRowEditor(tr, colspan) {
    closeRowEditors(tr.closest('table'));
    const editTr = el('tr', 'snmp-edit-row');
    const td = el('td'); td.colSpan = colspan;
    const host = el('div', 'snmp-edit-host');
    td.appendChild(host); editTr.appendChild(td);
    tr.insertAdjacentElement('afterend', editTr);
    host.scrollIntoView({ block: 'nearest' });
    return host;
  }
  function closeRowEditors(scope) {
    const root = scope || document;
    root.querySelectorAll('.snmp-edit-row').forEach((r) => r.remove());
  }

  // ---- Malformed target rows (BADTDOMAIN debris) ----
  function snmpBadRowsSection(s, bad, editable) {
    const sec = snmpSection('Malformed target rows');
    const warn = el('div', 'snmp-access-banner warn');
    warn.appendChild(el('span', 'snmp-access-icon', '\u26A0'));
    warn.appendChild(el('span', '', 'These snmpTargetAddrTable rows have a transport domain the switch cannot turn into a UDP address. ' +
      'They trigger the switch\u2019s %SNMP-F-BADTDOMAIN fault and can crash configuration saves. ' +
      'They are usually left behind by a write that was interrupted. Removing them is safe.'));
    sec.appendChild(warn);
    const cols = ['Row', 'Transport domain', 'TAddress bytes', 'Problem'].concat(editable ? [''] : []);
    const rows = bad.map((b) => {
      const base = [b.name, b.domain || '(none)', String(b.taddrLen), b.reason];
      if (editable) base.push(actGroup([
        actBtnConfirm('Remove', (e) => delBadTargetRow(s, b), 'danger', 'Remove this malformed row')
      ]));
      return base;
    });
    sec.appendChild(plainTable(s, cols, rows));
    return sec;
  }
  function delBadTargetRow(s, b) {
    snmpDeleteDirect(s, 'target-row-delete-apply', { key: { destroyOid: b.destroyOid } }, 'malformed row ' + b.name);
  }

  // ---- Recipients ----
  function snmpRecipientsSection(s, data, editable) {
    const sec = snmpSection('Notification recipients');
    const addHost = editable ? addControl('Add recipient', () => openEditPopout(s, 'Add recipient', (pane, close) => addSnmpRecipient(s, pane, close))) : null;
    if (addHost) sec._addHost = addHost;
    if (!data || !data.ok) { sec.appendChild(el('div', 'card-sub', 'Recipients unavailable.')); return sec; }
    const recips = data.recipients || [];
    if (data.auth_failure_traps && data.auth_failure_traps !== 'unknown') {
      sec.appendChild(el('div', 'snmp-subnote', 'Authentication-failure traps: ' + data.auth_failure_traps));
    }
    if (!recips.length) { sec.appendChild(el('div', 'card-sub', 'No notification recipients configured.')); if (addHost) sec.appendChild(addHost); return sec; }
    const cols = ['Address', 'Port', 'Type', 'Version', 'Community / user', 'Status'].concat(editable ? [''] : []);
    const rows = recips.map((r) => {
      const base = [r.address, r.port, r.type, r.version, r.security_name, r.status];
      if (editable) base.push(r.key ? actGroup([
        actBtnConfirm('Delete', (e) => delSnmpRecipient(s, r), 'danger', 'Delete this recipient')
      ]) : '');
      return base;
    });
    sec.appendChild(plainTable(s, cols, rows));
    if (addHost) sec.appendChild(addHost);
    return sec;
  }

  function delSnmpRecipient(s, r) {
    snmpDeleteDirect(s, 'recipient-delete-apply', { key: r.key }, 'recipient ' + r.address);
  }

  function snmpCommunitiesSection(s, data, editable) {
    const sec = snmpSection('SNMP communities');
    const addHost = editable ? addControl('Add community', () => openEditPopout(s, 'Add community', (pane, close) => addSnmpCommunity(s, pane, close))) : null;
    if (!data || !data.ok) { sec.appendChild(el('div', 'card-sub', 'Communities unavailable.')); return sec; }
    const comms = data.communities || [];
    s._snmp.communities = comms;
    if (!comms.length) { sec.appendChild(el('div', 'card-sub', 'No communities found.')); if (addHost) sec.appendChild(addHost); return sec; }
    // Traps and Status are not shown: Traps is only populated for the legacy
    // Cisco station-restricted community table (unused here, always blank), and
    // Status cannot be changed through the tool (a community is present or
    // deleted), so it is an assumed constant.
    const cols = ['Community', 'Station', 'Access', 'View'].concat(editable ? [''] : []);
    const rows = comms.map((c, i) => {
      const base = [c.community, c.station || 'any', c.access || '', c.view || '\u2014'];
      if (editable) base.push(c.key ? actGroup([
        actBtnConfirm('Delete', (e) => runButtonAction(e.currentTarget, {
          failLabel: 'Delete community',
          run: () => snmpDeleteDirect(s, 'community-delete-apply', { key: c.key }, 'community \u201C' + c.community + '\u201D'),
          ok: (r) => r && r.ok,
          error: (r) => (r && r.error) || 'the switch rejected it',
          settle: () => reloadSnmpSection(s, 'communities')
        }), 'danger', 'Delete this community')
      ]) : '');
      return base;
    });
    // Row-click opens the standard tabbed popout hosting the editor.
    sec.appendChild(plainTable(s, cols, rows, editable ? (i) => {
      const c = comms[i];
      if (c && c.key) openEditPopout(s, 'Community \u00b7 ' + c.community,
        (pane, close) => editSnmpCommunity(s, c, pane, close));
    } : null));
    if (addHost) sec.appendChild(addHost);
    return sec;
  }

  function snmpGroupsSection(s, data, editable) {
    const sec = snmpSection('SNMPv3 groups');
    const addHost = editable ? addControl('Add group', () => openEditPopout(s, 'Add group', (pane, close) => addSnmpGroup(s, pane, close))) : null;
    if (!data || !data.ok) { sec.appendChild(el('div', 'card-sub', 'Groups unavailable.')); return sec; }
    const groups = data.groups || [];
    s._snmp.groups = groups;
    if (!groups.length) { sec.appendChild(el('div', 'card-sub', 'No SNMPv3 groups found.')); if (addHost) sec.appendChild(addHost); return sec; }
    const vcell = (views, lvl) => { const v = (views || {})[lvl]; if (!v) return '\u2014'; return [v.read, v.write, v.notify].map((x) => x || '\u2014').join(' / '); };
    // Group editing is now via row-click (its only action was Edit), so no
    // action column is needed.
    const cols = ['Group', 'No Auth (R/W/N)', 'Auth (R/W/N)', 'Privacy (R/W/N)', 'Members'];
    const rows = groups.map((g) => [g.group, vcell(g.views, 'noAuthNoPriv'), vcell(g.views, 'authNoPriv'), vcell(g.views, 'authPriv'), g.members]);
    sec.appendChild(plainTable(s, cols, rows, editable ? (i) => {
      const g = groups[i];
      openEditPopout(s, 'Group \u00b7 ' + g.group, (pane, close) => editSnmpGroup(s, g, pane, close));
    } : null));
    if (addHost) sec.appendChild(addHost);
    return sec;
  }

  function snmpUsersSection(s, data, editable) {
    const sec = snmpSection('SNMPv3 users');
    if (!data || !data.ok) { sec.appendChild(el('div', 'card-sub', 'Users unavailable.')); return sec; }
    const users = data.users || [];
    sec.appendChild(el('div', 'snmp-subnote', 'Users are created in the switch web GUI; this lists them, their group mapping, and can delete them.'));
    if (!users.length) { sec.appendChild(el('div', 'card-sub', 'No SNMPv3 users found.')); return sec; }
    const cols = ['User', 'Auth', 'Privacy', 'Group', 'Status'].concat(editable ? [''] : []);
    const rows = users.map((u) => {
      const base = [u.name, u.auth, u.priv, u.group, u.status];
      if (editable) base.push(u.key ? actGroup([
        actBtnConfirm('Delete', (e) => runButtonAction(e.currentTarget, {
          failLabel: 'Delete user',
          run: () => snmpDeleteDirect(s, 'user-delete-apply', { key: u.key }, 'SNMPv3 user \u201C' + u.name + '\u201D'),
          ok: (r) => r && r.ok,
          error: (r) => (r && r.error) || 'the switch rejected it',
          settle: () => reloadSnmpSection(s, 'users')
        }), 'danger', 'Delete this user')
      ]) : '');
      return base;
    });
    sec.appendChild(plainTable(s, cols, rows));
    return sec;
  }

  // Delete an SNMP object (the two-tap button already confirmed). Returns a
  // normalized result for runButtonAction; the caller owns the button lifecycle
  // and the per-section refresh in settle. The two-tap confirm already happened.
  async function snmpDeleteDirect(s, applyAction, payload, label) {
    s.writeBusy = true;
    try {
      const j = await snmpCfgPost(s, applyAction, payload);
      s.writeBusy = false;
      if (!j.ok || (j.applied && !j.applied.ok)) {
        const detail = (j.applied && (j.applied.log || []).find((x) => !x.ok)) || null;
        return { ok: false, error: j.error || (detail && detail.detail) || 'the switch rejected it' };
      }
      markConfigDirty(s);
      return { ok: true };
    } catch (e) { s.writeBusy = false; return { ok: false, error: e.message }; }
  }

  // ---- inline form infrastructure ----
  // Forms render inline: add forms into a host at the foot of their section,
  // and row actions (edit group, delete) into an editor row directly beneath
  // the item. This keeps every edit as close to its target as possible. The
  // original tool's inline add/edit UX: fill fields, Preview to see the exact
  // SETs, then Apply. No browser prompt dialogs.

  // Dismiss a form/preview: if it sits in an inline row-editor, remove that
  // whole row; otherwise just empty the host it rendered into.
  function dismissHost(host) {
    if (!host) return;
    const editRow = host.closest ? host.closest('.snmp-edit-row') : null;
    if (editRow) editRow.remove(); else clear(host);
  }

  function snmpField(label, control) {
    const f = el('div', 'snmp-field');
    f.appendChild(el('label', '', label));
    f.appendChild(control);
    return f;
  }
  function textInput(value, placeholder) {
    const i = el('input'); i.type = 'text'; if (value != null) i.value = value; if (placeholder) i.placeholder = placeholder;
    return i;
  }
  function selectInput(options, value) {
    const sel = el('select');
    for (const o of options) {
      const opt = el('option', '', o.label); opt.value = o.value;
      if (o.value === value) opt.selected = true;
      sel.appendChild(opt);
    }
    return sel;
  }

  // Render a plan preview with an Apply button; on apply, run the action and
  // reload. cfgProvider returns the config/key object to send (captured now).
  function snmpFormMsg(host, kind, text) {
    let m = host.querySelector('.snmp-msg');
    if (!m) { m = el('div', 'snmp-msg'); host.appendChild(m); }
    m.className = 'snmp-msg ' + kind; m.textContent = text;
  }

  // Preview helper: POST the preview action, then show the plan.
  // Apply an SNMP add/modify directly. The old two-step preview (show the VACM
  // plan, then Apply) was a debugging aid; an end user just wants the change
  // made. The calling button already carries two-tap confirmation, so this
  // commits straight away and reloads the panel.
  // Apply an SNMP-config create/modify. Button lifecycle via runButtonAction
  // (standard B6); on success the form's popout closes and ONLY the affected
  // section is refreshed in place (standard B5), not the whole module. `section`
  // is which section to reload (communities/recipients/groups). Detailed errors
  // go to the form's own message line, which is better UX than a toast here.
  function snmpPreview(s, host, previewAction, applyAction, payload, title, applyBtn, section) {
    runButtonAction(applyBtn, {
      failLabel: title || 'Apply',
      run: async () => {
        s.writeBusy = true;
        try {
          const j = await snmpCfgPost(s, applyAction, payload);
          s.writeBusy = false;
          if (!j.ok) return { ok: false, error: j.error };
          const r = j.applied;
          if (r && !r.ok) { const bad = (r.log || []).find((x) => !x.ok); return { ok: false, error: 'Did not complete: ' + (bad ? bad.detail : 'unknown error') }; }
          return { ok: true };
        } catch (e) { s.writeBusy = false; return { ok: false, error: 'Lost contact with the local server: ' + e.message }; }
      },
      ok: (r) => r && r.ok,
      error: (r) => { snmpFormMsg(host, 'bad', (r && r.error) || 'the switch rejected it'); return (r && r.error) || 'the switch rejected it'; },
      onApplied: () => {
        const pop = host.closest && host.closest('.port-detail-back');
        if (pop) pop.remove();
        markConfigDirty(s);
      },
      settle: () => reloadSnmpSection(s, section || ['recipients', 'communities', 'groups', 'users'])
    });
  }

  // ---- Add recipient (inline form) ----
  async function addSnmpRecipient(s, host, onCancel) {
    clear(host);
    const form = el('div', 'snmp-form');
    form.appendChild(el('h5', '', 'Add notification recipient'));
    form.appendChild(el('p', 'intro', 'Creates the snmpTargetAddr / Params / Notify rows the switch uses for an snmp-server host, plus the community mapping row for v1/v2c.'));

    const ip = textInput('', '192.168.1.50');
    const port = textInput('162');
    const ntype = selectInput([{ label: 'Trap', value: 'trap' }, { label: 'Inform (acknowledged)', value: 'inform' }], 'trap');
    const version = selectInput([{ label: 'SNMPv2c', value: '2c' }, { label: 'SNMPv1', value: '1' }, { label: 'SNMPv3', value: '3' }], '2c');
    // Community is a dropdown of the communities that exist on the switch.
    let commNames = [];
    try { const cj = await snmpCfgPost(s, 'communities'); if (cj.ok) commNames = (cj.communities || []).map((c) => c.community).filter(Boolean); } catch (e) {}
    const community = selectInput(commNames.length
      ? commNames.map((c) => ({ label: c, value: c }))
      : [{ label: '(no communities found)', value: '' }], commNames[0] || '');
    const user = textInput('', 'existing SNMPv3 user');
    const level = selectInput([{ label: 'authPriv', value: 'authPriv' }, { label: 'authNoPriv', value: 'authNoPriv' }, { label: 'noAuthNoPriv', value: 'noAuthNoPriv' }], 'authPriv');
    const timeout = textInput('15'); const retries = textInput('3');

    const grid = el('div', 'snmp-form-grid');
    grid.appendChild(snmpField('Recipient IPv4 address', ip));
    grid.appendChild(snmpField('UDP port', port));
    grid.appendChild(snmpField('Notification type', ntype));
    grid.appendChild(snmpField('Version', version));
    const commField = snmpField('Community sent in notifications', community);
    const userField = snmpField('SNMPv3 user (must exist on switch)', user);
    const levelField = snmpField('Security level', level);
    const toField = snmpField('Inform timeout (s)', timeout);
    const rtField = snmpField('Inform retries', retries);
    grid.appendChild(commField); grid.appendChild(userField); grid.appendChild(levelField);
    grid.appendChild(toField); grid.appendChild(rtField);
    form.appendChild(grid);

    function sync() {
      const v3 = version.value === '3';
      const inform = ntype.value === 'inform';
      commField.style.display = v3 ? 'none' : '';
      userField.style.display = v3 ? '' : 'none';
      levelField.style.display = v3 ? '' : 'none';
      toField.style.display = inform ? '' : 'none';
      rtField.style.display = inform ? '' : 'none';
    }
    version.addEventListener('change', sync); ntype.addEventListener('change', sync); sync();

    const actions = el('div', 'snmp-form-actions');
    const preview = el('button', 'btn btn-small btn-blue', 'Apply');
    const cancel = el('button', 'btn btn-small secondary', 'Cancel');
      cancel.addEventListener('click', () => { if (onCancel) onCancel(); else dismissHost(host); });
    withConfirm(preview, () => {
      const cfg = { ip: ip.value.trim(), port: port.value.trim(), ntype: ntype.value, version: version.value };
      if (version.value === '3') { cfg.user = user.value.trim(); cfg.level = level.value; }
      else cfg.community = community.value;
      if (ntype.value === 'inform') { cfg.timeout = timeout.value; cfg.retries = retries.value; }
      snmpPreview(s, host, 'recipient-add-preview', 'recipient-add-apply', { cfg }, 'Add recipient ' + cfg.ip, preview, 'recipients');
    });
    actions.appendChild(preview); actions.appendChild(cancel);
    form.appendChild(actions);
    host.appendChild(form); host.scrollIntoView({ block: 'nearest' });
    ip.focus();
  }

  // ---- Add community (inline form) ----
  // Edit a community: all fields shown, but only access mode and view are
  // editable — the others are greyed out (read-only) because only the VACM
  // access row can be meaningfully changed over SNMP.
  async function editSnmpCommunity(s, c, host, onCancel) {
    const form = el('div', 'snmp-form');
    form.appendChild(el('h5', '', 'Edit community ' + c.community));
    form.appendChild(el('p', 'intro', 'Only the access mode and view can be changed. The community string and allowed stations are fixed — to change those, delete and re-add the community.'));
    // Community string — shown, disabled.
    const nameRO = textInput(c.community); nameRO.disabled = true;
    const station = textInput(c.station || 'any'); station.disabled = true;
    const access = selectInput([{ label: 'Read Only', value: 'read-only' }, { label: 'Read Write', value: 'read-write' }, { label: 'SNMP Admin', value: 'snmp-admin' }],
      /write/i.test(c.access || '') ? (/admin/i.test(c.access || '') ? 'snmp-admin' : 'read-write') : 'read-only');
    const views = await viewOptions(s);
    const view = selectInput([{ label: '(default for the mode)', value: '' }].concat(views.map((v) => ({ label: v, value: v }))),
      (c.view && c.view !== '\u2014') ? c.view : '');
    const grid = el('div', 'snmp-form-grid');
    grid.appendChild(snmpField('Community string', nameRO));
    grid.appendChild(snmpField('Station', station));
    grid.appendChild(snmpField('Access mode', access));
    grid.appendChild(snmpField('View', view));
    form.appendChild(grid);
    const actions = el('div', 'snmp-form-actions');
    const preview = el('button', 'btn btn-small btn-blue', 'Apply');
    const cancel = el('button', 'btn btn-small secondary', 'Cancel');
    cancel.addEventListener('click', () => { if (onCancel) onCancel(); });
    withConfirm(preview, () => {
      snmpPreview(s, host, 'community-modify-preview', 'community-modify-apply',
        { cfg: { community: c.community, access: access.value, view: view.value } },
        'Modify community \u201C' + c.community + '\u201D', preview, 'communities');
    });
    actions.appendChild(preview); actions.appendChild(cancel);
    form.appendChild(actions);
    host.appendChild(form);
  }

  async function addSnmpCommunity(s, host, onCancel) {
    clear(host);
    const form = el('div', 'snmp-form');
    form.appendChild(el('h5', '', 'Add SNMP community'));
    form.appendChild(el('p', 'intro', "Adds a community with its VACM group rows and the matched IPv4 + IPv6 manager-binding rows, exactly the way the switch's own Community page does. Pick an access mode and, optionally, a specific view (loaded from the switch; leave as the mode default)."));
    const name = textInput('', 'community string');
    const access = selectInput([{ label: 'Read Only', value: 'read-only' }, { label: 'Read Write', value: 'read-write' }, { label: 'SNMP Admin', value: 'snmp-admin' }], 'read-only');
    const views = await viewOptions(s);
    const view = selectInput([{ label: '(default for the mode)', value: '' }].concat(views.map((v) => ({ label: v, value: v }))), '');
    const grid = el('div', 'snmp-form-grid');
    grid.appendChild(snmpField('Community string', name));
    grid.appendChild(snmpField('Access mode', access));
    grid.appendChild(snmpField('View', view));
    form.appendChild(grid);
    const actions = el('div', 'snmp-form-actions');
    const preview = el('button', 'btn btn-small btn-blue', 'Apply');
    const cancel = el('button', 'btn btn-small secondary', 'Cancel');
      cancel.addEventListener('click', () => { if (onCancel) onCancel(); else dismissHost(host); });
    withConfirm(preview, () => {
      if (!name.value.trim()) { snmpFormMsg(host, 'bad', 'Enter a community string.'); return; }
      snmpPreview(s, host, 'community-add-preview', 'community-add-apply',
        { cfg: { community: name.value.trim(), access: access.value, view: view.value } },
        'Add community \u201C' + name.value.trim() + '\u201D', preview, 'communities');
    });
    actions.appendChild(preview); actions.appendChild(cancel);
    form.appendChild(actions);
    host.appendChild(form); host.scrollIntoView({ block: 'nearest' }); name.focus();
  }

  // ---- group view grid (shared by add + edit) ----
  async function viewOptions(s) {
    let views = [];
    try { const j = await snmpCfgPost(s, 'views'); if (j.ok) views = j.views || []; } catch (e) {}
    return views;
  }
  function viewSelect(views, current) {
    const opts = [{ label: '(none)', value: '' }].concat(views.map((v) => ({ label: v, value: v })));
    if (current && !views.includes(current)) opts.push({ label: current + ' (current)', value: current });
    return selectInput(opts, current || '');
  }
  function groupLevelGrid(views, existing) {
    // returns { table, read(level), write(level), notify(level) accessors }
    const table = el('table', 'snmp-view-table');
    const thead = el('thead'); const htr = el('tr');
    ['Security level', 'Read view', 'Write view', 'Notify view'].forEach((h) => htr.appendChild(el('th', '', h)));
    thead.appendChild(htr); table.appendChild(thead);
    const tb = el('tbody');
    const cells = {};
    const levels = [['noAuthNoPriv', 'No Authentication'], ['authNoPriv', 'Authentication'], ['authPriv', 'Privacy']];
    for (const [key, label] of levels) {
      const lv = (existing || {})[key] || {};
      const tr = el('tr');
      const lc = el('td');
      lc.appendChild(el('div', 'snmp-lvl-label', label));
      lc.appendChild(el('div', 'snmp-lvl-sub', key));
      tr.appendChild(lc);
      const rSel = viewSelect(views, lv.read), wSel = viewSelect(views, lv.write), nSel = viewSelect(views, lv.notify);
      [rSel, wSel, nSel].forEach((sel) => { const td = el('td'); td.appendChild(sel); tr.appendChild(td); });
      cells[key] = { read: rSel, write: wSel, notify: nSel };
      tb.appendChild(tr);
    }
    table.appendChild(tb);
    return { table, cells };
  }
  function collectLevels(cells) {
    const levels = {};
    for (const key of Object.keys(cells)) {
      levels[key] = { read: cells[key].read.value, write: cells[key].write.value, notify: cells[key].notify.value };
    }
    return levels;
  }

  // ---- Add group (inline form with view grid) ----
  async function addSnmpGroup(s, host, onCancel) {
    clear(host);
    const form = el('div', 'snmp-form');
    form.appendChild(el('h5', '', 'Add SNMPv3 group'));
    form.appendChild(el('p', 'intro', "A group sets Read / Write / Notify views per security level, like the switch's Groups page. Leave a level's views as (none) to not configure it. Views load from the switch."));
    const name = textInput('', 'group name');
    const grid = el('div', 'snmp-form-grid'); grid.appendChild(snmpField('Group name', name));
    form.appendChild(grid);
    const views = await viewOptions(s);
    const { table, cells } = groupLevelGrid(views, { authPriv: { read: 'DefaultSuper', notify: 'DefaultSuper' } });
    const tw = el('div', 'tablewrap'); tw.appendChild(table); form.appendChild(tw);
    const actions = el('div', 'snmp-form-actions');
    const preview = el('button', 'btn btn-small btn-blue', 'Apply');
    const cancel = el('button', 'btn btn-small secondary', 'Cancel');
      cancel.addEventListener('click', () => { if (onCancel) onCancel(); else dismissHost(host); });
    withConfirm(preview, () => {
      if (!name.value.trim()) { snmpFormMsg(host, 'bad', 'Enter a group name.'); return; }
      snmpPreview(s, host, 'group-add-preview', 'group-add-apply',
        { cfg: { group: name.value.trim(), levels: collectLevels(cells) } }, 'Add group \u201C' + name.value.trim() + '\u201D', preview, 'groups');
    });
    actions.appendChild(preview); actions.appendChild(cancel);
    form.appendChild(actions);
    host.appendChild(form); host.scrollIntoView({ block: 'nearest' }); name.focus();
  }

  // ---- Edit group views (inline form with view grid, prefilled) ----
  async function editSnmpGroup(s, g, host, onCancel) {
    const form = el('div', 'snmp-form');
    form.appendChild(el('h5', '', 'Edit views for group ' + g.group));
    form.appendChild(el('p', 'intro', "Change the Read / Write / Notify view for each security level. Clearing all three of a level removes that level's access row. Levels you don't change are left as-is."));
    const views = await viewOptions(s);
    const { table, cells } = groupLevelGrid(views, g.views || {});
    const tw = el('div', 'tablewrap'); tw.appendChild(table); form.appendChild(tw);
    const actions = el('div', 'snmp-form-actions');
    const preview = el('button', 'btn btn-small btn-blue', 'Apply');
    const cancel = el('button', 'btn btn-small secondary', 'Cancel');
    cancel.addEventListener('click', () => { if (onCancel) onCancel(); });
    withConfirm(preview, () => {
      snmpPreview(s, host, 'group-modify-preview', 'group-modify-apply',
        { cfg: { group: g.key.display || g.group, levels: collectLevels(cells) } }, 'Modify group \u201C' + g.group + '\u201D', preview, 'groups');
    });
    actions.appendChild(preview); actions.appendChild(cancel);
    form.appendChild(actions);
    host.appendChild(form);
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
