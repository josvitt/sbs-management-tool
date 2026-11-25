  // =================================================================
  // 25-updates.js: The Updates window: the installed version, the newest
  // GitHub release and its notes, Install and Go back, and an optional
  // GitHub token (the repository is public, so none is needed).
  // =================================================================
  // The server does the work (updater.js, update-boot.js). This window only
  // shows its status and asks it to act; nothing installs without a click.

  const updateToggleEl = document.getElementById('update-toggle');
  const updateDialogEl = document.getElementById('update-dialog');
  const updateBodyEl = updateDialogEl.querySelector('.update-body');
  let updateBusyTimer = null;

  function updateFmtTime(iso) {
    if (!iso) return '';
    const d = new Date(iso);
    return isNaN(d) ? '' : d.toLocaleString();
  }

  // The last thing an update did, in words (update-boot.js writes it).
  function updateOutcomeText(o) {
    if (!o) return null;
    const when = updateFmtTime(o.at);
    if (o.kind === 'installed') return { tone: 'good', text: 'Updated from ' + o.from + ' to ' + o.version + ' on ' + when + '.' };
    // Going back on request is not a fault; going back by itself is.
    if (o.kind === 'rolled-back') return { tone: /asked/.test(o.message || '') ? '' : 'crit', text: 'Went back from ' + o.from + ' to ' + o.version + ' on ' + when + ' (' + o.message + ').' };
    if (o.kind === 'install-failed') return { tone: 'crit', text: 'The update' + (o.version ? ' to ' + o.version : '') + ' was not installed on ' + when + ': ' + o.message };
    if (o.kind === 'rollback-failed') return { tone: 'crit', text: 'Going back failed on ' + when + ': ' + o.message };
    return null;
  }

  function setUpdateBadge(st) {
    updateToggleEl.classList.toggle('has-update', !!(st && st.available));
    updateToggleEl.title = st && st.available ? 'Version ' + st.latest.version + ' is available' : 'Updates';
  }

  // After Install or Go back the server restarts: wait until it answers again
  // as a different version (or with a new outcome), then reload the page.
  function waitForRestart(before) {
    const started = Date.now();
    return new Promise((resolve) => {
      const tick = () => {
        getJson('/api/update/status').then((st) => {
          const outcomeAt = st.lastOutcome && st.lastOutcome.at;
          if (st.phase !== 'restarting' && (st.current !== before.current || outcomeAt !== before.outcomeAt)) {
            resolve(st);
            setTimeout(() => location.reload(), 600);
            return;
          }
          retry();
        }).catch(retry);
      };
      const retry = () => {
        if (Date.now() - started > 5 * 60 * 1000) {
          toast('The app has not come back after the restart. If you started it without start.bat or the service, start it again.', 'error');
          resolve(null);
          return;
        }
        setTimeout(tick, 2000);
      };
      setTimeout(tick, 2500);
    });
  }

  function renderUpdates(st) {
    clear(updateBodyEl);
    setUpdateBadge(st);
    clearTimeout(updateBusyTimer);
    const before = { current: st.current, outcomeAt: st.lastOutcome && st.lastOutcome.at };

    // ---- versions ----
    updateBodyEl.appendChild(el('div', 'section-title', 'Version'));
    updateBodyEl.appendChild(el('div', 'update-line', 'Installed: ' + st.current));
    if (st.latest) {
      updateBodyEl.appendChild(el('div', 'update-line',
        'Newest release: ' + st.latest.version + (st.latest.publishedAt ? ' (' + updateFmtTime(st.latest.publishedAt) + ')' : '') +
        (st.available ? '' : ' — you have it')));
    }
    updateBodyEl.appendChild(el('div', 'card-sub', st.checkedAt ? 'Last checked ' + updateFmtTime(st.checkedAt) + '.' : 'Not checked yet.'));
    if (st.checkError) updateBodyEl.appendChild(el('div', 'update-msg crit', st.checkError));
    const outcome = updateOutcomeText(st.lastOutcome);
    if (outcome) updateBodyEl.appendChild(el('div', 'update-msg ' + outcome.tone, outcome.text));
    if (st.phaseError) updateBodyEl.appendChild(el('div', 'update-msg crit', 'Update failed, nothing was changed: ' + st.phaseError));

    const actions = el('div', 'row-split update-actions');
    const checkBtn = el('button', 'btn btn-blue', 'Check now'); checkBtn.type = 'button';
    checkBtn.addEventListener('click', () => runButtonAction(checkBtn, {
      failLabel: 'Check for updates',
      run: () => apiPost('/api/update/check'),
      settle: (res) => renderUpdates(res.body)
    }));
    actions.appendChild(checkBtn);
    updateBodyEl.appendChild(actions);

    // ---- what's new + install ----
    if (st.available) {
      updateBodyEl.appendChild(el('div', 'section-title', 'What’s new in ' + st.latest.version));
      updateBodyEl.appendChild(el('pre', 'update-notes', st.latest.notes || 'No notes were published with this release.'));
      updateBodyEl.appendChild(el('div', 'card-sub',
        'Installing downloads the release, prepares it beside the running app, then restarts the app into it (collection pauses for a few seconds). ' +
        'Your saved switches, keys, logs and history are kept. If the new version does not start, the app goes back to ' + st.current + ' by itself.'));
      const installBtn = el('button', 'btn', 'Install ' + st.latest.version + ' and restart'); installBtn.type = 'button';
      withConfirm(installBtn, (e) => runButtonAction(e.currentTarget, {
        failLabel: 'Update',
        spinLabel: 'Installing…',
        run: () => apiPost('/api/update/install'),
        settle: () => waitForRestart(before)
      }));
      const row = el('div', 'row-split update-actions'); row.appendChild(installBtn);
      updateBodyEl.appendChild(row);
    }
    if (st.phase !== 'idle') {
      const words = { checking: 'Checking GitHub…', downloading: 'Downloading the update…', preparing: 'Preparing the update (installing its dependencies)…', restarting: 'Restarting into the update…' };
      updateBodyEl.appendChild(el('div', 'update-msg', words[st.phase] || st.phase));
      updateBusyTimer = setTimeout(() => refreshUpdates(), 2000);
    }

    // ---- go back ----
    if (st.previous && !st.available) {
      updateBodyEl.appendChild(el('div', 'section-title', 'Previous version'));
      updateBodyEl.appendChild(el('div', 'card-sub', 'The version you updated from, ' + st.previous.version + ', is kept so you can go back to it. The app restarts.'));
      const backBtn = el('button', 'btn btn-danger', 'Go back to ' + st.previous.version); backBtn.type = 'button';
      withConfirm(backBtn, (e) => runButtonAction(e.currentTarget, {
        failLabel: 'Go back',
        run: () => apiPost('/api/update/rollback'),
        settle: () => waitForRestart(before)
      }), { danger: true });
      const row = el('div', 'row-split update-actions'); row.appendChild(backBtn);
      updateBodyEl.appendChild(row);
    }

    // ---- GitHub access ----
    // The repository is public, so updates need no token. One only lifts
    // GitHub's hourly limit, for many PCs behind one shared address.
    updateBodyEl.appendChild(el('div', 'section-title', 'GitHub access (optional)'));
    const tokenNote = st.token.source === 'environment'
      ? 'Using the token in SBS_UPDATE_TOKEN.'
      : (st.token.set ? 'A token is saved (encrypted with the vault key). Paste a new one to replace it.' : 'No token needed: updates come from the public repository ' + st.repo + '.');
    updateBodyEl.appendChild(el('div', 'update-line', tokenNote));
    if (st.token.refused) {
      updateBodyEl.appendChild(el('div', 'update-msg', 'GitHub refused this token (it may have expired), so the app checked without it. ' +
        (st.token.source === 'saved' ? 'You can remove it.' : 'You can remove SBS_UPDATE_TOKEN.')));
    }
    const tokenInput = el('input'); tokenInput.type = 'password'; tokenInput.autocomplete = 'off'; tokenInput.spellcheck = false;
    tokenInput.placeholder = 'github_pat_…';
    const tokenField = field('Token (optional)', tokenInput, 'field');
    updateBodyEl.appendChild(tokenField);
    updateBodyEl.appendChild(el('div', 'card-sub',
      'Only needed if checks say GitHub\'s hourly limit is used up, for example when many PCs share one internet address. ' +
      'Make one on GitHub: Settings → Developer settings → Fine-grained tokens → Generate, with Public repositories (read-only) access and no permissions. It is sent only to api.github.com.'));
    const tokRow = el('div', 'row-split update-actions');
    const saveTok = el('button', 'btn', 'Save token'); saveTok.type = 'button';
    saveTok.addEventListener('click', () => runButtonAction(saveTok, {
      failLabel: 'Save token',
      run: () => tokenInput.value.trim()
        ? apiPost('/api/update/token', { token: tokenInput.value })
        : { ok: false, body: { error: 'paste a token first' } },
      // Check straight away, so a wrong token shows up now, not tomorrow.
      settle: () => apiPost('/api/update/check').then((res) => renderUpdates(res.body))
    }));
    tokRow.appendChild(saveTok);
    if (st.token.source === 'saved') {
      const delTok = el('button', 'btn btn-danger', 'Remove token'); delTok.type = 'button';
      withConfirm(delTok, (e) => runButtonAction(e.currentTarget, {
        failLabel: 'Remove token',
        run: () => apiPost('/api/update/token', { token: '' }),
        settle: (res) => renderUpdates(res.body)
      }), { danger: true });
      tokRow.appendChild(delTok);
    }
    updateBodyEl.appendChild(tokRow);

    // ---- setting ----
    const auto = el('label', 'check-label update-auto');
    const box = el('input'); box.type = 'checkbox'; box.checked = !!st.settings.autoCheck;
    auto.appendChild(box); auto.appendChild(el('span', '', 'Check for updates once a day (never installs on its own)'));
    box.addEventListener('change', () => {
      apiPost('/api/update/settings', { autoCheck: box.checked }).then((res) => {
        if (!res.ok) { toast('Saving the setting failed: ' + ((res.body && res.body.error) || res.status), 'error'); box.checked = !box.checked; return; }
        flashValue(box.parentNode);
      }).catch((e) => { toast('Saving the setting failed: ' + e.message, 'error'); box.checked = !box.checked; });
    });
    updateBodyEl.appendChild(auto);
  }

  function refreshUpdates() {
    return getJson('/api/update/status').then((st) => {
      if (updateDialogEl.classList.contains('open')) renderUpdates(st); else setUpdateBadge(st);
      return st;
    }).catch((e) => {
      if (updateDialogEl.classList.contains('open')) {
        clear(updateBodyEl);
        updateBodyEl.appendChild(el('div', 'update-msg crit', 'Could not read the update status: ' + e.message));
      }
    });
  }

  updateToggleEl.addEventListener('click', () => { updateDialogEl.classList.add('open'); refreshUpdates(); });
  updateDialogEl.querySelector('.update-close').addEventListener('click', () => {
    updateDialogEl.classList.remove('open'); clearTimeout(updateBusyTimer);
  });
  // The badge follows the server's daily check; this reads its status only.
  refreshUpdates();
  setInterval(() => { if (!updateDialogEl.classList.contains('open')) refreshUpdates(); }, 60 * 60 * 1000);
