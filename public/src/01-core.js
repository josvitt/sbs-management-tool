  // =================================================================
  // 01-core.js: Logging, small helpers, runButtonAction and the shared building blocks every module uses (writes, confirm, table actions, index codecs).
  // =================================================================

  // =================================================================
  // Logging
  // =================================================================
  const logListEl = document.getElementById('log-list');
  const logPanelEl = document.getElementById('log-panel');
  const logToggleEl = document.getElementById('log-toggle');

  function appLog(level, message, meta) {
    const ts = new Date().toISOString();
    const fn = level === 'error' ? console.error : (level === 'warn' ? console.warn : console.log);
    fn('[' + ts + ']', message, meta || '');

    const entry = document.createElement('div');
    entry.className = 'log-entry ' + level;
    const metaStr = meta ? (typeof meta === 'string' ? meta : safeStringify(meta)) : '';
    entry.innerHTML =
      '<span class="ts">' + ts.split('T')[1].replace('Z', '') + '</span>' +
      '<span class="lvl">' + level.toUpperCase() + '</span>' +
      '<span class="msg"></span>' + (metaStr ? '<span class="meta"></span>' : '');
    entry.querySelector('.msg').textContent = message;
    if (metaStr) entry.querySelector('.meta').textContent = metaStr;
    logListEl.appendChild(entry);
    logListEl.scrollTop = logListEl.scrollHeight;
    if (level === 'error') logToggleEl.classList.add('has-errors');

    try {
      fetch('/api/log', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ level, message, meta: sanitizeMeta(meta) })
      }).catch(() => {});
    } catch (e) { /* ignore */ }
  }
  function safeStringify(o) { try { return JSON.stringify(o); } catch (e) { return String(o); } }
  function sanitizeMeta(meta) {
    if (!meta || typeof meta !== 'object') return meta;
    const c = {};
    for (const k in meta) c[k] = /pass(word)?|secret|token|community|authkey|privkey/i.test(k) ? '[REDACTED]' : meta[k];
    return c;
  }

  window.addEventListener('error', (e) => appLog('error', e.message || 'Uncaught error',
    { source: e.filename, line: e.lineno, col: e.colno, stack: e.error && e.error.stack }));
  window.addEventListener('unhandledrejection', (e) => appLog('error', 'Unhandled promise rejection',
    { reason: e.reason && e.reason.message ? e.reason.message : String(e.reason) }));

  logToggleEl.addEventListener('click', () => logPanelEl.classList.toggle('open'));
  document.getElementById('log-close').addEventListener('click', () => logPanelEl.classList.remove('open'));
  document.getElementById('log-clear').addEventListener('click', () => {
    logListEl.innerHTML = ''; logToggleEl.classList.remove('has-errors');
  });

  const librariesLoaded = () =>
    typeof window.Terminal === 'function' && typeof window.FitAddon === 'object';
  if (!librariesLoaded()) {
    appLog('error', 'Terminal library failed to load from vendor/xterm/. SSH cannot start.');
  }

  // =================================================================
  // Small helpers
  // =================================================================
  // Sentinel for "show the whole capture" in the section rail.
  const FULL_OUTPUT = '__full__';

  function el(tag, cls, text, title) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined && text !== null) e.textContent = String(text);
    if (title) e.title = title;
    return e;
  }
  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }

  // One consistent row-action button, used for Edit/Delete/etc. across every
  // table so they look and behave identically. `variant`: '' (neutral),
  // 'danger' (red on hover), or 'primary' (blue). onClick receives the event.
  // ---- action feedback ----
  // A completed action is shown, not announced: the button briefly morphs to a
  // check with a success tint then settles back, and (optionally) the value
  // that changed gets a soft highlight that fades. No "Applied" text.
  // Put an inline spinner in an action button and disable it, remembering the
  // resting label so flashButtonOk can restore it. Used for the "click -> spin
  // while applying AND refreshing -> Done" flow, so the button only says Done
  // once the UI actually reflects the change.
  function buttonSpin(btn, label) {
    if (!btn) return;
    if (btn.dataset && !btn.dataset.restLabel) {
      const t = (btn.textContent || '').trim();
      if (t && !/\u2026$/.test(t)) btn.dataset.restLabel = t;
    }
    btn._okOriginal = (btn.dataset && btn.dataset.restLabel) || btn._okOriginal || (btn.textContent || '').trim();
    clearTimeout(btn._okTimer);
    btn.classList.remove('is-ok');
    clear(btn);
    btn.appendChild(el('span', 'spinner inline'));
    if (label) btn.appendChild(document.createTextNode(label));
    btn.disabled = true;
  }

  function flashButtonOk(btn, holdMs) {
    if (!btn) return;
    // The original label must be the button's RESTING label, not whatever it
    // shows mid-action ("Applying…"). Prefer an explicit one stored at creation
    // (dataset.restLabel), fall back to a previously captured one, else the
    // current text - and never capture a transient "…" label.
    let original = btn.dataset && btn.dataset.restLabel;
    if (!original) original = btn._okOriginal;
    if (!original) {
      const t = btn.textContent || '';
      original = /\u2026$/.test(t) ? t.replace(/\u2026$/, '').replace(/ing$/, '') : t;
    }
    btn._okOriginal = original;
    clearTimeout(btn._okTimer);
    clear(btn);
    const check = el('span', 'ok-check', '\u2713');
    btn.appendChild(check);
    btn.appendChild(document.createTextNode('Done'));
    btn.classList.add('is-ok');
    btn.disabled = false;
    clearTimeout(btn._okTimer);
    btn._okTimer = setTimeout(() => {
      btn.classList.remove('is-ok');
      btn.textContent = original;
    }, holdMs || 1400);
  }

  // ===========================================================================
  // runButtonAction - the single, reusable flow for any action button.
  // ---------------------------------------------------------------------------
  // Every button that performs a change should go through this so the behavior
  // is identical everywhere: the button shows a spinner the instant it is
  // clicked, keeps spinning through BOTH the write AND the UI refresh, and only
  // resolves once the interface actually reflects the change - never a premature
  // "Done" ahead of the table catching up. The caller declares WHAT happens, not
  // how to sequence it:
  //
  //   runButtonAction(btn, {
  //     run:    () => apiPost('/api/port/admin', {...}),  // the write; returns a promise
  //     settle: () => refreshOnePort(s, ifIndex),         // the UI refresh; returns a promise
  //     ok:     (res) => true,          // optional: did it succeed? (default: res.ok && !res.body.error)
  //     error:  (res) => 'message',     // optional: error text for a toast
  //     find:   () => theNewButton,     // optional: locate the button after a reconcile replaced it
  //     spinLabel, doneHoldMs, onDone   // optional extras
  //   })
  //
  // After settle(), if the original button is still in the DOM it flashes Done;
  // if a reconcile replaced it (e.g. a shut flips the label), find() locates the
  // fresh button to flash, or - if there is none - the flipped button already on
  // screen is itself the confirmation. On failure the button is restored and a
  // toast shown. Returns the flow's promise.
  // ===========================================================================
  function runButtonAction(btn, spec) {
    spec = spec || {};
    const restLabel = (btn && btn.dataset && btn.dataset.restLabel) || (btn && (btn.textContent || '').trim()) || '';
    const okOf = spec.ok || ((res) => res && res.ok && !(res.body && res.body.error));
    const errOf = spec.error || ((res) => (res && res.body && res.body.error) || 'the switch rejected it');
    const restore = () => { if (btn) { btn.disabled = false; btn.classList.remove('is-ok'); clear(btn); btn.appendChild(document.createTextNode(restLabel)); } };

    if (btn) buttonSpin(btn, spec.spinLabel);
    // Floor the spinner's visible duration so a near-instant write (a single fast
    // SET resolves in ~15ms) still shows a perceptible "working" moment rather
    // than flashing straight to Done. Only the SUCCESS path waits this out - a
    // failure should surface immediately. Overridable (or 0 to disable) via
    // spec.minSpinMs; default 250ms is enough to register without feeling slow.
    const spinStart = Date.now();
    const minSpinMs = spec.minSpinMs != null ? spec.minSpinMs : 250;
    const waitMinSpin = () => {
      const remaining = minSpinMs - (Date.now() - spinStart);
      return remaining > 0 ? new Promise((r) => setTimeout(r, remaining)) : Promise.resolve();
    };
    let runPromise;
    try { runPromise = Promise.resolve(spec.run ? spec.run() : null); }
    catch (e) { runPromise = Promise.reject(e); }

    return runPromise.then((res) => {
      if (!okOf(res)) {
        toast((spec.failLabel || restLabel || 'Action') + ' failed: ' + errOf(res), 'error');
        restore();
        return res;
      }
      if (spec.onApplied) { try { spec.onApplied(res); } catch (e) { /* non-fatal */ } }
      // Wait for the UI to actually reflect the change before confirming, and for
      // the minimum spin floor, so the spinner is always perceptible.
      const settle = spec.settle ? Promise.resolve(spec.settle(res)) : Promise.resolve();
      return Promise.all([settle, waitMinSpin()]).then(() => {
        let target = btn && btn.isConnected ? btn : null;
        if (!target && spec.find) { try { target = spec.find(); } catch (e) { target = null; } }
        if (target) flashButtonOk(target, spec.doneHoldMs);
        // else: a reconcile replaced the button with its new correct label, which
        // is itself the confirmation.
        if (spec.onDone) { try { spec.onDone(res); } catch (e) { /* non-fatal */ } }
        return res;
      });
    }).catch((e) => {
      toast((spec.failLabel || restLabel || 'Action') + ' failed: ' + (e && e.message ? e.message : e), 'error');
      restore();
      throw e;
    });
  }

  // Highlight an element (a table cell, a display value) so a change is felt as
  // it lands. Re-triggers cleanly if called again.
  // Briefly highlight a changed value so the user sees the change land. Works
  // on a display cell (dd/span) or a form control (input/select) - the CSS
  // targets both. Pass the control itself; a null/undefined node is ignored.
  function flashValue(node) {
    if (!node) return;
    node.classList.remove('value-changed');
    // Force reflow so the animation restarts even on a repeated change.
    void node.offsetWidth;
    node.classList.add('value-changed');
    setTimeout(() => { node.classList.remove('value-changed'); }, 1700);
  }
  // Highlight several controls at once (convenience for an editor's apply).
  function flashValues(nodes) { for (const n of nodes || []) flashValue(n); }

  // ---- apply/save button lifecycle ----
  // The scaffold every editor shares: an actions row holding a primary (blue)
  // Apply/Save button, and a message element for inline status/errors. Returns
  // { actions, apply, msg } so the caller wires its own handler and placement.
  // opts: { extra: [buttons beside the primary], msgClass: 'port-detail-msg' }.
  function applyActions(label, opts) {
    opts = opts || {};
    const actions = el('div', 'snmp-form-actions');
    const apply = el('button', 'btn btn-small', label || 'Apply'); apply.type = 'button';
    const msg = el('div', opts.msgClass || 'port-detail-msg');
    actions.appendChild(apply);
    for (const b of opts.extra || []) if (b) actions.appendChild(b);
    return { actions, apply, msg };
  }

  // ---- shared building blocks (used by every module) ----
  // A labelled form field: <div class="FIELDCLASS"><label>..</label><control></div>.
  // The default class suits the form grids; pass another for a different layout.
  function field(labelText, control, cls) {
    const f = el('div', cls || 'snmp-field');
    f.appendChild(el('label', '', labelText));
    f.appendChild(control);
    return f;
  }
  // A text input, optionally pre-filled, with a placeholder.
  function textInput(value, placeholder) {
    const i = el('input'); i.type = 'text'; if (value != null) i.value = value; if (placeholder) i.placeholder = placeholder;
    return i;
  }
  // A <select> from [{ label, value }], with `value` selected.
  function selectInput(options, value) {
    const sel = el('select');
    for (const o of options) {
      const opt = el('option', '', o.label); opt.value = o.value;
      if (o.value === value) opt.selected = true;
      sel.appendChild(opt);
    }
    return sel;
  }

  // One place that knows how to POST JSON to the local API and parse the reply.
  // Returns { ok, body } (never throws on HTTP status); throws only on a network
  // failure. Every module should go through this instead of hand-rolling fetch.
  async function apiPost(path, payload) {
    const r = await fetch(path, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload || {})
    });
    let body = null;
    try { body = await r.json(); } catch (e) { body = null; }
    return { ok: r.ok, status: r.status, body };
  }

  // The single SNMP write path. Accepts one varbind ({oid,type,value|valueHex})
  // or an array of them, sends them in ONE atomic SET PDU, and THROWS on any
  // failure (so callers can try/catch uniformly). Returns the parsed body on
  // success. Every write in the app should use this rather than its own fetch.
  async function snmpSet(s, varbinds) {
    const vbs = Array.isArray(varbinds) ? varbinds : [varbinds];
    const { ok, status, body } = await apiPost('/api/snmp/set', { target: s.target, varbinds: vbs });
    if (!ok || (body && body.error)) throw new Error((body && body.error) || ('HTTP ' + status));
    return body;
  }
  // Non-throwing variant for callers that want to branch on the result instead
  // of catching - returns { ok, body } like the raw fetch used to.
  async function snmpSetResult(s, varbinds) {
    const vbs = Array.isArray(varbinds) ? varbinds : [varbinds];
    return apiPost('/api/snmp/set', { target: s.target, varbinds: vbs });
  }

  // Delete a conceptual-row by its RowStatus column OID (already including the
  // row index). Some Cisco tables reject a direct destroy(6) with CommitFailed
  // when the row is active - they require it be moved to notInService(2) first.
  // This tries the direct destroy, and on failure falls back to
  // notInService -> destroy, so one helper handles both kinds of table. Returns
  // the { ok, body } of the set that settled it.
  async function rowStatusDelete(s, statusOid) {
    const DESTROY = 6, NOT_IN_SERVICE = 2;
    const first = await snmpSetResult(s, { oid: statusOid, type: 'Integer', value: DESTROY });
    if (first && first.ok && !(first.body && first.body.error)) return first;
    // Fallback: suspend the row, then destroy it.
    const suspend = await snmpSetResult(s, { oid: statusOid, type: 'Integer', value: NOT_IN_SERVICE });
    if (!suspend || !suspend.ok || (suspend.body && suspend.body.error)) return first; // report the original failure
    return snmpSetResult(s, { oid: statusOid, type: 'Integer', value: DESTROY });
  }

  // Interpret a snmpSetResult into the common { ok, error } shape many callers
  // return, checking both the top-level error and any per-varbind error.
  function interpretSet(res) {
    const { ok, status, body } = res;
    if (!ok || (body && body.error)) return { ok: false, error: (body && body.error) || ('HTTP ' + status) };
    const bad = (body && (body.results || []).find((v) => v.error)) || null;
    return bad ? { ok: false, error: bad.error } : { ok: true };
  }

  // The single SNMP read path for ad-hoc GETs. Returns the array of result
  // varbinds (possibly empty); throws on network/HTTP/agent error.
  async function snmpGet(s, oids) {
    const { ok, status, body } = await apiPost('/api/snmp/get', { target: s.target, oids: Array.isArray(oids) ? oids : [oids] });
    if (!ok || (body && body.error)) throw new Error((body && body.error) || ('HTTP ' + status));
    return (body && body.results) || [];
  }

  // A brief floating notice for actions whose result isn't shown in place -
  // e.g. a table-row delete that failed (the row is still there and the user
  // needs to know why). kind: 'error' | 'ok'. Auto-dismisses; stacks at the
  // bottom-right; clicking it dismisses early.
  function toast(message, kind) {
    let host = document.querySelector('.toast-host');
    if (!host) { host = el('div', 'toast-host'); document.body.appendChild(host); }
    const t = el('div', 'toast toast-' + (kind === 'ok' ? 'ok' : 'error'));
    t.appendChild(el('span', 'toast-icon', kind === 'ok' ? '\u2713' : '\u26A0'));
    t.appendChild(el('span', 'toast-msg', message));
    host.appendChild(t);
    void t.offsetWidth; t.classList.add('toast-in');
    const dismiss = () => { t.classList.remove('toast-in'); setTimeout(() => t.remove(), 250); };
    t.addEventListener('click', dismiss);
    setTimeout(dismiss, kind === 'ok' ? 2600 : 5000);
  }

  // Two-tap confirmation, modern and inline: the first click arms the button
  // (it morphs to "Confirm?" with a warning tint); a second click within a few
  // seconds runs the action; otherwise it disarms and returns to its label.
  // Wrap a click handler with this to require confirmation. `danger` tints red.
  // opts.when (optional) decides per click whether this click needs the
  // confirm at all: when it returns false the action runs on the first tap
  // (an editor whose Apply only sometimes does something drastic). confirmText
  // may be a function, so the armed label can name what the click will do.
  function withConfirm(btn, run, opts) {
    opts = opts || {};
    const label = opts.label || btn.textContent;
    const textOf = () => (typeof opts.confirmText === 'function' ? opts.confirmText() : opts.confirmText) || 'Confirm?';
    const danger = opts.danger;
    btn._armed = false;
    const disarm = () => {
      btn._armed = false;
      clearTimeout(btn._armTimer);
      btn.classList.remove('is-arming', 'is-arming-danger');
      btn.textContent = label;
    };
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      if (!btn._armed && opts.when && !opts.when()) { run(e); return; }
      if (!btn._armed) {
        btn._armed = true;
        btn.classList.add(danger ? 'is-arming-danger' : 'is-arming');
        btn.textContent = textOf();
        clearTimeout(btn._armTimer);
        btn._armTimer = setTimeout(disarm, 3500);
        return;
      }
      disarm();
      run(e);
    });
    return btn;
  }

  function actBtn(label, onClick, variant, title) {
    const b = el('button', 'tbl-act-btn' + (variant ? ' ' + variant : ''), label);
    b.type = 'button';
    if (title) b.title = title;
    b.addEventListener('click', (e) => { e.stopPropagation(); onClick(e); });
    return b;
  }
  // A table action button that requires a second tap to confirm (for deletes
  // and other destructive actions). First tap -> "Confirm?"; second runs it.
  function actBtnConfirm(label, onClick, variant, title) {
    const b = el('button', 'tbl-act-btn' + (variant ? ' ' + variant : ''), label);
    b.type = 'button';
    if (title) b.title = title;
    withConfirm(b, (e) => onClick(e), { label, danger: variant === 'danger' });
    return b;
  }
  // A right-aligned group of row-action buttons, as a DOM node for a table cell.
  function actGroup(buttons) {
    const g = el('span', 'tbl-acts');
    for (const b of buttons) if (b) g.appendChild(b);
    return g;
  }

  // One consistent "+ Add ..." control, placed bottom-left below the table it
  // relates to. Returns the wrapping div (so callers can also render the inline
  // add form into it). onClick receives the host div.
  function addControl(label, onClick) {
    const host = el('div', 'tbl-add');
    const btn = el('button', 'tbl-add-btn', '+ ' + label); btn.type = 'button';
    btn.addEventListener('click', () => onClick(host, btn));
    host.appendChild(btn);
    return host;
  }

  function stripAnsi(str) {
    if (!str) return str;
    let out = str;
    out = out.replace(/\x1b\[[0-?]*[ -\/]*[@-~]/g, '');
    out = out.replace(/\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)/g, '');
    out = out.replace(/\x1b./g, '').replace(/\x1b/g, '').replace(/\x07/g, '');
    let r = '';
    for (const ch of out) { if (ch === '\b') r = r.slice(0, -1); else r += ch; }
    return r;
  }

  function padTo(s, w) { s = String(s == null ? '' : s); return s + ' '.repeat(Math.max(0, w - s.length)); }
  function textTable(headers, rows) {
    const widths = headers.map((h, i) =>
      Math.max(String(h).length, ...rows.map((r) => String(r[i] == null ? '' : r[i]).length)));
    const line = (cells) => cells.map((c, i) => padTo(c, widths[i])).join('  ').replace(/\s+$/, '');
    const out = [line(headers), widths.map((w) => '-'.repeat(w)).join('  ')];
    for (const r of rows) out.push(line(r));
    return out.join('\n') + '\n';
  }
  function fmtBytes(n) {
    const v = Number(n);
    if (!Number.isFinite(v)) return String(n);
    if (v >= 1048576) return (v / 1048576).toFixed(1) + ' MB';
    if (v >= 1024) return (v / 1024).toFixed(0) + ' KB';
    return v + ' B';
  }
  function download(name, text) {
    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = name;
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }
  const stamp = () => new Date().toISOString().replace(/[:.]/g, '-');
  const safeHost = (h) => String(h || 'switch').replace(/[^a-zA-Z0-9.\-]/g, '_');

  // Build a CISCOSB VlanListN 128-byte bitmap for one 1024-VLAN block.
  // Encoding (confirmed against live switch data): byte 0 holds VLANs 1-8,
  // MSB = lowest VLAN. blockBase is 1, 1025, 2049 or 3073.
  function buildVlanListBlock(vlans, blockBase) {
    const buf = new Uint8Array(128);
    for (const v of vlans) {
      if (v < blockBase || v > blockBase + 1023) continue;
      const bit = v - blockBase;              // 0-based within the block
      buf[Math.floor(bit / 8)] |= (0x80 >> (bit % 8));
    }
    let hex = '';
    for (const b of buf) hex += b.toString(16).padStart(2, '0');
    return hex;
  }
  const vlanListBlocks = (vlans) => ([
    ['vlanTrunkModeList1to1024', buildVlanListBlock(vlans, 1)],
    ['vlanTrunkModeList1025to2048', buildVlanListBlock(vlans, 1025)],
    ['vlanTrunkModeList2049to3072', buildVlanListBlock(vlans, 2049)],
    ['vlanTrunkModeList3073to4094', buildVlanListBlock(vlans, 3073)]
  ]);

  // ---- config history (read-only: nothing here talks to the switch) ----

  async function getJson(url) {
    const r = await fetch(url);
    const body = await r.json().catch(() => ({}));
    if (!r.ok || body.error) throw new Error(body.error || ('HTTP ' + r.status));
    return body;
  }
  // A dotted-IPv4 string -> hex OctetString of its 4 bytes (for InetAddress).
  function ipv4ToHex(ip) {
    const m = String(ip).trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (!m) return null;
    const o = m.slice(1).map(Number);
    if (o.some((n) => n < 0 || n > 255)) return null;
    return o.map((n) => n.toString(16).padStart(2, '0')).join('');
  }
  // Raw InetAddress bytes (from a GET) -> dotted IPv4, or '' if not 4 bytes.
  function hexToIpv4(cell) {
    if (!cell) return '';
    // The value may arrive as a display string of bytes or a hex string.
    const disp = cell.display !== undefined ? cell.display : cell.value;
    const s = String(disp || '');
    // "0A 00 00 01" or "10.0.0.1" or hex "0a000001"
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) return s;
    const hex = s.replace(/0x|\s|:/gi, '');
    if (/^[0-9a-f]{8}$/i.test(hex)) {
      return [0, 2, 4, 6].map((i) => parseInt(hex.substr(i, 2), 16)).join('.');
    }
    return s;
  }

  // Length-prefixed IPv4 address portion of an InetAddress OID index ("4.o.o.o.o"),
  // matching the server-side aaa.js encoder. InetAddressType ipv4 = 1.
  const INET_IPV4 = 1;
  function ipv4IndexV4(ip) {
    const m = String(ip || '').trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (!m) return null;
    const o = m.slice(1).map(Number);
    if (o.some((n) => n < 0 || n > 255)) return null;
    return '4.' + o.join('.');
  }
  // Full nameserver row index: AddrType . <len.bytes> . SubTree(root) . Class(IN).
  function nameserverIndex(ip) {
    const a = ipv4IndexV4(ip);
    return a ? (INET_IPV4 + '.' + a + '.0.1') : null;
  }
  // Inverse: pull the IPv4 address out of a nameserver row index. The index is
  // AddrType . <len> . <len address bytes> . <rest>; for ipv4(1) the four octets
  // follow the length byte. Returns '' if it does not parse as an IPv4 inet index.
  function inetIndexToIp(idx) {
    const p = String(idx || '').split('.').map((n) => parseInt(n, 10));
    if (p.length < 6 || p[0] !== INET_IPV4 || p[1] !== 4) return '';
    const octets = p.slice(2, 6);
    if (octets.some((o) => !Number.isFinite(o) || o < 0 || o > 255)) return '';
    return octets.join('.');
  }

  // Decode a DNS-client-v2 servers-table row index (93.15), whose INDEX is
  // Source . IfIndex . Preference . AddrType . InetAddr(len-prefixed) . SubTree
  // (DnsNameAsIndex) . Class. Verified against switch rows like
  // 1.1.0.1.4.192.168.1.69.0.1 (source static, if 1, pref 0, ipv4,
  // 192.168.1.69, root subtree, class IN). Returns { addr, source, pref } for
  // display, or null if it does not parse as an IPv4 server row.
  function dnsV2ServerIndex(idx) {
    const p = String(idx || '').split('.').map((n) => parseInt(n, 10));
    if (p.length < 10) return null;
    const source = p[0], ifIndex = p[1], pref = p[2], addrType = p[3], addrLen = p[4];
    if (addrType !== 1 || addrLen !== 4) return null;          // IPv4 only
    const octets = p.slice(5, 9);
    if (octets.some((o) => !Number.isFinite(o) || o < 0 || o > 255)) return null;
    void ifIndex;
    return { addr: octets.join('.'), source: source, pref: pref };
  }

  // Encode a dotted IPv4 as the dot-separated OID index fragment it becomes in a
  // table keyed by an IpAddress (each octet is one sub-identifier).
  function ipToOidIndex(ip) { return String(ip || '').split('.').map((o) => parseInt(o, 10)).join('.'); }
  // Encode a string as a length-prefixed OID index fragment (DnsNameAsIndex etc).
  // DnsNameAsIndex (the real Cisco DNS table index, decoded from switch-created
  // rows): <total-length> . <DNS wire-format name>. DNS wire format is, per label,
  // <label-length><label-bytes>, terminated by a 0 byte. So "example" becomes
  // 9.7.101.120.97.109.112.108.101.0  (9 = length of "7example\0"), and
  // "internal.example.com" becomes 20.8.i..7.example.3.com.0. An earlier flat-ASCII
  // encoding (dots as literal bytes) was rejected by the switch with
  // NotWritable/NoCreation; these encode/decode the real DnsNameAsIndex format.
  function dnsNameIndex(name) {
    const labels = String(name || '').split('.').filter((l) => l.length);
    const wire = [];
    for (const lab of labels) { wire.push(lab.length); for (const ch of lab) wire.push(ch.charCodeAt(0)); }
    wire.push(0);                       // root terminator
    return [wire.length].concat(wire).join('.');   // total-length prefix + wire bytes
  }
  // Inverse: the leading DnsNameAsIndex portion of an OID index back to a name.
  // Returns { name, rest } where rest is the array of index sub-ids after the name
  // (e.g. the host table's Owner.Index), or null if it does not parse.
  function dnsNameIndexParse(idx) {
    const parts = String(idx || '').split('.').map((n) => parseInt(n, 10));
    if (parts.length < 2 || !Number.isFinite(parts[0])) return null;
    const total = parts[0];
    const wire = parts.slice(1, 1 + total);
    if (wire.length < total) return null;
    const labels = []; let i = 0;
    while (i < wire.length) {
      const l = wire[i];
      if (l === 0) break;
      if (!Number.isFinite(l) || i + 1 + l > wire.length) return null;
      labels.push(wire.slice(i + 1, i + 1 + l).map((c) => String.fromCharCode(c)).join(''));
      i += 1 + l;
    }
    return { name: labels.join('.'), rest: parts.slice(1 + total) };
  }
  function dnsNameIndexToStr(idx) { const r = dnsNameIndexParse(idx); return r ? r.name : String(idx || ''); }

  // A titled section inside an editor form.
  function formSection(title) {
    const sec = el('div', 'acl-fsec');
    sec.appendChild(el('div', 'acl-fsec-title', title));
    const body = el('div', 'acl-fsec-body');
    sec.appendChild(body);
    return { sec, body };
  }

  // A cell's display text, falling back to its raw value (ACL and port-channel
  // cells).
  function dvc(cell) { return cell ? (cell.display !== undefined && cell.display !== null && cell.display !== '' ? cell.display : cell.value) : ''; }

  const q2 = (s, sel) => s.pane.querySelector(sel);
