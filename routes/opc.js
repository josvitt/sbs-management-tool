'use strict';

/**
 * Onboard Packet Capture: configure, run, export and fetch captures.
 */

const snmp = require('net-snmp');
const log = require('../logger');
const configFetch = require('../config-fetch');
const opc = require('../opc');
const { copyFinishedWaiter, buildSnmpSession, describeVarbind, redactTarget, snmpResponder, mapSetVarbinds, snmpSetPromise } = require('../snmp-core');
const { snmpGetPromise, boundedWalkPromise } = require('../collection');

module.exports = function register(app) {
  // -----------------------------------------------------------------
  // Onboard Packet Capture (OPC)
  // -----------------------------------------------------------------


  // Run a sequence of varbind groups as separate SETs, in order, over one
  // session. Returns on the first failure (attributable to its group).
  async function runOpcSteps(target, groups) {
    const session = buildSnmpSession(target);
    try {
      for (const g of groups) {
        if (!g.varbinds || !g.varbinds.length) continue;
        await snmpSetPromise(session, mapSetVarbinds(g.varbinds));
      }
    } finally {
      try { session.close(); } catch (e) { /* ignore */ }
    }
  }

  // Configure (create) the capture point + bind the control plane. Body:
  // { target, name, bufferType, bufferSizeMb, filter, aclName, direction,
  //   limitDurationSec, limitPackets, limitMaxLen }
  app.post('/api/opc/configure', async (req, res) => {
    const b = req.body || {};
    if (!b.target || !b.target.host) return res.status(400).json({ error: 'target.host is required.' });
    if (!b.name) return res.status(400).json({ error: 'A capture name is required.' });
    try {
      const steps = [{ varbinds: opc.planCreateCapture(b) }];
      // For a new capture, bind the control plane. The action row is NOT created
      // here: its columns are written (and the row created implicitly) at export
      // time, which is the form the switch accepts. For a reconfigure the rows
      // already exist, so only the direction is updated.
      if (!b.existing) {
        steps.push({ varbinds: opc.planBindControlPlane(b.name, b.direction || 'both') });
      } else {
        // Only update the direction on the existing control-plane row.
        steps.push({ varbinds: [{ oid: opc.OID.ifDirection + '.' + opc.ifIndex(b.name, opc.CONTROL_PLANE_IFINDEX),
          type: 'Integer', value: opc.DIRECTION[b.direction] || opc.DIRECTION.both }] });
      }
      await runOpcSteps(b.target, steps);
      res.json({ ok: true });
    } catch (e) {
      log.error('opc', 'configure failed', { target: redactTarget(b.target), message: e.message });
      res.status(502).json({ error: e.message });
    }
  });

  // List existing capture points. Body: { target }
  app.post('/api/opc/list', async (req, res) => {
    const b = req.body || {};
    if (!b.target || !b.target.host) return res.status(400).json({ error: 'target.host is required.' });
    const session = buildSnmpSession(b.target);
    try {
      const rows = await boundedWalkPromise(session, opc.WALK.capturePoint, 'getbulk', { maxRows: 2000 });
      // Reduce to {oid, value} using decoded display where it differs.
      const simple = rows.map((vb) => {
        const d = describeVarbind(vb);
        return { oid: vb.oid, value: (d.display !== undefined && d.display !== null && d.display !== String(d.value)) ? d.display : d.value };
      });
      res.json({ ok: true, captures: opc.parseCaptureList(simple) });
    } catch (e) {
      res.status(502).json({ error: e.message });
    } finally {
      try { session.close(); } catch (e) {}
    }
  });

  // Start / stop / clear. Body: { target, name, action: 'start'|'stop'|'clear' }
  // rlOpcAction lives in rlOpcActionTable, and that row must exist before the
  // action column can be SET (otherwise the switch returns CommitFailed). The
  // action row is NOT created with the capture point — it is created on demand —
  // so every start/stop/export first ensures the row exists. Creating a row that
  // already exists is refused, which is fine: we ignore that and proceed.
  app.post('/api/opc/action', async (req, res) => {
    const b = req.body || {};
    if (!b.target || !b.target.host) return res.status(400).json({ error: 'target.host is required.' });
    if (!b.name || !opc.ACTION[b.action]) return res.status(400).json({ error: 'name and a valid action are required.' });
    try {
      // rlOpcAction is one column whose write creates/uses the action row
      // implicitly, so it is set on its own in a single PDU.
      await runOpcSteps(b.target, [{ varbinds: opc.planAction(b.name, b.action) }]);
      res.json({ ok: true });
    } catch (e) {
      log.error('opc', 'action failed', { target: redactTarget(b.target), action: b.action, message: e.message });
      res.status(502).json({ error: e.message });
    }
  });

  // Live status of a capture point. Body: { target, name }
  app.post('/api/opc/status', async (req, res) => {
    const b = req.body || {};
    if (!b.target || !b.target.host) return res.status(400).json({ error: 'target.host is required.' });
    if (!b.name) return res.status(400).json({ error: 'name is required.' });
    const session = buildSnmpSession(b.target);
    const responder = snmpResponder(res, session, 'opc-status', 10000);
    const so = opc.statusOids(b.name);
    const names = Object.keys(so);
    session.get(names.map((k) => so[k]), (error, varbinds) => {
      if (error) return responder.fail(502, error.message);
      const out = {};
      varbinds.forEach((vb, i) => {
        out[names[i]] = snmp.isVarbindError(vb) ? null : vb.value;
      });
      // Decode state 1=active 2=inactive.
      out.stateText = out.state === 1 ? 'active' : (out.state === 2 ? 'inactive' : null);
      responder.ok(out);
    });
  });

  // Delete the capture point. Body: { target, name }
  app.post('/api/opc/delete', async (req, res) => {
    const b = req.body || {};
    if (!b.target || !b.target.host) return res.status(400).json({ error: 'target.host is required.' });
    if (!b.name) return res.status(400).json({ error: 'name is required.' });
    try {
      // Each destroy is attempted independently: a missing companion row should
      // not block removing the capture point itself.
      const session = buildSnmpSession(b.target);
      for (const vb of opc.planDeleteCapture(b.name)) {
        try { await snmpSetPromise(session, mapSetVarbinds([vb])); } catch (e) { /* ignore */ }
      }
      try { session.close(); } catch (e) {}
      res.json({ ok: true });
    } catch (e) {
      res.status(502).json({ error: e.message });
    }
  });

  // Export the capture to a flash .pcap, then copy that flash file to the
  // built-in TFTP receiver and stream it back as a download.
  // Body: { target, name, tftpPort }
  // Read one capture point's state + packet count, for export preconditions.
  function readCaptureState(target, name) {
    return new Promise((resolve) => {
      const session = buildSnmpSession(target);
      const so = opc.statusOids(name);
      session.get([so.state, so.packets], (error, varbinds) => {
        try { session.close(); } catch (e) {}
        if (error) return resolve({ error: error.message });
        const state = varbinds[0] && !snmp.isVarbindError(varbinds[0]) ? Number(varbinds[0].value) : null;
        const packets = varbinds[1] && !snmp.isVarbindError(varbinds[1]) ? Number(varbinds[1].value) : null;
        resolve({ state, packets });
      });
    });
  }

  // Export the capture buffer to a flash .pcap, switch-side only. Two methods:
  //   'combined'  : dest + filename + action=export in ONE PDU, no RowStatus.
  //                 The switch acks noError and writes a valid pcap, but it
  //                 crashes the control plane. Kept only as a comparison.
  //   'cw-setup'  : the RFC 2579 createAndWait lifecycle WITHOUT the trigger -
  //                 createAndWait, populate (dest+filename), activate - reading
  //                 the row back after each step so its state is reported. Leaves
  //                 an active, managed action row ready to trigger.
  //   'cw-trigger': set action=export on the active row, then destroy it (clean
  //                 teardown). Run after a successful 'cw-setup'.
  // All require confirm:true. cw-setup/combined enforce the capture is present,
  // stopped, and non-empty; cw-trigger acts on the row left by cw-setup.
  // Body: { target, name, confirm, method, flashFileName? }
  app.post('/api/opc/export-to-flash', async (req, res) => {
    const b = req.body || {};
    if (!b.target || !b.target.host) return res.status(400).json({ error: 'target.host is required.' });
    if (!b.name) return res.status(400).json({ error: 'name is required.' });
    if (!b.confirm) return res.status(400).json({ error: 'Export is not confirmed.' });
    const method = b.method || 'combined';

    if (method !== 'cw-trigger') {
      const st = await readCaptureState(b.target, b.name);
      if (st.error) return res.status(502).json({ error: 'Could not read capture state: ' + st.error });
      if (st.state === null) return res.status(409).json({ error: 'Capture "' + b.name + '" does not exist on the switch.' });
      if (st.state === 1) return res.status(409).json({ error: 'Capture is still running. Stop it before exporting.' });
      if (!st.packets || st.packets <= 0) {
        return res.status(409).json({ error: 'Capture buffer is empty (0 packets). Exporting an empty capture previously crashed the switch, so it is blocked. Start the capture, collect packets, stop it, then export.' });
      }
      req._packets = st.packets;
    }

    const flashName = (method === 'cw-trigger' && b.flashFileName)
      ? b.flashFileName
      : ('cap_' + b.name + '_' + Date.now().toString(36) + '.pcap').replace(/[^A-Za-z0-9._-]/g, '_');

    // Read the action row's columns and return a compact state object.
    const readActionRow = async () => {
      const o = opc.actionRowOids(b.name);
      const session = buildSnmpSession(b.target);
      try {
        const vbs = await snmpGetPromise(session, [o.dest, o.fileName, o.rowStatus]);
        const v = (x) => (x && !x.error) ? x.value : null;
        return { dest: v(vbs[0]), fileName: v(vbs[1]), rowStatus: v(vbs[2]) };
      } catch (e) { return { error: e.message }; }
      finally { try { session.close(); } catch (x) {} }
    };

    try {
      if (method === 'combined') {
        await runOpcSteps(b.target, [{ varbinds: opc.planExport(b.name, flashName) }]);
        return res.json({ ok: true, flashFileName: flashName, method, packets: req._packets });
      }
      if (method === 'order-action-first') {
        await runOpcSteps(b.target, [{ varbinds: opc.planExportActionFirst(b.name, flashName) }]);
        return res.json({ ok: true, flashFileName: flashName, method, packets: req._packets });
      }
      if (method === 'order-filename-first') {
        await runOpcSteps(b.target, [{ varbinds: opc.planExportFilenameFirst(b.name, flashName) }]);
        return res.json({ ok: true, flashFileName: flashName, method, packets: req._packets });
      }

      if (method === 'create-go-name' || method === 'create-wait-name') {
        // Create the action row WITH the index/name column explicitly included.
        // No export is triggered - this only attempts to make the row exist and
        // reads it back, so it is safe. If the row materialises (readback shows
        // values, not null), the action table CAN be managed after all.
        const steps = [];
        const plan = method === 'create-go-name'
          ? opc.planActionCreateGoWithName(b.name, flashName)
          : opc.planActionCreateWaitWithName(b.name);
        try { await runOpcSteps(b.target, [{ varbinds: plan }]); steps.push(method + ': ok'); }
        catch (e) { steps.push(method + ': ' + e.message); }
        const after = await readActionRow();
        steps.push('  row after create: ' + JSON.stringify(after));
        const exists = after && !after.error &&
          (after.rowStatus !== null || after.dest !== null || after.fileName !== null);
        steps.push(exists ? '  ROW EXISTS - the action table can be managed!' : '  row still absent (null) - create was not honoured.');
        return res.json({ ok: true, flashFileName: flashName, method, setupOnly: true, rowExists: exists, packets: req._packets, steps });
      }

      if (method === 'cw-setup') {
        const steps = [];
        // Step 1: createAndWait.
        try { await runOpcSteps(b.target, [{ varbinds: opc.planCwCreate(b.name) }]); steps.push('createAndWait: ok'); }
        catch (e) { steps.push('createAndWait: ' + e.message); }
        let after1 = await readActionRow();
        steps.push('  row after create: ' + JSON.stringify(after1));
        // Step 2: populate dest + filename.
        try { await runOpcSteps(b.target, [{ varbinds: opc.planCwPopulate(b.name, flashName) }]); steps.push('populate dest+filename: ok'); }
        catch (e) { steps.push('populate dest+filename: ' + e.message); }
        let after2 = await readActionRow();
        steps.push('  row after populate: ' + JSON.stringify(after2));
        // Step 3: activate.
        try { await runOpcSteps(b.target, [{ varbinds: opc.planCwActivate(b.name) }]); steps.push('activate: ok'); }
        catch (e) { steps.push('activate: ' + e.message); }
        let after3 = await readActionRow();
        steps.push('  row after activate: ' + JSON.stringify(after3));
        log.info('opc', 'cw-setup', { host: b.target.host, name: b.name, flashName });
        return res.json({ ok: true, flashFileName: flashName, method, setupOnly: true, packets: req._packets, steps });
      }

      if (method === 'cw-trigger') {
        const steps = [];
        try { await runOpcSteps(b.target, [{ varbinds: opc.planCwTrigger(b.name) }]); steps.push('trigger export: ok'); }
        catch (e) { steps.push('trigger export: ' + e.message); }
        // Best-effort teardown.
        try { await runOpcSteps(b.target, [{ varbinds: opc.planCwDestroy(b.name) }]); steps.push('destroy row: ok'); }
        catch (e) { steps.push('destroy row: ' + e.message); }
        return res.json({ ok: true, flashFileName: flashName, method, packets: req._packets, steps });
      }

      if (method === 'two-pdu') {
        // The key experiment. The combined (same-PDU) export crashes; the action
        // alone does not. This separates them: PDU1 sets dest+filename, PDU2 sets
        // the action alone. The readback after PDU1 shows whether the dest/
        // filename persisted despite an expected InconsistentValue - which is what
        // determines whether a separated export can work at all.
        const steps = [];
        // PDU1: dest + filename, no action, no RowStatus.
        try { await runOpcSteps(b.target, [{ varbinds: opc.planCwPopulate(b.name, flashName) }]); steps.push('PDU1 set dest+filename: ok'); }
        catch (e) { steps.push('PDU1 set dest+filename: ' + e.message); }
        const afterSet = await readActionRow();
        steps.push('  row after PDU1: ' + JSON.stringify(afterSet));
        const persisted = afterSet && !afterSet.error &&
          (afterSet.fileName !== null && afterSet.fileName !== undefined && String(afterSet.fileName).length > 0);
        if (!persisted) {
          steps.push('  dest/filename did NOT persist -> triggering the action now would just CommitFailed (safe but useless). Not triggering.');
          return res.json({ ok: true, flashFileName: flashName, method, packets: req._packets, steps, persisted: false });
        }
        steps.push('  dest/filename PERSISTED -> triggering action in a SEPARATE PDU.');
        // Small settle before the separate trigger.
        await new Promise((r) => setTimeout(r, 600));
        // PDU2: action alone.
        try { await runOpcSteps(b.target, [{ varbinds: opc.planCwTrigger(b.name) }]); steps.push('PDU2 action=export: ok'); }
        catch (e) { steps.push('PDU2 action=export: ' + e.message); }
        const afterTrigger = await readActionRow();
        steps.push('  row after PDU2: ' + JSON.stringify(afterTrigger));
        return res.json({ ok: true, flashFileName: flashName, method, packets: req._packets, steps, persisted: true });
      }

      return res.status(400).json({ error: 'Unknown export method: ' + method });
    } catch (e) {
      log.error('opc', 'export-to-flash failed', { target: redactTarget(b.target), method, message: e.message });
      res.status(502).json({ error: e.message, flashFileName: flashName });
    }
  });

  // STEP 2: Copy a flash .pcap to this app over TFTP and return it. Separate so
  // it only runs after a successful flash export, and never auto-chains into the
  // step that crashed. Body: { target, flashFileName, tftpPort }
  app.post('/api/opc/fetch-flash', async (req, res) => {
    const b = req.body || {};
    if (!b.target || !b.target.host) return res.status(400).json({ error: 'target.host is required.' });
    if (!b.flashFileName) return res.status(400).json({ error: 'flashFileName is required.' });
    try {
      const result = await configFetch.fetchPcap(() => buildSnmpSession(b.target), {
        host: b.target.host, flashFileName: b.flashFileName,
        tftpPort: b.tftpPort || Number(process.env.TFTP_PORT) || undefined
      });
      res.json({ ok: true, flashFileName: b.flashFileName, bytes: result.bytes, pcapBase64: result.buf.toString('base64') });
    } catch (e) {
      log.error('opc', 'fetch-flash failed', { target: redactTarget(b.target), message: e.message });
      res.status(502).json({ error: e.message });
    }
  });

  // Diagnostic: walk every OPC table and the copy table, returning the raw
  // varbinds as a downloadable blob (the client saves it; nothing is shown in
  // the browser). Body: { target }
  app.post('/api/opc/diag', async (req, res) => {
    const b = req.body || {};
    if (!b.target || !b.target.host) return res.status(400).json({ error: 'target.host is required.' });
    const session = buildSnmpSession(b.target);
    const roots = [
      ['rlOpcCapturePointTable', opc.WALK.capturePoint],
      ['rlOpcInterfaceTable', opc.WALK.iface],
      ['rlOpcActionTable', opc.WALK.action],
      ['rlOpcOperState', opc.WALK.operState],
      ['rlCopyTable', '1.3.6.1.4.1.9.6.1.101.87.2.1']
    ];
    const lines = ['OPC diagnostic  .  ' + b.target.host + '  .  ' + new Date().toISOString(), ''];
    try {
      for (const [label, root] of roots) {
        lines.push('=== ' + label + '  [' + root + '] ===');
        try {
          const rows = await boundedWalkPromise(session, root, 'getbulk', { maxRows: 2000 });
          if (!rows.length) lines.push('  (no rows)');
          for (const vb of rows) {
            const d = describeVarbind(vb);
            const val = d.display !== undefined && d.display !== null && d.display !== String(d.value)
              ? (d.value + '  (' + d.display + ')') : d.value;
            lines.push('  ' + vb.oid + ' = ' + val);
          }
        } catch (e) {
          lines.push('  (walk failed: ' + e.message + ')');
        }
        lines.push('');
      }
    } finally {
      try { session.close(); } catch (e) {}
    }
    res.json({ ok: true, text: lines.join('\n') });
  });

  // -----------------------------------------------------------------
  // TEST (RISK): export a capture to flash via rlCopyTable instead of
  // rlOpcAction. This EXECUTES a copy (createAndGo) and may crash the switch -
  // it is gated by confirm:true and clearly labelled in the UI. The point is to
  // test whether the stable copy engine behaves differently from the OPC action.
  // Body: { target, name, confirm }
  app.post('/api/copy/capture-to-flash', async (req, res) => {
    const b = req.body || {};
    if (!b.target || !b.target.host) return res.status(400).json({ error: 'target.host is required.' });
    if (!b.name) return res.status(400).json({ error: 'name (capture name) is required.' });
    if (!b.confirm) return res.status(400).json({ error: 'Not confirmed.' });
    try {
      const result = await configFetch.copyCaptureToFlash(() => buildSnmpSession(b.target), {
        host: b.target.host, captureName: b.name,
        // Event-driven completion: await the switch's rlCopyFinished trap rather
        // than guessing with a timer. Polling remains a backstop inside the copy.
        waitForFinish: copyFinishedWaiter(b.target.host)
      });
      res.json(result);
    } catch (e) {
      log.error('opc', 'copy-capture-to-flash failed', { target: redactTarget(b.target), message: e.message });
      res.status(502).json({ error: e.message });
    }
  });
};
