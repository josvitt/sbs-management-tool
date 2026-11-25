/**
 * Pull a configuration off the switch.
 *
 * There is no MIB object that returns configuration text, so SNMP can only
 * *trigger* a file transfer: create a row in rlCopyTable telling the switch
 * to copy runningConfig/startupConfig to a TFTP server, then wait for the
 * file to land. The TFTP server is the one embedded in this app, so the
 * only thing the operator has to provide is SNMP write access.
 *
 * The switch has to be able to reach us, so the destination address is
 * worked out per request from the route to that switch rather than
 * configured -- on a machine with several interfaces, guessing is wrong.
 */

const crypto = require('crypto');
const dgram = require('dgram');
const snmp = require('net-snmp');
const log = require('./logger');
const tftp = require('./tftp');

const COPY = '1.3.6.1.4.1.9.6.1.101.87.2.1';   // rlCopyEntry
// rlRunningCDBequalToStartupCDB: the switch's own answer to "is the
// running configuration saved?", used to confirm a save actually took.
const CONFIG_EQUAL_OID = '1.3.6.1.4.1.9.6.1.101.1.13.0';
const COL = {
  sourceLocation: 3,
  sourceIp: 4,
  sourceUnit: 5,
  sourceFileName: 6,
  sourceFileType: 7,
  destLocation: 8,
  destIp: 9,
  destUnit: 10,
  destFileName: 11,
  destFileType: 12,
  operationState: 14,
  bytesTransferred: 15,
  rowStatus: 17
};

const LOCATION = { local: 1, anotherUnit: 2, tftp: 3, xmodem: 4, scp: 5, serial: 6, http: 7, https: 8 };
const FILE_TYPE = {
  other: 1, runningConfig: 2, startupConfig: 3, backupConfig: 4,
  runningMibConfig: 5, startupMibConfig: 6, backupMibConfig: 7,
  image: 8, boot: 9, null: 10, logging: 11, mirrorConfig: 12,
  usb: 13, support: 14, pcap: 15, language: 16
};
const STATE = { 1: 'uploadInProgress', 2: 'downloadInProgress', 3: 'copyFailed', 4: 'copyTimedout', 5: 'copyFinished' };
const ROW = { active: 1, notInService: 2, notReady: 3, createAndGo: 4, createAndWait: 5, destroy: 6 };

const KINDS = {
  running: FILE_TYPE.runningConfig,
  startup: FILE_TYPE.startupConfig,
  backup: FILE_TYPE.backupConfig
};

/**
 * Which of our addresses can the switch reach us on? Connecting a UDP
 * socket performs a route lookup without sending anything, and the kernel
 * then reports the source address it would use.
 */
function localAddressFor(host) {
  return new Promise((resolve, reject) => {
    const s = dgram.createSocket('udp4');
    s.on('error', (e) => { try { s.close(); } catch (x) {} reject(e); });
    try {
      s.connect(9, host, () => {
        let addr = null;
        try { addr = s.address().address; } catch (e) { /* fall through */ }
        try { s.close(); } catch (e) {}
        if (!addr || addr === '0.0.0.0') reject(new Error('Could not determine a local address reachable from ' + host));
        else resolve(addr);
      });
    } catch (e) { reject(e); }
  });
}

const oid = (col, index) => COPY + '.' + col + '.' + index;

function setVarbinds(session, varbinds) {
  return new Promise((resolve, reject) => {
    session.set(varbinds, (error, result) => {
      if (error) return reject(error);
      const bad = (result || []).find((vb) => snmp.isVarbindError(vb));
      if (bad) return reject(new Error(snmp.varbindError(bad)));
      resolve(result);
    });
  });
}

function getValue(session, target) {
  return new Promise((resolve, reject) => {
    session.get([target], (error, varbinds) => {
      if (error) return reject(error);
      const vb = varbinds[0];
      if (snmp.isVarbindError(vb)) return reject(new Error(snmp.varbindError(vb)));
      resolve(vb.value);
    });
  });
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ===========================================================================
// awaitCopyCompletion - ONE place that decides when an rlCopyTable operation
// (config fetch, config save, pcap fetch, capture-to-flash) has finished.
// ---------------------------------------------------------------------------
// Every copy op triggers a row in rlCopyTable and then has to wait for the
// result. The signals available differ per op, so this tool RACES whichever
// ones the caller supplies and returns as soon as any says "done":
//
//   waitForFinish() -> promise   the rlCopyFinished trap, event-driven and
//                                authoritative (supplied by the server, which
//                                receives traps). Resolves { timedOut } if its
//                                own wait lapses, so we defer to the others.
//   donePredicate() -> bool|Promise<bool>   a caller-specific "already done?"
//                                check polled each cycle: the TFTP file having
//                                arrived (a download), or the saved-flag being
//                                set (save running->startup). Authoritative.
//   session + index              poll rlCopyOperationState as a BACKSTOP:
//                                finished(5) completes, failed(3)/timedout(4)
//                                fail. Tolerant of the row being torn down on
//                                completion (a read error is not evidence).
//
// Returns { finished, failed, via, state }. Never throws for a normal failure
// (the caller decides how to message state/failed). 'via' says which signal
// won, for logging. ceilingMs is a safety net only - with a good primary
// signal it is never reached.
// ===========================================================================
async function awaitCopyCompletion(opts) {
  opts = opts || {};
  const session = opts.session;
  const index = opts.index;
  const ceilingMs = Number(opts.ceilingMs) || 600000;
  const pollMs = Number(opts.pollMs) || 1500;
  const hasState = session && (index !== undefined && index !== null);
  let lastState = null;
  let stopPolling = false;   // set once the race resolves, so the loser stops at once

  // (a) the completion trap, if the caller wired one up.
  const trapWait = (typeof opts.waitForFinish === 'function')
    ? Promise.resolve(opts.waitForFinish()).then((r) => ({ via: 'trap', trap: r }), () => ({ via: 'trap', trap: { timedOut: true } }))
    : new Promise(() => {});   // never resolves

  // (b) the caller's done-predicate + the state-column backstop, polled together.
  const pollWait = (async () => {
    const deadline = Date.now() + ceilingMs;
    while (!stopPolling && Date.now() < deadline) {
      await sleep(pollMs);
      // Caller's authoritative "already done" check (file arrived / flag set).
      if (typeof opts.donePredicate === 'function') {
        let done = false;
        try { done = await opts.donePredicate(); } catch (e) { done = false; }
        if (done) return { via: 'predicate', terminal: 'finished' };
      }
      // State-column backstop. A read error means the row is gone. By default
      // that is not evidence either way (some firmware tears the row down the
      // instant it finishes, so we keep waiting for a better signal). When the
      // caller sets rowGoneMeansDone - true only where a vanished row reliably
      // signals completion AND there is no other authoritative check - treat it
      // as finished, preserving behavior that would otherwise need that read.
      if (hasState) {
        let polledOnce = false;
        try {
          const st = Number(await getValue(session, oid(COL.operationState, index)));
          polledOnce = true;
          if (Number.isFinite(st)) lastState = STATE[st] || String(st);
          if (st === 5) return { via: 'state', terminal: 'finished' };
          if (st === 3 || st === 4) return { via: 'state', terminal: 'failed', state: STATE[st] };
        } catch (e) {
          // Row gone. Only infer completion from this once we have seen the row
          // exist at least once in a prior cycle, to avoid a transient first-read
          // error masquerading as success.
          if (opts.rowGoneMeansDone && lastState !== null) { lastState = 'row removed on completion'; return { via: 'rowGone', terminal: 'finished' }; }
        }
        void polledOnce;
      }
    }
    return { via: 'ceiling', terminal: 'ceiling' };
  })();

  const winner = await Promise.race([trapWait, pollWait]);
  if (winner.via === 'trap') {
    if (winner.trap && winner.trap.timedOut) {
      // Trap wait lapsed - defer to whatever the polling found (keep polling).
      const pr = await pollWait;
      return { finished: pr.terminal === 'finished', failed: pr.terminal === 'failed', via: pr.via, state: lastState };
    }
    stopPolling = true;   // trap won - stop the backstop poll immediately
    return { finished: true, failed: false, via: 'trap', state: lastState };
  }
  // The poll decided (terminal state, rowGone, or ceiling); the trap, if any,
  // is abandoned by the surrounding operation closing the session.
  return { finished: winner.terminal === 'finished', failed: winner.terminal === 'failed', via: winner.via, state: lastState };
}

/**
 * @param buildSession  () => net-snmp session (write community / v3 user)
 * @param opts { host, kind, tftpPort, index, timeoutMs }
 */
async function fetchConfig(buildSession, opts) {
  const kind = opts.kind || 'running';
  const fileType = KINDS[kind];
  if (!fileType) throw new Error('Unknown configuration type: ' + kind);

  let port;
  try {
    port = await tftp.start(opts.tftpPort);
  } catch (e) {
    throw new Error('Could not start the built-in TFTP receiver on UDP ' +
      (opts.tftpPort || 69) + ': ' + e.message +
      (e.code === 'EACCES'
        ? '. Ports below 1024 need elevated privileges on this OS - run elevated, or set TFTP_PORT to something above 1024 (note the switch will still try port 69 unless it can be told otherwise).'
        : '. Another TFTP server may already be running.'));
  }
  const localIp = await localAddressFor(opts.host);
  // Unique per attempt so a stale file from an earlier run can never be
  // mistaken for this one, and unguessable: the TFTP receiver accepts an
  // upload from any address, so a predictable name would let another host on
  // the LAN race the switch with a forged configuration.
  const fileName = kind + '-' + Date.now().toString(36) + '-' + crypto.randomBytes(6).toString('hex') + '.cfg';
  const index = opts.index || (Math.floor(Math.random() * 900) + 100);

  log.info('config', 'Requesting configuration over TFTP', {
    host: opts.host, kind, fileName, tftpServer: localIp + ':' + port, copyIndex: index
  });

  const session = buildSession();
  session.on('error', (err) => log.error('config', 'SNMP session error', { message: err.message }));

  const cleanup = async () => {
    try {
      await setVarbinds(session, [
        { oid: oid(COL.rowStatus, index), type: snmp.ObjectType.Integer, value: ROW.destroy }
      ]);
    } catch (e) { /* the row may already be gone; not worth failing over */ }
  };

  try {
    const columns = [
      { oid: oid(COL.sourceLocation, index), type: snmp.ObjectType.Integer, value: LOCATION.local },
      { oid: oid(COL.sourceFileType, index), type: snmp.ObjectType.Integer, value: fileType },
      { oid: oid(COL.destLocation, index), type: snmp.ObjectType.Integer, value: LOCATION.tftp },
      { oid: oid(COL.destIp, index), type: snmp.ObjectType.IpAddress, value: localIp },
      { oid: oid(COL.destFileName, index), type: snmp.ObjectType.OctetString, value: fileName },
      { oid: oid(COL.destFileType, index), type: snmp.ObjectType.Integer, value: FILE_TYPE.other }
    ];
    const rowStatus = (v) => ({ oid: oid(COL.rowStatus, index), type: snmp.ObjectType.Integer, value: v });

    // RowStatus creation is not handled identically everywhere, so try the
    // correct form first and fall back rather than failing outright:
    //   1. one PDU, columns + createAndGo  (what RowStatus is designed for)
    //   2. createAndGo, then populate      (agents that need the row first)
    //   3. createAndWait, populate, active (the long-hand sequence)
    const attempts = [
      { name: 'single-PDU createAndGo', run: () => setVarbinds(session, columns.concat([rowStatus(ROW.createAndGo)])) },
      { name: 'createAndGo then populate', run: async () => {
        await setVarbinds(session, [rowStatus(ROW.createAndGo)]);
        await setVarbinds(session, columns);
      } },
      { name: 'createAndWait then activate', run: async () => {
        await setVarbinds(session, [rowStatus(ROW.createAndWait)]);
        await setVarbinds(session, columns);
        await setVarbinds(session, [rowStatus(ROW.active)]);
      } }
    ];
    let created = false, lastErr = null;
    for (const attempt of attempts) {
      try {
        await attempt.run();
        created = true;
        log.info('config', 'Copy row created', { host: opts.host, method: attempt.name });
        break;
      } catch (e) {
        lastErr = e;
        log.info('config', 'Row creation attempt refused', { host: opts.host, method: attempt.name, reason: e.message });
      }
    }
    if (!created) {
      throw new Error('The switch refused to create a copy request. Last error: ' + (lastErr && lastErr.message) +
        '. This usually means the SNMP credentials are read-only.');
    }

    const timeoutMs = opts.timeoutMs || 90000;
    const deadline = Date.now() + timeoutMs;
    let lastState = null;

    // Wait on the file rather than only on the state column: some firmware
    // clears the row as soon as it finishes, and polling a destroyed row
    // would look like a failure even though the transfer worked.
    const filePromise = tftp.expect(fileName, timeoutMs).then(
      (buf) => ({ buf }), (err) => ({ err }));

    while (Date.now() < deadline) {
      await sleep(1500);
      let state = null;
      try {
        state = Number(await getValue(session, oid(COL.operationState, index)));
        lastState = STATE[state] || String(state);
      } catch (e) {
        lastState = lastState || 'row no longer present';
      }
      if (state === 3 || state === 4) {
        session.close();
        await cleanup();
        throw new Error('The switch reported ' + (STATE[state] || state) +
          '. Check that SNMP write access is allowed and that the switch can reach ' +
          localIp + ':' + port + ' over UDP.');
      }
      const raced = await Promise.race([filePromise, sleep(0).then(() => null)]);
      if (raced && raced.buf) break;
      if (raced && raced.err) break;
    }

    const outcome = await filePromise;
    session.close();
    await cleanup();

    if (outcome.err) {
      throw new Error(outcome.err.message +
        '. Last reported copy state: ' + (lastState || 'unknown') +
        '. The switch must be able to reach this machine on UDP ' + port + '.');
    }

    const text = outcome.buf.toString('utf8');
    tftp.forget(fileName);
    log.info('config', 'Configuration received', { host: opts.host, kind, bytes: text.length });
    return {
      kind, text, bytes: text.length,
      lines: text.split('\n').length,
      via: { tftpServer: localIp, tftpPort: port, fileName },
      state: lastState
    };
  } catch (e) {
    try { session.close(); } catch (x) {}
    await cleanup();
    throw e;
  }
}

/**
 * Copy one file on the switch to another -- the SNMP equivalent of
 * "copy running-config startup-config". Same rlCopyTable mechanism as a
 * fetch, but both ends are local, so no TFTP is involved.
 *
 * Success is decided by the switch's own answer to "is the running
 * configuration saved?" (rlRunningCDBequalToStartupCDB), not by the copy
 * row. The row routinely vanishes the moment the operation ends, and a
 * vanished row says nothing about whether anything was written -- treating
 * it as success reported a save that had not happened.
 */
async function copyConfig(buildSession, opts) {
  const from = KINDS[opts.from];
  const to = KINDS[opts.to];
  if (!from || !to) throw new Error('Unknown configuration type in copy ' + opts.from + ' -> ' + opts.to);
  if (from === to) throw new Error('Source and destination are the same.');

  const savingRunning = opts.from === 'running' && opts.to === 'startup';
  const session = buildSession();
  session.on('error', (err) => log.error('config', 'SNMP session error', { message: err.message }));

  const readSaved = async () => {
    try { return Number(await getValue(session, CONFIG_EQUAL_OID)) === 1; } catch (e) { return null; }
  };

  const destroyRow = async (index) => {
    try {
      await setVarbinds(session, [
        { oid: oid(COL.rowStatus, index), type: snmp.ObjectType.Integer, value: ROW.destroy }
      ]);
    } catch (e) { /* already gone */ }
  };

  try {
    const savedBefore = savingRunning ? await readSaved() : null;
    if (savingRunning && savedBefore === true) {
      session.close();
      return { from: opts.from, to: opts.to, state: 'already saved', alreadyEqual: true };
    }

    /**
     * Two shapes are tried. Some firmware performs a local copy only when
     * the unit numbers are set -- with them left at zero the row is
     * accepted and then quietly does nothing, which is exactly the
     * silent no-op this had been reporting as a success.
     */
    const unit = Number(opts.unit) || 1;
    const shapes = [
      { name: 'with unit numbers', extra: [
        { col: COL.sourceUnit, value: unit }, { col: COL.destUnit, value: unit }
      ] },
      { name: 'without unit numbers', extra: [] }
    ];

    const attempted = [];
    for (const shape of shapes) {
      const index = Math.floor(Math.random() * 900) + 100;
      log.info('config', 'Copying configuration on the switch', {
        host: opts.host, from: opts.from, to: opts.to, copyIndex: index, shape: shape.name
      });

      const columns = [
        { oid: oid(COL.sourceLocation, index), type: snmp.ObjectType.Integer, value: LOCATION.local },
        { oid: oid(COL.sourceFileType, index), type: snmp.ObjectType.Integer, value: from },
        { oid: oid(COL.destLocation, index), type: snmp.ObjectType.Integer, value: LOCATION.local },
        { oid: oid(COL.destFileType, index), type: snmp.ObjectType.Integer, value: to }
      ].concat(shape.extra.map((e) => ({
        oid: oid(e.col, index), type: snmp.ObjectType.Integer, value: e.value
      })));
      const rowStatus = (v) => ({ oid: oid(COL.rowStatus, index), type: snmp.ObjectType.Integer, value: v });

      const forms = [
        { name: 'single-PDU createAndGo', run: () => setVarbinds(session, columns.concat([rowStatus(ROW.createAndGo)])) },
        { name: 'createAndGo then populate', run: async () => {
          await setVarbinds(session, [rowStatus(ROW.createAndGo)]);
          await setVarbinds(session, columns);
        } },
        { name: 'createAndWait then activate', run: async () => {
          await setVarbinds(session, [rowStatus(ROW.createAndWait)]);
          await setVarbinds(session, columns);
          await setVarbinds(session, [rowStatus(ROW.active)]);
        } }
      ];

      let created = null;
      for (const form of forms) {
        try {
          await form.run();
          created = form.name;
          log.info('config', 'Copy row created', { host: opts.host, method: form.name, shape: shape.name });
          break;
        } catch (e) {
          log.info('config', 'Row creation attempt refused', {
            host: opts.host, shape: shape.name, method: form.name, reason: e.message
          });
        }
      }
      if (!created) { attempted.push(shape.name + ': the switch refused every row-creation form'); continue; }

      // Wait for confirmation via the shared completion tool. When saving
      // running->startup the authoritative signal is the saved-flag scalar
      // (donePredicate); for other directions it is the state column. The trap
      // (if the server wired one in via opts.waitForFinish) completes either
      // sooner. Bounded per shape: a local copy is near-instant when it works at
      // all, and two shapes are tried, so a long wait only delays telling the
      // user it did not.
      const done = await awaitCopyCompletion({
        session, index,
        waitForFinish: opts.waitForFinish,
        // Saving running->startup: the saved-flag is authoritative. Other
        // directions: completion is the state column, and on firmware that tears
        // the row down the instant it finishes, a vanished row means done.
        donePredicate: savingRunning ? (async () => (await readSaved()) === true) : null,
        rowGoneMeansDone: !savingRunning,
        ceilingMs: opts.timeoutMs || 15000, pollMs: 1000
      });
      const confirmed = done.finished;
      const lastState = done.state;

      await destroyRow(index);
      if (confirmed) {
        session.close();
        log.info('config', 'Configuration copied', {
          host: opts.host, from: opts.from, to: opts.to, shape: shape.name, state: lastState, via: done.via
        });
        return { from: opts.from, to: opts.to, state: lastState, shape: shape.name, method: created };
      }
      attempted.push(shape.name + ': ' +
        (done.failed ? 'the switch reported ' + (lastState || 'a failure')
          : 'the row was accepted but the configuration was still unsaved afterwards' +
            (lastState ? ' (last state: ' + lastState + ')' : '')));
    }

    session.close();
    throw new Error('The switch accepted the copy request but the configuration was not saved. ' +
      'What was tried:\n' + attempted.map((a) => '  \u2022 ' + a).join('\n') +
      '\nSome firmware does not perform this copy over SNMP. From the CLI it is ' +
      '"copy running-config startup-config", or "write memory".');
  } catch (e) {
    try { session.close(); } catch (x) {}
    throw e;
  }
}

/**
 * Copy a named .pcap file already on the switch's flash to this app's
 * embedded TFTP receiver, and return its raw bytes. Same rlCopyTable
 * machinery as fetchConfig, but the source is a specific flash file of type
 * pcap(15) rather than a configuration type, and the result is binary.
 * @param buildSession () => net-snmp session (needs write access)
 * @param opts { host, flashFileName, tftpPort, index, timeoutMs }
 */
async function fetchPcap(buildSession, opts) {
  if (!opts.flashFileName) throw new Error('flashFileName is required.');
  let port;
  try {
    port = await tftp.start(opts.tftpPort);
  } catch (e) {
    throw new Error('Could not start the built-in TFTP receiver on UDP ' +
      (opts.tftpPort || 69) + ': ' + e.message);
  }
  const localIp = await localAddressFor(opts.host);
  // Use the source file's own (bare) name as the TFTP transfer name, so the
  // switch's "flash://x.pcap -> tftp://.../x.pcap" log reads naturally rather
  // than showing a confusing generated name. The receiver keys transfers by
  // sender address, so this does not need to be globally unique.
  const destName = String(opts.flashFileName).replace(/^flash:\/\//i, '').replace(/^flash:/i, '') || ('capture-' + Date.now().toString(36) + '.pcap');
  const index = opts.index || (Math.floor(Math.random() * 900) + 100);

  log.info('opc', 'Requesting pcap over TFTP', {
    host: opts.host, flashFileName: opts.flashFileName, destName, tftpServer: localIp + ':' + port, copyIndex: index
  });

  const session = buildSession();
  session.on('error', (err) => log.error('opc', 'SNMP session error', { message: err.message }));

  const cleanup = async () => {
    try {
      await setVarbinds(session, [
        { oid: oid(COL.rowStatus, index), type: snmp.ObjectType.Integer, value: ROW.destroy }
      ]);
    } catch (e) { /* row may already be gone */ }
  };

  try {
    // Copy an existing NAMED file off flash to a plain file on the TFTP server,
    // exactly as the CLI "copy flash://<name> tftp://<host>/<name>" does: both
    // ends are generic files identified by name (type other). The earlier
    // version set the file type to pcap(15) on both ends; telling the switch the
    // transfer is a special "pcap" file appears to invoke capture-specific
    // handling that overloads the control plane, whereas a plain file copy -
    // the same thing the CLI and the working config fetch do - does not.
    // Source file type controls the URL SCHEME the switch uses:
    //   pcap(15) -> capture://<name>  (a live capture buffer)
    //   other(1) -> flash://<name>    (a file on flash)
    // For a flash->TFTP download the source is a FILE on flash, so it MUST be
    // other(1); pcap(15) makes the switch look for a capture point by that name
    // and the copy fails (confirmed by the switch's "source URL capture://..."
    // syslog). Default to other; callers can override.
    const srcType = (opts.sourceFileType !== undefined) ? opts.sourceFileType : FILE_TYPE.other;
    // The local source needs its unit number set, same as the working config
    // copy - without it the switch rejects the row with InconsistentValue on
    // rlCopySourceLocation. The TFTP destination's unit is left implicit.
    // The flash file listing reports names with a "flash://" prefix, but the
    // copy table's source location column already says "local", so the filename
    // must be the BARE name - the prefix here causes the copy to fail at
    // execution (rlCopyFailed trap). Strip any flash:// or flash: prefix.
    const bareName = String(opts.flashFileName).replace(/^flash:\/\//i, '').replace(/^flash:/i, '');
    const columns = [
      { oid: oid(COL.sourceLocation, index), type: snmp.ObjectType.Integer, value: LOCATION.local },
      { oid: oid(COL.sourceUnit, index), type: snmp.ObjectType.Integer, value: Number(opts.unit) || 1 },
      { oid: oid(COL.sourceFileName, index), type: snmp.ObjectType.OctetString, value: bareName },
      { oid: oid(COL.sourceFileType, index), type: snmp.ObjectType.Integer, value: srcType },
      { oid: oid(COL.destLocation, index), type: snmp.ObjectType.Integer, value: LOCATION.tftp },
      { oid: oid(COL.destIp, index), type: snmp.ObjectType.IpAddress, value: localIp },
      { oid: oid(COL.destFileName, index), type: snmp.ObjectType.OctetString, value: destName },
      { oid: oid(COL.destFileType, index), type: snmp.ObjectType.Integer, value: FILE_TYPE.other }
    ];
    const rowStatus = (v) => ({ oid: oid(COL.rowStatus, index), type: snmp.ObjectType.Integer, value: v });
    const attempts = [
      { name: 'single-PDU createAndGo', run: () => setVarbinds(session, columns.concat([rowStatus(ROW.createAndGo)])) },
      { name: 'createAndGo then populate', run: async () => {
        await setVarbinds(session, [rowStatus(ROW.createAndGo)]);
        await setVarbinds(session, columns);
      } },
      { name: 'createAndWait then activate', run: async () => {
        await setVarbinds(session, [rowStatus(ROW.createAndWait)]);
        await setVarbinds(session, columns);
        await setVarbinds(session, [rowStatus(ROW.active)]);
      } }
    ];
    let created = false, lastErr = null;
    for (const attempt of attempts) {
      try { await attempt.run(); created = true; break; }
      catch (e) { lastErr = e; }
    }
    if (!created) throw new Error('The switch refused to create the pcap copy request. Last error: ' + (lastErr && lastErr.message));

    const timeoutMs = opts.timeoutMs || 120000;
    const deadline = Date.now() + timeoutMs;
    let lastState = null;
    const filePromise = tftp.expect(destName, timeoutMs).then((buf) => ({ buf }), (err) => ({ err }));

    while (Date.now() < deadline) {
      await sleep(1500);
      let state = null;
      try { state = Number(await getValue(session, oid(COL.operationState, index))); lastState = STATE[state] || String(state); }
      catch (e) { lastState = lastState || 'row no longer present'; }
      if (state === 3 || state === 4) {
        session.close(); await cleanup();
        throw new Error('The switch reported ' + (STATE[state] || state) +
          ' copying the pcap. Check the file exists on flash and that the switch can reach ' + localIp + ':' + port + '.');
      }
      const raced = await Promise.race([filePromise, sleep(0).then(() => null)]);
      if (raced && (raced.buf || raced.err)) break;
    }

    const outcome = await filePromise;
    session.close(); await cleanup();
    if (outcome.err) {
      throw new Error(outcome.err.message + '. Last copy state: ' + (lastState || 'unknown') +
        '. The switch must be able to reach this machine on UDP ' + port + '.');
    }
    tftp.forget(destName);
    // Integrity check: a valid pcap starts with a known magic number. If the
    // transfer dropped a block (e.g. the header), this catches it rather than
    // handing back a corrupt file that Wireshark silently rejects.
    const buf = outcome.buf;
    const magics = ['d4c3b2a1', 'a1b2c3d4', '4d3cb2a1', 'a1b23c4d', '0a0d0d0a']; // pcap LE/BE, ns, pcapng
    const head = buf.slice(0, 4).toString('hex');
    if (buf.length < 24 || magics.indexOf(head) < 0) {
      throw new Error('The downloaded capture is not a valid pcap (header ' + head + ', ' + buf.length +
        ' bytes) - the transfer was incomplete. Please try the export again.');
    }
    log.info('opc', 'pcap received', { host: opts.host, bytes: buf.length });
    return { buf, bytes: buf.length, via: { tftpServer: localIp, tftpPort: port, destName }, state: lastState };
  } catch (e) {
    try { session.close(); } catch (x) {}
    await cleanup();
    throw e;
  }
}

/**
 * EXPERIMENTAL / RISK: drive the capture->flash export through rlCopyTable
 * instead of rlOpcAction, to test whether the stable copy engine avoids the
 * crash. Creates a copy row (createAndGo, which executes) with the capture as a
 * pcap(15) source and a plain file on flash as the destination. This EXECUTES a
 * copy and may crash the switch. Returns { steps, state }.
 * @param buildSession () => net-snmp session (write access)
 * @param opts { host, captureName, flashFileName }
 */
async function copyCaptureToFlash(buildSession, opts) {
  if (!opts.captureName) throw new Error('captureName is required.');
  const flashName = opts.flashFileName ||
    ('cap_' + opts.captureName + '_' + Date.now().toString(36) + '.pcap').replace(/[^A-Za-z0-9._-]/g, '_');
  const session = buildSession();
  session.on('error', (err) => log.error('opc', 'copy-capture SNMP session error', { message: err.message }));
  const index = Math.floor(Math.random() * 900) + 100;
  const steps = [];
  const destroyRow = async () => {
    try { await setVarbinds(session, [{ oid: oid(COL.rowStatus, index), type: snmp.ObjectType.Integer, value: ROW.destroy }]); }
    catch (e) { /* already gone */ }
  };
  try {
    // Source = the capture, as a pcap(15) file on 'local'; destination = a plain
    // file on flash. Columns + createAndGo in one PDU, as the working config
    // copy does.
    const unit = Number(opts.unit) || 1;
    const columns = [
      { oid: oid(COL.sourceLocation, index), type: snmp.ObjectType.Integer, value: LOCATION.local },
      { oid: oid(COL.sourceUnit, index), type: snmp.ObjectType.Integer, value: unit },
      { oid: oid(COL.sourceFileType, index), type: snmp.ObjectType.Integer, value: FILE_TYPE.pcap },
      { oid: oid(COL.sourceFileName, index), type: snmp.ObjectType.OctetString, value: opts.captureName },
      { oid: oid(COL.destLocation, index), type: snmp.ObjectType.Integer, value: LOCATION.local },
      { oid: oid(COL.destUnit, index), type: snmp.ObjectType.Integer, value: unit },
      { oid: oid(COL.destFileType, index), type: snmp.ObjectType.Integer, value: FILE_TYPE.other },
      { oid: oid(COL.destFileName, index), type: snmp.ObjectType.OctetString, value: flashName }
    ];
    const rowStatus = (v) => ({ oid: oid(COL.rowStatus, index), type: snmp.ObjectType.Integer, value: v });

    log.info('opc', 'copy-capture-to-flash via rlCopyTable', { host: opts.host, captureName: opts.captureName, flashName, copyIndex: index });
    try {
      await setVarbinds(session, columns.concat([rowStatus(ROW.createAndGo)]));
      steps.push('createAndGo copy row (pcap source -> flash): ok');
    } catch (e) {
      steps.push('createAndGo copy row: ' + e.message);
      session.close();
      return { ok: false, steps, flashFileName: flashName, error: e.message };
    }

    // Wait for the copy to FINISH via the shared completion tool: it races the
    // rlCopyFinished trap (authoritative, event-driven) against a state-column
    // backstop, so a lost trap or a torn-down row still resolves.
    const done = await awaitCopyCompletion({
      session, index, waitForFinish: opts.waitForFinish,
      ceilingMs: Number(opts.timeoutMs) || 600000, pollMs: 2000
    });
    const finished = done.finished, failed = done.failed;
    const lastState = done.state;
    steps.push('completion via: ' + done.via + (lastState ? ' (last state: ' + lastState + ')' : ''));
    await destroyRow();
    session.close();
    return { ok: finished, finished, failed, steps, flashFileName: flashName, state: lastState,
      error: failed ? ('copy to flash ' + (lastState || 'failed')) : (finished ? undefined : 'copy to flash did not finish in time') };
  } catch (e) {
    try { session.close(); } catch (x) {}
    await destroyRow();
    return { ok: false, steps, flashFileName: flashName, error: e.message };
  }
}

module.exports = { fetchConfig, copyConfig, fetchPcap, copyCaptureToFlash, awaitCopyCompletion, localAddressFor, KINDS, COPY_COL: COL };
