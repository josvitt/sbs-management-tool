'use strict';

/**
 * Switch maintenance over SNMP: reboot, the firmware images, and copying a
 * file from this app to the switch (a configuration to restore, or a
 * firmware image).
 *
 * Objects (CISCOSB-mng, CISCOSB-deviceparams, CISCOSB-COPY MIBs):
 *   rlRebootDelay      101.1.10.0   TimeTicks, rw. Setting it reboots the
 *                                   switch that many ticks later. Reads
 *                                   4294967295 when no reboot is scheduled.
 *   rndAction          101.1.2.0    reset(1) reboots at once (fallback only).
 *   rndActiveSoftwareFileTable 101.2.13.1.1, per unit:
 *     .2 rndActiveSoftwareFile            image1(1) | image2(2), read-only
 *     .3 rndActiveSoftwareFileAfterReset  image1(1) | image2(2), rw
 *   rndImageInfoTable  101.2.16.1.1, per unit: .2/.3 names, .4/.5 versions,
 *                                   .6/.7 dates, .8/.9 times of image 1/2.
 *   rlCopyTable        101.87.2.1   (see config-fetch.js), here with a TFTP
 *                                   source and a local destination.
 *
 * rlManualReboot (101.94.2) is NOT a reboot control: it is read-only and
 * says whether the last restart was orderly.
 *
 * What the switch accepts for a TFTP-to-switch copy is decided by the
 * supervised switch test (scripts/switch-test-maint.js); until then the
 * shapes below are tried in order and the one used is reported.
 */

const crypto = require('crypto');
const snmp = require('net-snmp');
const log = require('./logger');
const tftp = require('./tftp');
const configFetch = require('./config-fetch');

const MNG = '1.3.6.1.4.1.9.6.1.101.1';
const REBOOT_DELAY = MNG + '.10.0';
const RND_ACTION = MNG + '.2.0';
const NO_REBOOT = 4294967295;
const ACTIVE_T = '1.3.6.1.4.1.9.6.1.101.2.13.1.1';
const IMAGE_T = '1.3.6.1.4.1.9.6.1.101.2.16.1.1';
const IMAGE_NAMES = { 1: 'image1', 2: 'image2', 3: 'invalidImage' };

const COPY = '1.3.6.1.4.1.9.6.1.101.87.2.1';
const COL = configFetch.COPY_COL;
const LOCATION = { local: 1, tftp: 3 };
const FILE_TYPE = { other: 1, startupConfig: 3, image: 8 };
const ROW = { active: 1, createAndGo: 4, createAndWait: 5, destroy: 6 };
const STATE = { 1: 'uploadInProgress', 2: 'downloadInProgress', 3: 'copyFailed', 4: 'copyTimedout', 5: 'copyFinished' };

const copyOid = (col, index) => COPY + '.' + col + '.' + index;

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

function getVarbinds(session, oids) {
  return new Promise((resolve, reject) => {
    session.get(oids, (error, varbinds) => {
      if (error) return reject(error);
      resolve(varbinds);
    });
  });
}

// The shared bounded walk (collection.js), so the recorder and the offline
// replay see the same requests the collector sends.
async function walkSubtree(session, base) {
  const { boundedWalkPromise } = require('./collection');
  const rows = await boundedWalkPromise(session, base, 'getbulk', { maxRows: 200 });
  return rows.filter((vb) => !snmp.isVarbindError(vb) && String(vb.oid).indexOf(base + '.') === 0);
}

const text = (v) => (Buffer.isBuffer(v) ? v.toString('utf8') : (v == null ? '' : String(v))).replace(/\0+$/, '').trim();
const present = (s) => s && !/^no info$/i.test(s);

/**
 * The reboot schedule and the firmware images, per unit.
 * Resolves { reboot: { scheduled, inSeconds }, units: [ { unit, active,
 * nextBoot, images: [ { slot, name, version, date } ] } ] }.
 */
async function readMaint(session) {
  const [delayVb] = await getVarbinds(session, [REBOOT_DELAY]);
  let reboot = { scheduled: false, inSeconds: null, readable: !snmp.isVarbindError(delayVb) };
  if (reboot.readable) {
    const ticks = Number(delayVb.value);
    if (Number.isFinite(ticks) && ticks !== NO_REBOOT) reboot = { scheduled: true, inSeconds: Math.round(ticks / 100), readable: true };
  }

  const units = new Map();
  const unitOf = (u) => {
    if (!units.has(u)) units.set(u, { unit: u, active: null, nextBoot: null, images: [] });
    return units.get(u);
  };
  for (const vb of await walkSubtree(session, ACTIVE_T)) {
    const tail = vb.oid.slice(ACTIVE_T.length + 1).split('.');
    const col = Number(tail[0]), unit = Number(tail[1]);
    if (col === 2) unitOf(unit).active = IMAGE_NAMES[Number(vb.value)] || String(vb.value);
    if (col === 3) unitOf(unit).nextBoot = IMAGE_NAMES[Number(vb.value)] || String(vb.value);
  }
  const info = new Map();
  for (const vb of await walkSubtree(session, IMAGE_T)) {
    const tail = vb.oid.slice(IMAGE_T.length + 1).split('.');
    const col = Number(tail[0]), unit = Number(tail[1]);
    if (!info.has(unit)) info.set(unit, {});
    info.get(unit)[col] = text(vb.value);
  }
  for (const [unit, c] of info) {
    const u = unitOf(unit);
    for (const slot of [1, 2]) {
      const name = c[1 + slot], version = c[3 + slot];
      if (!present(name) && !present(version)) continue;
      u.images.push({
        slot: 'image' + slot,
        name: present(name) ? name : '',
        version: present(version) ? version : '',
        date: [c[5 + slot], c[7 + slot]].filter(present).join(' ')
      });
    }
  }
  return { reboot, units: Array.from(units.values()).sort((a, b) => a.unit - b.unit) };
}

/**
 * Reboot in `seconds` (0 = now). rlRebootDelay with a short delay is used
 * even for "now", so the switch can answer the SET before it goes down; an
 * immediate reset can lose the reply and look like a failure.
 */
async function scheduleReboot(session, seconds) {
  const secs = Math.max(0, Math.floor(Number(seconds) || 0));
  if (secs > 24 * 3600) throw new Error('A reboot can be scheduled at most 24 hours ahead.');
  const ticks = Math.max(secs, 2) * 100;
  try {
    await setVarbinds(session, [{ oid: REBOOT_DELAY, type: snmp.ObjectType.TimeTicks, value: ticks }]);
    return { via: 'rlRebootDelay', inSeconds: ticks / 100 };
  } catch (e) {
    if (secs > 0) throw e;
    log.info('maint', 'rlRebootDelay refused; rebooting with rndAction reset', { message: e.message });
    try {
      await setVarbinds(session, [{ oid: RND_ACTION, type: snmp.ObjectType.Integer, value: 1 }]);
    } catch (e2) {
      // The switch may go down before it answers a reset.
      if (!/timed? ?out/i.test(e2.message)) throw e2;
    }
    return { via: 'rndAction', inSeconds: 0 };
  }
}

/** Cancel a scheduled reboot. */
async function cancelReboot(session) {
  await setVarbinds(session, [{ oid: REBOOT_DELAY, type: snmp.ObjectType.TimeTicks, value: NO_REBOOT }]);
  const [vb] = await getVarbinds(session, [REBOOT_DELAY]);
  const still = !snmp.isVarbindError(vb) && Number(vb.value) !== NO_REBOOT;
  if (still) throw new Error('The switch still reports a reboot in ' + Math.round(Number(vb.value) / 100) + ' s.');
  return { cancelled: true };
}

/** Choose the image a unit boots next. image: 'image1' | 'image2'. */
async function setNextBoot(session, unit, image) {
  const v = image === 'image1' ? 1 : (image === 'image2' ? 2 : null);
  if (!v) throw new Error('image must be image1 or image2.');
  const u = Number(unit) || 1;
  await setVarbinds(session, [{ oid: ACTIVE_T + '.3.' + u, type: snmp.ObjectType.Integer, value: v }]);
  return { unit: u, nextBoot: image };
}

/**
 * The copy-row shapes tried for a TFTP-to-switch copy, in order. The first
 * mirrors the working fetch (a plain file on the TFTP side, the typed file
 * on the switch side, with the unit set); the second also types the source.
 */
function pushShapes(destType, unit) {
  return [
    { name: 'plain source', srcType: FILE_TYPE.other, destType, unit },
    { name: 'typed source', srcType: destType, destType, unit }
  ];
}

/**
 * Have the switch copy `buffer` from this app's TFTP server into its
 * startup configuration ('startup') or its inactive image slot ('image').
 * Resolves { finished, shape, state, served, via }. Rejects when the switch
 * refuses every shape, reports a failure, or never reads the file.
 */
async function pushFile(buildSession, opts) {
  const dest = opts.dest;
  const destType = dest === 'startup' ? FILE_TYPE.startupConfig : (dest === 'image' ? FILE_TYPE.image : null);
  if (!destType) throw new Error('dest must be startup or image.');
  if (!Buffer.isBuffer(opts.buffer) || !opts.buffer.length) throw new Error('Nothing to send.');

  let port;
  try { port = await tftp.start(opts.tftpPort); }
  catch (e) { throw new Error('Could not start the built-in TFTP server on UDP ' + (opts.tftpPort || 69) + ': ' + e.message); }
  const localIp = await configFetch.localAddressFor(opts.host);
  // The TFTP server hands an offered file to anyone who asks by name. A
  // configuration gets a random, short-lived name, so the name is the secret.
  // A firmware image is public, so it keeps the uploaded file's name, which
  // is the name the switch stores it under and shows in its image list.
  const given = dest === 'image' && opts.fileName
    ? String(opts.fileName).replace(/[^A-Za-z0-9._-]/g, '_').replace(/^[._]+/, '').slice(0, 120) : '';
  const fileName = given || ((dest === 'startup' ? 'restore-' : 'image-') + Date.now().toString(36) + '-' +
    crypto.randomBytes(6).toString('hex') + (dest === 'startup' ? '.cfg' : '.bin'));
  const timeoutMs = Number(opts.timeoutMs) || (dest === 'image' ? 20 * 60000 : 120000);
  tftp.offer(fileName, opts.buffer, timeoutMs + 60000);

  const session = buildSession();
  session.on('error', (err) => log.error('maint', 'SNMP session error', { message: err.message }));
  const refused = [];
  try {
    for (const shape of (opts.shapes || pushShapes(destType, Number(opts.unit) || 1))) {
      const index = Math.floor(Math.random() * 900) + 100;
      const columns = [
        { oid: copyOid(COL.sourceLocation, index), type: snmp.ObjectType.Integer, value: LOCATION.tftp },
        { oid: copyOid(COL.sourceIp, index), type: snmp.ObjectType.IpAddress, value: localIp },
        { oid: copyOid(COL.sourceFileName, index), type: snmp.ObjectType.OctetString, value: fileName },
        { oid: copyOid(COL.sourceFileType, index), type: snmp.ObjectType.Integer, value: shape.srcType },
        { oid: copyOid(COL.destLocation, index), type: snmp.ObjectType.Integer, value: LOCATION.local },
        { oid: copyOid(COL.destUnit, index), type: snmp.ObjectType.Integer, value: shape.unit },
        { oid: copyOid(COL.destFileType, index), type: snmp.ObjectType.Integer, value: shape.destType },
        { oid: copyOid(COL.rowStatus, index), type: snmp.ObjectType.Integer, value: ROW.createAndGo }
      ];
      log.info('maint', 'Copying a file to the switch over TFTP', {
        host: opts.host, dest, shape: shape.name, bytes: opts.buffer.length, tftpServer: localIp + ':' + port, copyIndex: index
      });
      try {
        await setVarbinds(session, columns);
      } catch (e) {
        refused.push(shape.name + ': ' + e.message);
        log.info('maint', 'Copy row refused', { host: opts.host, shape: shape.name, reason: e.message });
        continue;
      }
      const done = await configFetch.awaitCopyCompletion({
        session, index, waitForFinish: opts.waitForFinish,
        // A vanished row is only "done" once the switch has read the whole file.
        donePredicate: null, rowGoneMeansDone: true,
        ceilingMs: timeoutMs, pollMs: 2000
      });
      try { await setVarbinds(session, [{ oid: copyOid(COL.rowStatus, index), type: snmp.ObjectType.Integer, value: ROW.destroy }]); }
      catch (e) { /* already gone */ }
      const served = tftp.wasServed(fileName);
      if (done.failed) throw new Error('The switch reported ' + (done.state || 'a failure') + ' copying the file' +
        (served ? '' : '. It never read the file: it must reach this machine on UDP ' + port) + '.');
      if (!done.finished) throw new Error('The copy did not finish in ' + Math.round(timeoutMs / 1000) + ' s (last state: ' + (done.state || 'unknown') + ').');
      if (!served) throw new Error('The switch reported the copy finished but never read the file from this machine.');
      log.info('maint', 'File copied to the switch', { host: opts.host, dest, shape: shape.name, via: done.via });
      return { finished: true, shape: shape.name, state: done.state, served, via: done.via };
    }
    throw new Error('The switch refused the copy request. ' + refused.join('; ') +
      '. This usually means the SNMP credentials are read-only.');
  } finally {
    tftp.withdraw(fileName);
    try { session.close(); } catch (e) {}
  }
}

/**
 * Compare two configurations as the switch writes them: line endings and
 * trailing blank lines differ between a stored copy and a fresh one.
 */
function sameConfig(a, b) {
  const norm = (t) => String(t || '').replace(/\r\n?/g, '\n').split('\n').map((l) => l.replace(/\s+$/, ''))
    .join('\n').replace(/\n+$/, '');
  return norm(a) === norm(b);
}

module.exports = {
  readMaint, scheduleReboot, cancelReboot, setNextBoot, pushFile, pushShapes, sameConfig,
  REBOOT_DELAY, RND_ACTION, ACTIVE_T, IMAGE_T, NO_REBOOT, FILE_TYPE, LOCATION
};
