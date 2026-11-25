'use strict';
// Reboot, firmware images and copying a file to the switch (switch-maint.js),
// against a fake SNMP session. The copy test runs a real TFTP read: the fake
// switch reads the offered file from the app's TFTP server when the copy row
// is created, as the real one does.
const test = require('node:test');
const assert = require('node:assert/strict');
const dgram = require('dgram');
const snmp = require('net-snmp');
const tftp = require('../tftp');
const maint = require('../switch-maint');

const T = snmp.ObjectType;
const COPY = '1.3.6.1.4.1.9.6.1.101.87.2.1';

function fakeSession(values, hooks) {
  const sets = [];
  return {
    sets,
    on() {},
    close() {},
    get(oids, cb) {
      setImmediate(() => cb(null, oids.map((oid) => (oid in values)
        ? { oid, type: values[oid][0], value: values[oid][1] }
        : { oid, type: T.NoSuchInstance, value: null })));
    },
    set(varbinds, cb) {
      sets.push(varbinds.map((v) => ({ oid: v.oid, type: v.type, value: v.value })));
      const refuse = hooks && hooks.refuse && hooks.refuse(varbinds);
      if (refuse) return setImmediate(() => cb(new Error(refuse)));
      for (const v of varbinds) values[v.oid] = [v.type, v.value];
      if (hooks && hooks.onSet) hooks.onSet(varbinds, values);
      setImmediate(() => cb(null, varbinds));
    },
    subtree(base, maxRep, feed, done) {
      const rows = Object.keys(values).filter((o) => o.indexOf(base + '.') === 0)
        .sort((a, b) => a.localeCompare(b, undefined, { numeric: true }))
        .map((oid) => ({ oid, type: values[oid][0], value: values[oid][1] }));
      setImmediate(() => { if (rows.length) feed(rows); done(); });
    }
  };
}

test('readMaint reads the reboot schedule and both images per unit', async () => {
  const s = fakeSession({
    [maint.REBOOT_DELAY]: [T.TimeTicks, maint.NO_REBOOT],
    [maint.ACTIVE_T + '.2.1']: [T.Integer, 1],
    [maint.ACTIVE_T + '.3.1']: [T.Integer, 2],
    [maint.IMAGE_T + '.2.1']: [T.OctetString, Buffer.from('image1.bin')],
    [maint.IMAGE_T + '.3.1']: [T.OctetString, Buffer.from('image2.bin')],
    [maint.IMAGE_T + '.4.1']: [T.OctetString, Buffer.from('4.1.6.53')],
    [maint.IMAGE_T + '.5.1']: [T.OctetString, Buffer.from('4.1.3.36')],
    [maint.IMAGE_T + '.6.1']: [T.OctetString, Buffer.from('12-Mar-2025')],
    [maint.IMAGE_T + '.7.1']: [T.OctetString, Buffer.from('no info')],
    [maint.IMAGE_T + '.8.1']: [T.OctetString, Buffer.from('10:11:12')]
  });
  const r = await maint.readMaint(s);
  assert.deepEqual(r.reboot, { scheduled: false, inSeconds: null, readable: true });
  assert.equal(r.units.length, 1);
  const u = r.units[0];
  assert.equal(u.active, 'image1');
  assert.equal(u.nextBoot, 'image2');
  assert.deepEqual(u.images, [
    { slot: 'image1', name: 'image1.bin', version: '4.1.6.53', date: '12-Mar-2025 10:11:12' },
    { slot: 'image2', name: 'image2.bin', version: '4.1.3.36', date: '' }
  ]);
});

test('a scheduled reboot reads as seconds', async () => {
  const s = fakeSession({ [maint.REBOOT_DELAY]: [T.TimeTicks, 360000] });
  const r = await maint.readMaint(s);
  assert.deepEqual(r.reboot, { scheduled: true, inSeconds: 3600, readable: true });
});

test('reboot now sets a two-second rlRebootDelay; later sets the delay in ticks', async () => {
  const s = fakeSession({});
  assert.deepEqual(await maint.scheduleReboot(s, 0), { via: 'rlRebootDelay', inSeconds: 2 });
  assert.deepEqual(s.sets[0], [{ oid: maint.REBOOT_DELAY, type: T.TimeTicks, value: 200 }]);
  await maint.scheduleReboot(s, 600);
  assert.equal(s.sets[1][0].value, 60000);
  await assert.rejects(maint.scheduleReboot(s, 2 * 86400), /24 hours/);
});

test('reboot now falls back to rndAction reset when rlRebootDelay is refused', async () => {
  const s = fakeSession({}, { refuse: (vbs) => (vbs[0].oid === maint.REBOOT_DELAY ? 'NotWritable' : null) });
  assert.deepEqual(await maint.scheduleReboot(s, 0), { via: 'rndAction', inSeconds: 0 });
  assert.deepEqual(s.sets[1], [{ oid: maint.RND_ACTION, type: T.Integer, value: 1 }]);
  // A refused delayed reboot is an error, never a silent reboot now.
  await assert.rejects(maint.scheduleReboot(s, 60), /NotWritable/);
});

test('cancel writes the no-reboot value and checks it took', async () => {
  const s = fakeSession({ [maint.REBOOT_DELAY]: [T.TimeTicks, 50000] });
  assert.deepEqual(await maint.cancelReboot(s), { cancelled: true });
  const stuck = fakeSession({ [maint.REBOOT_DELAY]: [T.TimeTicks, 50000] }, {
    onSet: (vbs, values) => { values[maint.REBOOT_DELAY] = [T.TimeTicks, 49000]; }
  });
  await assert.rejects(maint.cancelReboot(stuck), /still reports a reboot in 490 s/);
});

test('the next boot image is rndActiveSoftwareFileAfterReset for the unit', async () => {
  const s = fakeSession({});
  await maint.setNextBoot(s, 1, 'image2');
  assert.deepEqual(s.sets[0], [{ oid: maint.ACTIVE_T + '.3.1', type: T.Integer, value: 2 }]);
  await assert.rejects(maint.setNextBoot(s, 1, 'image3'), /image1 or image2/);
});

// A TFTP read client acting as the switch.
function tftpRead(port, name) {
  return new Promise((resolve, reject) => {
    const sock = dgram.createSocket('udp4');
    const chunks = [];
    sock.on('message', (m) => {
      const op = m.readUInt16BE(0);
      if (op === 5) { sock.close(); return reject(new Error(m.toString('ascii', 4))); }
      if (op !== 3) return;
      const block = m.readUInt16BE(2);
      chunks.push(m.subarray(4));
      const a = Buffer.alloc(4); a.writeUInt16BE(4, 0); a.writeUInt16BE(block, 2);
      sock.send(a, port, '127.0.0.1');
      if (m.length - 4 < 512) { setTimeout(() => sock.close(), 50); resolve(Buffer.concat(chunks)); }
    });
    sock.send(Buffer.concat([Buffer.from([0, 1]), Buffer.from(name + '\0octet\0')]), port, '127.0.0.1');
  });
}

test('pushFile: the switch reads the offered file, the copy finishes, the offer is withdrawn', async () => {
  const port = await tftp.start(0);
  const body = Buffer.from('hostname test\n'.repeat(80));
  let got = null, fileName = null;
  const values = {};
  const s = fakeSession(values, {
    onSet: (vbs) => {
      const row = vbs.find((v) => v.oid.indexOf(COPY + '.17.') === 0 && v.value === 4);
      if (!row) return;
      const index = row.oid.split('.').pop();
      fileName = String(values[COPY + '.6.' + index][1]);
      values[COPY + '.14.' + index] = [T.Integer, 2];
      tftpRead(port, fileName).then((buf) => { got = buf; values[COPY + '.14.' + index] = [T.Integer, 5]; });
    }
  });
  const r = await maint.pushFile(() => s, { host: '127.0.0.1', dest: 'startup', buffer: body, tftpPort: port, timeoutMs: 15000 });
  assert.equal(r.finished, true);
  assert.equal(r.shape, 'plain source');
  assert.deepEqual(got, body);
  // The row: TFTP source with our address and the random name, a typed local destination on unit 1.
  const created = s.sets[0];
  const col = (c) => created.find((v) => new RegExp('^' + COPY.replace(/\./g, '\\.') + '\\.' + c + '\\.').test(v.oid)).value;
  assert.equal(col(3), 3);              // source: tftp
  assert.equal(col(4), '127.0.0.1');
  assert.match(String(col(6)), /^restore-[0-9a-z]+-[0-9a-f]{12}\.cfg$/);
  assert.equal(col(7), 1);              // source type: other
  assert.equal(col(8), 1);              // destination: local
  assert.equal(col(10), 1);             // unit 1
  assert.equal(col(12), 3);             // startupConfig
  assert.equal(col(17), 4);             // createAndGo
  // No longer offered once done.
  await assert.rejects(tftpRead(port, fileName), /not found/i);
});

test('pushFile tries the typed source when the plain one is refused, and reports a copy failure', async () => {
  const port = await tftp.start(0);
  const values = {};
  const s = fakeSession(values, {
    refuse: (vbs) => (vbs.some((v) => /\.7\.\d+$/.test(v.oid) && v.oid.indexOf(COPY) === 0 && v.value === 1) ? 'InconsistentValue' : null),
    onSet: (vbs) => {
      const row = vbs.find((v) => v.oid.indexOf(COPY + '.17.') === 0 && v.value === 4);
      if (row) values[COPY + '.14.' + row.oid.split('.').pop()] = [T.Integer, 3];
    }
  });
  await assert.rejects(
    maint.pushFile(() => s, { host: '127.0.0.1', dest: 'image', buffer: Buffer.alloc(10), tftpPort: port, timeoutMs: 10000 }),
    /copyFailed.*never read the file/);
  assert.equal(s.sets.length >= 2, true);
  const second = s.sets[1];
  assert.equal(second.find((v) => /\.12\.\d+$/.test(v.oid)).value, 8);   // image
  assert.equal(second.find((v) => /\.7\.\d+$/.test(v.oid)).value, 8);    // typed source
});

test('sameConfig ignores line endings and trailing blanks only', () => {
  assert.equal(maint.sameConfig('a\r\nb  \r\n\r\n', 'a\nb'), true);
  assert.equal(maint.sameConfig('a\nb', 'a\nc'), false);
});
