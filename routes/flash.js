'use strict';

/**
 * The switch's flash file system: list and delete.
 */

const snmp = require('net-snmp');
const log = require('../logger');
const { buildSnmpSession, describeVarbind, redactTarget, snmpSetPromise } = require('../snmp-core');
const { snmpGetPromise, boundedWalkPromise } = require('../collection');

const FILE_T = '1.3.6.1.4.1.9.6.1.101.96.2.1';   // rlFileEntry
const FILE_COL = { name: 1, permission: 2, size: 3, date: 4, time: 5, rowStatus: 6, flashSize: 7, fullName: 8 };
const FILE_FLASH_TOTAL = '1.3.6.1.4.1.9.6.1.101.96.4.0';
const FILE_FLASH_FREE = '1.3.6.1.4.1.9.6.1.101.96.5.0';

// The table is indexed by IMPLIED rlFileName: the raw filename bytes, no length
// prefix. Decode the tail of an OID after the column number back to a string.
function decodeImpliedName(tailParts) {
  return tailParts.map((n) => String.fromCharCode(Number(n))).join('');
}


// The flash listing: files (name, size, date, permission bits) and capacity.
// Shared by POST /api/flash/list and the server collector (SERVER-STANDARD §3).
async function listFlash(session) {
  // The columns the listing shows, walked together (one GETBULK stream); the
  // file name is the row index, so the name column itself is not needed.
  const cols = [FILE_COL.size, FILE_COL.date, FILE_COL.time, FILE_COL.flashSize, FILE_COL.fullName]
    .map((c) => FILE_T + '.' + c);
  const rows = await boundedWalkPromise(session, cols, 'getbulk', { maxRows: 4000 });
  // Pivot by filename (the implied index after the column sub-id).
  const byName = new Map();
  const base = FILE_T + '.';
  for (const vb of rows) {
    const oid = String(vb.oid);
    if (oid.indexOf(base) !== 0) continue;
    const tail = oid.slice(base.length).split('.');
    const col = Number(tail[0]);
    const name = decodeImpliedName(tail.slice(1));
    if (!name) continue;
    if (!byName.has(name)) byName.set(name, { name });
    const d = describeVarbind(vb);
    const val = (d.display !== undefined && d.display !== null && d.display !== String(d.value)) ? d.display : d.value;
    if (col === FILE_COL.size) byName.get(name).size = val;
    else if (col === FILE_COL.date) byName.get(name).date = val;
    else if (col === FILE_COL.time) byName.get(name).time = val;
    else if (col === FILE_COL.flashSize) byName.get(name).flashSize = val;
    else if (col === FILE_COL.fullName) byName.get(name).fullName = val;
    // Permission is handled separately below via a raw GET, because the walk
    // runs values through describeVarbind, which turns a BITS octet into a
    // printable character when the byte happens to be printable ASCII - losing
    // the raw bits. A direct GET preserves the Buffer.
  }
  // Fetch the permission BITS for each file with a RAW get (reading vb.value
  // directly, not through describeVarbind), so the bits survive. FilePermission
  // BITS { read(0), write(1), execute(2), dir(3) } — bit 0 is the MSB of the
  // first octet. Done in batches to keep PDUs small.
  const names = Array.from(byName.keys());
  const rawGet = (oids) => new Promise((resolve) => {
    session.get(oids, (error, vbs) => resolve(error ? [] : vbs));
  });
  for (let i = 0; i < names.length; i += 10) {
    const slice = names.slice(i, i + 10);
    const permOids = slice.map((nm) => FILE_T + '.' + FILE_COL.permission + '.' + Array.from(Buffer.from(nm, 'latin1')).join('.'));
    const vbs = await rawGet(permOids);
    vbs.forEach((vb, k) => {
      const nm = slice[k];
      if (!vb || snmp.isVarbindError(vb)) return;
      const raw = vb.value;
      let b0 = 0;
      if (Buffer.isBuffer(raw)) b0 = raw.length ? raw[0] : 0;
      else if (typeof raw === 'number') b0 = raw;
      // This firmware encodes FilePermission LSB-first (a plain integer),
      // confirmed against the switch: a read+write file reads 0x03. So
      // read=0x01(bit0), write=0x02(bit1), execute=0x04(bit2), dir=0x08(bit3)
      // - NOT the MSB-first order the SMIv2 BITS convention would imply.
      const bitSet = (n) => !!(b0 & (1 << n));
      if (byName.has(nm)) {
        byName.get(nm).writable = bitSet(1);        // write
        byName.get(nm).isDir = bitSet(3);           // dir
        byName.get(nm).permByte = b0;               // shown in UI for verification
      }
    });
  }
  const files = Array.from(byName.values()).sort((a, b2) => String(a.name).localeCompare(String(b2.name)));
  // Flash capacity (best-effort).
  let flash = null;
  try {
    const vbs = await snmpGetPromise(session, [FILE_FLASH_TOTAL, FILE_FLASH_FREE]);
    const num = (x) => (x && !x.error) ? Number(x.value) : null;
    flash = { total: num(vbs[0]), free: num(vbs[1]) };
  } catch (e) { /* capacity is optional */ }
  return { ok: true, files, flash };
}

module.exports = function register(app) {
  // -----------------------------------------------------------------
  // Flash file system (CISCOSB-FILE-MIB, rlFileTable = ...101.96.2)
  // -----------------------------------------------------------------

  // List flash files. Body: { target }

  app.post('/api/flash/list', async (req, res) => {
    const b = req.body || {};
    if (!b.target || !b.target.host) return res.status(400).json({ error: 'target.host is required.' });
    const session = buildSnmpSession(b.target);
    try {
      res.json(await listFlash(session));
    } catch (e) {
      res.status(502).json({ error: e.message });
    } finally {
      try { session.close(); } catch (e) {}
    }
  });

  // Delete a flash file: rlFileRowStatus = destroy(6), keyed by the implied
  // filename. Body: { target, fileName }
  app.post('/api/flash/delete', async (req, res) => {
    const b = req.body || {};
    if (!b.target || !b.target.host) return res.status(400).json({ error: 'target.host is required.' });
    if (!b.fileName) return res.status(400).json({ error: 'fileName is required.' });
    // Build the implied index: raw filename bytes, dot-joined.
    const idx = Array.from(Buffer.from(String(b.fileName), 'latin1')).join('.');
    const oid = FILE_T + '.' + FILE_COL.rowStatus + '.' + idx;
    const session = buildSnmpSession(b.target);
    try {
      await snmpSetPromise(session, [{ oid, type: snmp.ObjectType.Integer, value: 6 }]); // destroy
      log.info('flash', 'file deleted', { host: b.target.host, fileName: b.fileName });
      res.json({ ok: true, fileName: b.fileName });
    } catch (e) {
      log.error('flash', 'delete failed', { target: redactTarget(b.target), message: e.message });
      res.status(502).json({ error: e.message });
    } finally {
      try { session.close(); } catch (e) {}
    }
  });
};

module.exports.listFlash = listFlash;
