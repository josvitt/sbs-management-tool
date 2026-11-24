/**
 * Reading and configuring the switch's syslog collectors.
 *
 * The switch keeps a small table of destinations (snmpSyslogCollectorTable,
 * eight rows on a Catalyst 1300). This module reads it to answer "is this
 * switch already sending to us?" and, if not, can add a row pointing at the
 * receiver built into this app.
 *
 * Adding a row is a write to the device, so it is a separate, explicit
 * action rather than something the health poll does on its own.
 */

const dgram = require('dgram');
const snmp = require('net-snmp');
const log = require('./logger');

const GLOBAL_ENABLE_OID = '1.3.6.1.4.1.9.6.1.101.82.2.1.0';

/**
 * Catalyst 1200/1300 firmware carries *three* collector tables: the IETF
 * draft one it inherits, and two vendor tables. Which of them a given
 * build actually implements for writes varies, and a switch that stores
 * its collectors in one while we read another looks "not configured" and
 * then refuses the write.
 *
 * So all three are read, and a write is attempted against each in turn
 * until one is accepted. Listed most standard first.
 */
const TABLES = [
  {
    name: 'snmpSyslogCollectorTable',
    entry: '1.3.6.1.4.1.9.6.1.101.82.1.2.4.1',
    nextIndexOid: '1.3.6.1.4.1.9.6.1.101.82.1.2.3.0',
    cols: { description: 2, addressType: 3, address: 4, udpPort: 5, facility: 6, severity: 7, rowStatus: 9 }
  },
  {
    name: 'rlsnmpSyslogCollectorTable',
    entry: '1.3.6.1.4.1.9.6.1.101.82.2.22.1',
    cols: { addressType: 2, address: 3, rowStatus: 4 }
  },
  {
    name: 'rlRegisteredLogsSyslogCollectorTable',
    entry: '1.3.6.1.4.1.9.6.1.101.82.2.30.1',
    cols: { addressType: 2, address: 3, udpPort: 4, rowStatus: 5 }
  }
];
const ADDRESS_TYPE_IPV4 = 1;
const ROW = { active: 1, createAndGo: 4, createAndWait: 5, destroy: 6 };

// snmpSyslogCollectorSeverity: 0 emergency .. 7 debug. The value is a
// threshold -- everything at that level or more severe is sent.
const SEVERITY_NAMES = ['emergency', 'alert', 'critical', 'error', 'warning', 'notice', 'info', 'debug'];

const oid = (table, col, index) => table.entry + '.' + col + '.' + index;

/**
 * Which of our addresses can this switch reach us on? Connecting a UDP
 * socket performs a route lookup without sending anything, and the kernel
 * reports the source address it would use -- guessing is wrong on a
 * machine with several interfaces.
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

/**
 * An InetAddress is an octet string: four bytes for IPv4. Some agents hand
 * back a printable string instead, so both shapes are handled.
 */
function decodeInetAddress(value) {
  if (value === undefined || value === null) return null;
  if (Buffer.isBuffer(value)) {
    if (value.length === 4) return Array.from(value).join('.');
    return value.toString('utf8').replace(/\0+$/, '');
  }
  const s = String(value);
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) return s;
  // Hex dump from the generic formatter, e.g. "c0 a8 01 0a".
  const hex = s.replace(/[^0-9a-f]/gi, '');
  if (hex.length === 8) {
    return (hex.match(/../g) || []).map((h) => parseInt(h, 16)).join('.');
  }
  return s;
}

/** Walk one collector table and return its rows. */
function walkTable(session, table) {
  return new Promise((resolve) => {
    const rows = new Map();
    session.subtree(table.entry, 20, (varbinds) => {
      for (const vb of varbinds) {
        if (snmp.isVarbindError(vb)) continue;
        const tail = String(vb.oid).slice(table.entry.length + 1);
        const m = tail.match(/^(\d+)\.(\d+)$/);
        if (!m) continue;
        const col = Number(m[1]);
        const index = m[2];
        if (!rows.has(index)) rows.set(index, { index, table: table.name });
        const row = rows.get(index);
        for (const [key, number] of Object.entries(table.cols)) {
          if (number !== col) continue;
          if (key === 'address') row.address = decodeInetAddress(vb.value);
          else if (key === 'description') {
            row.description = Buffer.isBuffer(vb.value) ? vb.value.toString('utf8') : String(vb.value);
          } else if (key === 'severity') {
            row.severity = Number(vb.value);
            row.severityName = SEVERITY_NAMES[row.severity] || String(row.severity);
          } else row[key] = Number(vb.value);
        }
      }
    }, () => resolve(Array.from(rows.values())));
  });
}

/**
 * Read every collector table and say whether `ourAddress` is already in
 * one of them. Reading all three matters: a switch that keeps its
 * collectors in the vendor table would otherwise look unconfigured.
 */
async function readCollectors(buildSession, opts) {
  const session = buildSession();
  session.on('error', (err) => log.error('syslog', 'SNMP session error', { message: err.message }));

  try {
    const collectors = [];
    const tablesSeen = [];
    for (const table of TABLES) {
      const rows = (await walkTable(session, table)).filter((r) => r.address);
      if (rows.length) tablesSeen.push(table.name + ' (' + rows.length + ')');
      for (const r of rows) collectors.push(r);
    }

    let globalEnabled = null;
    try {
      globalEnabled = Number(await getValue(session, GLOBAL_ENABLE_OID)) === 1;
    } catch (e) { /* not implemented on every build */ }

    session.close();
    const ours = opts && opts.ourAddress
      ? collectors.find((r) => r.address === opts.ourAddress) || null
      : null;
    return {
      collectors, tablesSeen,
      configured: !!ours, matching: ours, globalEnabled
    };
  } catch (e) {
    try { session.close(); } catch (x) {}
    throw e;
  }
}

/** Lowest index not already used in this table, 1..8. */
function firstFreeIndex(rows) {
  const used = new Set(rows.map((r) => String(r.index)));
  for (let i = 1; i <= 8; i++) if (!used.has(String(i))) return i;
  return null;
}

/** Try to create a collector row in one specific table. */
async function tryTable(session, table, opts) {
  const existing = await walkTable(session, table);

  let index = null;
  if (table.nextIndexOid) {
    try {
      const hinted = Number(await getValue(session, table.nextIndexOid));
      if (hinted >= 1) index = hinted;
    } catch (e) { /* fall back to scanning */ }
  }
  if (!index) index = firstFreeIndex(existing);
  if (!index) throw new Error('all eight collector slots are in use');

  // The UDP port column is Unsigned32 in both MIBs that define it
  // (SyslogUdpPort, and rlRegisteredLogsSyslogCollectorUdpPort directly),
  // not INTEGER. Sending it as INTEGER is what a switch answers with
  // WrongType on exactly that OID. `portType` is a parameter so a failure
  // can be retried with the other encoding rather than given up on.
  const portType = opts.portType === undefined ? snmp.ObjectType.Unsigned32 : opts.portType;

  const columns = [];
  const add = (key, type, value) => {
    if (table.cols[key] === undefined) return;
    columns.push({ oid: oid(table, table.cols[key], index), type, value });
  };
  add('addressType', snmp.ObjectType.Integer, ADDRESS_TYPE_IPV4);
  add('address', snmp.ObjectType.OctetString,
    Buffer.from(opts.address.split('.').map((n) => Number(n))));
  add('udpPort', portType, opts.port);
  add('severity', snmp.ObjectType.Integer, opts.severity);
  add('description', snmp.ObjectType.OctetString, 'sbs-management-tool');
  const rowStatus = (v) => ({
    oid: oid(table, table.cols.rowStatus, index), type: snmp.ObjectType.Integer, value: v
  });

  // RowStatus creation is not handled identically by every build, so the
  // same three forms used elsewhere are tried in order.
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

  const tried = [];
  for (const attempt of attempts) {
    try {
      await attempt.run();
      log.info('syslog', 'Collector row created', {
        host: opts.host, table: table.name, index, method: attempt.name
      });
      return { index, method: attempt.name, table: table.name };
    } catch (e) {
      tried.push(attempt.name + ': ' + e.message);
      log.info('syslog', 'Row creation attempt refused', {
        host: opts.host, table: table.name, method: attempt.name, reason: e.message
      });
    }
  }
  throw new Error(tried.join('; '));
}

/**
 * Point the switch at us, trying each collector table in turn. When every
 * one refuses, the error names what each said -- guessing at "check your
 * credentials" is no help when the credentials are fine.
 */
async function addCollector(buildSession, opts) {
  const address = opts.address;
  const port = opts.port || 514;
  const severity = opts.severity === undefined ? 6 : Number(opts.severity);
  if (!address) throw new Error('No local address to give the switch.');

  const session = buildSession();
  session.on('error', (err) => log.error('syslog', 'SNMP session error', { message: err.message }));

  const failures = [];
  try {
    let created = null;
    for (const table of TABLES) {
      // Unsigned32 is what the MIBs specify for the port column; if a
      // build disagrees it says so with WrongType, and INTEGER is the only
      // other thing it could mean, so try that before moving on.
      const encodings = [snmp.ObjectType.Unsigned32, snmp.ObjectType.Integer];
      let tableError = null;
      for (const portType of encodings) {
        try {
          created = await tryTable(session, table, {
            host: opts.host, address, port, severity, portType
          });
          break;
        } catch (e) {
          tableError = e;
          if (!/WrongType/i.test(e.message)) break;   // not a type problem
          log.info('syslog', 'Retrying with INTEGER for the port column', {
            host: opts.host, table: table.name
          });
        }
      }
      if (created) break;
      failures.push(table.name + ' \u2014 ' + (tableError && tableError.message));
    }

    if (!created) {
      throw new Error('No collector table accepted the new entry. What each returned:\n' +
        failures.map((f) => '  \u2022 ' + f).join('\n') +
        '\nThe same thing can be done from the CLI with "logging host ' + address +
        (port === 514 ? '' : ' port ' + port) + '".');
    }

    // Logging can be globally off, in which case the row alone changes
    // nothing -- turn it on rather than leaving a silent no-op behind.
    let enabledNow = null;
    try {
      const enabled = Number(await getValue(session, GLOBAL_ENABLE_OID));
      if (enabled !== 1) {
        await setVarbinds(session, [
          { oid: GLOBAL_ENABLE_OID, type: snmp.ObjectType.Integer, value: 1 }
        ]);
        enabledNow = true;
        log.info('syslog', 'Enabled global logging on the switch', { host: opts.host });
      }
    } catch (e) { /* not implemented; the row may still be enough */ }

    session.close();
    return Object.assign({ address, port, severity, severityName: SEVERITY_NAMES[severity], enabledNow },
      created);
  } catch (e) {
    try { session.close(); } catch (x) {}
    throw e;
  }
}

/** Remove a collector row, from whichever table holds it. */
async function removeCollector(buildSession, index, tableName) {
  const session = buildSession();
  session.on('error', () => {});
  const table = TABLES.find((t) => t.name === tableName) || TABLES[0];
  try {
    await setVarbinds(session, [
      { oid: oid(table, table.cols.rowStatus, index), type: snmp.ObjectType.Integer, value: ROW.destroy }
    ]);
    session.close();
    return { removed: index, table: table.name };
  } catch (e) {
    try { session.close(); } catch (x) {}
    throw e;
  }
}

module.exports = {
  readCollectors, addCollector, removeCollector, localAddressFor,
  SEVERITY_NAMES, TABLES
};
