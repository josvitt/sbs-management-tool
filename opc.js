'use strict';

// Onboard Packet Capture (OPC) control over SNMP, via the CISCOSB-OPC-MIB
// (rlOpc = 1.3.6.1.4.1.9.6.1.101.248). The C1300's onboard capture records
// CONTROL-PLANE traffic only (not interface mirroring); the control plane is
// addressed in the interface table by the special ifIndex 2147483646.
//
// Three tables, all keyed by the capture-point name (a DisplayString, which
// as a single variable-length SNMP index is encoded length-prefixed):
//   rlOpcCapturePointTable  (248.1) - buffer, filter, limits, state, RowStatus
//   rlOpcInterfaceTable     (248.2) - which source (control plane) + direction
//   rlOpcActionTable        (248.3) - export destination/filename + start/stop/export/clear
//
// This module only assembles the varbind plans and exposes a small set of
// operations; the HTTP layer runs them through the shared SNMP set/get with
// the watchdog, and pcap retrieval reuses config-fetch's rlCopyTable + TFTP.

const CP = '1.3.6.1.4.1.9.6.1.101.248';

const OID = {
  // capture point (248.1.1.C)
  cpName: CP + '.1.1.1',
  cpBufferType: CP + '.1.1.2',
  cpBufferSize: CP + '.1.1.3',
  cpBufferUsed: CP + '.1.1.4',
  cpBufferPacketNum: CP + '.1.1.5',
  cpBufferPacketsDropped: CP + '.1.1.6',
  cpBufferPps: CP + '.1.1.7',
  cpFilterType: CP + '.1.1.8',
  cpFilterAclName: CP + '.1.1.9',
  cpLimitDuration: CP + '.1.1.10',
  cpLimitNumPackets: CP + '.1.1.11',
  cpLimitMaxPacketLen: CP + '.1.1.12',
  cpState: CP + '.1.1.13',
  cpRowStatus: CP + '.1.1.14',
  // interface (248.2.1.C) - indexed by (name, ifIndex)
  ifDirection: CP + '.2.1.3',
  ifRowStatus: CP + '.2.1.4',
  // action (248.3.1.C)
  actName: CP + '.3.1.1',
  actExportDest: CP + '.3.1.2',
  actExportFileName: CP + '.3.1.3',
  actAction: CP + '.3.1.4',
  actRowStatus: CP + '.3.1.5',
  // global
  operState: CP + '.6'
};

const BUFFER_TYPE = { linear: 1, circular: 2 };
const FILTER_TYPE = { none: 0, any: 1, acl: 2 };
const DIRECTION = { none: 0, in: 1, out: 2, both: 3 };
const EXPORT_DEST = { flash: 0, usb: 1 };
const ACTION = { start: 1, stop: 2, export: 3, clear: 4 };
const ROW = { active: 1, createAndGo: 4, createAndWait: 5, destroy: 6 };
const CONTROL_PLANE_IFINDEX = 2147483646;

// A single variable-length string table index: length byte then the ASCII of
// each character, dot-joined (e.g. "cap" -> "3.99.97.112").
function nameIndex(name) {
  const bytes = Buffer.from(String(name), 'latin1');
  return [bytes.length].concat(Array.from(bytes)).join('.');
}
// The interface table is indexed by (name, ifIndex): the length-prefixed name
// followed by the ifIndex as a single sub-identifier.
function ifIndex(name, ifIdx) {
  return nameIndex(name) + '.' + ifIdx;
}

// Varbinds (as {oid,type,value|valueHex}) accepted by /api/snmp/set.
const I = (oid, value) => ({ oid, type: 'Integer', value });
const U = (oid, value) => ({ oid, type: 'Gauge', value });        // Unsigned32
const S = (oid, value) => ({ oid, type: 'OctetString', value });

// Create (or reconfigure) the capture point in one plan. cfg:
//   { name, bufferType:'linear'|'circular', bufferSizeMb, filter:'any'|'acl',
//     aclName?, limitDurationSec?, limitPackets?, limitMaxLen? }
function planCreateCapture(cfg) {
  const i = nameIndex(cfg.name);
  const vbs = [
    I(OID.cpBufferType + '.' + i, BUFFER_TYPE[cfg.bufferType] || BUFFER_TYPE.linear),
    I(OID.cpFilterType + '.' + i, FILTER_TYPE[cfg.filter] || FILTER_TYPE.any)
  ];
  if (Number.isFinite(cfg.bufferSizeMb) && cfg.bufferSizeMb > 0) vbs.push(U(OID.cpBufferSize + '.' + i, cfg.bufferSizeMb));
  if (cfg.filter === 'acl' && cfg.aclName) vbs.push(S(OID.cpFilterAclName + '.' + i, cfg.aclName));
  if (Number.isFinite(cfg.limitDurationSec)) vbs.push(U(OID.cpLimitDuration + '.' + i, cfg.limitDurationSec));
  if (Number.isFinite(cfg.limitPackets)) vbs.push(U(OID.cpLimitNumPackets + '.' + i, cfg.limitPackets));
  if (Number.isFinite(cfg.limitMaxLen)) vbs.push(U(OID.cpLimitMaxPacketLen + '.' + i, cfg.limitMaxLen));
  // For a NEW capture, RowStatus createAndGo goes last so the row is created
  // with its columns in one PDU. For an existing one (reconfigure) the row is
  // already active, so creating it again would be refused — set columns only.
  if (!cfg.existing) vbs.push(I(OID.cpRowStatus + '.' + i, ROW.createAndGo));
  return vbs;
}

// Bind the capture point to the control plane with a direction.
function planBindControlPlane(name, direction) {
  const idx = ifIndex(name, CONTROL_PLANE_IFINDEX);
  return [
    I(OID.ifDirection + '.' + idx, DIRECTION[direction] || DIRECTION.both),
    I(OID.ifRowStatus + '.' + idx, ROW.createAndGo)
  ];
}

function planAction(name, action) {
  const i = nameIndex(name);
  return [I(OID.actAction + '.' + i, ACTION[action])];
}

// BASELINE (combined): destination + filename + export action in ONE PDU, no
// RowStatus. The switch acks this noError and writes a valid pcap, but it
// crashes the control plane. Kept as a comparison point.
function planExport(name, fileName) {
  const i = nameIndex(name);
  return [
    I(OID.actExportDest + '.' + i, EXPORT_DEST.flash),
    S(OID.actExportFileName + '.' + i, fileName),
    I(OID.actAction + '.' + i, ACTION.export)
  ];
}

// Same three varbinds, reordered within the single PDU. SMIv2 says order is not
// significant, and since v2c and v3 crash identically the crash is downstream
// of PDU processing - so this is a long shot - but it is the one untried SNMP
// variable: whether the firmware's commit handler is order-sensitive.
function planExportActionFirst(name, fileName) {
  const i = nameIndex(name);
  return [
    I(OID.actAction + '.' + i, ACTION.export),
    I(OID.actExportDest + '.' + i, EXPORT_DEST.flash),
    S(OID.actExportFileName + '.' + i, fileName)
  ];
}
function planExportFilenameFirst(name, fileName) {
  const i = nameIndex(name);
  return [
    S(OID.actExportFileName + '.' + i, fileName),
    I(OID.actExportDest + '.' + i, EXPORT_DEST.flash),
    I(OID.actAction + '.' + i, ACTION.export)
  ];
}

// Create the action row with the INDEX column (rlOpcActionCaptureName, col 1)
// EXPLICITLY included. RFC 2579's InconsistentValue on create means either the
// row exists (it doesn't - readback was null) or "insufficient information".
// The one column never supplied before is the name/index column, which this
// firmware marks read-write. These include it. No export is triggered - safe.
function planActionCreateGoWithName(name, fileName) {
  const i = nameIndex(name);
  return [
    S(OID.actName + '.' + i, name),
    I(OID.actExportDest + '.' + i, EXPORT_DEST.flash),
    S(OID.actExportFileName + '.' + i, fileName),
    I(OID.actRowStatus + '.' + i, ROW.createAndGo)
  ];
}
function planActionCreateWaitWithName(name) {
  const i = nameIndex(name);
  return [
    S(OID.actName + '.' + i, name),
    I(OID.actRowStatus + '.' + i, ROW.createAndWait)
  ];
}

// --- createAndWait lifecycle (RFC 2579), the standards-correct way to manage
// a RowStatus row. The earlier createAndGo attempt returned inconsistentValue,
// which per the RFC means either a required column was missing or the row
// already existed; createAndWait negotiates creation in steps instead. ---

// Step 1: create the row empty (notReady/notInService). RowStatus alone.
function planCwCreate(name) {
  const i = nameIndex(name);
  return [I(OID.actRowStatus + '.' + i, ROW.createAndWait)];
}
// Step 2: populate the row's columns on the now-existing row.
function planCwPopulate(name, fileName) {
  const i = nameIndex(name);
  return [
    I(OID.actExportDest + '.' + i, EXPORT_DEST.flash),
    S(OID.actExportFileName + '.' + i, fileName)
  ];
}
// Step 3: activate the row.
function planCwActivate(name) {
  const i = nameIndex(name);
  return [I(OID.actRowStatus + '.' + i, ROW.active)];
}
// Step 4: trigger the export on the active, managed row.
function planCwTrigger(name) {
  const i = nameIndex(name);
  return [I(OID.actAction + '.' + i, ACTION.export)];
}
// Step 5: destroy the row (clean teardown).
function planCwDestroy(name) {
  const i = nameIndex(name);
  return [I(OID.actRowStatus + '.' + i, ROW.destroy)];
}
// Read back the action row's columns, to report its state between steps.
function actionRowOids(name) {
  const i = nameIndex(name);
  return {
    dest: OID.actExportDest + '.' + i,
    fileName: OID.actExportFileName + '.' + i,
    rowStatus: OID.actRowStatus + '.' + i
  };
}

// Tear down the capture point and its companion rows.
function planDeleteCapture(name) {
  const i = nameIndex(name);
  const cpIdx = ifIndex(name, CONTROL_PLANE_IFINDEX);
  return [
    I(OID.actRowStatus + '.' + i, ROW.destroy),
    I(OID.ifRowStatus + '.' + cpIdx, ROW.destroy),
    I(OID.cpRowStatus + '.' + i, ROW.destroy)
  ];
}

// OIDs to read back the live status of a capture point (scalars under its row).
function statusOids(name) {
  const i = nameIndex(name);
  return {
    state: OID.cpState + '.' + i,
    bufferUsed: OID.cpBufferUsed + '.' + i,
    packets: OID.cpBufferPacketNum + '.' + i,
    dropped: OID.cpBufferPacketsDropped + '.' + i,
    pps: OID.cpBufferPps + '.' + i
  };
}

// Which capture-point column each sub-identifier after 248.1.1 maps to.
const CP_COL = {
  1: 'name', 2: 'bufferType', 3: 'bufferSize', 4: 'bufferUsed',
  5: 'packets', 6: 'dropped', 7: 'pps', 8: 'filterType', 9: 'aclName',
  10: 'limitDuration', 11: 'limitPackets', 12: 'limitMaxLen',
  13: 'state', 14: 'rowStatus'
};
const BUFFER_TYPE_NAME = { 1: 'linear', 2: 'circular' };
const FILTER_TYPE_NAME = { 0: 'none', 1: 'any', 2: 'acl' };

// Decode a length-prefixed string index that starts at position `start` in a
// dotted-OID tail array. Returns { name, rest } where rest is the remaining
// sub-identifiers after the name (e.g. an ifIndex).
function decodeNameIndex(parts, start) {
  const len = Number(parts[start]);
  const chars = parts.slice(start + 1, start + 1 + len).map((n) => String.fromCharCode(Number(n)));
  return { name: chars.join(''), rest: parts.slice(start + 1 + len) };
}

// Turn a walk of rlOpcCapturePointTable (248.1) into one object per capture.
// `rows` is an array of { oid, value } (value already decoded to string/number).
function parseCaptureList(rows) {
  const base = CP + '.1.1.';
  const byName = new Map();
  for (const r of rows || []) {
    const oid = String(r.oid || '');
    if (oid.indexOf(base) !== 0) continue;
    const tail = oid.slice(base.length).split('.');       // [col, lenPrefixedName...]
    const col = Number(tail[0]);
    const colName = CP_COL[col];
    if (!colName) continue;
    const { name } = decodeNameIndex(tail, 1);
    if (!name) continue;
    if (!byName.has(name)) byName.set(name, { name });
    byName.get(name)[colName] = r.value;
  }
  // Add friendly decodes.
  const out = [];
  for (const cap of byName.values()) {
    cap.bufferTypeText = BUFFER_TYPE_NAME[Number(cap.bufferType)] || cap.bufferType;
    cap.filterText = FILTER_TYPE_NAME[Number(cap.filterType)] || cap.filterType;
    cap.stateText = Number(cap.state) === 1 ? 'active' : (Number(cap.state) === 2 ? 'inactive' : 'unknown');
    out.push(cap);
  }
  out.sort((a, b) => String(a.name).localeCompare(String(b.name)));
  return out;
}

module.exports = {
  OID, BUFFER_TYPE, FILTER_TYPE, DIRECTION, EXPORT_DEST, ACTION, ROW,
  CONTROL_PLANE_IFINDEX, nameIndex, ifIndex, decodeNameIndex, parseCaptureList,
  planCreateCapture, planBindControlPlane, planAction,
  planExport, planExportActionFirst, planExportFilenameFirst,
  planActionCreateGoWithName, planActionCreateWaitWithName,
  planCwCreate, planCwPopulate, planCwActivate, planCwTrigger, planCwDestroy, actionRowOids,
  planDeleteCapture, statusOids,
  // Table roots, for the diagnostic walk.
  WALK: {
    capturePoint: CP + '.1',
    iface: CP + '.2',
    action: CP + '.3',
    operState: CP + '.6'
  }
};
