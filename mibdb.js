/**
 * MIB database for the Cisco Catalyst 1200/1300 switch family.
 *
 * public/mib/oid-db.json is generated from the official C1300 MIB archive
 * (185 files, ~11.4k OID definitions) by tools-parse-mibs.py. It is loaded
 * once at startup so the SNMP endpoints accept symbolic names
 * ("rlPethPsePortPowerLimit") as well as raw numeric OIDs, and so results
 * can be labelled with the name they correspond to.
 *
 * The browser loads the same file directly for autocomplete, so there is a
 * single source of truth for both sides.
 */

const fs = require('fs');
const path = require('path');

const DB_PATH = path.join(__dirname, 'public', 'mib', 'oid-db.json');

let byName = new Map();   // lowercase name -> entry
let byOid = new Map();    // numeric oid -> name
let byOidEntry = new Map(); // numeric oid -> entry
let entries = [];
let loaded = false;
let loadError = null;

function load() {
  if (loaded) return;
  loaded = true;
  try {
    const raw = JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
    const enums = raw.enums || [];
    for (const row of raw.entries) {
      const [name, oid, access, syntax, description, mib, enumId, units] = row;
      const entry = { name, oid, access, syntax, description, mib, units: units || '' };
      // Enumerations are shared between objects (IANAifType is referenced by
      // many), so the file stores an index into a dedup table.
      if (typeof enumId === 'number' && enumId >= 0 && enums[enumId]) {
        entry.enum = enums[enumId];
      }
      entries.push(entry);
      byName.set(name.toLowerCase(), entry);
      // First definition wins on the handful of OIDs that carry two names.
      if (!byOid.has(oid)) byOid.set(oid, name);
      byOidEntry.set(oid, entry);
    }
  } catch (e) {
    loadError = e.message;
  }
}

const NUMERIC_OID = /^\.?\d+(\.\d+)*$/;

/**
 * Accepts any of:
 *   "1.3.6.1.2.1.1.5.0"        -> unchanged (leading dot trimmed)
 *   "sysName"                  -> "1.3.6.1.2.1.1.5"
 *   "sysName.0"                -> "1.3.6.1.2.1.1.5.0"
 *   "rlPethPsePortPowerLimit.1.5" -> resolved base + ".1.5"
 * Throws if a non-numeric name isn't in the MIB set.
 */
function resolveOid(input) {
  load();
  if (input === undefined || input === null) throw new Error('Empty OID');
  let s = String(input).trim();
  if (!s) throw new Error('Empty OID');
  if (s.startsWith('.')) s = s.slice(1);

  if (NUMERIC_OID.test(s)) return s;

  // Split a trailing numeric instance suffix off the symbolic part.
  const m = s.match(/^([A-Za-z][A-Za-z0-9_-]*)((?:\.\d+)*)$/);
  if (!m) throw new Error(`Not a valid OID or MIB name: "${input}"`);

  const entry = byName.get(m[1].toLowerCase());
  if (!entry) throw new Error(`Unknown MIB name: "${m[1]}"`);
  return entry.oid + (m[2] || '');
}

/**
 * Turn a numeric OID from a response back into something readable, using
 * longest-prefix matching so instance suffixes survive:
 *   1.3.6.1.2.1.2.2.1.2.3 -> "ifDescr.3"
 * Returns null when nothing in the MIB set matches.
 */
function describeOid(oid) {
  load();
  if (!oid) return null;
  let parts = String(oid).replace(/^\./, '').split('.');
  const suffix = [];
  while (parts.length > 0) {
    const candidate = parts.join('.');
    const name = byOid.get(candidate);
    if (name) {
      return suffix.length ? `${name}.${suffix.reverse().join('.')}` : name;
    }
    suffix.push(parts.pop());
  }
  return null;
}

/**
 * Like describeOid, but returns the MIB entry (with enum/units/syntax) and
 * the instance suffix, so a response value can be formatted using the
 * definition it came from.
 *   1.3.6.1.4.1.9.6.1.101.54.43.1.8.3 -> { entry: rlifPresentOperStatus, index: '3' }
 */
function entryForOid(oid) {
  load();
  if (!oid) return null;
  const parts = String(oid).replace(/^\./, '').split('.');
  const suffix = [];
  while (parts.length > 0) {
    const entry = byOidEntry.get(parts.join('.'));
    if (entry) {
      return { entry, index: suffix.slice().reverse().join('.') };
    }
    suffix.push(parts.pop());
  }
  return null;
}

function lookup(name) {
  load();
  return byName.get(String(name).toLowerCase()) || null;
}

function stats() {
  load();
  return { count: entries.length, loadError };
}

module.exports = { resolveOid, describeOid, entryForOid, lookup, stats };
