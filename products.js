/**
 * Product registry (server side).
 *
 * The three switch lines the app supports differ in what they can do, and the
 * MIB proves some of it: C1200 and C1300 ship an identical MIB set, while the
 * C1300X MIB adds OSPF/OSPFv3 and PTP and renumbers the 802.3bt PoE table. So
 * "which product is this, and what does its MIB support" is a real question
 * that both the collector and the UI need answered the same way.
 *
 * The definitions live in public/mib/products.json so the browser and the
 * server read ONE source (the browser fetches it directly; this module reads
 * the same file). This module adds the detection logic: given a switch's model
 * string, which line is it.
 */

const fs = require('fs');
const path = require('path');

const FILE = path.join(__dirname, 'public', 'mib', 'products.json');

let registry = null;
function load() {
  if (registry) return registry;
  try {
    registry = JSON.parse(fs.readFileSync(FILE, 'utf8'));
  } catch (e) {
    // A missing/broken registry must not break collection; fall back to the
    // original single-product assumption.
    registry = {
      default: 'C1300',
      products: [{ line: 'C1300', label: 'Catalyst 1200/1300', db: 'mib/oid-db.json', match: ['C1300'], features: {} }]
    };
  }
  return registry;
}

function list() { return load().products.slice(); }
function byLine(line) { return load().products.find((p) => p.line === line) || null; }
function defaultLine() { return load().default; }

/**
 * Identify the product line from any model-bearing string (the switch's
 * rlPhdUnitGenParamModelName, sysDescr, or stack product id). Match prefixes
 * are tested most-specific-first so "C1300X-24T-4X" matches C1300X, not C1300.
 * Returns the product object, or null if nothing matched.
 */
function detect(strings) {
  const reg = load();
  const hay = (Array.isArray(strings) ? strings : [strings])
    .filter(Boolean).map((s) => String(s).toUpperCase());
  let best = null, bestLen = -1;
  for (const p of reg.products) {
    for (const m of (p.match || [])) {
      const needle = String(m).toUpperCase();
      if (hay.some((h) => h.indexOf(needle) >= 0) && needle.length > bestLen) {
        best = p; bestLen = needle.length;
      }
    }
  }
  return best;
}

module.exports = { load, list, byLine, defaultLine, detect };
