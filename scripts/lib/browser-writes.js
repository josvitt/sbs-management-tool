'use strict';

/**
 * The browser's own write code (public/src), loaded outside the browser so a
 * script or a test can send exactly the SETs the dashboard sends. Only the
 * pieces that build and send writes are loaded; nothing that draws the page.
 *
 *   const w = loadBrowserWrites({ fetch, onSet });
 *   await w.applySwitchportConfig(s, cfg);
 *
 * fetch(path, init) answers the app's /api calls (a real server in
 * scripts/switch-test.js). onSet(varbinds) is optional: return a string to
 * refuse that SET without sending it (a forced failure), or nothing to send it.
 */

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const SRC = path.join(__dirname, '..', '..', 'public', 'src');
const read = (f) => fs.readFileSync(path.join(SRC, f), 'utf8');

function between(src, start, end, file) {
  const a = src.indexOf(start);
  const b = src.indexOf(end, a + 1);
  if (a < 0 || b < 0) throw new Error(file + ': cannot find "' + start + '" .. "' + end + '"');
  return src.slice(a, b);
}

function loadBrowserWrites(opts) {
  const ctx = {
    console,
    setTimeout,
    appLog: () => {},
    fetch: opts.fetch,
    onSet: opts.onSet || (() => null)
  };
  vm.createContext(ctx);
  const core = read('01-core.js');
  const ipv4 = read('15-ipv4-addressing.js');
  const ports = read('07-ports.js');
  const code = [
    between(core, '  // One place that knows how to POST JSON', '  // Interpret a snmpSetResult', '01-core.js'),
    between(core, '  function buildVlanListBlock', '  // ---- config history', '01-core.js'),
    between(core, '  const INET_IPV4 = 1;', '  // A titled section inside an editor form.', '01-core.js'),
    between(ipv4, '  const SVI_IP = {', '  // A routable unicast IPv4', '15-ipv4-addressing.js'),
    between(ipv4, '  // Remove one interface\'s IPv4 configuration', '  // The ifIndex of the SVI carrying', '15-ipv4-addressing.js'),
    between(ipv4, '  const DNS_ROUTE = {', '  function paintRoutingPanel', '15-ipv4-addressing.js'),
    between(ipv4, '  // The SET that adds a nameserver', '  function openStaticRouteForm', '15-ipv4-addressing.js'),
    between(ports, '  // The SET steps that put a port', '  // 802.1X per-port editor:', '07-ports.js')
  ].join('\n');
  // A forced failure is decided before the SET leaves: the switch never sees
  // it, and the caller gets the same shape a refused varbind comes back in.
  const hook = `
    const __realSetResult = snmpSetResult;
    snmpSetResult = async function (s, varbinds) {
      const vbs = Array.isArray(varbinds) ? varbinds : [varbinds];
      const refuse = onSet(vbs);
      if (refuse) return { ok: true, status: 200, body: { results: [{ oid: vbs[0].oid, error: refuse }] } };
      return __realSetResult(s, vbs);
    };`;
  return vm.runInContext(code.replace(/async function snmpSetResult\(/, 'let snmpSetResult = async function (') + hook +
    `\n;({ apiPost, snmpSet, snmpSetResult, rowStatusDelete, nameserverIndex, ipToOidIndex, dnsNameIndex,
       dnsNameIndexParse, dnsV2ServerIndex, inetIndexToIp, SVI_IP, DHCP_CL, DNS_ROUTE, ifAddressVarbinds, removeIfAddress,
       teardownSvi, nameserverVarbinds, dnsDomainVarbinds, dnsHostVarbinds, dnsHostIndex, staticRouteVarbinds,
       planSwitchportChange, applySwitchportConfig })`, ctx);
}

// One top-level function's source, by name (brace-matched).
function pickFunction(src, name, file) {
  const start = src.search(new RegExp('(async )?function ' + name + '\\('));
  if (start < 0) throw new Error(file + ': no function ' + name);
  let i = src.indexOf('{', start), depth = 0;
  for (; i < src.length; i++) {
    if (src[i] === '{') depth++;
    else if (src[i] === '}' && --depth === 0) return src.slice(start, i + 1);
  }
  throw new Error(file + ': unbalanced ' + name);
}

/**
 * The access-list writes (public/src/14-acl.js, loaded whole: its drawing code
 * is only ever called, never run at load). refreshTables(s, tables) must put
 * fresh aclNames/aclAces/aclTuples rows in s.health, as the page does.
 */
function loadAclWrites(opts) {
  const ctx = { console, setTimeout, appLog: () => {}, fetch: opts.fetch, refreshTables: opts.refreshTables };
  vm.createContext(ctx);
  const core = read('01-core.js');
  const code = [
    between(core, '  // One place that knows how to POST JSON', '  // Interpret a snmpSetResult', '01-core.js'),
    ...['interpretSet', 'snmpGet', 'ipv4ToHex', 'dvc'].map((n) => pickFunction(core, n, '01-core.js')),
    read('14-acl.js')
  ].join('\n');
  return vm.runInContext(code + `\n;({ snmpSet, snmpGet, aclModel, aclRuleView, createQosAce, editQosAce, deleteQosAce,
    deleteQosAcl, readIfAclBinding, QOS_IFPOL, IFTYPE_PORT })`, ctx);
}

module.exports = { loadBrowserWrites, loadAclWrites };
