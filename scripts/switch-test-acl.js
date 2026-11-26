'use strict';

/**
 * Supervised write test for the Access lists panel (public/src/14-acl.js) on
 * a test switch. It makes three lists of its own, sbs-test-ip, sbs-test-v6 and sbs-test-mac,
 * fills them with every kind of rule the panel offers, binds them to one port
 * and unbinds them, and deletes them again. Nothing is saved to startup.
 *
 *   SBS_COMM=<community> node scripts/switch-test-acl.js <address> [port ifIndex] [--keep | --cleanup] [results folder]
 *
 * The port (default 4) should have nothing plugged in: the lists are bound to
 * it for a moment, with its default actions left as they are.
 *
 *   --keep     leave the two lists on the switch (unbound) at the end, so
 *              "show access-lists" on the switch can be compared with what
 *              the panel shows. Run again with --cleanup to remove them.
 *   --cleanup  only remove sbs-test-ip, sbs-test-v6 and sbs-test-mac.
 *
 * Every write goes through the panel's own code, over the app's own routes on
 * 127.0.0.1. No community is written to the results file.
 */

process.env.SNMP_MAX_RPS = process.env.SNMP_MAX_RPS || '20';
const fs = require('fs');
const path = require('path');
const http = require('http');
const { loadAclWrites } = require('./lib/browser-writes');

const flags = process.argv.slice(2).filter((a) => a.startsWith('--'));
const args = process.argv.slice(2).filter((a) => !a.startsWith('--'));
const host = args[0];
const ifx = /^\d+$/.test(args[1] || '') ? Number(args[1]) : 4;
const outDir = /^\d+$/.test(args[1] || '') ? (args[2] || null) : (args[1] || null);
const keep = flags.includes('--keep');
const cleanupOnly = flags.includes('--cleanup');
const community = process.env.SBS_COMM;
if (!host || !community) {
  console.error('Usage: SBS_COMM=<community> node scripts/switch-test-acl.js <address> [port ifIndex] [--keep | --cleanup] [results folder]');
  process.exit(2);
}
const LISTS = ['sbs-test-ip', 'sbs-test-v6', 'sbs-test-mac'];

const lines = [];
function say(msg) {
  const l = '[' + new Date().toISOString().slice(11, 19) + '] ' + msg;
  lines.push(l);
  console.log(l);
}
const results = [];
function check(name, ok, detail) {
  results.push({ name, ok: !!ok, detail: detail || '' });
  say((ok ? 'PASS ' : 'FAIL ') + name + (detail ? ': ' + detail : ''));
  return !!ok;
}

async function startApp() {
  const out = console.log;
  console.log = (...a) => { if (typeof a[0] === 'string' && /^\[[0-9T:.\-Z]+\] \[INFO\]/.test(a[0])) return; out(...a); };
  const app = require('../web');
  require('../routes/snmp')(app);
  require('../routes/health')(app);
  const server = http.createServer(app);
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return server;
}

// What a rule reads back as, in one line.
const ruleText = (v) => [v.action, v.proto, 'from', v.src, 'to', v.dst].concat(v.extra).join(' ');

async function main() {
  const server = await startApp();
  const base = 'http://127.0.0.1:' + server.address().port;
  const s = { target: { host, port: 161, version: '2c', community, timeout: 8000, retries: 1 }, host, health: {} };
  const refreshTables = async (sess, tables) => {
    const r = await fetch(base + '/api/health', { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: sess.target, only: tables }) });
    const body = await r.json();
    if (!r.ok || body.error) throw new Error('reading the lists: ' + (body.error || 'HTTP ' + r.status));
    for (const k of body.keys || []) sess.health[k] = body[k];
  };
  const w = loadAclWrites({ fetch: (p, init) => fetch(base + p, init), refreshTables });
  const read = async () => { await refreshTables(s, ['aclNames', 'aclAces', 'aclTuples']); return w.aclModel(s.health); };
  const listOf = (m, name) => m.acls.find((a) => a.name === name);
  const tupleCount = (m) => m.tupleMap.size;

  // ---- 0. remove what an earlier run left ----------------------------------
  let m = await read();
  for (const name of LISTS) {
    const acl = listOf(m, name);
    if (!acl) continue;
    const r = await w.deleteQosAcl(s, acl.idx);
    check('removed ' + name + ' left by an earlier run', r.ok, r.error || '');
    m = await read();
  }
  if (cleanupOnly) return finish(server);
  const before = { names: m.acls.map((a) => a.name).sort().join(','), tuples: tupleCount(m) };
  say('  lists on the switch: ' + before.names + '; ' + before.tuples + ' tuples');

  // ---- 1. rules: each is added, read back, and its text compared -------------
  // want: the line the rule must read back as (ruleText of aclRuleView).
  const add = async (label, cfg, want, opts) => {
    let err = null;
    try { await w.createQosAce(s, cfg); } catch (e) { err = e.message; }
    m = await read();
    const acl = listOf(m, cfg.aclName);
    const last = acl && acl.aceList[acl.aceList.length - 1];
    const v = last && w.aclRuleView(last, m.tupleMap);
    const got = v ? ruleText(v) : '(no rule)';
    if (opts && opts.probe && err) {
      say('INFO ' + label + ': the switch refused it (' + err + '). The panel should not offer this.');
      return null;
    }
    check(label, !err && got === want && v.unsupported.length === 0, err || (got === want ? got : 'reads "' + got + '", wanted "' + want + '"'));
    return last;
  };
  const ip = (o) => Object.assign({ aclName: 'sbs-test-ip', family: 'ip', action: 1, src: { any: true }, dst: { any: true } }, o);
  const v6 = (o) => Object.assign({ aclName: 'sbs-test-v6', family: 'ipv6', action: 1, src: { any: true }, dst: { any: true } }, o);

  await add('IPv4: a new list with ICMP echo request (type 8 code 0)', ip({ proto: 'icmp', icmpType: 8, icmpCode: 0 }), 'permit icmp from any to any icmp type 8 code 0');
  await add('IPv4: ICMP to one host, any type', ip({ proto: 'icmp', dst: { any: false, ip: '192.0.2.10', pref: 32 } }), 'permit icmp from any to 192.0.2.10/32');
  await add('IPv4: deny protocol 47', ip({ action: 2, proto: 'num', protoNum: 47 }), 'deny protocol 47 from any to any');
  await add('IPv4: plain rule to a /24', ip({ dst: { any: false, ip: '10.253.246.0', pref: 24 } }), 'permit ip from any to 10.253.246.0/24');
  const ranged = await add('IPv4: TCP from a /24 to ports 8000-8080', ip({ proto: 'tcp', src: { any: false, ip: '10.253.244.0', pref: 24 }, dstPort: { from: 8000, to: 8080 } }),
    'permit tcp from 10.253.244.0/24 to any destination ports 8000-8080');
  await add('IPv4: UDP from source port 53', ip({ proto: 'udp', srcPort: { from: 53, to: 53 } }), 'permit udp from any to any source port 53');
  await add('IPv4: UDP to ports 5000-5010', ip({ proto: 'udp', dstPort: { from: 5000, to: 5010 } }), 'permit udp from any to any destination ports 5000-5010');
  await add('IPv4: TCP to port 22 with SYN set and ACK unset', ip({ action: 4, proto: 'tcp', dstPort: { from: 22, to: 22 }, tcpFlags: { val: 0x02, dc: 0x2d } }),
    'deny-log tcp from any to any destination port 22 flags -ack +syn');
  await add('IPv4: TCP from source ports 1000-2000', ip({ proto: 'tcp', srcPort: { from: 1000, to: 2000 } }), 'permit tcp from any to any source ports 1000-2000');

  // An edit keeps the rule's number and replaces its match.
  if (ranged) {
    let err = null;
    const list = listOf(m, 'sbs-test-ip');
    try { await w.editQosAce(s, list.idx, ranged.idx, ip({ proto: 'udp', dstPort: { from: 6000, to: 6001 } })); } catch (e) { err = e.message; }
    m = await read();
    const ace = listOf(m, 'sbs-test-ip').aces.get(ranged.idx);
    const got = ace ? ruleText(w.aclRuleView(ace, m.tupleMap)) : '(gone)';
    check('IPv4: rule ' + ranged.idx + ' edited in place to UDP ports 6000-6001', !err && got === 'permit udp from any to any destination ports 6000-6001', err || got);
  }

  await add('IPv6: a new list with TCP from 2001:db8::/32 to port 443', v6({ proto: 'tcp', src: { any: false, ip: '2001:db8::', pref: 32 }, dstPort: { from: 443, to: 443 } }),
    'permit tcp from 2001:db8::/32 to any destination port 443');
  await add('IPv6: ICMP echo request (type 128)', v6({ proto: 'icmp', icmpType: 128 }), 'permit icmp from any to any icmp type 128');
  await add('IPv6: UDP to 2001:db8:1::/48 port 53', v6({ proto: 'udp', dst: { any: false, ip: '2001:db8:1::', pref: 48 }, dstPort: { from: 53, to: 53 } }),
    'permit udp from any to 2001:db8:1::/48 destination port 53');
  await add('IPv6: plain rule to a /64', v6({ action: 2, dst: { any: false, ip: '2001:db8:2::', pref: 64 } }), 'deny ipv6 from any to 2001:db8:2::/64');
  await add('IPv6: deny protocol 47', v6({ action: 2, proto: 'num', protoNum: 47 }), 'deny protocol 47 from any to any');

  const mac = (o) => Object.assign({ aclName: 'sbs-test-mac', family: 'mac', action: 1, proto: 'any', src: { any: true }, dst: { any: true } }, o);
  await add('MAC: a new list from one device', mac({ src: { any: false, ip: '02:00:5e:10:00:01', pref: 48 } }), 'permit any from 02:00:5e:10:00:01/48 to any');
  await add('MAC: deny to every IPv4 multicast address', mac({ action: 2, dst: { any: false, ip: '01:00:5e:00:00:00', pref: 24 } }), 'deny any from any to 01:00:5e:00:00:00/24');
  await add('MAC: one maker to one device on VLAN 1', mac({ src: { any: false, ip: '02:00:5e:00:00:00', pref: 24 }, dst: { any: false, ip: '02:00:5e:10:00:02', pref: 48 }, vlan: 1 }),
    'permit any from 02:00:5e:00:00:00/24 to 02:00:5e:10:00:02/48 vlan 1');

  // ---- 2. binding to the port and back -----------------------------------
  {
    const ipList = listOf(m, 'sbs-test-ip'), v6List = listOf(m, 'sbs-test-v6');
    const b0 = await w.readIfAclBinding(s, ifx, w.IFTYPE_PORT);
    say('  port ' + ifx + ' binding before: ' + JSON.stringify(b0));
    const sfx = '.' + ifx + '.' + w.IFTYPE_PORT;
    const setBinding = async (inAcl, v6In) => {
      const vbs = [{ oid: w.QOS_IFPOL.aclIn + sfx, type: 'Integer', value: inAcl }];
      if (b0.v6In != null) vbs.push({ oid: w.QOS_IFPOL.v6In + sfx, type: 'Integer', value: v6In });
      try { await w.snmpSet(s, vbs); return null; } catch (e) { return e.message; }
    };
    if (ipList && v6List && !b0.inAcl && !b0.v6In) {
      let err = await setBinding(Number(ipList.idx), Number(v6List.idx));
      let b = await w.readIfAclBinding(s, ifx, w.IFTYPE_PORT);
      check('both lists bound to port ' + ifx + ' (input)', !err && b.inAcl === Number(ipList.idx) && (b0.v6In == null || b.v6In === Number(v6List.idx)), err || JSON.stringify(b));
      m = await read();
      check('the panel shows them as bound', listOf(m, 'sbs-test-ip').bound && (b0.v6In == null || listOf(m, 'sbs-test-v6').bound), '');
      const refused = await w.deleteQosAcl(s, ipList.idx);
      check('a bound list cannot be deleted from the panel', !refused.ok && /bound/.test(refused.error || ''), refused.error || 'it was deleted');
      const macList = listOf(m, 'sbs-test-mac');
      if (macList) {
        err = await setBinding(Number(macList.idx), 0);
        b = await w.readIfAclBinding(s, ifx, w.IFTYPE_PORT);
        check('the MAC list bound to port ' + ifx + ' in its place', !err && b.inAcl === Number(macList.idx), err || JSON.stringify(b));
      }
      err = await setBinding(0, 0);
      b = await w.readIfAclBinding(s, ifx, w.IFTYPE_PORT);
      check('port ' + ifx + ' unbound again', !err && JSON.stringify(b) === JSON.stringify(b0), err || JSON.stringify(b));
    } else say('SKIP binding: port ' + ifx + ' already has a list bound, or a list is missing');
  }

  // ---- 3. delete, or keep for a look on the switch ---------------------------
  m = await read();
  if (keep) {
    say('KEPT sbs-test-ip, sbs-test-v6 and sbs-test-mac on the switch, unbound. Compare with "show access-lists" on the switch,');
    say('then run this again with --cleanup to remove them.');
    return finish(server);
  }
  for (const name of LISTS) {
    const acl = listOf(m, name);
    if (!acl) continue;
    const r = await w.deleteQosAcl(s, acl.idx);
    check('deleted ' + name, r.ok, r.error || '');
  }
  m = await read();
  const after = { names: m.acls.map((a) => a.name).sort().join(','), tuples: tupleCount(m) };
  check('the lists are as they were', after.names === before.names, after.names);
  check('no tuples left behind', after.tuples === before.tuples, after.tuples + ' tuples, ' + before.tuples + ' before');
  return finish(server);
}

function finish(server) {
  const failed = results.filter((r) => !r.ok).length;
  const verdict = failed ? failed + ' CHECK(S) FAILED' : 'ALL ' + results.length + ' CHECKS PASSED';
  console.log(verdict);
  lines.push(verdict);
  console.log('Nothing was saved to startup.');
  if (outDir) {
    fs.mkdirSync(outDir, { recursive: true });
    const file = path.join(outDir, 'switch-test-acl-' + host.replace(/[^0-9a-z.]/gi, '_') + '.txt');
    fs.writeFileSync(file, lines.join('\n') + '\n\n' + JSON.stringify(results, null, 2) + '\n');
    console.log('Wrote ' + file);
  }
  server.close();
  setTimeout(() => process.exit(failed ? 1 : 0), 200);
}

main().catch((e) => { console.error(e); process.exit(1); });
