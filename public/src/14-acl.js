  // =================================================================
  // 14-acl.js: IP access lists (the QoS ACL tables) and their interface/VLAN
  // bindings.
  // =================================================================

  // ACL is a keyed panel (standard B1b), built like VLANs and IPv4 Addressing.
  // Its three tables (aclNames/aclAces/aclTuples) are raw-mode health tables,
  // loaded on demand once per visit (B4) and refreshed through refreshTables
  // (B5). The panel joins them client-side: ACL header -> ACEs -> tuple values.
  const ACL_TABLES = ['aclNames', 'aclAces', 'aclTuples'];
  function aclRefresh(s) {
    if (!s.target) return Promise.resolve();
    s._aclFetchedAt = Date.now();
    return refreshTables(s, ACL_TABLES);
  }
  function ensureAclLoaded(s) {
    if (s._aclFetching || !s.target) return;
    if (s.health && s.health.complete) return;      // the full collection carries the ACL tables
    if (Date.now() - (s._aclFetchedAt || 0) < 30000) return;
    s._aclFetching = true;
    aclRefresh(s).then(() => { s._aclFetching = false; }, () => { s._aclFetching = false; });
  }
  // The ACL tables have been read at least once (an empty list is still an
  // answer). Until then the panel says "Waiting for data", not "no lists".
  function aclLoaded(s) { return !!(s.health && Array.isArray(s.health.aclNames)); }

  // --- QoS ACL tables (where this switch actually stores ACLs) ---
  const QOS_ACL = {
    // ACL table (88.7), indexed by aclIndex.
    name:   '1.3.6.1.4.1.9.6.1.101.88.7.1.2',   // rlQosAclName
    type:   '1.3.6.1.4.1.9.6.1.101.88.7.1.3',   // rlQosAclType (AclObjectType: mac1 ip2 ipv6 3)
    aclStatus:'1.3.6.1.4.1.9.6.1.101.88.7.1.4', // rlQosAclStatus (RowStatus)
    numAces:'1.3.6.1.4.1.9.6.1.101.88.7.1.5',
    bound:  '1.3.6.1.4.1.9.6.1.101.88.7.1.6',  // rlQosAclIsBoundToInterface (TruthValue)
    origin: '1.3.6.1.4.1.9.6.1.101.88.7.1.8',  // rlQosAclOriginType (static 1 / dynamic 2 / system 3)
    // ACE table (88.31), indexed by aclIndex.aceIndex.
    aceTidx:'1.3.6.1.4.1.9.6.1.101.88.31',
    aceAction:'1.3.6.1.4.1.9.6.1.101.88.31.1.3',  // rlQosAceTidxAction
    aceType:'1.3.6.1.4.1.9.6.1.101.88.31.1.4',    // rlQosAceTidxType
    aceTupleBase: '1.3.6.1.4.1.9.6.1.101.88.31.1.', // +col, see ACE_TUPLE_COLS
    aceStatus:'1.3.6.1.4.1.9.6.1.101.88.31.1.14', // rlQosAceTidxStatus (RowStatus)
    // Tuple table (88.5), indexed by tupleIndex.
    tuple:  '1.3.6.1.4.1.9.6.1.101.88.5',
    tupType:'1.3.6.1.4.1.9.6.1.101.88.5.1.2',   // rlQosTupleType (ClassTupleType)
    tupVal1:'1.3.6.1.4.1.9.6.1.101.88.5.1.3',   // rlQosTupleValue1 (INTEGER)
    tupVal2:'1.3.6.1.4.1.9.6.1.101.88.5.1.4',   // rlQosTupleValue2 (OctetString value||mask)
    tupStatus:'1.3.6.1.4.1.9.6.1.101.88.5.1.5'  // rlQosTupleStatus (RowStatus)
  };
  // The column of each ACE Tuple pointer, from CISCOSB-qosclimib: Tuple1..8 are
  // columns 5..12 and Tuple9..11 are 17..19 (13 is Accounting, 14 the RowStatus,
  // 15 the time range, so the pointers are not one contiguous run).
  const ACE_TUPLE_COLS = [5, 6, 7, 8, 9, 10, 11, 12, 17, 18, 19];
  // The list types (AclObjectType: mac 1, ip 2, ipv6 3) and their words.
  const ACL_FAMILY = { 1: 'mac', 2: 'ip', 3: 'ipv6' };
  const ACL_FAMILY_VAL = { mac: 1, ip: 2, ipv6: 3 };
  const ACL_FAMILY_WORD = { mac: 'MAC', ip: 'IPv4', ipv6: 'IPv6' };
  // The ACE type (AceObjectType) for each list type and protocol choice, and
  // back. "num" is a plain rule that names a protocol number (the switch makes
  // "deny 47 any any" a type 1 rule with a protocol tuple).
  const ACE_TYPE_FOR = { ip: { any: 1, num: 1, tcp: 2, udp: 3, icmp: 7 }, ipv6: { any: 9, num: 9, tcp: 10, udp: 11, icmp: 13 }, mac: { any: 5 } };
  const ACE_KIND = { 1: ['ip', 'any'], 2: ['ip', 'tcp'], 3: ['ip', 'udp'], 7: ['ip', 'icmp'], 5: ['mac', 'any'],
    9: ['ipv6', 'any'], 10: ['ipv6', 'tcp'], 11: ['ipv6', 'udp'], 13: ['ipv6', 'icmp'] };
  // The protocol number a TCP, UDP or ICMP rule carries in its protocol tuple
  // (ICMP for IPv6 is 58, "3aff" on the switch).
  function protoNumber(family, proto) {
    if (proto === 'tcp') return 6;
    if (proto === 'udp') return 17;
    if (proto === 'icmp') return family === 'ipv6' ? 58 : 1;
    return null;
  }
  // Reverse maps for building writes.
  const TUPLE_TYPE_VAL = { protocol: 1, 'ip-src': 2, 'ip-dest': 3, 'mac-src': 10, 'mac-dest': 11, vlan: 12, 'tcp-flags': 18, 'icmp-type': 19, 'icmp-code': 20, 'ipv6-src': 23, 'ipv6-dest': 24 };
  // Port tuple types: one port, and the start of a range (its end is start + 1).
  const PORT_TUPLE = { udp: { src: { one: 6, start: 25 }, dst: { one: 7, start: 27 } },
    tcp: { src: { one: 8, start: 29 }, dst: { one: 9, start: 31 } } };
  // The ACE Tuple slot (1 to 11) the switch itself puts each match in, read
  // from switch-made rows on .253 and .254. TCP and UDP: 1 protocol, 2 source,
  // 3 source port or range start, 4 destination, 5 destination port or range
  // start, 6 source range end, 7 destination range end, 8 TCP flags. ICMP has
  // no ports, so its destination moves up: 3 destination, 4 type, 5 code.
  // A MAC rule: 1 source, 2 destination, 3 VLAN.
  const ACE_SLOT = {
    mac: { src: 1, dst: 2, vlan: 3 },
    l4: { proto: 1, src: 2, srcPort: 3, dst: 4, dstPort: 5, srcEnd: 6, dstEnd: 7, flags: 8 },
    icmp: { proto: 1, src: 2, dst: 3, icmpType: 4, icmpCode: 5 },
    ip: { proto: 1, src: 2, dst: 4 }
  };
  // ACE action enum (rlQosAceTidxAction / AceActionType), verified from the MIB.
  const ACE_ACTION = { 1: 'permit', 2: 'deny', 3: 'deny-shutdown', 4: 'deny-log', 5: 'permit-log' };
  // ACE type enum (AceObjectType).
  const ACE_TYPE = { 1: 'ip', 2: 'ip-tcp', 3: 'ip-udp', 4: 'ip-offset', 5: 'mac', 6: 'mac-offset', 7: 'ip-icmp', 8: 'ip-igmp',
    9: 'ipv6', 10: 'ipv6-tcp', 11: 'ipv6-udp', 12: 'ipv6-offset', 13: 'ipv6-icmp' };
  // ClassTupleType -> field name.
  const TUPLE_TYPE = { 1: 'protocol', 2: 'ip-src', 3: 'ip-dest', 4: 'dscp', 5: 'ip-prec',
    6: 'udp-src', 7: 'udp-dst', 8: 'tcp-src', 9: 'tcp-dst', 10: 'mac-src', 11: 'mac-dest',
    12: 'vlan', 13: 'in-port', 14: 'out-port', 17: 'ethertype', 18: 'tcp-flags',
    19: 'icmp-type', 20: 'icmp-code', 21: 'igmp-type', 22: 'inner-vlan', 23: 'ipv6-src', 24: 'ipv6-dest', 33: 'ipv6-flow-label' };

  // Build a lookup of tuple index -> { type, v1 (hex), n1 (Value1 as a number), v2 (hex) }.
  function buildTupleMap(tupleRows) {
    const m = new Map();
    for (const r of tupleRows) {
      const ix = String(r.index);
      if (!m.has(ix)) m.set(ix, {});
      const t = m.get(ix);
      const col = r.column || '';
      if (/TupleType$/.test(col)) t.type = parseInt(aclNum(r), 10);
      else if (/TupleValue1$/.test(col)) { t.v1 = aclHex(r); t.n1 = parseInt(aclNum(r), 10); }
      else if (/TupleValue2$/.test(col)) t.v2 = aclHex(r);
    }
    return m;
  }
  // Numeric value from a cell (strip "(n)" display formatting).
  // The raw number wins: the display of a big INTEGER can carry a thousands
  // separator ("8,000"), which once read as port 8.
  function aclNum(cell) {
    if (cell && typeof cell.value === 'number') return String(cell.value);
    const s = String(dvc(cell)).replace(/(\d),(?=\d{3}\b)/g, '$1');
    const m = s.match(/\((\d+)\)/) || s.match(/^(\d+)/);
    return m ? m[1] : s;
  }
  // Raw hex bytes from a cell's value/display.
  function aclHex(cell) {
    const s = String(cell && (cell.display !== undefined ? cell.display : cell.value) || '');
    const hex = s.replace(/0x|\s|\(hex\)|:/gi, '');
    return /^[0-9a-f]*$/i.test(hex) ? hex.toLowerCase() : '';
  }
  // How many mask bits a wildcard (hex, 1 = don't care) leaves cared about:
  // the prefix length of a value||wildcard address tuple.
  function wildcardPrefix(hex) {
    let n = 0;
    for (let i = 0; i < hex.length; i += 2) { let b = (~parseInt(hex.substr(i, 2), 16)) & 0xff; while (b) { n += b & 1; b >>= 1; } }
    return n;
  }
  // The 6-byte wildcard (hex) that ignores all but the first pref bits.
  function macWildcard(pref) {
    let out = '';
    for (let byte = 0; byte < 6; byte++) out += ((0xff >> Math.max(0, Math.min(8, pref - byte * 8))) & 0xff).toString(16).padStart(2, '0');
    return out;
  }
  // "00:11:22:33:44:55" (or with - or no separators) -> 12 hex digits, or null.
  function macToHex(text) {
    const h = String(text || '').trim().toLowerCase().replace(/[:.\-]/g, '');
    return /^[0-9a-f]{12}$/.test(h) ? h : null;
  }
  // "2001:db8::1" -> 32 hex digits, or null.
  function ipv6ToHex(text) {
    const s = String(text || '').trim().toLowerCase();
    if (!/^[0-9a-f:]+$/.test(s) || s.indexOf(':') < 0) return null;
    const halves = s.split('::');
    if (halves.length > 2) return null;
    const part = (x) => (x ? x.split(':') : []);
    const head = part(halves[0]), tail = halves.length === 2 ? part(halves[1]) : [];
    const fill = 8 - head.length - tail.length;
    if (halves.length === 2 ? fill < 1 : fill !== 0) return null;
    const groups = head.concat(new Array(halves.length === 2 ? fill : 0).fill('0'), tail);
    if (groups.some((g) => !/^[0-9a-f]{1,4}$/.test(g))) return null;
    return groups.map((g) => g.padStart(4, '0')).join('');
  }
  // 32 hex digits -> the short form ("2001:db8::"), longest zero run folded.
  function hexToIpv6(hex) {
    const g = [];
    for (let i = 0; i < 32; i += 4) g.push(parseInt(hex.substr(i, 4), 16).toString(16));
    let best = -1, len = 1;
    for (let i = 0; i < 8;) {
      if (g[i] !== '0') { i++; continue; }
      let j = i; while (j < 8 && g[j] === '0') j++;
      if (j - i > len) { best = i; len = j - i; }
      i = j;
    }
    if (best < 0) return g.join(':');
    return g.slice(0, best).join(':') + '::' + g.slice(best + len).join(':');
  }
  // Decode a tuple to { field, text, ... }: the rule field it fills and how
  // the table shows it.
  function decodeTuple(t) {
    if (!t || t.type === undefined) return null;
    const field = TUPLE_TYPE[t.type] || ('type' + t.type);
    const hex = t.v2 || t.v1 || '';
    // ip-src/ip-dest: 8 bytes = 4 value + 4 wildcard-mask.
    if ((t.type === 2 || t.type === 3) && hex.length >= 8) {
      const ip = [0, 2, 4, 6].map((i) => parseInt(hex.substr(i, 2), 16)).join('.');
      const pref = hex.length >= 16 ? wildcardPrefix(hex.substr(8, 8)) : 32;
      return { field: t.type === 2 ? 'src' : 'dst', text: ip + '/' + pref };
    }
    // ipv6-src/ipv6-dest: 32 bytes = 16 value + 16 wildcard-mask (2001:db8::/32
    // reads 20010db8 0000... then 00000000 ffff...).
    if ((t.type === 23 || t.type === 24) && hex.length >= 32) {
      const pref = hex.length >= 64 ? wildcardPrefix(hex.substr(32, 32)) : 128;
      return { field: t.type === 23 ? 'src' : 'dst', text: hexToIpv6(hex.substr(0, 32)) + '/' + pref };
    }
    // mac-src/mac-dest: 12 bytes = 6 value + 6 wildcard-mask. A wildcard that
    // ignores only the last bits reads as a prefix (00:11:22:00:00:00/24 is
    // one maker); any other wildcard is shown as it is.
    if ((t.type === 10 || t.type === 11) && hex.length >= 12) {
      const mac = hex.substr(0, 12).match(/../g).join(':');
      const wild = hex.length >= 24 ? hex.substr(12, 12) : '000000000000';
      const pref = wildcardPrefix(wild);
      const field = t.type === 10 ? 'src' : 'dst';
      if (macWildcard(pref) === wild) return { field, text: mac + '/' + pref };
      return { field, text: mac + ' ignoring ' + wild.match(/../g).join(':'), oddMask: true };
    }
    // vlan: the VLAN number in Value1.
    if (t.type === 12 && Number.isFinite(t.n1)) return { field: 'vlan', text: 'vlan ' + t.n1, n: t.n1 };
    // protocol: 1 byte value + 1 byte mask.
    if (t.type === 1 && hex.length >= 2) {
      const p = parseInt(hex.substr(0, 2), 16);
      const names = { 1: 'icmp', 6: 'tcp', 17: 'udp', 58: 'icmp' };
      return { field: 'proto', text: names[p] || ('protocol ' + p), num: p };
    }
    // L4 ports: the port is rlQosTupleValue1 (an INTEGER); Value2 reads 0000
    // on every switch-made row. A range is a start tuple and an end tuple
    // (types 25 to 32), each with its port in Value1.
    if (t.type >= 6 && t.type <= 9 && Number.isFinite(t.n1)) {
      return { field: PORT_FIELD[t.type], text: PORT_WORD[t.type] + ' ' + t.n1, port: t.n1 };
    }
    if (t.type >= 25 && t.type <= 32 && Number.isFinite(t.n1)) {
      const r = PORT_RANGE[t.type];
      return { field: r.field, text: r.word + ' ' + t.n1, port: t.n1, end: r.end };
    }
    // ICMP type and code: the number is Value1, Value2 is empty.
    if ((t.type === 19 || t.type === 20) && Number.isFinite(t.n1)) {
      return { field: t.type === 19 ? 'icmpType' : 'icmpCode', text: (t.type === 19 ? 'icmp type ' : 'icmp code ') + t.n1, n: t.n1 };
    }
    // tcp-flags: byte1 = value (1=Set, 0=Unset), byte2 = don't-care mask
    // (1=don't care, 0=care). Verified against the switch UI: pnp "11 00" =
    // ACK+FIN Set, the rest Unset, all cared about. Show only the flags we care
    // about, with a + for Set and - for Unset.
    if (t.type === 18 && hex.length >= 2) {
      const val = parseInt(hex.substr(0, 2), 16);
      const dc = hex.length >= 4 ? parseInt(hex.substr(2, 2), 16) : 0;
      const parts = [];
      for (const [name, bit] of TCP_FLAGS) { if (!(dc & bit)) parts.push((val & bit ? '+' : '-') + name); }
      return { field: 'flags', text: parts.length ? ('flags ' + parts.join(' ')) : 'flags any' };
    }
    // Fallback: show the field name and raw hex.
    return { field: field, text: field + '=' + hex };
  }
  // Port tuple types -> the rule field they fill and how the table names them.
  const PORT_FIELD = { 6: 'srcPort', 7: 'dstPort', 8: 'srcPort', 9: 'dstPort' };
  const PORT_WORD = { 6: 'source port', 7: 'destination port', 8: 'source port', 9: 'destination port' };
  const PORT_RANGE = {
    25: { field: 'srcPort', end: false, word: 'source ports from' }, 26: { field: 'srcPort', end: true, word: 'source ports to' },
    27: { field: 'dstPort', end: false, word: 'destination ports from' }, 28: { field: 'dstPort', end: true, word: 'destination ports to' },
    29: { field: 'srcPort', end: false, word: 'source ports from' }, 30: { field: 'srcPort', end: true, word: 'source ports to' },
    31: { field: 'dstPort', end: false, word: 'destination ports from' }, 32: { field: 'dstPort', end: true, word: 'destination ports to' }
  };
  // TCP flag bit layout and helpers.
  const TCP_FLAGS = [['urg', 0x20], ['ack', 0x10], ['psh', 0x08], ['rst', 0x04], ['syn', 0x02], ['fin', 0x01]];

  // "192.168.1.0/24" or "2001:db8::/32" -> { any:false, ip, pref } for pre-filling.
  function parseCidr(text) {
    const m = String(text).match(/^([0-9a-f.:]+)\/(\d+)$/i);
    if (!m) return { any: true };
    return { any: false, ip: m[1], pref: parseInt(m[2], 10) };
  }
  // A tcp-flags tuple -> { <flag>: 'set'|'unset'|'care' } per-flag state, from
  // byte1 (value) and byte2 (don't-care mask).
  function parseFlagsTuple(t) {
    const hex = (t && (t.v2 || t.v1)) || '';
    if (hex.length < 2) return null;
    const val = parseInt(hex.substr(0, 2), 16);
    const dc = hex.length >= 4 ? parseInt(hex.substr(2, 2), 16) : 0;
    const out = {};
    for (const [name, bit] of TCP_FLAGS) {
      out[name] = (dc & bit) ? 'care' : (val & bit ? 'set' : 'unset');
    }
    return out;   // e.g. { ack:'set', fin:'set', urg:'unset', ... }
  }

  // ---- The joined model ----
  // Join the three raw tables into ACLs -> rules, the one place the panel, the
  // write paths and the binding editor read them from. Only ACLs with a name
  // row are listed (as before); an ACE whose ACL is unknown is ignored. Each
  // rule keeps its tuples in slot order (tuples) and by slot (bySlot), so an
  // edit that fails can put the rule back exactly as the switch had it.
  function aclModel(h) {
    h = h || {};
    const byIdx = new Map();
    for (const r of (h.aclNames || [])) {
      if (!/QosAclName$/.test(r.column || '')) continue;
      const idx = String(r.index);
      byIdx.set(idx, { idx, name: String(dvc(r)), type: null, family: 'ip', bound: false, origin: null, aces: new Map() });
    }
    for (const r of (h.aclNames || [])) {
      const acl = byIdx.get(String(r.index));
      if (!acl) continue;
      const col = r.column || '';
      if (/QosAclType$/.test(col)) { acl.type = parseInt(aclNum(r), 10); acl.family = ACL_FAMILY[acl.type] || 'ip'; }
      else if (/QosAclIsBoundToInterface$/.test(col)) acl.bound = parseInt(aclNum(r), 10) === 1;   // TruthValue true(1)
      else if (/QosAclOriginType$/.test(col)) acl.origin = parseInt(aclNum(r), 10);              // static 1 / dynamic 2 / system 3
    }
    for (const r of (h.aclAces || [])) {
      const parts = String(r.index).split('.');
      if (parts.length < 2) continue;
      const acl = byIdx.get(parts[0]);
      if (!acl) continue;
      const aceIdx = parts.slice(1).join('.');
      if (!acl.aces.has(aceIdx)) acl.aces.set(aceIdx, { idx: aceIdx, tuples: [], bySlot: {} });
      const ace = acl.aces.get(aceIdx);
      const col = r.column || '';
      const slot = col.match(/TidxTuple(\d+)$/);
      if (/TidxAction$/.test(col)) ace.action = parseInt(aclNum(r), 10);
      else if (/TidxType$/.test(col)) ace.type = parseInt(aclNum(r), 10);
      else if (slot) {
        const ptr = parseInt(dvc(r), 10);
        if (ptr > 0) { ace.tuples.push(String(ptr)); ace.bySlot[slot[1]] = String(ptr); }
      }
    }
    const acls = Array.from(byIdx.values());
    for (const a of acls) a.aceList = Array.from(a.aces.values()).sort((x, y) => parseInt(x.idx, 10) - parseInt(y.idx, 10));
    return { acls, byIdx, tupleMap: buildTupleMap(h.aclTuples || []) };
  }

  // One rule as the table shows it, plus the values that pre-fill its editor.
  // init: { family, action, proto ('any' 'num' 'tcp' 'udp' 'icmp'), protoNum,
  // src, dst ({ any, ip, pref }), srcPort, dstPort ({ from, to }), icmpType,
  // icmpCode, flags }. Anything the form cannot make again goes in
  // unsupported, so the editor shows the rule instead of dropping that part.
  function aclRuleView(ace, tupleMap) {
    const action = ACE_ACTION[ace.action] || (ace.action ? ('action ' + ace.action) : '?');
    const kind = ACE_KIND[ace.type];
    const family = kind ? kind[0] : 'ip';
    const p = kind ? kind[1] : 'any';
    const unsupported = [];
    if (!kind) unsupported.push(ACE_TYPE[ace.type] || ('type ' + ace.type));
    if ([1, 2, 4, 5].indexOf(ace.action) === -1) unsupported.push(action);
    const init = { family, action: ace.action, proto: p, src: { any: true }, dst: { any: true } };
    let proto = !kind ? (ACE_TYPE[ace.type] || ('type ' + ace.type)) : (p === 'any' ? (family === 'ipv6' ? 'ipv6' : (family === 'mac' ? 'any' : 'ip')) : p);
    let src = 'any', dst = 'any', flagsText = null, vlanText = null;
    const ports = { src: {}, dst: {} }, other = [];
    const l4 = p === 'tcp' || p === 'udp';
    for (const tp of ace.tuples) {
      const t = tupleMap.get(tp);
      const dec = decodeTuple(t);
      if (!dec) { unsupported.push('tuple ' + tp); continue; }
      if (dec.field === 'src') { src = dec.text; init.src = parseCidr(dec.text); if (dec.oddMask) unsupported.push('a source mask that is not a prefix'); }
      else if (dec.field === 'dst') { dst = dec.text; init.dst = parseCidr(dec.text); if (dec.oddMask) unsupported.push('a destination mask that is not a prefix'); }
      else if (dec.field === 'vlan') { init.vlan = dec.n; vlanText = dec.text; if (family !== 'mac') unsupported.push(dec.text); }
      else if (dec.field === 'proto') {
        // A TCP, UDP or ICMP rule carries its own protocol; a plain rule may
        // name any protocol number.
        if (kind && p === 'any' && family !== 'mac') { init.proto = 'num'; init.protoNum = dec.num; proto = 'protocol ' + dec.num; }
        else if (!kind || dec.num !== protoNumber(family, p)) { other.push(dec.text); unsupported.push(dec.text); }
      }
      else if (dec.field === 'srcPort' || dec.field === 'dstPort') {
        const side = ports[dec.field === 'srcPort' ? 'src' : 'dst'];
        side[dec.end ? 'to' : 'from'] = dec.port;
        if (!l4) unsupported.push(dec.text);
      }
      else if (dec.field === 'icmpType' || dec.field === 'icmpCode') {
        init[dec.field] = dec.n;
        if (p !== 'icmp') unsupported.push(dec.text);
      }
      else if (dec.field === 'flags') { flagsText = dec.text; init.flags = parseFlagsTuple(t); if (p !== 'tcp') unsupported.push(dec.text); }
      else { other.push(dec.text); unsupported.push(dec.text); }
    }
    const extra = [];
    for (const side of ['src', 'dst']) {
      const r = ports[side];
      if (r.from == null && r.to == null) continue;
      const word = side === 'src' ? 'source port' : 'destination port';
      if (r.from == null) { extra.push(word + ' range end ' + r.to); unsupported.push(word + ' range with no start'); continue; }
      const to = r.to != null ? r.to : r.from;
      init[side + 'Port'] = { from: r.from, to };
      extra.push(to !== r.from ? word + 's ' + r.from + '-' + to : word + ' ' + r.from);
    }
    if (init.icmpType != null) extra.push('icmp type ' + init.icmpType + (init.icmpCode != null ? ' code ' + init.icmpCode : ''));
    else if (init.icmpCode != null) { extra.push('icmp code ' + init.icmpCode); unsupported.push('an ICMP code with no type'); }
    if (flagsText) extra.push(flagsText);
    if (vlanText) extra.push(vlanText);
    extra.push(...other);
    return { action, isPermit: /permit/.test(action), proto, src, dst, extra, init, unsupported };
  }

  // The panel (standard B2): scaffolding on a full paint only, keyed tables
  // through mountInto on every pass, and each ACL's rule count kept in a stable
  // note refreshed in place so it stays right after a write.
  function paintAclPanel(s, body, p) {
    if (!s._ktReconcile) clear(body);
    if (!s.target) { if (!s._ktReconcile) body.appendChild(el('div', 'card-sub', 'Add SNMP credentials for this switch first.')); return; }
    if (!s._ktReconcile) ensureAclLoaded(s);
    if (!aclLoaded(s)) {
      if (!s._ktReconcile) { body.appendChild(el('div', 'card-sub', 'Waiting for data\u2026')); p._aclWaiting = true; }
      return;
    }
    // The first load arrived while "Waiting for data" was showing: that is a
    // structural change (no tables existed yet), so ask for a full repaint.
    if (s._ktReconcile && p._aclWaiting) { s._ktStructural = true; return; }
    p._aclWaiting = false;

    const section = (title, note, addLabel, onAdd) => {
      if (s._ktReconcile) return null;
      const st = el('div', 'section-title', title);
      const noteEl = el('span', 'st-note', note || '');
      st.appendChild(noteEl);
      body.appendChild(st);
      if (addLabel && s.target) body.appendChild(addControl(addLabel, onAdd));
      return noteEl;
    };
    const emptyNote = (msg) => { if (!s._ktReconcile) body.appendChild(el('div', 'card-sub', msg)); };

    const model = aclModel(s.health);
    section('Access lists', model.acls.length ? model.acls.length + ' list(s)' : '', 'New ACL', () => openAclRuleForm(s, { newAcl: true }));
    if (!model.acls.length) { emptyNote('No access lists configured.'); return; }

    if (!s._ktReconcile) { p._aclNotes = {}; p._aclDel = {}; }
    const cols = ['#', 'Action', 'Protocol', 'Source', 'Destination', 'Extra', ''];
    for (const acl of model.acls) {
      const noteEl = section(ACL_FAMILY_WORD[acl.family] + ' ACL \u00b7 ' + acl.name, '', 'Add rule', () => openAclRuleForm(s, { aclIdx: acl.idx, aclName: acl.name, family: acl.family }));
      if (noteEl) {
        p._aclNotes[acl.idx] = noteEl;
        // The list's own Delete sits beside its "+ Add rule": a stable slot,
        // refreshed in place (B2) because its bound/unbound lock can change.
        const slot = el('span', 'acl-list-acts');
        body.lastChild.appendChild(slot);
        p._aclDel[acl.idx] = { slot, state: null };
      }
      const note = p._aclNotes && p._aclNotes[acl.idx];
      if (note) note.textContent = acl.aceList.length + ' rule(s)' + (acl.bound ? ' \u00b7 bound to an interface' : '');
      const delSlot = p._aclDel && p._aclDel[acl.idx];
      if (delSlot) paintAclDelete(s, delSlot, acl);
      if (!acl.aceList.length) { emptyNote('No rules.'); continue; }
      const rows = acl.aceList.map((ace) => {
        const v = aclRuleView(ace, model.tupleMap);
        const del = actGroup([actBtnConfirm('Delete', (e) => {
          runButtonAction(e.currentTarget, {
            failLabel: 'Delete rule',
            run: () => deleteQosAce(s, acl.idx, ace.idx),
            ok: (r) => r && r.ok,
            error: (r) => (r && r.error) || 'the switch rejected it',
            onApplied: () => markConfigDirty(s),
            settle: () => aclRefresh(s)
          });
        }, 'danger', 'Delete rule ' + ace.idx)]);
        return { key: 'ace:' + acl.idx + '.' + ace.idx, cells: [
          { v: ace.idx, click: { open: () => openAclRuleEditor(s, acl.idx, ace.idx) } },
          { cellNode: el('span', 'pill ' + (v.isPermit ? 'good' : 'warn'), v.action), sig: 'a:' + v.action },
          { v: v.proto }, { v: v.src }, { v: v.dst }, { v: v.extra.join(', ') || '\u2014' },
          { cellNode: del, sig: 'del' } ] };
      });
      mountInto(body, s, p, 'acl:' + acl.idx, cols, rows);
    }
  }

  // ---- Interface / VLAN ACL binding (rlQosIfPolicyTable, base 88.13) ----
  // Indexed by { ifIndex, ifType } where ifType is port(2) or vlan(1).
  const QOS_IFPOL = {
    aclIn:   '1.3.6.1.4.1.9.6.1.101.88.13.1.14',   // rlQosIfAclIn  (ACL index, 0=none)
    aclOut:  '1.3.6.1.4.1.9.6.1.101.88.13.1.15',   // rlQosIfAclOut
    defIn:   '1.3.6.1.4.1.9.6.1.101.88.13.1.12',   // rlQosAclDefaultAction (ingress)
    defOut:  '1.3.6.1.4.1.9.6.1.101.88.13.1.22',   // rlQosAclDefaultActionOut
    v6In:    '1.3.6.1.4.1.9.6.1.101.88.13.1.20',   // rlQosIfIpv6AclIn  (IPv6 ACL index, 0=none)
    v6Out:   '1.3.6.1.4.1.9.6.1.101.88.13.1.21'    // rlQosIfIpv6AclOut
  };
  const IFTYPE_PORT = 2, IFTYPE_VLAN = 1;

  // Read the current binding for an interface (ifIndex + ifType). Returns
  // { inAcl, outAcl, defIn, defOut, v6In, v6Out } as numbers (ACL index /
  // action enum); v6In and v6Out are null where the switch has no such column.
  async function readIfAclBinding(s, ifIndex, ifType) {
    const suffix = ifIndex + '.' + ifType;
    const oids = [QOS_IFPOL.aclIn, QOS_IFPOL.aclOut, QOS_IFPOL.defIn, QOS_IFPOL.defOut, QOS_IFPOL.v6In, QOS_IFPOL.v6Out].map((o) => o + '.' + suffix);
    const results = await snmpGet(s, oids);
    const byOid = {};
    for (const r of results) { if (!r.error) byOid[String(r.oid).replace(/^\./, '')] = r.value; }
    const pick = (base) => { const k = Object.keys(byOid).find((o) => o.indexOf(base + '.') === 0); const n = k ? parseInt(byOid[k], 10) : NaN; return Number.isFinite(n) ? n : null; };
    return { inAcl: pick(QOS_IFPOL.aclIn), outAcl: pick(QOS_IFPOL.aclOut), defIn: pick(QOS_IFPOL.defIn), defOut: pick(QOS_IFPOL.defOut),
      v6In: pick(QOS_IFPOL.v6In), v6Out: pick(QOS_IFPOL.v6Out) };
  }

  // Build the ACL-binding editor for an interface. ifType port(2) or vlan(1).
  // For VLANs, pass opts.noDirection to show a single (default-action-only) set.
  // The list of ACLs comes from the panel's own tables (loaded first if the
  // panel has not been opened this visit), not a separate walk.
  async function buildIfAclBinding(s, detail, pane, opts) {
    opts = opts || {};
    const ifType = opts.ifType || IFTYPE_PORT;
    const ifIndex = detail.ifIndex;
    pane.appendChild(el('div', 'card-sub', 'Loading ACL binding\u2026'));
    try {
      if (!aclLoaded(s)) await aclRefresh(s);
      const bind = await readIfAclBinding(s, ifIndex, ifType);
      clear(pane);
      renderIfAclBinding(s, pane, ifIndex, ifType, aclModel(s.health).acls, bind, opts);
    } catch (e) { clear(pane); pane.appendChild(el('div', 'sw-err', 'Could not read ACL binding: ' + e.message)); }
  }

  function renderIfAclBinding(s, pane, ifIndex, ifType, acls, bind, opts) {
    // The in/out columns hold an IPv4 or MAC list, and IPv6 lists have their
    // own columns, so each select offers its own kind of list, plus whatever
    // is bound now if it is something else.
    const optionsFor = (families, current) => {
      const out = [{ label: '(none)', value: '0' }];
      for (const a of acls) {
        const now = current.some((c) => String(a.idx) === String(c));
        if (families.indexOf(a.family) !== -1 || now) out.push({ label: a.name + (a.family === 'mac' ? ' (MAC)' : ''), value: String(a.idx) });
      }
      return out;
    };
    const aclOptions = optionsFor(['ip', 'mac'], [bind.inAcl, bind.outAcl]);
    const v6Options = optionsFor(['ipv6'], [bind.v6In, bind.v6Out]);
    const defOptions = [{ label: 'Deny Any', value: '1' }, { label: 'Permit Any (forward)', value: '2' }];

    const form = el('div', 'snmp-form acl-form');
    const mkDir = (titleWord, aclOid, defOid, curAcl, curDef, v6Oid, curV6) => {
      const sec = formSection(titleWord);
      const aclSel = selectInput(aclOptions, curAcl != null ? String(curAcl) : '0');
      sec.body.appendChild(field(opts.noDirection ? 'IPv4 or MAC ACL' : (titleWord + ' IPv4 or MAC ACL'), aclSel));
      // The IPv6 select only where the switch answered for that column.
      let v6Sel = null;
      if (curV6 != null) {
        v6Sel = selectInput(v6Options, String(curV6));
        sec.body.appendChild(field(opts.noDirection ? 'IPv6 ACL' : (titleWord + ' IPv6 ACL'), v6Sel));
      }
      const defSel = selectInput(defOptions, curDef === 2 ? '2' : '1');
      sec.body.appendChild(field('Default action', defSel));
      form.appendChild(sec.sec);
      return { aclSel, defSel, aclOid, defOid, v6Sel, v6Oid };
    };

    const controls = [];
    if (opts.noDirection) {
      // VLAN: a single binding (no in/out direction), default action only.
      controls.push(mkDir('Access list', QOS_IFPOL.aclIn, QOS_IFPOL.defIn, bind.inAcl, bind.defIn, QOS_IFPOL.v6In, bind.v6In));
    } else {
      controls.push(mkDir('Input', QOS_IFPOL.aclIn, QOS_IFPOL.defIn, bind.inAcl, bind.defIn, QOS_IFPOL.v6In, bind.v6In));
      controls.push(mkDir('Output', QOS_IFPOL.aclOut, QOS_IFPOL.defOut, bind.outAcl, bind.defOut, QOS_IFPOL.v6Out, bind.v6Out));
    }

    // Binding an ACL can stop traffic on the interface, so this keeps its
    // two-tap confirm (standard B8: confirm when the click is drastic).
    const { actions, apply, msg } = applyActions('Apply binding');
    withConfirm(apply, (ev) => {
      const suffix = ifIndex + '.' + ifType;
      const vbs = [];
      const changedCtls = [];
      for (const c of controls) {
        vbs.push({ oid: c.aclOid + '.' + suffix, type: 'Integer', value: parseInt(c.aclSel.value, 10) });
        vbs.push({ oid: c.defOid + '.' + suffix, type: 'Integer', value: parseInt(c.defSel.value, 10) });
        changedCtls.push(c.aclSel, c.defSel);
        if (c.v6Sel) { vbs.push({ oid: c.v6Oid + '.' + suffix, type: 'Integer', value: parseInt(c.v6Sel.value, 10) }); changedCtls.push(c.v6Sel); }
      }
      clear(msg);
      runButtonAction(ev.currentTarget, {
        failLabel: 'Apply binding',
        run: () => snmpSet(s, vbs).then(() => ({ ok: true }), (e) => ({ ok: false, error: e.message })),
        ok: (r) => r && r.ok,
        error: (r) => {
          msg.appendChild(el('div', 'sw-err', 'Could not apply binding \u2014 ' + ((r && r.error) || 'failed')));
          // On .253 a MAC list was refused (WrongValue) when it replaced an
          // IPv4 list in the same step while an IPv6 list was bound, and taken
          // on the port with nothing else bound.
          const macChosen = controls.some((c) => { const a = acls.find((x) => String(x.idx) === c.aclSel.value); return a && a.family === 'mac'; });
          if (macChosen) msg.appendChild(el('div', 'card-sub', 'The switch can refuse a MAC list in place of another list, or next to an IPv6 list. Set both lists to (none) and apply, then choose the MAC list on its own.'));
          return (r && r.error) || 'failed';
        },
        onApplied: () => markConfigDirty(s, changedCtls),
        // Read the binding back and re-read the ACL tables, so the form shows
        // what the switch now holds before the spinner turns to Done.
        settle: () => Promise.all([
          readIfAclBinding(s, ifIndex, ifType).then((b) => {
            const vals = opts.noDirection ? [[b.inAcl, b.defIn, b.v6In]] : [[b.inAcl, b.defIn, b.v6In], [b.outAcl, b.defOut, b.v6Out]];
            vals.forEach(([a, d, v6], i) => {
              const c = controls[i];
              if (!c) return;
              c.aclSel.value = String(a || 0); c.defSel.value = d === 2 ? '2' : '1';
              if (c.v6Sel) c.v6Sel.value = String(v6 || 0);
            });
          }).catch(() => {}),
          aclRefresh(s)
        ])
      });
    });
    form.appendChild(actions); form.appendChild(msg);
    pane.appendChild(form);
  }

  // ---- ACL writes (QoS tuple model) ----
  // An ACE is a row in rlQosAceTidxTable that points (via Tuple columns) at
  // value rows in rlQosTupleTable, all under an ACL in rlQosAclTable. So
  // creating a rule is:
  //   1. ensure the ACL exists (create it if the name is new),
  //   2. create one tuple row per match field (type + value||mask + createAndGo),
  //   3. create the ACE row (action, type, the tuple pointers, createAndGo).
  // Every step is a single atomic SET and its result is checked, so a rejection
  // is attributed to the exact step. Indices are chosen as max-existing + 1
  // because this firmware exposes no free-index scalar for these tables.

  // Highest index currently in a walked set of rows (by their first index arc).
  function maxIndex(rows) {
    let m = 0;
    for (const r of rows || []) {
      const first = parseInt(String(r.index).split('.')[0], 10);
      if (Number.isFinite(first) && first > m) m = first;
    }
    return m;
  }

  // Tuple rows are separate from the ACEs that point at them, so removing an
  // ACE leaves its tuples behind unless they are removed too. Only tuples that
  // no remaining ACE points at are removed (a tuple may be shared).
  function unusedTuples(model, tuples, goneKeys) {
    const used = new Set();
    for (const a of model.acls) {
      for (const ace of a.aceList) {
        if (goneKeys.has(a.idx + '.' + ace.idx)) continue;
        for (const t of ace.tuples) used.add(t);
      }
    }
    return Array.from(new Set(tuples)).filter((t) => !used.has(t));
  }
  // Best effort: a tuple that will not go is left, and logged. The rule change
  // itself has already succeeded, so this never fails the action.
  async function dropTuples(s, tuples) {
    for (const t of tuples) {
      let res;
      try { res = interpretSet(await rowStatusDelete(s, QOS_ACL.tupStatus + '.' + t)); } catch (e) { res = { ok: false, error: e.message }; }
      if (!res.ok) appLog('warn', 'ACL tuple not removed', { host: s.host, tuple: t, error: res.error });
    }
  }

  // Delete one ACE with the shared rowStatusDelete (destroy, falling back to
  // notInService -> destroy), then the tuples only it used. Returns { ok, error }.
  async function deleteQosAce(s, aclIdx, aceIdx) {
    const model = aclModel(s.health);
    const acl = model.byIdx.get(String(aclIdx));
    const ace = acl && acl.aces.get(String(aceIdx));
    let res;
    try { res = interpretSet(await rowStatusDelete(s, QOS_ACL.aceStatus + '.' + aclIdx + '.' + aceIdx)); }
    catch (e) { return { ok: false, error: e.message }; }
    if (res.ok && ace) await dropTuples(s, unusedTuples(model, ace.tuples, new Set([aclIdx + '.' + aceIdx])));
    return res;
  }

  // Why a list cannot be deleted from here, or '' when it can.
  function aclDeleteLock(acl) {
    if (acl.bound) return 'this list is bound to a port or VLAN. Unbind it on that port\u2019s or VLAN\u2019s ACL tab first, so deleting it cannot change what traffic passes.';
    if (acl.origin != null && acl.origin !== 1) return 'this list was created by the switch (' + (acl.origin === 2 ? 'dynamic' : 'system') + '), not configured by hand, so it is not deleted from here.';
    return '';
  }
  // Delete a whole access list: its rules first, then the tuples nothing else
  // uses, then the list itself. A bound or switch-created list is locked in the
  // panel and refused here too.
  async function deleteQosAcl(s, aclIdx) {
    const model = aclModel(s.health);
    const acl = model.byIdx.get(String(aclIdx));
    if (!acl) return { ok: false, error: 'the list is no longer on the switch' };
    const lock = aclDeleteLock(acl);
    if (lock) return { ok: false, error: lock };
    const gone = new Set(acl.aceList.map((a) => acl.idx + '.' + a.idx));
    const tuples = [];
    for (const ace of acl.aceList) {
      let res;
      try { res = interpretSet(await rowStatusDelete(s, QOS_ACL.aceStatus + '.' + acl.idx + '.' + ace.idx)); }
      catch (e) { res = { ok: false, error: e.message }; }
      if (!res.ok) return { ok: false, error: 'removing rule ' + ace.idx + ': ' + res.error };
      tuples.push(...ace.tuples);
    }
    await dropTuples(s, unusedTuples(model, tuples, gone));
    let res;
    try { res = interpretSet(await rowStatusDelete(s, QOS_ACL.aclStatus + '.' + acl.idx)); }
    catch (e) { res = { ok: false, error: e.message }; }
    return res.ok ? res : { ok: false, error: 'removing the list: ' + res.error };
  }
  // The list's Delete control: a two-tap Delete, or a lock with its reason.
  // Rebuilt only when its state changes, so a reconcile does not disarm it.
  function paintAclDelete(s, slotRec, acl) {
    const lock = aclDeleteLock(acl);
    const state = lock ? 'lock:' + lock : 'del';
    if (slotRec.state === state) return;
    slotRec.state = state;
    clear(slotRec.slot);
    if (lock) {
      const locked = el('span', 'card-sub', '\uD83D\uDD12 Delete ACL');
      locked.title = 'Locked: ' + lock;
      slotRec.slot.appendChild(locked);
      return;
    }
    slotRec.slot.appendChild(actBtnConfirm('Delete ACL', (e) => {
      runButtonAction(e.currentTarget, {
        failLabel: 'Delete ACL',
        run: () => deleteQosAcl(s, acl.idx),
        ok: (r) => r && r.ok,
        error: (r) => (r && r.error) || 'the switch rejected it',
        onApplied: () => markConfigDirty(s),
        settle: () => aclRefresh(s)
      });
    }, 'danger', 'Delete ACL ' + acl.name + ' and all its rules'));
  }

  // Build the value||mask octet string for an ip-src/ip-dest tuple from a
  // dotted IP and prefix length: 4 value bytes + 4 wildcard-mask bytes.
  function ipTupleHex(ip, pref) {
    const v = ipv4ToHex(ip);
    if (!v) return null;
    const p = Math.max(0, Math.min(32, parseInt(pref, 10) || 32));
    const netMask = p === 0 ? 0 : (0xffffffff << (32 - p)) >>> 0;
    const wild = (~netMask) >>> 0;
    const wildHex = wild.toString(16).padStart(8, '0');
    return v + wildHex;
  }
  // The same for an ipv6-src/ipv6-dest tuple: 16 value bytes + 16 wildcard
  // bytes (1 bits are don't care), as the switch made 2001:db8::/32.
  function ipv6TupleHex(ip, pref) {
    const v = ipv6ToHex(ip);
    if (!v) return null;
    const n = parseInt(pref, 10);
    const p = Number.isFinite(n) ? Math.max(0, Math.min(128, n)) : 128;
    let wild = '';
    for (let byte = 0; byte < 16; byte++) {
      const cared = Math.max(0, Math.min(8, p - byte * 8));
      wild += ((0xff >> cared) & 0xff).toString(16).padStart(2, '0');
    }
    return v + wild;
  }
  // The same for a mac-src/mac-dest tuple: 6 value bytes + 6 wildcard bytes,
  // as the switch made 00:11:22:33:44:55 00:00:00:ff:ff:ff.
  function macTupleHex(mac, pref) {
    const v = macToHex(mac);
    if (!v) return null;
    const n = parseInt(pref, 10);
    return v + macWildcard(Number.isFinite(n) ? Math.max(0, Math.min(48, n)) : 48);
  }
  // protocol tuple value||mask: 1 value byte + 1 exact mask (ff).
  function protoTupleHex(proto) { return proto.toString(16).padStart(2, '0') + 'ff'; }

  // Create a rule. cfg: { aclName, family ('ip' 'ipv6'), action, proto ('any'
  // 'num' 'tcp' 'udp' 'icmp'), protoNum, src, dst ({ any, ip, pref }), srcPort,
  // dstPort ({ from, to }), icmpType, icmpCode, tcpFlags ({ val, dc }) }.
  // Throws with the failing step on error.
  // cfg.aclIdx (optional) names the ACL directly; `at` (optional) places the
  // ACE at that index instead of the next free one (a rule edit keeps its place
  // in the list). Whatever this call created is removed again if a later step
  // fails, so a failed add leaves no stray tuples or empty new list behind.
  async function createQosAce(s, cfg, at) {
    const made = { tuples: [], acl: null };
    try { await createQosAceSteps(s, s.health || {}, cfg, at, made); }
    catch (e) {
      await dropTuples(s, made.tuples);
      if (made.acl) { try { await rowStatusDelete(s, QOS_ACL.aclStatus + '.' + made.acl); } catch (x) { /* the error below is the one that matters */ } }
      throw e;
    }
  }
  async function createQosAceSteps(s, h, cfg, at, made) {
    const family = cfg.family || 'ip';
    const p = cfg.proto || 'any';
    const aceType = ACE_TYPE_FOR[family] && ACE_TYPE_FOR[family][p];
    if (!aceType) throw new Error('a ' + ACL_FAMILY_WORD[family] + ' list cannot hold a ' + p + ' rule');
    const l4 = p === 'tcp' || p === 'udp';
    const slots = family === 'mac' ? ACE_SLOT.mac : (l4 ? ACE_SLOT.l4 : (p === 'icmp' ? ACE_SLOT.icmp : ACE_SLOT.ip));

    // 1. Resolve or create the ACL by name.
    let aclIdx = cfg.aclIdx != null ? String(cfg.aclIdx) : null;
    if (aclIdx === null) for (const a of aclModel(h).acls) { if (a.name === cfg.aclName) aclIdx = a.idx; }
    if (aclIdx === null) {
      aclIdx = String(maxIndex(h.aclNames) + 1);
      try {
        await snmpSet(s, [
          { oid: QOS_ACL.aclStatus + '.' + aclIdx, type: 'Integer', value: 4 },         // createAndGo
          { oid: QOS_ACL.name + '.' + aclIdx, type: 'OctetString', value: cfg.aclName },
          { oid: QOS_ACL.type + '.' + aclIdx, type: 'Integer', value: ACL_FAMILY_VAL[family] }
        ]);
      } catch (e) { throw new Error('creating ACL "' + cfg.aclName + '": ' + e.message); }
      made.acl = aclIdx;
    }

    // 2. Create the tuple rows for each requested match field, each in the
    //    ACE pointer slot the switch itself uses for it (ACE_SLOT).
    let nextTuple = maxIndex(h.aclTuples) + 1;
    const pointers = [];   // tuple indices this ACE will reference, by slot
    const addTuple = async (slot, typeVal, valueHex, value1) => {
      const tIdx = String(nextTuple++);
      const vbs = [
        { oid: QOS_ACL.tupStatus + '.' + tIdx, type: 'Integer', value: 4 },     // createAndGo
        { oid: QOS_ACL.tupType + '.' + tIdx, type: 'Integer', value: typeVal }
      ];
      if (value1 != null) vbs.push({ oid: QOS_ACL.tupVal1 + '.' + tIdx, type: 'Integer', value: value1 });
      vbs.push({ oid: QOS_ACL.tupVal2 + '.' + tIdx, type: 'OctetString', valueHex });
      try { await snmpSet(s, vbs); } catch (e) { throw new Error('creating tuple (type ' + typeVal + '): ' + e.message); }
      made.tuples.push(tIdx);
      pointers[slot - 1] = tIdx;
    };
    const protoNum = p === 'num' ? cfg.protoNum : protoNumber(family, p);
    if (protoNum != null) {
      if (!(Number.isInteger(protoNum) && protoNum >= 0 && protoNum <= 255)) throw new Error('the protocol number must be 0 to 255');
      await addTuple(slots.proto, TUPLE_TYPE_VAL.protocol, protoTupleHex(protoNum));
    }
    for (const side of ['src', 'dst']) {
      const a = cfg[side];
      if (!a || a.any) continue;
      const word = side === 'src' ? 'source' : 'destination';
      if (family === 'mac') {
        const hx = macTupleHex(a.ip, a.pref); if (!hx) throw new Error('bad ' + word + ' MAC address');
        await addTuple(slots[side], TUPLE_TYPE_VAL[side === 'src' ? 'mac-src' : 'mac-dest'], hx);
      } else if (family === 'ipv6') {
        const hx = ipv6TupleHex(a.ip, a.pref); if (!hx) throw new Error('bad ' + word + ' address');
        await addTuple(slots[side], TUPLE_TYPE_VAL[side === 'src' ? 'ipv6-src' : 'ipv6-dest'], hx);
      } else {
        const hx = ipTupleHex(a.ip, a.pref); if (!hx) throw new Error('bad ' + word + ' address');
        await addTuple(slots[side], TUPLE_TYPE_VAL[side === 'src' ? 'ip-src' : 'ip-dest'], hx);
      }
    }
    // VLAN, MAC rules only: the VLAN number in Value1, Value2 empty.
    if (cfg.vlan != null) {
      if (family !== 'mac') throw new Error('a VLAN match needs a MAC list');
      if (!(Number.isInteger(cfg.vlan) && cfg.vlan >= 1 && cfg.vlan <= 4094)) throw new Error('the VLAN must be 1 to 4094');
      await addTuple(slots.vlan, TUPLE_TYPE_VAL.vlan, '', cfg.vlan);
    }
    // Ports, TCP or UDP only. One port: a port tuple, the port in Value1 and
    // 0000 in Value2. A range: a start tuple and an end tuple, Value2 empty.
    for (const side of ['src', 'dst']) {
      const pr = cfg[side + 'Port'];
      if (!pr) continue;
      if (!l4) throw new Error('ports need TCP or UDP');
      const base = PORT_TUPLE[p][side];
      if (pr.to == null || pr.to === pr.from) await addTuple(slots[side + 'Port'], base.one, '0000', pr.from);
      else {
        await addTuple(slots[side + 'Port'], base.start, '', pr.from);
        await addTuple(slots[side + 'End'], base.start + 1, '', pr.to);
      }
    }
    // ICMP type and code: the number in Value1, Value2 empty.
    if (cfg.icmpType != null || cfg.icmpCode != null) {
      if (p !== 'icmp') throw new Error('an ICMP type needs an ICMP rule');
      if (cfg.icmpType == null) throw new Error('an ICMP code needs an ICMP type');
      await addTuple(slots.icmpType, TUPLE_TYPE_VAL['icmp-type'], '', cfg.icmpType);
      if (cfg.icmpCode != null) await addTuple(slots.icmpCode, TUPLE_TYPE_VAL['icmp-code'], '', cfg.icmpCode);
    }
    // TCP flags tuple: byte1 = value (Set bits), byte2 = don't-care mask.
    // e.g. ACK+FIN Set, rest Unset-and-cared -> "11 00" (matches the switch).
    if (cfg.tcpFlags) {
      if (p !== 'tcp') throw new Error('TCP flags need a TCP rule');
      const fh = cfg.tcpFlags.val.toString(16).padStart(2, '0') + cfg.tcpFlags.dc.toString(16).padStart(2, '0');
      await addTuple(slots.flags, TUPLE_TYPE_VAL['tcp-flags'], fh);
    }

    // 3. Create the ACE under the ACL, pointing at the tuples.
    let maxAce = 0;
    for (const r of (h.aclAces || [])) { const parts = String(r.index).split('.'); if (parts[0] === aclIdx) { const a = parseInt(parts[1], 10); if (a > maxAce) maxAce = a; } }
    const aceIdx = at != null ? String(at) : String(maxAce + 1);
    const suffix = aclIdx + '.' + aceIdx;
    const vbs = [
      { oid: QOS_ACL.aceStatus + '.' + suffix, type: 'Integer', value: 4 },  // createAndGo
      { oid: QOS_ACL.aceAction + '.' + suffix, type: 'Integer', value: cfg.action },
      { oid: QOS_ACL.aceType + '.' + suffix, type: 'Integer', value: aceType }
    ];
    pointers.forEach((tIdx, i) => {
      if (tIdx && i < ACE_TUPLE_COLS.length) vbs.push({ oid: QOS_ACL.aceTupleBase + ACE_TUPLE_COLS[i] + '.' + suffix, type: 'Integer', value: parseInt(tIdx, 10) });
    });
    try { await snmpSet(s, vbs); } catch (e) { throw new Error('creating ACE: ' + e.message); }
  }

  // Edit an ACE. The tuple model has no clean in-place "change the match fields"
  // operation (the ACE points at tuple rows; changing the match means different
  // tuples), so editing replaces the ACE row and keeps its index, so the rule
  // keeps its place in the list:
  //   1. remove the old ACE row only - its tuples stay, untouched;
  //   2. create the replacement (new tuples + ACE) at the same index;
  //   3. if that fails, put the old ACE back at its index, pointing at its
  //      original tuples, and say so; if it worked, remove the old tuples that
  //      nothing else uses.
  async function editQosAce(s, aclIdx, aceIdx, cfg) {
    const model = aclModel(s.health);
    const acl = model.byIdx.get(String(aclIdx));
    const old = acl && acl.aces.get(String(aceIdx));
    if (!old) throw new Error('the rule is no longer on the switch');
    const suffix = acl.idx + '.' + old.idx;
    let del;
    try { del = interpretSet(await rowStatusDelete(s, QOS_ACL.aceStatus + '.' + suffix)); }
    catch (e) { del = { ok: false, error: e.message }; }
    if (!del.ok) throw new Error('removing the old rule: ' + del.error);
    try {
      await createQosAce(s, Object.assign({}, cfg, { aclIdx: acl.idx }), old.idx);
    } catch (e) {
      const vbs = [
        { oid: QOS_ACL.aceStatus + '.' + suffix, type: 'Integer', value: 4 },   // createAndGo
        { oid: QOS_ACL.aceAction + '.' + suffix, type: 'Integer', value: old.action },
        { oid: QOS_ACL.aceType + '.' + suffix, type: 'Integer', value: old.type }
      ];
      // Each tuple goes back in the slot it was read from.
      for (const [slot, t] of Object.entries(old.bySlot || {})) {
        const col = ACE_TUPLE_COLS[parseInt(slot, 10) - 1];
        if (col) vbs.push({ oid: QOS_ACL.aceTupleBase + col + '.' + suffix, type: 'Integer', value: parseInt(t, 10) });
      }
      let back;
      try { await snmpSet(s, vbs); back = ' The original rule was put back.'; }
      catch (x) { back = ' The original rule could not be put back (' + x.message + '); add it again.'; }
      throw new Error(e.message + '.' + back);
    }
    await dropTuples(s, unusedTuples(model, old.tuples, new Set([suffix])));
  }
  // An address group: "Any" toggle + IP + prefix, wired so the inputs enable
  // only when "Any" is off. init: { any, ip, pref }. setFamily switches the
  // placeholder and the prefix limit between IPv4 (32) and IPv6 (128).
  function addressGroup(labelWord, init, family) {
    init = init || {};
    const wrap = el('div', 'acl-addr');
    const anyLab = el('label', 'acl-any');
    const any = el('input'); any.type = 'checkbox'; any.checked = init.any !== false;
    anyLab.appendChild(any); anyLab.appendChild(el('span', '', 'Any ' + labelWord));
    wrap.appendChild(anyLab);
    const detail = el('div', 'acl-addr-detail');
    const ip = el('input'); ip.type = 'text'; ip.className = 'acl-ip-in';
    ip.setAttribute('aria-label', labelWord + ' address');
    if (init.ip) ip.value = init.ip;
    const pref = el('input'); pref.type = 'number'; pref.min = '0'; pref.className = 'acl-pref-in';
    pref.setAttribute('aria-label', labelWord + ' prefix length');
    if (init.pref != null) pref.value = String(init.pref);
    const slash = el('span', 'acl-slash', '/');
    detail.appendChild(ip); detail.appendChild(slash); detail.appendChild(pref);
    wrap.appendChild(detail);
    const sync = () => { const off = any.checked; ip.disabled = off; pref.disabled = off; detail.classList.toggle('is-off', off); };
    any.addEventListener('change', sync); sync();
    // Placeholder, prefix limit and default prefix for each list type. The
    // first call keeps a prefix the rule already has; a change of type resets it.
    let current = null;
    const setFamily = (f) => {
      const shape = { ip: ['192.168.1.0', 32, 24], ipv6: ['2001:db8::', 128, 64], mac: ['00:11:22:33:44:55', 48, 48] }[f] || ['192.168.1.0', 32, 24];
      ip.placeholder = shape[0];
      pref.max = String(shape[1]);
      if (current === null ? init.pref == null : f !== current) pref.value = String(shape[2]);
      current = f;
    };
    setFamily(family || 'ip');
    return { wrap, any, ip, pref, setFamily };
  }
  // A port or port range: two number boxes, "from" and an optional "to".
  // Both blank means any port. init: { from, to }.
  function portRange(labelWord, init) {
    init = init || {};
    const wrap = el('div', 'acl-addr-detail acl-port-range');
    const mk = (v, word) => {
      const i = el('input'); i.type = 'number'; i.min = '0'; i.max = '65535'; i.className = 'acl-port-in';
      i.placeholder = word; i.setAttribute('aria-label', labelWord + ' ' + word);
      if (v != null) i.value = String(v);
      return i;
    };
    const from = mk(init.from, 'port'), to = mk(init.to != null && init.to !== init.from ? init.to : null, 'to');
    wrap.appendChild(from); wrap.appendChild(el('span', 'acl-slash', '–')); wrap.appendChild(to);
    return { wrap, from, to };
  }
  // A number box's value: null when blank, NaN when not a whole number.
  function numIn(input) {
    const t = String(input.value || '').trim();
    if (t === '') return null;
    return /^\d+$/.test(t) ? parseInt(t, 10) : NaN;
  }

  // Open the rule form in the standard popout (Esc or x closes it). opts:
  //   { newAcl: true }                     -> create a new ACL by name with its first rule
  //   { aclIdx, aclName, family }          -> add a rule to that existing ACL
  //   { edit: {aclIdx, aceIdx, aclName, init} } -> edit an existing rule
  function openAclRuleForm(s, opts) {
    const title = opts.edit ? ('ACL · ' + opts.edit.aclName + ' · rule ' + opts.edit.aceIdx)
      : (opts.newAcl ? 'New access list' : ('Add rule to ' + opts.aclName));
    const tab = opts.edit ? 'Rule' : (opts.newAcl ? 'New ACL' : 'Add rule');
    openTabbedPopout(s, title, [{ label: tab, fill: (pane, close) => aclRuleForm(s, pane, close, opts) }], []);
  }
  // A table row opens its rule, looked up from the current tables so the form
  // is always pre-filled with what the switch holds now.
  function openAclRuleEditor(s, aclIdx, aceIdx) {
    const model = aclModel(s.health);
    const acl = model.byIdx.get(String(aclIdx));
    const ace = acl && acl.aces.get(String(aceIdx));
    if (!acl || !ace) return;
    const view = aclRuleView(ace, model.tupleMap);
    if (view.unsupported.length || view.init.family !== acl.family) {
      const what = view.unsupported.length ? view.unsupported.join(', ') : 'a match this editor does not handle';
      openTabbedPopout(s, 'ACL · ' + acl.name + ' · rule ' + ace.idx, [{ label: 'Rule', fill: (pane) => {
        pane.appendChild(el('div', 'card-sub', view.action + ' ' + view.proto + ' from ' + view.src + ' to ' + view.dst + (view.extra.length ? ', ' + view.extra.join(', ') : '')));
        pane.appendChild(el('div', 'card-sub', 'This rule also matches ' + what + ', so saving it here would drop that part of the match. Change it in the switch’s web interface or CLI, or delete it and add it again.'));
      } }], []);
      return;
    }
    openAclRuleForm(s, { edit: { aclIdx: acl.idx, aceIdx: ace.idx, aclName: acl.name, init: view.init } });
  }

  function aclRuleForm(s, pane, close, opts) {
    const editing = !!opts.edit;
    const init = (opts.edit && opts.edit.init) || {};
    const aclName = opts.aclName || (opts.edit && opts.edit.aclName) || '';
    let family = init.family || opts.family || 'ip';
    const form = el('div', 'snmp-form acl-form');

    // --- Section: the list (only when naming a new one) + the basics ---
    const basics = formSection(opts.newAcl ? 'List & rule' : 'Rule');
    let nameIn = null, familySel = null;
    if (opts.newAcl) {
      nameIn = el('input'); nameIn.type = 'text'; nameIn.maxLength = 32; nameIn.placeholder = 'list name';
      basics.body.appendChild(field('ACL name', nameIn));
      familySel = selectInput([{ label: 'IPv4', value: 'ip' }, { label: 'IPv6', value: 'ipv6' }, { label: 'MAC', value: 'mac' }], family);
      basics.body.appendChild(field('List type', familySel));
    }
    const actionSel = selectInput([
      { label: 'permit', value: '1' }, { label: 'deny', value: '2' },
      { label: 'deny + log', value: '4' }, { label: 'permit + log', value: '5' }
    ], init.action ? String(init.action) : '1');
    basics.body.appendChild(field('Action', actionSel));
    const protoSel = selectInput([
      { label: 'any', value: 'any' }, { label: 'TCP', value: 'tcp' }, { label: 'UDP', value: 'udp' },
      { label: 'ICMP', value: 'icmp' }, { label: 'other protocol number', value: 'num' }
    ], init.proto || 'any');
    const protoField = field('Protocol', protoSel);
    basics.body.appendChild(protoField);
    const protoNumIn = el('input'); protoNumIn.type = 'number'; protoNumIn.min = '0'; protoNumIn.max = '255'; protoNumIn.placeholder = '47';
    if (init.protoNum != null) protoNumIn.value = String(init.protoNum);
    const protoNumField = field('Protocol number', protoNumIn);
    basics.body.appendChild(protoNumField);
    form.appendChild(basics.sec);

    // --- Section: match (source, then destination stacked below it so each
    //     address line - IP / prefix - has the full width and is never cut) ---
    const match = formSection('Match');
    match.body.classList.add('acl-stack');
    const src = addressGroup('source', init.src || { any: true }, family);
    const dst = addressGroup('destination', init.dst || { any: true }, family);
    match.body.appendChild(field('Source', src.wrap));
    match.body.appendChild(field('Destination', dst.wrap));
    // MAC lists: a prefix of 48 is one device, 24 is every device of one maker.
    const macHint = el('div', 'card-sub', 'The number after / is how many bits must match: 48 is one device, 24 is every device from one maker.');
    match.body.appendChild(macHint);
    const vlanIn = el('input'); vlanIn.type = 'number'; vlanIn.min = '1'; vlanIn.max = '4094'; vlanIn.placeholder = 'any';
    if (init.vlan != null) vlanIn.value = String(init.vlan);
    const vlanField = field('VLAN', vlanIn);
    match.body.appendChild(vlanField);
    form.appendChild(match.sec);

    // --- Section: ports (TCP and UDP). Blank is any port; a "to" makes a range. ---
    const portsSec = formSection('Ports');
    portsSec.body.classList.add('acl-stack');
    const srcPort = portRange('source', init.srcPort);
    const dstPort = portRange('destination', init.dstPort);
    portsSec.body.appendChild(field('Source port', srcPort.wrap));
    portsSec.body.appendChild(field('Destination port', dstPort.wrap));
    portsSec.body.appendChild(el('div', 'card-sub', 'Leave a port blank for any port. Fill in both boxes for a range.'));
    form.appendChild(portsSec.sec);

    // --- Section: ICMP type and code (ICMP only). Blank is any. ---
    const icmpSec = formSection('ICMP');
    const icmpTypeIn = el('input'); icmpTypeIn.type = 'number'; icmpTypeIn.min = '0'; icmpTypeIn.max = '255'; icmpTypeIn.placeholder = 'any';
    const icmpCodeIn = el('input'); icmpCodeIn.type = 'number'; icmpCodeIn.min = '0'; icmpCodeIn.max = '255'; icmpCodeIn.placeholder = 'any';
    if (init.icmpType != null) icmpTypeIn.value = String(init.icmpType);
    if (init.icmpCode != null) icmpCodeIn.value = String(init.icmpCode);
    icmpSec.body.appendChild(field('Type', icmpTypeIn));
    icmpSec.body.appendChild(field('Code', icmpCodeIn));
    const icmpHint = el('div', 'card-sub', '');
    icmpSec.body.appendChild(icmpHint);
    form.appendChild(icmpSec.sec);

    // --- Section: TCP flags (only for TCP). Each flag is tri-state: Set (must
    //     be 1), Unset (must be 0), or Don't care (ignored) - matching the
    //     switch's value + don't-care-mask encoding. ---
    const flagsSec = formSection('TCP flags');
    const flagRow = el('div', 'acl-flags-row');
    const flagCtl = {};
    const initFlags = (init.flags && typeof init.flags === 'object') ? init.flags : {};
    for (const [name] of TCP_FLAGS) {
      const cell = el('div', 'acl-flag-cell');
      cell.appendChild(el('div', 'acl-flag-name', name.toUpperCase()));
      const state = initFlags[name] || 'care';   // default don't care
      const radios = {};
      for (const opt of [['set', 'Set'], ['unset', 'Unset'], ['care', "Don't care"]]) {
        const rl = el('label', 'acl-flag-opt');
        const r = el('input'); r.type = 'radio'; r.name = 'flag-' + name + '-' + (editing ? 'e' : 'n'); r.value = opt[0];
        if (state === opt[0]) r.checked = true;
        rl.appendChild(r); rl.appendChild(el('span', '', opt[1]));
        cell.appendChild(rl);
        radios[opt[0]] = r;
      }
      flagRow.appendChild(cell);
      flagCtl[name] = radios;
    }
    flagsSec.body.appendChild(flagRow);
    form.appendChild(flagsSec.sec);

    // Show only the sections the chosen protocol uses.
    const syncVisible = () => {
      const mac = family === 'mac';
      if (mac) protoSel.value = 'any';
      protoField.style.display = mac ? 'none' : '';
      macHint.style.display = mac ? '' : 'none';
      vlanField.style.display = mac ? '' : 'none';
      const pv = protoSel.value;
      protoNumField.style.display = pv === 'num' ? '' : 'none';
      portsSec.sec.style.display = (pv === 'tcp' || pv === 'udp') ? '' : 'none';
      icmpSec.sec.style.display = pv === 'icmp' ? '' : 'none';
      flagsSec.sec.style.display = pv === 'tcp' ? '' : 'none';
      icmpHint.textContent = family === 'ipv6' ? 'For example type 128 is echo request (ping) and 135 is neighbor solicitation.' : 'For example type 8 is echo request (ping) and 0 is echo reply.';
    };
    protoSel.addEventListener('change', syncVisible);
    if (familySel) familySel.addEventListener('change', () => { family = familySel.value; src.setFamily(family); dst.setFamily(family); syncVisible(); });
    syncVisible();

    // Adding is one tap; saving an edit replaces the rule, so it asks for a
    // second tap (standard B8: confirm only when the click is drastic).
    const { actions, apply, msg } = applyActions(editing ? 'Save rule' : (opts.newAcl ? 'Create ACL' : 'Add rule'));
    withConfirm(apply, (ev) => {
      const name = aclName || (nameIn ? (nameIn.value || '').trim() : '');
      clear(msg);
      const fail = (text) => { msg.appendChild(el('div', 'sw-err', text)); };
      if (!name) return fail('Enter an ACL name.');
      if (opts.newAcl && aclModel(s.health).acls.some((a) => a.name === name)) return fail('An ACL named “' + name + '” already exists. Use its Add rule instead.');
      const addrOk = { ip: ipv4ToHex, ipv6: ipv6ToHex, mac: macToHex }[family];
      const maxPref = { ip: 32, ipv6: 128, mac: 48 }[family];
      const addr = (g, word) => {
        if (g.any.checked) return { any: true };
        if (!addrOk(g.ip.value)) return 'Enter a valid ' + word + ' ' + ACL_FAMILY_WORD[family] + ' address.';
        const pr = numIn(g.pref);
        if (pr == null || !(pr <= maxPref)) return 'The ' + word + ' prefix length must be 0 to ' + maxPref + '.';
        return { any: false, ip: g.ip.value.trim(), pref: pr };
      };
      const srcA = addr(src, 'source'), dstA = addr(dst, 'destination');
      if (typeof srcA === 'string') return fail(srcA);
      if (typeof dstA === 'string') return fail(dstA);
      const pv = protoSel.value;
      const cfg = { aclName: name, family, action: parseInt(actionSel.value, 10), proto: pv, src: srcA, dst: dstA };
      if (family === 'mac') {
        const v = numIn(vlanIn);
        if (v != null && !(v >= 1 && v <= 4094)) return fail('The VLAN must be 1 to 4094.');
        if (v != null) cfg.vlan = v;
      }
      if (pv === 'num') {
        const n = numIn(protoNumIn);
        if (n == null || !(n <= 255)) return fail('Enter a protocol number from 0 to 255.');
        cfg.protoNum = n;
      }
      if (pv === 'tcp' || pv === 'udp') {
        for (const [side, g, word] of [['srcPort', srcPort, 'source'], ['dstPort', dstPort, 'destination']]) {
          const a = numIn(g.from), b = numIn(g.to);
          if (a == null && b == null) continue;
          if (a == null) return fail('Enter the first ' + word + ' port of the range.');
          if (!(a <= 65535) || (b != null && !(b <= 65535))) return fail('A ' + word + ' port must be 0 to 65535.');
          if (b != null && b < a) return fail('The ' + word + ' port range must run from the lower port to the higher one.');
          cfg[side] = { from: a, to: b == null ? a : b };
        }
      }
      if (pv === 'icmp') {
        const t = numIn(icmpTypeIn), c = numIn(icmpCodeIn);
        if (t != null && !(t <= 255)) return fail('The ICMP type must be 0 to 255.');
        if (c != null && !(c <= 255)) return fail('The ICMP code must be 0 to 255.');
        if (c != null && t == null) return fail('An ICMP code needs a type.');
        if (t != null) cfg.icmpType = t;
        if (c != null) cfg.icmpCode = c;
      }
      if (pv === 'tcp') {
        let val = 0, dc = 0;
        for (const [nm, bit] of TCP_FLAGS) {
          const st = flagCtl[nm].set.checked ? 'set' : (flagCtl[nm].unset.checked ? 'unset' : 'care');
          if (st === 'care') dc |= bit; else if (st === 'set') val |= bit;
        }
        // Only emit a flags tuple if at least one flag is actually constrained.
        if (dc !== 0x3f) cfg.tcpFlags = { val, dc };
      }
      runButtonAction(ev.currentTarget, {
        failLabel: editing ? 'Save rule' : 'Add rule',
        spinLabel: editing ? 'Saving…' : (opts.newAcl ? 'Creating…' : 'Adding…'),
        run: async () => {
          try {
            if (editing) await editQosAce(s, opts.edit.aclIdx, opts.edit.aceIdx, cfg);
            else await createQosAce(s, cfg);
            return { ok: true };
          } catch (e) { return { ok: false, error: e.message }; }
        },
        ok: (r) => r && r.ok,
        error: (r) => { fail((editing ? 'Could not save rule — ' : 'Could not add rule — ') + ((r && r.error) || 'failed')); return (r && r.error) || 'failed'; },
        onApplied: () => markConfigDirty(s),
        settle: () => aclRefresh(s).then(() => close())
      });
    }, { when: () => editing });
    form.appendChild(actions); form.appendChild(msg);
    pane.appendChild(form);
  }
