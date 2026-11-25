  // =================================================================
  // 02-mib-db.js: The MIB database and product registry, shared by every switch.
  // =================================================================

  // =================================================================
  // MIB database (shared by every switch)
  // =================================================================
  // The active MIB view. Which product's database it holds can change (the MIB
  // Explorer's product picker), so loadMib takes a product line; each product's
  // DB is fetched once and cached. C1200 and C1300 share one DB; C1300X has its
  // own (it adds OSPF/PTP and renumbers some OIDs), so the set MUST match the
  // product being browsed - see products.json.
  const MIB = { entries: [], byOid: new Map(), loaded: false, error: null, product: null };
  const MIB_DB_CACHE = {};      // db file -> Promise<{entries, byOid}>
  let PRODUCTS = null, PRODUCTS_LOADING = null;

  function loadProducts() {
    if (PRODUCTS) return Promise.resolve(PRODUCTS);
    if (PRODUCTS_LOADING) return PRODUCTS_LOADING;
    PRODUCTS_LOADING = fetch('mib/products.json')
      .then((r) => { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
      .then((d) => { PRODUCTS = d; return d; })
      .catch(() => {
        PRODUCTS = { default: 'C1300', products: [
          { line: 'C1300', label: 'Catalyst 1200/1300', db: 'mib/oid-db.json', match: ['C1300'], features: {} }] };
        return PRODUCTS;
      });
    return PRODUCTS_LOADING;
  }
  function productByLine(line) { return (PRODUCTS && PRODUCTS.products.find((p) => p.line === line)) || null; }

  // Identify the product line from any model-bearing strings, most-specific
  // match first (so "C1300X-..." matches C1300X, not C1300). Mirrors
  // products.js on the server.
  function detectProductLine(strings) {
    if (!PRODUCTS) return null;
    const hay = (Array.isArray(strings) ? strings : [strings]).filter(Boolean).map((s) => String(s).toUpperCase());
    let best = null, bestLen = -1;
    for (const p of PRODUCTS.products) for (const m of (p.match || [])) {
      const n = String(m).toUpperCase();
      if (hay.some((h) => h.indexOf(n) >= 0) && n.length > bestLen) { best = p; bestLen = n.length; }
    }
    return best;
  }

  function buildMibFrom(data) {
    const entries = [], byOid = new Map(), enums = data.enums || [];
    for (const row of data.entries) {
      const e = { name: row[0], oid: row[1], access: row[2], syntax: row[3],
        description: row[4], mib: row[5], units: row[7] || '' };
      if (typeof row[6] === 'number' && row[6] >= 0 && enums[row[6]]) e.enum = enums[row[6]];
      entries.push(e);
      if (!byOid.has(e.oid)) byOid.set(e.oid, e.name);
    }
    return { entries, byOid };
  }
  function dbFor(dbFile) {
    if (!MIB_DB_CACHE[dbFile]) {
      MIB_DB_CACHE[dbFile] = fetch(dbFile)
        .then((r) => { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
        .then(buildMibFrom);
    }
    return MIB_DB_CACHE[dbFile];
  }

  // Load (and make active) the MIB set for a product line. No argument loads the
  // default line's DB, which keeps every existing caller (autocomplete, status)
  // working against the C1200/C1300 set.
  function loadMib(line) {
    return loadProducts().then(() => {
      const prod = productByLine(line) || productByLine(PRODUCTS.default) || PRODUCTS.products[0];
      return dbFor(prod.db).then((built) => {
        MIB.entries = built.entries; MIB.byOid = built.byOid;
        MIB.loaded = true; MIB.product = prod.line; MIB.error = null;
        appLog('info', 'MIB database loaded', { product: prod.line, oids: MIB.entries.length });
        return MIB;
      }).catch((e) => {
        MIB.error = e.message;
        appLog('error', 'Could not load MIB database', { message: e.message, product: prod.line });
        return MIB;
      });
    });
  }

  // The product line in effect for a switch: a manual override wins, else the
  // server-detected line, else the registry default. This is what drives the
  // Explorer default and feature gating.
  function effectiveProductLine(s) {
    if (s && s.productOverride) return s.productOverride;
    if (s && s.product && s.product.line) return s.product.line;
    return (PRODUCTS && PRODUCTS.default) || null;
  }
  function effectiveProduct(s) { return productByLine(effectiveProductLine(s)); }

  // The MIB half of the hybrid gate: a built-in panel that declares a required
  // `mibFeature` (e.g. OSPF/PTP) is shown only on a product whose MIB proves
  // that feature. A panel with no `mibFeature` is common to all three lines and
  // always passes here - its runtime data presence is handled by `needs`
  // (the runtime half). See SERVER-STANDARD.md Products section.
  function productSupports(s, def) {
    if (!def || !def.mibFeature) return true;
    const prod = effectiveProduct(s);
    const feats = (prod && prod.features) || (s && s.product && s.product.features) || {};
    return !!feats[def.mibFeature];
  }

  function describeOid(oid) {
    if (!MIB.loaded || !oid) return null;
    const parts = String(oid).replace(/^\./, '').split('.');
    const suffix = [];
    while (parts.length) {
      const name = MIB.byOid.get(parts.join('.'));
      if (name) return suffix.length ? name + '.' + suffix.slice().reverse().join('.') : name;
      suffix.push(parts.pop());
    }
    return null;
  }

  /**
   * True when an object is a column of a table rather than a scalar. Name
   * alone is not enough: rlifPresentName looks like a scalar but lives
   * under rlifPresentEntry, so appending ".0" and doing a GET returns
   * nothing. Check whether the parent OID is a table entry instead.
   */
  function isColumnar(entry) {
    if (!entry || !entry.oid) return false;
    if (/Table$|Entry$/.test(entry.name)) return true;
    const parent = String(entry.oid).split('.').slice(0, -1).join('.');
    const parentName = MIB.byOid.get(parent);
    return !!(parentName && /Entry$/.test(parentName));
  }

  function searchMib(query, limit) {
    limit = limit || 40;
    if (!MIB.loaded) return [];
    const q = query.trim().toLowerCase();
    if (!q) return [];
    const prefix = [], contains = [];
    for (const e of MIB.entries) {
      const ln = e.name.toLowerCase();
      const i = ln.indexOf(q);
      if (i === 0) { prefix.push(e); if (prefix.length >= limit) break; }
      else if (i > 0) { if (contains.length < limit) contains.push(e); }
      else if (e.oid.indexOf(q) === 0) { if (contains.length < limit) contains.push(e); }
    }
    return prefix.concat(contains).slice(0, limit);
  }

  // Interface presets use rlifPresentTable rather than ifTable: per the
  // 4.1.9.85 release notes it reports only interfaces physically present
  // in the stack, whereas ifTable also lists ones that do not exist.
  const PRESETS_STD = [
    { label: 'System Info', op: 'get', oids: ['sysDescr.0', 'sysName.0', 'sysUpTime.0', 'sysContact.0', 'sysLocation.0', 'sysObjectID.0'] },
    { label: 'VLANs', op: 'walk', oid: 'dot1qVlanStaticName' },
    { label: 'Inventory', op: 'walk', oid: 'entPhysicalName' },
    { label: 'PoE (standard)', op: 'walk', oid: 'pethPsePortTable' },
    { label: 'ifTable (all, incl. absent)', op: 'walk', oid: 'ifDescr' }
  ];
  const PRESETS_VENDOR = [
    { label: 'Interfaces (present only)', op: 'walk', oid: 'rlifPresentName' },
    { label: 'Interface Status (present)', op: 'walk', oid: 'rlifPresentOperStatus' },
    { label: 'Interface Detail (present)', op: 'walk', oid: 'rlifPresentTable' },
    { label: 'CPU Utilisation', op: 'get', oids: ['rlCpuUtilDuringLastSecond.0', 'rlCpuUtilDuringLastMinute.0', 'rlCpuUtilDuringLast5Minutes.0'] },
    { label: 'PoE Ports', op: 'walk', oid: 'rlPethPsePortTable' },
    { label: 'Fans', op: 'walk', oid: 'rlEnvMonFanStatusTable' },
    { label: 'Power Supplies', op: 'walk', oid: 'rlEnvMonSupplyStatusTable' },
    { label: 'Stack Units', op: 'walk', oid: 'rlPhdStackTable' }
  ];
