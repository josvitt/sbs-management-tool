#!/usr/bin/env python3
"""
Compact tools-parse-mibs.py's oid-map.json into the oid-db.json the app loads.

Two-step pipeline (the second step was previously undocumented):
  python3 tools-parse-mibs.py   path/to/MIBs_dir      # -> oid-map.json
  python3 tools-compact-oiddb.py oid-map.json "<label>" public/mib/oid-db.json

The app DB is a compact columnar form: a fields header, a deduplicated enums
array, and one positional row per object. This script reproduces exactly the
format mibdb.js / public/app.js parse:
  - access words are shortened (read-only -> r, read-write -> rw, read-create
    -> rc, not-accessible -> n, accessible-for-notify -> afn)
  - syntax has any inline enumeration body ("INTEGER { up(1)... }") stripped
    (the enum is stored separately) and is capped at 40 chars
  - description is capped at 180 chars
  - identical enumerations are stored once and referenced by index (enumId)

Verified: run on the 4.1.9.85 C1300 set it is functionally identical to the
shipped oid-db.json (same names, OIDs, access codes and resolved enums).

Per-product DBs are produced by pointing the parser at each product's MIB set
(see products.json): C1200 and C1300 share one set; C1300X has its own.
"""

import json
import sys

ACCESS = {'read-only': 'r', 'read-write': 'rw', 'read-create': 'rc',
          'not-accessible': 'n', 'accessible-for-notify': 'afn', 'write-only': 'w'}


def norm_syntax(s):
    s = s or ''
    if '{' in s:
        s = s.split('{', 1)[0]          # drop the inline enum body
    return s.rstrip()[:40]


def main():
    if len(sys.argv) < 4:
        print('usage: tools-compact-oiddb.py <oid-map.json> "<label>" <out oid-db.json>')
        sys.exit(2)
    src, label, out = sys.argv[1], sys.argv[2], sys.argv[3]
    d = json.load(open(src))

    enums = []
    idx = {}

    def enum_id(e):
        if not e:
            return -1
        k = json.dumps(e, sort_keys=True)
        if k not in idx:
            idx[k] = len(enums)
            enums.append(e)
        return idx[k]

    entries = []
    for name in sorted(d.keys(), key=lambda s: s.lower()):
        e = d[name]
        entries.append([
            name, e['oid'],
            ACCESS.get(e.get('access', ''), e.get('access', '')),
            norm_syntax(e.get('syntax', '')),
            (e.get('description', '') or '')[:180],
            e.get('mib', ''),
            enum_id(e.get('enum')),
            e.get('units', ''),
        ])

    obj = {
        'generated_from': label,
        'vendor_root': '1.3.6.1.4.1.9.6.1.101',
        'fields': ['name', 'oid', 'access', 'syntax', 'description', 'mib', 'enumId', 'units'],
        'enums': enums,
        'entries': entries,
    }
    with open(out, 'w') as f:
        json.dump(obj, f, separators=(',', ':'))
    print(f'Wrote {out}: {len(entries)} entries, {len(enums)} enums')


if __name__ == '__main__':
    main()
