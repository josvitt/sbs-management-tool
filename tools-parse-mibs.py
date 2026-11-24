#!/usr/bin/env python3
"""
Parse the C1200/C1300 MIB set into a name -> numeric OID map.

Handles the three ways an OID gets defined in these files:
  name OBJECT IDENTIFIER ::= { parent N }
  name OBJECT-TYPE ... ::= { parent N }
  name MODULE-IDENTITY ... ::= { parent N }
(plus OBJECT-GROUP / NOTIFICATION-TYPE / MODULE-COMPLIANCE / NOTIFICATION-GROUP)

Assignments can be multi-level (::= { enterprises 9 6 1 101 }) and can
reference a parent defined in a different file, so resolution is done
iteratively until no further progress is made.
"""

import json
import os
import re
import sys
from collections import OrderedDict

MIB_DIR = sys.argv[1] if len(sys.argv) > 1 else "MIBs_Cat1200_1300_4.1.9.85"

# Well-known roots that the MIBs assume exist but never define numerically.
SEED = {
    "iso": "1",
    "org": "1.3",
    "dod": "1.3.6",
    "internet": "1.3.6.1",
    "directory": "1.3.6.1.1",
    "mgmt": "1.3.6.1.2",
    "mib-2": "1.3.6.1.2.1",
    "mib_2": "1.3.6.1.2.1",
    "transmission": "1.3.6.1.2.1.10",
    "experimental": "1.3.6.1.3",
    "private": "1.3.6.1.4",
    "enterprises": "1.3.6.1.4.1",
    "security": "1.3.6.1.5",
    "snmpV2": "1.3.6.1.6",
    "snmpDomains": "1.3.6.1.6.1",
    "snmpProxys": "1.3.6.1.6.2",
    "snmpModules": "1.3.6.1.6.3",
    "cisco": "1.3.6.1.4.1.9",
}

# Strip comments (-- to end of line) but keep string literals intact enough
# for our purposes; we only care about the ::= { ... } assignment clauses.
COMMENT_RE = re.compile(r"--.*?$", re.MULTILINE)

# An IMPORTS block lists type keywords as imported symbols, e.g.
#   IMPORTS
#       OBJECT-TYPE, MODULE-IDENTITY  FROM SNMPv2-SMI
#       switch001                     FROM CISCOSB-MIB;
# Left in place, the assignment regex happily matches "IMPORTS ...
# MODULE-IDENTITY ... ::= { switch001 38 }" and swallows the first real
# definition after the block. IMPORTS never contains OID assignments, so
# remove the section before parsing.
#
# Must be anchored to the start of a line and applied only once: the bare
# word "IMPORTS" also shows up inside DESCRIPTION strings (e.g. "Removed
# TRAP-TYPE from IMPORTS."), and an unanchored global strip would match
# there too and delete everything up to the next semicolon -- silently
# eating hundreds of real definitions.
IMPORTS_RE = re.compile(r"^[ \t]*IMPORTS\b.*?;", re.DOTALL | re.MULTILINE)

# Some files in this archive (e.g. rfc2573.mib) contain several MIB modules
# concatenated together, each with its own IMPORTS block, so every block has
# to go -- not just the first. The length guard is a safety net: a real
# IMPORTS block is short, so an over-long match means the terminating ';'
# was missed and the match is about to eat real definitions.
MAX_IMPORTS_LEN = 4000


def strip_imports(text):
    """Remove every line-anchored IMPORTS block, leaving suspicious ones alone."""
    def repl(m):
        return " " if len(m.group(0)) <= MAX_IMPORTS_LEN else m.group(0)
    return IMPORTS_RE.sub(repl, text)

# name TYPE ... ::= { parent 1 2 3 }
# MIB DESCRIPTION/REFERENCE bodies are prose, and that prose sometimes
# contains what looks exactly like an assignment. rfc2668's ifMauType, for
# instance, documents:
#     unknownMauType OBJECT IDENTIFIER ::= { 0 0 }
# inside its DESCRIPTION. Matched literally that invents a bogus OID *and*
# hijacks the enclosing OBJECT-TYPE's own `::=`, which is how ifMauType and
# ifTestCode both ended up resolving to 0.0. Blank out string literals
# before looking for assignments (metadata is extracted from the original
# text beforehand, so descriptions are unaffected).
STRING_RE = re.compile(r'"[^"]*"', re.DOTALL)
#
# 1) A bare OID assignment has ::= immediately after the type:
#        rndMng OBJECT IDENTIFIER ::= { switch001 1 }
#    Requiring nothing but whitespace between IDENTIFIER and ::= matters:
#    inside a SEQUENCE block a column can be *declared* the same way --
#        rlifPresentSpecific   OBJECT IDENTIFIER, -- deprecated
#    -- and with a permissive `.*?::=` that declaration matches, then
#    swallows the next real definition in the file. That is exactly how
#    rlifPresentIndex went missing and rlifPresentSpecific ended up with
#    rlifPresentIndex's OID.
#
# 2) Everything else (OBJECT-TYPE, MODULE-IDENTITY, ...) has a body of
#    SYNTAX/ACCESS/DESCRIPTION clauses before ::=, so it needs `.*?`.
ASSIGN_OID_RE = re.compile(
    r"^[ \t]*([a-zA-Z][a-zA-Z0-9_-]*)\s+OBJECT\s+IDENTIFIER\s*::=\s*\{([^}]*)\}",
    re.MULTILINE,
)
ASSIGN_BODY_RE = re.compile(
    r"^\s*([a-zA-Z][a-zA-Z0-9_-]*)\s+"
    r"(?:OBJECT-TYPE|MODULE-IDENTITY|OBJECT-GROUP|"
    r"NOTIFICATION-TYPE|MODULE-COMPLIANCE|NOTIFICATION-GROUP|OBJECT-IDENTITY)"
    r"\b.*?::=\s*\{([^}]*)\}",
    re.DOTALL | re.MULTILINE,
)

# Metadata for OBJECT-TYPE entries so the UI can show something useful.
OBJTYPE_RE = re.compile(
    r"^\s*([a-zA-Z][a-zA-Z0-9_-]*)\s+OBJECT-TYPE\b(.*?)::=\s*\{([^}]*)\}",
    re.DOTALL | re.MULTILINE,
)
SYNTAX_RE = re.compile(r"\bSYNTAX\s+([^\n]+)")
ACCESS_RE = re.compile(r"\b(?:MAX-ACCESS|ACCESS)\s+([a-z-]+)")
DESC_RE = re.compile(r'\bDESCRIPTION\s*"(.*?)"', re.DOTALL)
UNITS_RE = re.compile(r'\bUNITS\s*"([^"]*)"')

# An enumeration body: INTEGER { up(1), down(2), ... } or BITS { ... }.
# Captured from the object itself when written inline, and from
# TEXTUAL-CONVENTIONs so that objects declared as `SYNTAX TruthValue`
# or `SYNTAX IANAifType` can be decoded too.
ENUM_BODY_RE = re.compile(r"\b(?:INTEGER|BITS)\s*\{(.*?)\}", re.DOTALL)
ENUM_PAIR_RE = re.compile(r"([a-zA-Z][a-zA-Z0-9_-]*)\s*\(\s*(-?\d+)\s*\)")

# name ::= TEXTUAL-CONVENTION ... SYNTAX <...>
TC_RE = re.compile(
    r"^\s*([A-Za-z][A-Za-z0-9_-]*)\s*::=\s*TEXTUAL-CONVENTION\b(.*?)(?=^\s*[A-Za-z][A-Za-z0-9_-]*\s*(?:::=|OBJECT-TYPE|MODULE-IDENTITY)|\Z)",
    re.DOTALL | re.MULTILINE,
)
# The declared type of an object, i.e. the first token after SYNTAX.
SYNTAX_TYPE_RE = re.compile(r"\bSYNTAX\s+([A-Za-z][A-Za-z0-9_-]*)")


def parse_enum(text):
    """Pull {name(value), ...} pairs out of an enumeration body."""
    m = ENUM_BODY_RE.search(text)
    if not m:
        return None
    pairs = ENUM_PAIR_RE.findall(m.group(1))
    if not pairs:
        return None
    # value -> label, since decoding goes from the wire value to a name.
    return {int(v): n for n, v in pairs}


TOKEN_RE = re.compile(r"([a-zA-Z][a-zA-Z0-9_-]*)\s*\((\d+)\)|([a-zA-Z][a-zA-Z0-9_-]*)|(\d+)")


def parse_assignment(body):
    """
    Turn the inside of ::= { ... } into a list of components.
    Each component is either ('name', str), ('num', int), or ('namenum', name, int)
    for the `foo(1)` form.
    """
    parts = []
    for m in TOKEN_RE.finditer(body):
        name_with_num, num_in_paren, bare_name, bare_num = m.groups()
        if name_with_num is not None:
            parts.append(("namenum", name_with_num, int(num_in_paren)))
        elif bare_name is not None:
            parts.append(("name", bare_name))
        elif bare_num is not None:
            parts.append(("num", int(bare_num)))
    return parts


def main():
    files = []
    for root, _dirs, names in os.walk(MIB_DIR):
        for n in names:
            if n.lower().endswith((".mib", ".my", ".txt")):
                files.append(os.path.join(root, n))
    files.sort()

    raw_defs = {}   # name -> (parts, source_file)
    meta = {}       # name -> {syntax, access, description, enum, units, tc}
    tcs = {}        # textual convention name -> {value: label}

    for path in files:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                text = f.read()
        except Exception as e:
            print(f"  ! could not read {path}: {e}", file=sys.stderr)
            continue

        text_nc = COMMENT_RE.sub("", text)
        text_nc = strip_imports(text_nc)
        # Assignments are matched against a copy with string literals blanked
        # out; metadata below still reads the original so DESCRIPTIONs survive.
        text_assign = STRING_RE.sub('""', text_nc)

        # Textual conventions first: objects reference them by name, and a
        # reference can point at a TC defined in a different file, so these
        # are gathered across all files before being resolved at the end.
        for m in TC_RE.finditer(text_nc):
            tc_name, body = m.group(1), m.group(2)
            enum = parse_enum(body)
            if enum and tc_name not in tcs:
                tcs[tc_name] = enum

        for regex in (ASSIGN_OID_RE, ASSIGN_BODY_RE):
            for m in regex.finditer(text_assign):
                name = m.group(1)
                parts = parse_assignment(m.group(2))
                if not parts:
                    continue
                # First definition wins; MIB sets sometimes repeat harmlessly.
                if name not in raw_defs:
                    raw_defs[name] = (parts, os.path.basename(path))

        for m in OBJTYPE_RE.finditer(text_nc):
            name, body = m.group(1), m.group(2)
            if name in meta:
                continue
            syn = SYNTAX_RE.search(body)
            acc = ACCESS_RE.search(body)
            desc = DESC_RE.search(body)
            entry = {}
            if syn:
                entry["syntax"] = " ".join(syn.group(1).split())[:120]
            if acc:
                entry["access"] = acc.group(1)
            if desc:
                d = " ".join(desc.group(1).split())
                entry["description"] = d[:300]
            units = UNITS_RE.search(body)
            if units:
                entry["units"] = units.group(1)[:32]
            # Inline enumeration wins; otherwise record the declared type so
            # it can be matched against a textual convention afterwards.
            inline = parse_enum(body.split("DESCRIPTION")[0])
            if inline:
                entry["enum"] = inline
            else:
                st = SYNTAX_TYPE_RE.search(body)
                if st:
                    entry["tc"] = st.group(1)
            if entry:
                meta[name] = entry

    print(f"Parsed {len(files)} files, found {len(raw_defs)} raw OID assignments")

    resolved = dict(SEED)

    # Iteratively resolve: a definition can only be resolved once its
    # parent name is known, and parents may live in other files.
    for _pass in range(60):
        progress = False
        for name, (parts, _src) in raw_defs.items():
            if name in resolved:
                continue
            head = parts[0]
            if head[0] == "name":
                base = resolved.get(head[1])
                if base is None:
                    continue
                tail = parts[1:]
            elif head[0] == "namenum":
                base = resolved.get(head[1])
                if base is None:
                    # `foo(1)` as the first component with unknown foo:
                    # can't anchor it, skip.
                    continue
                tail = parts[1:]
            else:
                # Starts with a bare number - absolute from iso.
                base = str(head[1])
                tail = parts[1:]

            nums = []
            ok = True
            for p in tail:
                if p[0] == "num":
                    nums.append(str(p[1]))
                elif p[0] == "namenum":
                    nums.append(str(p[2]))
                else:
                    ok = False
                    break
            if not ok:
                continue

            resolved[name] = base + ("." + ".".join(nums) if nums else "")
            progress = True
        if not progress:
            break

    unresolved = [n for n in raw_defs if n not in resolved]
    print(f"Resolved {len(resolved) - len(SEED)} names; {len(unresolved)} unresolved")
    if unresolved:
        print("  first few unresolved:", unresolved[:15])

    # Objects declared as `SYNTAX TruthValue` / `SYNTAX IANAifType` etc. get
    # their enumeration from the textual convention they reference.
    print(f"Collected {len(tcs)} textual conventions with enumerations")
    tc_hits = 0
    for name, entry in meta.items():
        if "enum" not in entry and entry.get("tc"):
            enum = tcs.get(entry["tc"])
            if enum:
                entry["enum"] = enum
                tc_hits += 1
        entry.pop("tc", None)
    print(f"  applied a textual convention enum to {tc_hits} objects")
    enum_total = sum(1 for e in meta.values() if "enum" in e)
    print(f"  {enum_total} objects now have a decodable enumeration")

    # Build output, dropping the seed-only entries we didn't actually see
    out = OrderedDict()
    for name in sorted(raw_defs.keys(), key=lambda s: s.lower()):
        if name not in resolved:
            continue
        entry = {"oid": resolved[name], "mib": raw_defs[name][1]}
        if name in meta:
            entry.update(meta[name])
        out[name] = entry

    with open("oid-map.json", "w") as f:
        json.dump(out, f, indent=0, sort_keys=True)

    print(f"Wrote oid-map.json with {len(out)} entries")

    # Sanity spot-checks against known-correct values
    checks = {
        "sysDescr": "1.3.6.1.2.1.1.1",
        "sysName": "1.3.6.1.2.1.1.5",
        "sysUpTime": "1.3.6.1.2.1.1.3",
        "ifTable": "1.3.6.1.2.1.2.2",
        "ifDescr": "1.3.6.1.2.1.2.2.1.2",
        "switch001": "1.3.6.1.4.1.9.6.1.101",
    }
    print("\nSpot checks:")
    for name, expected in checks.items():
        got = resolved.get(name)
        status = "OK " if got == expected else "FAIL"
        print(f"  [{status}] {name}: got={got} expected={expected}")


if __name__ == "__main__":
    main()
