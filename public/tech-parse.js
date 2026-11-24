/**
 * show tech-support parsing for Catalyst 1200/1300.
 *
 * The device prints a series of banner-delimited sections, most of which
 * contain fixed-width tables. Two details make naive parsing fail on real
 * captures, and both are handled here:
 *
 *  1. A table's dashed rule looks exactly like a section banner, so the
 *     splitter requires a section name to contain a letter.
 *  2. Rows wrap. "show vlan" continues its port list on following lines
 *     with an empty key column, and "show cdp neighbors" wraps the
 *     Platform field the same way. Those continuation lines have to be
 *     folded back into the row above or the table comes out mangled.
 *
 * Exposed as window.TechParse in the browser; module.exports under Node so
 * the same code can be tested against a real capture.
 */
(function (root) {
  'use strict';

  const BANNER = /^-{6,}\s*(.+?)\s*-{6,}\s*$/;
  const RULE = /^[\s-]*-{3,}/;

  function splitSections(text) {
    const lines = String(text).replace(/\r/g, '').split('\n');
    const order = [];
    const secs = {};
    let cur = null;
    let buf = [];

    const flush = () => {
      if (cur === null) {
        // Anything before the first banner is the command echo; keep it
        // only if it actually has content.
        if (buf.some((l) => l.trim())) {
          secs['(session start)'] = buf;
          order.push('(session start)');
        }
        return;
      }
      if (secs[cur]) secs[cur] = secs[cur].concat(buf);
      else { secs[cur] = buf; order.push(cur); }
    };

    for (const ln of lines) {
      const m = ln.match(BANNER);
      if (m && /[a-z]/i.test(m[1])) {
        flush();
        buf = [];
        cur = m[1].trim();
      } else {
        buf.push(ln);
      }
    }
    flush();
    return { order, secs };
  }

  function dashColumns(line) {
    const cols = [];
    const re = /-+/g;
    let m;
    while ((m = re.exec(line)) !== null) cols.push([m.index, m.index + m[0].length]);
    return cols;
  }

  const cut = (ln, c, last) => (last ? ln.slice(c[0]) : ln.slice(c[0], c[1])).trim();

  /**
   * Parse a fixed-width table.
   *  opts.from        - start searching for the rule at this line index
   *  opts.keyCol      - column that identifies a new row (default 0)
   *  opts.contCols    - columns that may continue onto following lines
   *  opts.stopBlank   - stop after this many consecutive blank lines
   */
  function parseTable(lines, opts) {
    opts = opts || {};
    if (!lines || !lines.length) return null;
    const from = opts.from || 0;

    let di = -1;
    for (let i = from; i < lines.length; i++) {
      if (RULE.test(lines[i]) && /-{3,}\s+-{3,}/.test(lines[i])) { di = i; break; }
    }
    if (di < 0) return null;

    const cols = dashColumns(lines[di]);
    if (cols.length < 2) return null;

    // Headers can span two lines ("Flow ctrl", "Time To Live"): join the
    // line above the rule with the one above that when it lines up.
    const h1 = lines[di - 1] || '';
    const h2 = lines[di - 2] || '';
    const useTwo = h2.trim() && !RULE.test(h2) && h2.trim().split(/\s{2,}/).length > 1;
    const headers = cols.map((c, i) => {
      const last = i === cols.length - 1;
      const a = useTwo ? cut(h2, c, last) : '';
      const b = cut(h1, c, last);
      return [a, b].filter(Boolean).join(' ').trim() || ('col' + (i + 1));
    });

    const keyCol = opts.keyCol === undefined ? 0 : opts.keyCol;
    const contCols = opts.contCols || cols.map((_, i) => i);
    const rows = [];
    let curr = null;
    let blanks = 0;
    let end = di + 1;

    for (let i = di + 1; i < lines.length; i++) {
      const ln = lines[i];
      end = i;
      if (!ln.trim()) {
        blanks++;
        if (blanks >= (opts.stopBlank || 2)) break;
        continue;
      }
      blanks = 0;
      if (RULE.test(ln) && /-{3,}\s+-{3,}/.test(ln)) break;   // next table starts
      if (BANNER.test(ln)) break;
      // A line directly above a dashed rule is the header of the *next*
      // table, not a row of this one. Without this check "show system"
      // folds its temperature header into the fan table and the
      // temperature table is never seen at all.
      const nxt = lines[i + 1];
      if (nxt && RULE.test(nxt) && /-{3,}\s+-{3,}/.test(nxt)) { end = i - 1; break; }

      const cells = cols.map((c, j) => cut(ln, c, j === cols.length - 1));
      const key = cells[keyCol];

      if (key || !curr) {
        curr = {};
        headers.forEach((h, j) => { curr[h] = cells[j]; });
        curr._cells = cells.slice();
        rows.push(curr);
      } else {
        // Continuation: append to the wrapped columns of the previous row.
        contCols.forEach((ci) => {
          if (cells[ci]) {
            const h = headers[ci];
            curr[h] = (curr[h] ? curr[h] + ' ' : '') + cells[ci];
            curr._cells[ci] = curr[h];
          }
        });
      }
    }
    return rows.length ? { headers, rows, ruleIndex: di, endIndex: end } : null;
  }

  /** Every table in a section, not just the first. */
  function parseAllTables(lines) {
    const out = [];
    let from = 0;
    for (let guard = 0; guard < 20; guard++) {
      const t = parseTable(lines, { from });
      if (!t) break;
      out.push(t);
      from = Math.max(t.endIndex + 1, t.ruleIndex + 2);
      if (from >= lines.length) break;
    }
    return out;
  }

  /** "Key:  value" lines, as used by show system / show power inline. */
  function parseKeyValues(lines) {
    const kv = [];
    for (const ln of lines) {
      // Split on the colon that is followed by run of spaces, not the
      // first colon: keys legitimately contain one, as in
      //   "System Up Time (days,hour:min:sec):       00,01:15:05"
      let m = ln.match(/^\s*([A-Za-z][^\n]*?):\s{2,}(.*)$/);
      if (!m) m = ln.match(/^\s*([A-Za-z][A-Za-z0-9 ()\/,.'-]*?):\s(.*)$/);
      if (!m) continue;
      const key = m[1].trim();
      if (!key || key.length > 60) continue;
      kv.push({ key, value: m[2].trim() });
    }
    return kv;
  }

  const get = (secs, ...names) => {
    for (const n of names) {
      const k = Object.keys(secs).find((x) => x.toLowerCase() === n.toLowerCase());
      if (k) return secs[k];
    }
    for (const n of names) {
      const k = Object.keys(secs).find((x) => x.toLowerCase().indexOf(n.toLowerCase()) === 0);
      if (k) return secs[k];
    }
    return null;
  };

  /**
   * The viewer needs sections and their tables, nothing more: the health
   * dashboard is driven purely by SNMP, so the per-section extraction that
   * used to feed it has been removed rather than left to rot.
   */
  function parse(text) {
    const { order, secs } = splitSections(text);
    return { order, secs };
  }

  const api = { parse, splitSections, parseTable, parseAllTables, parseKeyValues };

  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.TechParse = api;
})(typeof window !== 'undefined' ? window : globalThis);
