/**
 * Size-capped append-only line store with rotation.
 *
 * ONE place that decides when an on-disk log is "full" and rolls it over, so
 * every persistent store in the app (app.log, the event log, persisted traps
 * and syslog) caps its disk use the same way instead of each re-implementing
 * rotation (governing rule 3: use a helper, or create and document one).
 *
 * A store is `<file>`; its rotated generations are `<file>.1` (newest) …
 * `<file>.<keep>` (oldest). When `<file>` reaches `maxBytes` it becomes
 * `<file>.1`, the previous `.1` becomes `.2`, and the oldest beyond `keep` is
 * dropped. Appends are synchronous so a rotation can never interleave with a
 * concurrent write from the same process; every call is best-effort and never
 * throws (a logging store must not be able to crash the app).
 *
 * It also owns the other half of "how a store reaches disk": writeFileAtomic,
 * for the whole-file stores (state.enc, history.json, layouts.json). Those
 * were written in place, so a crash or power cut mid-write left a truncated
 * file. For the vault that meant every saved switch and credential at once.
 */

const fs = require('fs');
const path = require('path');

const DEFAULT_MAX_BYTES = 5 * 1024 * 1024;   // 5 MB per generation
const DEFAULT_KEEP = 5;                       // plus the live file

function rotateIfNeeded(file, maxBytes, keep) {
  let size;
  try {
    size = fs.statSync(file).size;
  } catch (e) {
    return;   // no file yet — nothing to rotate
  }
  if (size < maxBytes) return;
  try {
    const oldest = `${file}.${keep}`;
    if (fs.existsSync(oldest)) fs.unlinkSync(oldest);
    for (let i = keep - 1; i >= 1; i--) {
      const src = `${file}.${i}`;
      if (fs.existsSync(src)) fs.renameSync(src, `${file}.${i + 1}`);
    }
    fs.renameSync(file, `${file}.1`);
  } catch (e) {
    // Best effort: if rotation fails the next append simply lands on the
    // existing (over-size) file rather than losing the line.
  }
}

/**
 * Append one line to a rotating store. `opts.maxBytes` / `opts.keep` override
 * the defaults. Returns true on success, false if the write could not happen.
 */
function appendLine(file, line, opts) {
  const maxBytes = (opts && opts.maxBytes) || DEFAULT_MAX_BYTES;
  const keep = (opts && opts.keep) || DEFAULT_KEEP;
  try {
    const dir = path.dirname(file);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    rotateIfNeeded(file, maxBytes, keep);
    fs.appendFileSync(file, line.endsWith('\n') ? line : line + '\n');
    return true;
  } catch (e) {
    return false;
  }
}

/**
 * Read recent lines, newest-last, from the live file and (if asked) the
 * rotated generations, oldest first so chronological order is preserved.
 * `opts.limit` caps the returned count (default 500); `opts.generations`
 * includes `.1`…`.N` before the live file (default 0 = live file only).
 */
function readLines(file, opts) {
  const limit = (opts && opts.limit) || 500;
  const generations = (opts && opts.generations) || 0;
  const files = [];
  for (let i = generations; i >= 1; i--) files.push(`${file}.${i}`);
  files.push(file);
  const out = [];
  for (const f of files) {
    let text;
    try {
      text = fs.readFileSync(f, 'utf8');
    } catch (e) {
      continue;
    }
    for (const ln of text.split('\n')) {
      if (ln) out.push(ln);
    }
  }
  return out.slice(-limit);
}

/**
 * Replace a whole file so a reader only ever sees the old content or the new,
 * never half of one: write a sibling temp file, flush it to disk, then rename
 * it over the target (atomic on the same volume, Windows included).
 * `opts.mode` is applied to the new file (0o600 for secrets). Unlike
 * appendLine this THROWS on failure, because its callers already report a
 * failed save in their own words; the temp file is removed either way.
 */
function writeFileAtomic(file, data, opts) {
  const mode = opts && opts.mode;
  const tmp = `${file}.tmp-${process.pid}-${Date.now().toString(36)}`;
  let fd = null;
  try {
    fd = fs.openSync(tmp, 'w', mode === undefined ? 0o666 : mode);
    fs.writeFileSync(fd, data);
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = null;
    if (mode !== undefined) {
      try { fs.chmodSync(tmp, mode); } catch (e) { /* Windows has no mode */ }
    }
    fs.renameSync(tmp, file);
  } catch (e) {
    if (fd !== null) { try { fs.closeSync(fd); } catch (e2) { /* already closed */ } }
    try { fs.unlinkSync(tmp); } catch (e2) { /* never created */ }
    throw e;
  }
}

/**
 * Move a store written in an old place to where it belongs now, once. A file
 * moves when nothing is at the new path yet; a folder's files move one by
 * one, each only if the new folder has no file of that name (so nothing is
 * ever overwritten). Best-effort: returns how many entries moved and never
 * throws. Used when a store's path is corrected, e.g. the stores that sat
 * under routes/ after the route split.
 */
function adoptLegacy(from, to) {
  let moved = 0;
  let st;
  try { st = fs.statSync(from); } catch (e) { return 0; }
  try {
    if (!st.isDirectory()) {
      if (!fs.existsSync(to)) { fs.mkdirSync(path.dirname(to), { recursive: true }); fs.renameSync(from, to); moved++; }
      return moved;
    }
    for (const name of fs.readdirSync(from)) moved += adoptLegacy(path.join(from, name), path.join(to, name));
    try { fs.rmdirSync(from); } catch (e) { /* something stayed behind */ }
  } catch (e) { /* best effort */ }
  return moved;
}

module.exports = { appendLine, readLines, rotateIfNeeded, writeFileAtomic, adoptLegacy, DEFAULT_MAX_BYTES, DEFAULT_KEEP };
