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

module.exports = { appendLine, readLines, rotateIfNeeded, DEFAULT_MAX_BYTES, DEFAULT_KEEP };
