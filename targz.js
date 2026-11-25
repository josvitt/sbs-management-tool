'use strict';

/**
 * Unpacks a .tar.gz (the source archive GitHub serves for a release) into a
 * folder. Node has gzip but no tar, and the app must not depend on a tar
 * program being installed, so this reads the format itself: ustar headers,
 * the pax `path` record and GNU long names, which is what `git archive`
 * (GitHub's archiver) writes.
 *
 * It only ever creates plain files and folders inside `dest`: links and
 * device entries are skipped, and an entry whose path is absolute, has a
 * drive letter or climbs out with `..` stops the whole extraction. `strip`
 * drops leading path parts (GitHub wraps everything in `<owner>-<repo>-<sha>/`).
 */

const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const MAX_UNPACKED = 300 * 1024 * 1024;

function str(buf, start, len) {
  const s = buf.subarray(start, start + len);
  const nul = s.indexOf(0);
  return s.subarray(0, nul === -1 ? s.length : nul).toString('utf8');
}
function octal(buf, start, len) {
  const s = str(buf, start, len).trim();
  return s ? parseInt(s, 8) : 0;
}
function paxPath(data) {
  // Records are "<len> key=value\n".
  let i = 0; let found = null;
  while (i < data.length) {
    const sp = data.indexOf(0x20, i);
    if (sp === -1) break;
    const len = parseInt(data.subarray(i, sp).toString('utf8'), 10);
    if (!len) break;
    const rec = data.subarray(sp + 1, i + len - 1).toString('utf8');
    const eq = rec.indexOf('=');
    if (eq > 0 && rec.slice(0, eq) === 'path') found = rec.slice(eq + 1);
    i += len;
  }
  return found;
}

function safeRelative(name, strip) {
  if (/^[\\/]/.test(name) || /^[a-zA-Z]:/.test(name) || name.includes('\\')) {
    throw new Error('Archive entry has an unsafe path: ' + name);
  }
  const parts = name.split('/').filter((x) => x && x !== '.');
  if (parts.includes('..')) throw new Error('Archive entry has an unsafe path: ' + name);
  return parts.slice(strip).join('/');
}

/** Returns { files, dirs, skipped } counts. Throws on a malformed archive. */
function extractTarGz(gz, dest, opts) {
  opts = opts || {};
  const strip = opts.strip == null ? 1 : opts.strip;
  const tar = zlib.gunzipSync(gz, { maxOutputLength: opts.maxBytes || MAX_UNPACKED });
  const root = path.resolve(dest);
  fs.mkdirSync(root, { recursive: true });
  const out = { files: 0, dirs: 0, skipped: 0 };
  let nextName = null;
  let off = 0;
  while (off + 512 <= tar.length) {
    const h = tar.subarray(off, off + 512);
    if (h.every((b) => b === 0)) break;
    const size = octal(h, 124, 12);
    const type = String.fromCharCode(h[156] || 0x30);
    const data = tar.subarray(off + 512, off + 512 + size);
    if (data.length < size) throw new Error('Archive is truncated');
    off += 512 + Math.ceil(size / 512) * 512;

    if (type === 'x') { nextName = paxPath(data) || nextName; continue; }
    if (type === 'g') continue;
    if (type === 'L') { nextName = str(data, 0, data.length); continue; }

    let name = nextName;
    nextName = null;
    if (!name) {
      const prefix = str(h, 257, 5) === 'ustar' ? str(h, 345, 155) : '';
      name = (prefix ? prefix + '/' : '') + str(h, 0, 100);
    }
    const rel = safeRelative(name, strip);
    if (!rel) continue;
    const target = path.join(root, rel);
    if (target !== root && !target.startsWith(root + path.sep)) throw new Error('Archive entry has an unsafe path: ' + name);

    if (type === '5') {
      fs.mkdirSync(target, { recursive: true }); out.dirs++;
    } else if (type === '0' || type === '7') {
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.writeFileSync(target, data, { mode: (octal(h, 100, 8) & 0o755) | 0o600 });
      out.files++;
    } else {
      out.skipped++;   // symlink, hard link, device, fifo
    }
  }
  return out;
}

module.exports = { extractTarGz };
