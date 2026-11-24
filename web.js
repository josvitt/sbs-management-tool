'use strict';

/**
 * The Express app and the middleware every request passes through, in
 * order: the request guard, JSON parsing, compression, static files, request
 * logging, and the client log sink.
 */

const express = require('express');
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const crypto = require('crypto');
const log = require('./logger');
const guard = require('./request-guard');

const app = express();
// First, before any asset or route: refuse cross-site and DNS-rebinding
// requests (see request-guard.js). LAN access is unaffected.
app.use(guard.middleware(log));
app.use(express.json());
/**
 * Compress static assets. The MIB database alone is 2 MB of JSON fetched
 * on every page load and gzips to about 315 KB, so this is the single
 * biggest saving available. The files never change while the server runs,
 * so each compressed body is built once and reused.
 */
const gzipCache = new Map();
app.use((req, res, next) => {
  if (!/\.(json|js|css|html|svg|map)$/i.test(req.path)) return next();
  if (!/\bgzip\b/.test(req.headers['accept-encoding'] || '')) return next();

  const filePath = path.join(__dirname, 'public', path.normalize(req.path).replace(/^([.][.][/\\])+/, ''));
  if (!filePath.startsWith(path.join(__dirname, 'public'))) return next();   // no path escapes

  /**
   * Serve from the cache with a validator. Without one the browser
   * re-downloads every asset on every reload -- 315 KB of compressed MIB
   * database each time, for a file that has not changed. With it the
   * second load is a handful of 304s.
   */
  const serve = (entry) => {
    res.set({
      'Content-Encoding': 'gzip',
      'Content-Type': entry.type,
      Vary: 'Accept-Encoding',
      ETag: entry.etag,
      // Must-revalidate rather than a long max-age: these files change
      // when the app is updated, and a stale UI is worse than a request.
      'Cache-Control': 'no-cache'
    });
    if (req.headers['if-none-match'] === entry.etag) return res.status(304).end();
    return res.end(entry.body);
  };

  const cached = gzipCache.get(filePath);
  if (cached) return serve(cached);

  fs.readFile(filePath, (err, raw) => {
    if (err) return next();                        // not ours; let express.static answer
    zlib.gzip(raw, { level: 6 }, (gzErr, body) => {
      if (gzErr) return next();
      const type = express.static.mime.lookup(filePath) || 'application/octet-stream';
      const entry = {
        body, type,
        etag: '"' + crypto.createHash('sha1').update(raw).digest('base64').slice(0, 22) + '"'
      };
      gzipCache.set(filePath, entry);
      log.info('http', 'Compressed asset', {
        path: req.path, from: raw.length, to: body.length,
        saved: Math.round(100 - (100 * body.length) / raw.length) + '%'
      });
      serve(entry);
    });
  });
});

/**
 * Compress API responses too. A health collection from a switch with a
 * full forwarding database is a few hundred KB of highly repetitive JSON,
 * and it is re-fetched on every auto-refresh.
 */
app.use((req, res, next) => {
  const wantsGzip = /\bgzip\b/.test(req.headers['accept-encoding'] || '');
  if (!wantsGzip) return next();
  const original = res.json.bind(res);
  res.json = (body) => {
    let text;
    try { text = JSON.stringify(body); } catch (e) { return original(body); }
    if (text.length < 8192) return original(body);      // not worth the CPU
    zlib.gzip(text, { level: 6 }, (err, buf) => {
      if (err) return original(body);
      res.set({ 'Content-Type': 'application/json; charset=utf-8',
                'Content-Encoding': 'gzip', 'Vary': 'Accept-Encoding' });
      res.end(buf);
    });
    return res;
  };
  next();
});

app.use(express.static(path.join(__dirname, 'public')));

// Basic request logging.
app.use((req, res, next) => {
  log.info('http', `${req.method} ${req.url}`, { ip: req.ip });
  next();
});

// Frontend errors get POSTed here so they land in the same log file
// as backend events -- one place to look when something breaks.
app.post('/api/log', (req, res) => {
  const { level, message, meta } = req.body || {};
  const lvl = ['info', 'warn', 'error'].includes(level) ? level : 'error';
  log[lvl]('client', message || '(no message)', meta);
  res.status(204).end();
});

module.exports = app;
