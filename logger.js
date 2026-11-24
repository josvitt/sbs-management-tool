/**
 * Minimal structured logger.
 * - Writes timestamped lines to the console AND to logs/app.log
 * - Never logs password fields (redacted before formatting)
 * - No external dependencies, so nothing extra to install on Windows
 */

const fs = require('fs');
const path = require('path');
const rotate = require('./rotate');

const LOG_DIR = path.join(__dirname, 'logs');
const LOG_FILE = path.join(LOG_DIR, 'app.log');

// app.log is written for the life of the process; left unbounded it grows
// forever on a machine running as an unattended service. Cap each generation
// and keep a handful, through the shared rotation helper. Tunable via env.
const LOG_MAX_BYTES = Number(process.env.LOG_MAX_BYTES) || 10 * 1024 * 1024;
const LOG_KEEP = Number(process.env.LOG_KEEP) || 5;

if (!fs.existsSync(LOG_DIR)) {
  fs.mkdirSync(LOG_DIR, { recursive: true });
}

function redact(meta) {
  if (!meta || typeof meta !== 'object') return meta;
  const clone = { ...meta };
  for (const key of Object.keys(clone)) {
    if (/pass(word)?|secret|token/i.test(key)) {
      clone[key] = '[REDACTED]';
    }
  }
  return clone;
}

function format(level, source, message, meta) {
  const timestamp = new Date().toISOString();
  const safeMeta = redact(meta);
  const metaStr = safeMeta && Object.keys(safeMeta).length ? ' ' + JSON.stringify(safeMeta) : '';
  return `[${timestamp}] [${level}] [${source}] ${message}${metaStr}`;
}

function write(line) {
  // Console output
  console.log(line);
  // File output (best-effort, size-capped with rotation; a logging failure
  // must never crash the app).
  if (!rotate.appendLine(LOG_FILE, line, { maxBytes: LOG_MAX_BYTES, keep: LOG_KEEP })) {
    console.error(`[logger] Failed to write to ${LOG_FILE}`);
  }
}

function log(level, source, message, meta) {
  write(format(level, source, message, meta));
}

module.exports = {
  info: (source, message, meta) => log('INFO', source, message, meta),
  warn: (source, message, meta) => log('WARN', source, message, meta),
  error: (source, message, meta) => log('ERROR', source, message, meta),
  LOG_FILE
};
