'use strict';

/**
 * How many distinct senders the unsolicited receivers (syslog, traps) will
 * keep. The ONE rule for both, so they cannot drift (governing rule 3).
 *
 * Each receiver already bounds what it holds PER source, and each message is
 * also persisted to logs/<kind>/<source>.log. Neither bounded the NUMBER of
 * sources, and UDP source addresses are trivially spoofed: a flood from many
 * fake addresses grew memory and created a rotating file set per address.
 * Past the limit (SBS_MAX_STREAM_SOURCES, default 256: far more switches than
 * this app manages) a message from a source not already known is dropped and
 * logged once per minute. Sources already being heard are never affected.
 */

const LIMIT = Number(process.env.SBS_MAX_STREAM_SOURCES) || 256;
const WARN_EVERY_MS = 60000;

/**
 * `kind` names the receiver in the log; `known` is the receiver's own
 * Map of sources. Returns admit(source) -> true when the message may be kept.
 */
function sourceLimiter(kind, known, log) {
  let lastWarn = 0;
  let dropped = 0;
  return function admit(source) {
    if (known.has(source) || known.size < LIMIT) return true;
    dropped += 1;
    const now = Date.now();
    if (now - lastWarn >= WARN_EVERY_MS) {
      lastWarn = now;
      log.warn(kind, 'Dropping messages from new sources: source limit reached', {
        limit: LIMIT, dropped, latest: source
      });
    }
    return false;
  };
}

module.exports = { sourceLimiter, LIMIT };
