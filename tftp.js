/**
 * Minimal TFTP server, embedded so moving a file to or from a switch needs
 * no external server.
 *
 * Writes (RFC 1350 WRQ): the switch is told to copy its configuration or a
 * capture to us, and we receive it.
 *
 * Reads (RRQ): the switch is told to copy a file from us, a configuration
 * to restore or a firmware image. Only a file this app has offered can be
 * read (offer()), under a random name that expires; any other name is
 * refused, so the service never hands out anything it was not asked to.
 *
 * Received files are held in memory and handed to whoever asked for them.
 * Nothing touches the disk: a running-config contains credentials and
 * SNMP communities, and writing it out by default would be a poor trade
 * for something the user can save deliberately.
 */

const dgram = require('dgram');
const log = require('./logger');

const OP_RRQ = 1, OP_WRQ = 2, OP_DATA = 3, OP_ACK = 4, OP_ERROR = 5, OP_OACK = 6;
const DEFAULT_PORT = 69;
const BLOCK = 512;
const TRANSFER_TIMEOUT_MS = 60000;
// Limits on what an unauthenticated UDP sender can make this process hold.
// The receiver does not check the sender's address (doing so could refuse a
// switch that uploads from an interface other than the one it is managed on;
// not verified either way), so size and concurrency are what is capped. The
// largest legitimate upload is a packet capture copied off flash; the default
// leaves ample room for that. Tunable via env.
const MAX_FILE_BYTES = Number(process.env.TFTP_MAX_BYTES) || 256 * 1024 * 1024;
const MAX_TRANSFERS = Number(process.env.TFTP_MAX_TRANSFERS) || 16;

let socket = null;
let listening = false;
let listenPort = null;
const transfers = new Map();   // key: "ip:port" -> { name, chunks, block, ... }
const offers = new Map();      // filename -> { buffer, timer, served: [resolve], ... }
// A read transfer waits this long for each ACK before sending the block
// again, and gives up after READ_RETRIES silent tries.
const READ_RESEND_MS = 2000;
const READ_RETRIES = 6;
const completed = new Map();   // filename -> { buffer, from, at }
const waiters = new Map();     // filename -> [resolve, ...]

function cstr(buf, offset) {
  let end = offset;
  while (end < buf.length && buf[end] !== 0) end++;
  return { value: buf.toString('ascii', offset, end), next: end + 1 };
}

function sendError(rinfo, code, message) {
  const msg = Buffer.from(message, 'ascii');
  const pkt = Buffer.alloc(4 + msg.length + 1);
  pkt.writeUInt16BE(OP_ERROR, 0);
  pkt.writeUInt16BE(code, 2);
  msg.copy(pkt, 4);
  pkt[4 + msg.length] = 0;
  socket.send(pkt, rinfo.port, rinfo.address);
}

// Option Acknowledgement (RFC 2347): echoes the options the server accepts, as
// NUL-terminated name/value string pairs after the opcode. Without this, a
// client that offered options (e.g. blksize) errors out before falling back.
function sendOack(rinfo, options) {
  const parts = [Buffer.from([0x00, OP_OACK])];
  for (const [k, v] of Object.entries(options)) {
    parts.push(Buffer.from(String(k), 'ascii'), Buffer.from([0]),
      Buffer.from(String(v), 'ascii'), Buffer.from([0]));
  }
  const pkt = Buffer.concat(parts);
  socket.send(pkt, rinfo.port, rinfo.address);
}

function sendAck(rinfo, block) {
  const pkt = Buffer.alloc(4);
  pkt.writeUInt16BE(OP_ACK, 0);
  pkt.writeUInt16BE(block & 0xffff, 2);
  socket.send(pkt, rinfo.port, rinfo.address);
}

function finish(key, xfer) {
  clearTimeout(xfer.timer);
  const buffer = Buffer.concat(xfer.chunks);
  completed.set(xfer.name, { buffer, from: xfer.from, at: new Date() });
  log.info('tftp', 'Received file', { name: xfer.name, bytes: buffer.length, from: xfer.from });
  const list = waiters.get(xfer.name);
  if (list) {
    waiters.delete(xfer.name);
    for (const resolve of list) resolve(buffer);
  }
  // Don't forget the transfer immediately. The sender may retransmit the final
  // block if its last ACK was lost (a normal TFTP retry) - if the transfer is
  // already gone, that retry gets an "Unknown transfer" error, which the switch
  // logs as "Closed by application". Keep it in a 'done' state for a few
  // seconds so the retried final block is simply re-ACKed instead.
  xfer.done = true;
  clearTimeout(xfer.lingerTimer);
  xfer.lingerTimer = setTimeout(() => { transfers.delete(key); }, 5000);
}

function onMessage(msg, rinfo) {
  if (msg.length < 4) return;
  const op = msg.readUInt16BE(0);
  const key = rinfo.address + ':' + rinfo.port;

  if (op === OP_WRQ) {
    const name = cstr(msg, 2);
    const mode = cstr(msg, name.next);
    // After filename and mode come zero or more NUL-terminated option/value
    // pairs (RFC 2347): blksize, tsize, timeout, etc.
    const options = {};
    let pos = mode.next;
    while (pos < msg.length) {
      const opt = cstr(msg, pos); if (opt.next > msg.length) break;
      const val = cstr(msg, opt.next);
      options[opt.value.toLowerCase()] = val.value;
      pos = val.next;
    }
    // Accept the client's blksize offer (RFC 2348) with an OACK, which stops the
    // switch logging a "retrying with minimal block size" warning. IMPORTANT:
    // this switch, after an OACK, sends its FIRST data block numbered 0 (not 1
    // as RFC 2347 prescribes) - confirmed by packet capture against tftpd64,
    // which also accepts block 0. So after an OACK the first expected block is 0.
    // Getting this wrong is what dropped the first block (the pcap header) and
    // corrupted earlier exports.
    let blksize = BLOCK;
    if (options.blksize) {
      const want = parseInt(options.blksize, 10);
      if (Number.isFinite(want) && want >= 8) blksize = Math.min(want, 65464);
    }
    const accepted = {};
    if (options.blksize) accepted.blksize = String(blksize);
    if (options.tsize !== undefined) accepted.tsize = String(options.tsize);
    const hasOpts = Object.keys(accepted).length > 0;

    const existing = transfers.get(key);
    if (existing && !existing.done) {
      // Retransmitted WRQ for an in-progress transfer: repeat the original
      // response and keep the data already received (never reset).
      if (existing.oack) sendOack(rinfo, existing.oack);
      else sendAck(rinfo, 0);
      return;
    }

    if (transfers.size >= MAX_TRANSFERS) {
      log.warn('tftp', 'Write request refused: too many transfers in progress', { from: rinfo.address });
      sendError(rinfo, 3, 'Too many transfers in progress');
      return;
    }

    const xfer = {
      bytes: 0,
      name: name.value.replace(/^.*[\\/]/, ''),   // ignore any path the client sends
      chunks: [], from: rinfo.address,
      blksize: hasOpts ? blksize : BLOCK,
      oack: hasOpts ? accepted : null,
      // After an OACK this switch starts DATA at block 0, so the first expected
      // block is 0 (set lastBlock = -1). After a plain ACK-0, data starts at 1.
      block: hasOpts ? -1 : 0,
      timer: setTimeout(() => {
        transfers.delete(key);
        log.warn('tftp', 'Transfer timed out', { name: name.value, from: rinfo.address });
      }, TRANSFER_TIMEOUT_MS)
    };
    transfers.set(key, xfer);
    log.info('tftp', 'Write request', { name: xfer.name, from: rinfo.address, blksize: xfer.blksize });
    if (hasOpts) sendOack(rinfo, accepted);
    else sendAck(rinfo, 0);
    return;
  }

  if (op === OP_RRQ) {
    const name = cstr(msg, 2);
    const mode = cstr(msg, name.next);
    const options = {};
    let pos = mode.next;
    while (pos < msg.length) {
      const opt = cstr(msg, pos); if (opt.next > msg.length) break;
      const val = cstr(msg, opt.next);
      options[opt.value.toLowerCase()] = val.value;
      pos = val.next;
    }
    const bare = name.value.replace(/^.*[\\/]/, '');
    const offered = offers.get(bare);
    if (!offered) {
      log.warn('tftp', 'Read request refused: not an offered file', { name: bare, from: rinfo.address });
      sendError(rinfo, 1, 'File not found');
      return;
    }
    const existing = transfers.get(key);
    if (existing && existing.read && !existing.done) {
      // A repeated RRQ for a read in progress: repeat where we are.
      resendRead(key, existing);
      return;
    }
    if (transfers.size >= MAX_TRANSFERS) {
      sendError(rinfo, 3, 'Too many transfers in progress');
      return;
    }
    let blksize = BLOCK;
    if (options.blksize) {
      const want = parseInt(options.blksize, 10);
      // 1428 keeps a block inside one 1500-byte Ethernet frame.
      if (Number.isFinite(want) && want >= 8) blksize = Math.min(want, 1428);
    }
    const accepted = {};
    if (options.blksize) accepted.blksize = String(blksize);
    if (options.tsize !== undefined) accepted.tsize = String(offered.buffer.length);
    const hasOpts = Object.keys(accepted).length > 0;
    const xfer = {
      read: true, name: bare, buffer: offered.buffer, from: rinfo.address, rinfo,
      blksize, last: Math.floor(offered.buffer.length / blksize) + 1,
      // n: the block last sent. 0 means only the OACK is out.
      n: 0, oack: hasOpts ? accepted : null, tries: 0, timer: null
    };
    transfers.set(key, xfer);
    log.info('tftp', 'Read request', { name: bare, from: rinfo.address, bytes: offered.buffer.length, blksize });
    if (hasOpts) { sendOack(rinfo, accepted); armRead(key, xfer); }
    else sendBlock(key, xfer, 1);
    return;
  }

  if (op === OP_ACK) {
    const xfer = transfers.get(key);
    if (!xfer || !xfer.read || xfer.done) return;
    const block = msg.readUInt16BE(2);
    // Only the ACK for the block last sent moves on. An older one is a
    // duplicate, and answering it would double the traffic.
    if (block !== (xfer.n & 0xffff)) return;
    if (xfer.n === xfer.last) { finishRead(key, xfer); return; }
    sendBlock(key, xfer, xfer.n + 1);
    return;
  }

  if (op === OP_DATA) {
    const xfer = transfers.get(key);
    if (!xfer) { sendError(rinfo, 5, 'Unknown transfer'); return; }
    const block = msg.readUInt16BE(2);
    const data = msg.slice(4);
    // Transfer already finished: this is a retransmitted final block because
    // our last ACK was lost. Just re-ACK it (the data is already saved) - do
    // not error, do not finish again.
    if (xfer.done) { sendAck(rinfo, block); return; }
    const expected = (xfer.block + 1) & 0xffff;
    if (block === expected) {
      xfer.bytes += data.length;
      if (xfer.bytes > MAX_FILE_BYTES) {
        clearTimeout(xfer.timer);
        transfers.delete(key);
        log.warn('tftp', 'Upload refused: larger than TFTP_MAX_BYTES', { name: xfer.name, from: xfer.from, limit: MAX_FILE_BYTES });
        sendError(rinfo, 3, 'File too large');
        return;
      }
      xfer.chunks.push(data);
      xfer.block = block;
    }
    // Re-ACK duplicates too: a lost ACK makes the sender repeat the block,
    // and staying silent would stall the transfer.
    sendAck(rinfo, block);
    // A block shorter than the negotiated size is the last one.
    if (data.length < (xfer.blksize || BLOCK)) finish(key, xfer);
    return;
  }

  if (op === OP_ERROR) {
    const xfer = transfers.get(key);
    if (xfer) { clearTimeout(xfer.timer); clearTimeout(xfer.lingerTimer); transfers.delete(key); }
    const message = cstr(msg, 4).value;
    log.error('tftp', 'Client reported an error', { from: rinfo.address, message });
  }
}

// ---- the read side -------------------------------------------------------

function sendBlock(key, xfer, n) {
  xfer.n = n;
  xfer.tries = 0;
  writeBlock(xfer);
  armRead(key, xfer);
}

function writeBlock(xfer) {
  const n = xfer.n;
  const start = (n - 1) * xfer.blksize;
  const data = xfer.buffer.slice(start, Math.min(start + xfer.blksize, xfer.buffer.length));
  const pkt = Buffer.alloc(4 + data.length);
  pkt.writeUInt16BE(OP_DATA, 0);
  // Block numbers wrap past 65535 to 0, which is what switches and common
  // servers do for files larger than 65535 blocks.
  pkt.writeUInt16BE(n & 0xffff, 2);
  data.copy(pkt, 4);
  socket.send(pkt, xfer.rinfo.port, xfer.rinfo.address);
}

function resendRead(key, xfer) {
  if (xfer.n === 0) sendOack(xfer.rinfo, xfer.oack);
  else writeBlock(xfer);
}

function armRead(key, xfer) {
  clearTimeout(xfer.timer);
  xfer.timer = setTimeout(() => {
    if (xfer.done) return;
    if (++xfer.tries > READ_RETRIES) {
      transfers.delete(key);
      log.warn('tftp', 'Read transfer timed out', { name: xfer.name, from: xfer.from, block: xfer.n, of: xfer.last });
      return;
    }
    resendRead(key, xfer);
    armRead(key, xfer);
  }, READ_RESEND_MS);
}

function finishRead(key, xfer) {
  clearTimeout(xfer.timer);
  xfer.done = true;
  log.info('tftp', 'Sent file', { name: xfer.name, bytes: xfer.buffer.length, to: xfer.from });
  const offered = offers.get(xfer.name);
  if (offered) {
    offered.sentTo = xfer.from;
    for (const resolve of offered.served.splice(0)) resolve({ bytes: xfer.buffer.length, to: xfer.from });
  }
  transfers.delete(key);
}

/**
 * Make a file readable over TFTP under `name` for ttlMs. Returns a promise
 * that resolves once a client has read the whole file. The offer stays
 * until withdraw() or the ttl, so a switch that retries can read it again.
 */
function offer(name, buffer, ttlMs) {
  withdraw(name);
  const entry = { buffer, served: [], sentTo: null, timer: null };
  entry.timer = setTimeout(() => withdraw(name), ttlMs || 15 * 60000);
  offers.set(name, entry);
  return new Promise((resolve) => entry.served.push(resolve));
}

/** Stop serving an offered file. */
function withdraw(name) {
  const entry = offers.get(name);
  if (!entry) return;
  clearTimeout(entry.timer);
  offers.delete(name);
}

/** Has a client read the whole of this offered file? */
function wasServed(name) {
  const entry = offers.get(name);
  return !!(entry && entry.sentTo);
}

/** Start listening. Resolves with the port actually in use. */
function start(port) {
  if (listening) return Promise.resolve(listenPort);
  // 0 asks the OS for any free port (as in Node's own APIs); unset is 69.
  const want = port === 0 ? 0 : (port || DEFAULT_PORT);
  return new Promise((resolve, reject) => {
    socket = dgram.createSocket('udp4');
    socket.on('error', (err) => {
      log.error('tftp', 'Socket error', { message: err.message });
      listening = false;
      reject(err);
    });
    socket.on('message', (msg, rinfo) => {
      try { onMessage(msg, rinfo); }
      catch (e) { log.error('tftp', 'Failed handling packet', { message: e.message }); }
    });
    socket.bind(want, () => {
      listening = true;
      listenPort = socket.address().port;
      log.info('tftp', 'TFTP receiver listening', { port: listenPort });
      resolve(listenPort);
    });
  });
}

/** Wait for a named file to arrive, or time out. */
function expect(name, timeoutMs) {
  const done = completed.get(name);
  if (done) return Promise.resolve(done.buffer);
  return new Promise((resolve, reject) => {
    let timer = null;
    const settle = (buffer) => { clearTimeout(timer); resolve(buffer); };
    const list = waiters.get(name) || [];
    list.push(settle);
    waiters.set(name, list);
    timer = setTimeout(() => {
      const l = waiters.get(name);
      if (l) {
        const i = l.indexOf(settle);
        if (i >= 0) l.splice(i, 1);
        if (!l.length) waiters.delete(name);
      }
      if (!completed.has(name)) {
        reject(new Error('No file arrived over TFTP within ' + Math.round((timeoutMs || 60000) / 1000) + 's'));
      }
    }, timeoutMs || 60000);
  });
}

function forget(name) {
  completed.delete(name);
}

function status() {
  return { listening, port: listenPort, inFlight: transfers.size, held: completed.size, offered: offers.size };
}

module.exports = { start, expect, forget, status, offer, withdraw, wasServed, DEFAULT_PORT };
