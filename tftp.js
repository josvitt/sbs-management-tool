/**
 * Minimal TFTP receiver, embedded so pulling a configuration needs no
 * external server.
 *
 * Only the write direction is implemented (RFC 1350 WRQ): the switch is
 * told to copy its configuration to us, so we are always the receiver.
 * Read requests are answered with an error rather than being silently
 * ignored, so a misconfigured copy fails fast instead of hanging.
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

let socket = null;
let listening = false;
let listenPort = null;
const transfers = new Map();   // key: "ip:port" -> { name, chunks, block, ... }
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

    const xfer = {
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
    log.warn('tftp', 'Read request refused (receiver only)', { name: name.value, from: rinfo.address });
    sendError(rinfo, 4, 'This TFTP service only accepts uploads');
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
    if (xfer) { clearTimeout(xfer.timer); transfers.delete(key); }
    const message = cstr(msg, 4).value;
    log.error('tftp', 'Client reported an error', { from: rinfo.address, message });
  }
}

/** Start listening. Resolves with the port actually in use. */
function start(port) {
  if (listening) return Promise.resolve(listenPort);
  const want = port || DEFAULT_PORT;
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
    const list = waiters.get(name) || [];
    list.push(resolve);
    waiters.set(name, list);
    setTimeout(() => {
      const l = waiters.get(name);
      if (l) {
        const i = l.indexOf(resolve);
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
  return { listening, port: listenPort, inFlight: transfers.size, held: completed.size };
}

module.exports = { start, expect, forget, status, DEFAULT_PORT };
