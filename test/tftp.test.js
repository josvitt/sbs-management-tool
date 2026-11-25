'use strict';
// The TFTP server over real UDP on an ephemeral port: a normal upload still
// arrives whole, an oversized one is refused, and only an offered file can
// be read back.
const test = require('node:test');
const assert = require('node:assert/strict');
const dgram = require('dgram');

process.env.TFTP_MAX_BYTES = String(2048);
const tftp = require('../tftp');

function wrq(name, opts) {
  const parts = [Buffer.from([0, 2]), Buffer.from(name + '\0octet\0')];
  for (const [k, v] of Object.entries(opts || {})) parts.push(Buffer.from(k + '\0' + v + '\0'));
  return Buffer.concat(parts);
}
function data(block, payload) {
  const b = Buffer.alloc(4); b.writeUInt16BE(3, 0); b.writeUInt16BE(block, 2);
  return Buffer.concat([b, payload]);
}

// A tiny lock-step client: send a packet, wait for the reply.
function client(port) {
  const sock = dgram.createSocket('udp4');
  const queue = [];
  let waiting = null;
  sock.on('message', (m) => { if (waiting) { const w = waiting; waiting = null; w(m); } else queue.push(m); });
  const next = () => new Promise((resolve) => { if (queue.length) resolve(queue.shift()); else waiting = resolve; });
  return {
    send: (pkt) => new Promise((r) => sock.send(pkt, port, '127.0.0.1', r)).then(next),
    fire: (pkt) => new Promise((r) => sock.send(pkt, port, '127.0.0.1', r)),
    close: () => sock.close()
  };
}

test('an upload within the limit arrives whole (plain RFC 1350 transfer)', async () => {
  const port = await tftp.start(0);
  const c = client(port);
  const body = Buffer.alloc(700, 0x41);                   // two blocks: 512 + 188
  const got = tftp.expect('ok.cfg', 5000);
  let r = await c.send(wrq('ok.cfg'));
  assert.equal(r.readUInt16BE(0), 4);                     // ACK 0
  r = await c.send(data(1, body.subarray(0, 512)));
  assert.equal(r.readUInt16BE(2), 1);
  r = await c.send(data(2, body.subarray(512)));
  assert.equal(r.readUInt16BE(2), 2);
  assert.deepEqual(await got, body);
  c.close();
});

test('an upload over TFTP_MAX_BYTES is refused with a TFTP error and never delivered', async () => {
  const port = await tftp.start(0);
  const c = client(port);
  await c.send(wrq('big.cfg'));
  let r;
  for (let block = 1; block <= 5; block++) {
    r = await c.send(data(block, Buffer.alloc(512, 0x42)));
    if (r.readUInt16BE(0) === 5) break;                   // ERROR
  }
  assert.equal(r.readUInt16BE(0), 5);
  assert.match(r.toString('ascii', 4), /too large/i);
  await assert.rejects(tftp.expect('big.cfg', 300), /No file arrived/);
  c.close();
});

function rrq(name, opts) {
  const parts = [Buffer.from([0, 1]), Buffer.from(name + '\0octet\0')];
  for (const [k, v] of Object.entries(opts || {})) parts.push(Buffer.from(k + '\0' + v + '\0'));
  return Buffer.concat(parts);
}
function ack(block) {
  const b = Buffer.alloc(4); b.writeUInt16BE(4, 0); b.writeUInt16BE(block, 2);
  return b;
}
// Read a whole file: the reply to the RRQ (DATA 1 or an OACK), then ACK
// each block until a short one.
async function readAll(c, name, opts) {
  let r = await c.send(rrq(name, opts));
  const out = [];
  let oack = null;
  if (r.readUInt16BE(0) === 6) { oack = r; r = await c.send(ack(0)); }
  for (;;) {
    assert.equal(r.readUInt16BE(0), 3, 'expected DATA');
    const payload = r.subarray(4);
    out.push(payload);
    const size = opts && opts.blksize ? Number(opts.blksize) : 512;
    if (payload.length < size) { await c.fire(ack(r.readUInt16BE(2))); break; }
    r = await c.send(ack(r.readUInt16BE(2)));
  }
  return { body: Buffer.concat(out), oack };
}

test('a read of a name that was never offered is refused', async () => {
  const port = await tftp.start(0);
  const c = client(port);
  const r = await c.send(rrq('anything.cfg'));
  assert.equal(r.readUInt16BE(0), 5);
  assert.equal(r.readUInt16BE(2), 1);                     // file not found
  c.close();
});

test('an offered file is read whole (plain RFC 1350), and served resolves', async () => {
  const port = await tftp.start(0);
  const c = client(port);
  const body = Buffer.from('x'.repeat(700));
  const served = tftp.offer('restore-1.cfg', body, 5000);
  const got = await readAll(c, 'restore-1.cfg');
  assert.deepEqual(got.body, body);
  const s = await served;
  assert.equal(s.bytes, 700);
  assert.equal(tftp.wasServed('restore-1.cfg'), true);
  tftp.withdraw('restore-1.cfg');
  c.close();
});

test('blksize and tsize are answered with an OACK; an exact multiple ends with an empty block', async () => {
  const port = await tftp.start(0);
  const c = client(port);
  const body = Buffer.alloc(2048, 0x43);                  // two full 1024-byte blocks
  tftp.offer('img.bin', body, 5000);
  const got = await readAll(c, 'img.bin', { blksize: '1024', tsize: '0' });
  assert.match(got.oack.toString('ascii', 2), /blksize\0001024\000tsize\0002048\0/);
  assert.deepEqual(got.body, body);
  tftp.withdraw('img.bin');
  c.close();
});

test('a withdrawn offer can no longer be read', async () => {
  const port = await tftp.start(0);
  const c = client(port);
  tftp.offer('gone.cfg', Buffer.from('abc'), 5000);
  tftp.withdraw('gone.cfg');
  const r = await c.send(rrq('gone.cfg'));
  assert.equal(r.readUInt16BE(0), 5);
  c.close();
});
