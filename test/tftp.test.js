'use strict';
// The TFTP receiver over real UDP on an ephemeral port: a normal upload still
// arrives whole, and an oversized one is refused.
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
