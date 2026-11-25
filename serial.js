/**
 * Console (serial) connectivity.
 *
 * A switch that will not answer on the network still answers on its
 * console port, which is exactly when you most need to talk to it: no IP
 * yet, a bad VLAN, a locked-out management interface. Same terminal, same
 * capture machinery, different transport.
 *
 * `serialport` is treated as optional. It ships prebuilt binaries for
 * Windows and macOS, but a machine without them should lose the console
 * feature rather than fail to start the app, so the require is guarded and
 * the reason is reported to the UI.
 */

const log = require('./logger');

let SerialPort = null;
let loadError = null;
try {
  SerialPort = require('serialport').SerialPort;
} catch (e) {
  // The stack and paths go to the log; the person sees what to do.
  loadError = 'Serial support isn\u2019t installed on this computer. Run npm install in the app folder (or reinstall the app) to add it, then restart the app.';
  log.warn('serial', 'Serial support unavailable', { message: e.message, stack: e.stack });
}

// The rates a Catalyst console actually uses, most likely first. 115200 is
// the default on current firmware; 9600 is what older units ship with.
const BAUD_RATES = [115200, 9600, 19200, 38400, 57600, 230400];

/**
 * Which ports this process currently holds. A serial port is exclusive:
 * if a previous handle is still open -- a tab closed mid-write, a session
 * that ended untidily -- reopening fails with "Resource temporarily
 * unavailable", and the operator sees a dead console with a working
 * cable. Tracking our own handles means the stale one can be closed and
 * the open retried, rather than blaming the hardware.
 */
const openPorts = new Map();

const available = () => !!SerialPort;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Close a handle and wait for the OS to actually release it. */
function closeHandle(port, path) {
  return new Promise((resolve) => {
    if (!port || !port.isOpen) { resolve(); return; }
    let settled = false;
    const done = () => { if (!settled) { settled = true; resolve(); } };
    port.once('close', done);
    try {
      // Let anything queued go out before the handle disappears, so the
      // switch is not left mid-line.
      port.drain(() => port.close(() => done()));
    } catch (e) {
      done();
    }
    // A port that will not close should not hang the next attempt.
    setTimeout(done, 1500);
  }).then(() => {
    if (openPorts.get(path) === port) openPorts.delete(path);
  });
}

/** Release any handle this process still holds for a path. */
async function release(path) {
  const held = openPorts.get(path);
  if (!held) return false;
  log.info('serial', 'Releasing a port still held from a previous session', { path });
  await closeHandle(held, path);
  await sleep(250);   // the OS needs a moment before it will hand it back
  return true;
}

/**
 * List the serial ports the machine can see. On Linux this needs udevadm,
 * which is not always present; that is reported rather than thrown, since
 * an empty list and a broken list mean different things to the operator.
 */
async function listPorts() {
  if (!SerialPort) {
    return { available: false, error: loadError || 'Serial support isn\u2019t installed on this computer.', ports: [] };
  }
  try {
    const ports = await SerialPort.list();
    return {
      available: true,
      ports: ports.map((p) => ({
        path: p.path,
        // Windows gives a friendly name; Linux and macOS give ids.
        label: p.friendlyName || p.manufacturer || p.pnpId || p.path,
        manufacturer: p.manufacturer || null,
        serialNumber: p.serialNumber || null
      }))
    };
  } catch (e) {
    log.error('serial', 'Could not list serial ports', { message: e.message });
    return { available: true, error: e.message, ports: [] };
  }
}

/**
 * Bridge one serial port to a WebSocket. Mirrors the SSH bridge's message
 * shapes so the browser can use one terminal for both.
 */
async function attach(ws, opts, hooks) {
  const path = String(opts.path || '').trim();
  const baudRate = Number(opts.baudRate) || 115200;
  if (!SerialPort) throw new Error(loadError || 'Serial support is not available on this machine.');
  if (!path) throw new Error('No serial port given.');

  // Anything we are still holding on this path is ours to clean up.
  await release(path);

  const make = () => new SerialPort({
    path,
    baudRate,
    dataBits: Number(opts.dataBits) || 8,
    stopBits: Number(opts.stopBits) || 1,
    parity: opts.parity || 'none',
    autoOpen: false
  });

  let port = make();

  const started = (p) => {
    openPorts.set(path, p);
    log.info('serial', 'Console port open', { path, baudRate });
    hooks.onOpen({ path, baudRate });
    // A console gives nothing until it is prodded: a bare newline makes the
    // switch print its prompt, so the terminal is not blank on arrival.
    try { p.write('\r\n'); } catch (e) { /* nothing to do */ }
  };

  port.open(async (err) => {
    if (!err) { started(port); return; }
    // A handle that has not finished dying -- ours, or one the OS has not
    // reaped -- reports busy; a port that has just been plugged in can
    // report missing for a moment. Both are worth one retry after a pause,
    // which fixes them far more often than telling the operator to unplug
    // the cable.
    const busy = /busy|unavailable|EBUSY|EAGAIN|Access denied|cannot open|No such file/i.test(err.message || '');
    log.error('serial', 'Could not open the port', { path, baudRate, message: err.message, willRetry: busy });
    if (!busy) { hooks.onError(err.message); return; }
    await release(path);
    await sleep(600);
    port = make();
    port.on('data', onData);
    port.on('error', onError);
    port.on('close', onClose);
    port.open((err2) => {
      if (err2) {
        // Say what happened, not what probably caused it: "held by another
        // program" is a guess, and a wrong guess sends someone hunting for
        // a program that is not there.
        hooks.onError(err2.message + ' (retried once after releasing our own handle)');
        return;
      }
      log.info('serial', 'Console port opened on retry', { path });
      started(port);
    });
  });

  const onData = (buf) => hooks.onData(buf.toString('utf8'));
  const onError = (e) => {
    log.error('serial', 'Port error', { path, message: e.message });
    hooks.onError(e.message);
  };
  const onClose = () => {
    if (openPorts.get(path) === port) openPorts.delete(path);
    log.info('serial', 'Console port closed', { path });
    hooks.onClose();
  };
  port.on('data', onData);
  port.on('error', onError);
  port.on('close', onClose);

  return {
    write(data) {
      try { if (port && port.isOpen) port.write(data); } catch (e) { /* closed under us */ }
    },
    close() { return closeHandle(port, path); },
    describe() { return path + ' @ ' + baudRate; }
  };
}

module.exports = { available, listPorts, attach, release, BAUD_RATES };
