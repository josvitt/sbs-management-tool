'use strict';

/**
 * Spanning tree settings (switch-stp.js): on or off, the mode, the bridge
 * priority (switch, VLAN or MSTP instance) and per-port settings. Every
 * route that changes the switch passes writeHold(), so the collector is not
 * reading while it writes.
 */

const stp = require('../switch-stp');
const R = require('./lib/settings-route');
const writeRoute = (app, path, what, fn) => R.writeRoute(app, 'stp', path, what, fn);

module.exports = function register(app) {
  // Body: { target }
  R.readRoute(app, '/api/stp/status', (s) => stp.readStp(s));

  // { on }
  writeRoute(app, '/api/stp/enabled', 'Spanning tree turned on or off', (s, b) => stp.setEnabled(s, !!b.on));
  // { mode }
  writeRoute(app, '/api/stp/mode', 'Spanning tree mode changed', (s, b) => stp.setMode(s, b.mode));
  // { priority }
  writeRoute(app, '/api/stp/priority', 'Bridge priority changed', (s, b) => stp.setBridgePriority(s, b.priority));
  // { port, enabled?, priority?, cost?, edge?, autoEdge?, bpduGuard? }
  writeRoute(app, '/api/stp/port', 'Spanning tree port settings changed', (s, b) =>
    stp.setPort(s, b.port, { enabled: b.enabled, priority: b.priority, cost: b.cost, edge: b.edge, autoEdge: b.autoEdge, bpduGuard: b.bpduGuard }));
};
