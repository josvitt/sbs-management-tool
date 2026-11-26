'use strict';

/**
 * QoS settings (switch-qos.js): the QoS mode and trust, trust per port, the
 * port shaper and rate limit, queue shapers, and the CoS and DSCP queue
 * maps. Writes pass the write hold (routes/lib/settings-route.js).
 */

const qos = require('../switch-qos');
const R = require('./lib/settings-route');
const writeRoute = (app, path, what, fn) => R.writeRoute(app, 'qos', path, what, fn);

module.exports = function register(app) {
  // Body: { target }
  R.readRoute(app, '/api/qos/status', (s) => qos.readQos(s));

  // { mode: 'disable' | 'basic' | 'advanced' }
  writeRoute(app, '/api/qos/mode', 'QoS mode changed', (s, b) => qos.setMode(s, b.mode));
  // { trust: 'cos' | 'dscp' | 'cos-dscp' }
  writeRoute(app, '/api/qos/trust', 'QoS trust changed', (s, b) => qos.setTrust(s, b.trust));
  // { ifIndex, on }
  writeRoute(app, '/api/qos/port-trust', 'QoS trust on a port changed', (s, b) => qos.setPortTrust(s, b.ifIndex, !!b.on));
  // { ifIndex, cir, cbs? }  cir 0 turns the shaper off
  writeRoute(app, '/api/qos/port-shaper', 'Port shaper changed', (s, b) => qos.setPortShaper(s, b.ifIndex, b.cir, b.cbs));
  // { ifIndex, rate }  rate 0 turns the limit off
  writeRoute(app, '/api/qos/rate-limit', 'Port rate limit changed', (s, b) => qos.setRateLimit(s, b.ifIndex, b.rate));
  // { ifIndex, queue, cir, cbs? }
  writeRoute(app, '/api/qos/queue-shaper', 'Queue shaper changed', (s, b) => qos.setQueueShaper(s, b.ifIndex, b.queue, b.cir, b.cbs));
  // { cos, queue }
  writeRoute(app, '/api/qos/cos-map', 'CoS queue map changed', (s, b) => qos.setCosQueue(s, b.cos, b.queue));
  // { dscp, queue }
  writeRoute(app, '/api/qos/dscp-map', 'DSCP queue map changed', (s, b) => qos.setDscpQueue(s, b.dscp, b.queue));
  // { map: 'cos' | 'dscp' }
  writeRoute(app, '/api/qos/restore-map', 'QoS queue map put back to defaults', (s, b) => qos.restoreMap(s, b.map));
};
