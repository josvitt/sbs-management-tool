'use strict';

/**
 * The app, answering from a recorded switch instead of a real one, for
 * looking at the panels in a browser without touching a switch.
 *
 *   node scripts/replay-server.js [recording]     (default: switch-253)
 *
 * Every SNMP request, whatever address it names, is answered from
 * test/fixtures/live/<recording>-agent.json. SETs are refused. Run it in a
 * copy of the app folder: it saves switches and history like the real app.
 */

const path = require('path');
const { setSessionFactory } = require('../snmp-core');
const { fakeSession } = require('./lib/snmp-recording');

const name = process.argv[2] || 'switch-253';
const rec = require(path.join(__dirname, '..', 'test', 'fixtures', 'live', name + '-agent.json'));
setSessionFactory(() => fakeSession(rec.varbinds));
console.log('Answering SNMP from the ' + name + ' recording.');
require('../server');
