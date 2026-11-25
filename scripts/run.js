'use strict';

/**
 * Runs the server in this window and starts it again when it exits to
 * install an update (exit code 75, see update-boot.js). start.bat uses it,
 * so an interactive run updates the same way the service does. Any other
 * exit (Ctrl+C, a crash) ends it.
 *
 *   node scripts/run.js
 */

const path = require('path');
const { spawn } = require('child_process');

const RESTART = 75;
const SERVER = path.join(__dirname, '..', 'server.js');

function start() {
  const child = spawn(process.execPath, [SERVER], { stdio: 'inherit', cwd: path.dirname(SERVER) });
  child.on('exit', (code, signal) => {
    if (code === RESTART) {
      console.log('Restarting to finish an update...');
      setTimeout(start, 1000);
    } else {
      process.exit(code == null ? (signal ? 1 : 0) : code);
    }
  });
}
// Ctrl+C reaches the server too (same console); just wait for it to exit.
process.on('SIGINT', () => {});
start();
