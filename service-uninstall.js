/**
 * Remove the SBS Management Tool Windows service (node-windows).
 * Run by uninstall-service.bat (as Administrator). This removes the service
 * only; it leaves your data in place (the vault key, state.enc, history.json
 * and logs/ stay in the install directory).
 */

const path = require('path');

let Service;
try {
  ({ Service } = require('node-windows'));
} catch (e) {
  console.error('node-windows is not installed, so there is nothing to uninstall with it.');
  process.exit(1);
}

const svc = new Service({
  name: 'SBS Management Tool',
  script: path.join(__dirname, 'server.js')
});

svc.on('uninstall', () => {
  console.log('Service uninstalled.' + (svc.exists ? ' (it still reports as existing - give it a moment)' : ''));
  console.log('Your saved switches and history were left in place.');
});
svc.on('error', (e) => console.error('Service error:', e && e.message ? e.message : e));

console.log('Removing the SBS Management Tool Windows service...');
svc.uninstall();
