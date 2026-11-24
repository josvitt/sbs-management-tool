/**
 * Install SBS Management Tool as a Windows service via node-windows.
 *
 * Run by install-service.bat (as Administrator). The service runs server.js
 * headless under the LocalSystem account, auto-starts on boot, and restarts on
 * failure - so collection happens with no user logged in and survives a reboot
 * (SERVER-STANDARD §9). node-windows is only needed to create/remove the
 * service; the running service does not depend on it.
 *
 * Files stay in the install directory (__dirname): server.js, the vault key and
 * state.enc, history.json, and logs/. vault.js and the others are __dirname-
 * based, so the service and an interactive run resolve the SAME files.
 */

const path = require('path');

let Service;
try {
  ({ Service } = require('node-windows'));
} catch (e) {
  console.error('node-windows is not installed. Run install-service.bat, which installs it first.');
  process.exit(1);
}

const svc = new Service({
  name: 'SBS Management Tool',
  description: 'SBS Management Tool - Cisco Catalyst 1200/1300 management over SNMP/SSH/serial. ' +
    'Collects switch health, alerts, traps and syslog on its own, with no browser open.',
  script: path.join(__dirname, 'server.js'),
  workingDirectory: __dirname,
  // Restart on crash, backing off a little, but never give up for good.
  wait: 2,
  grow: 0.5,
  maxRestarts: 20,
  // Port / receiver ports can be overridden here if the defaults clash. The
  // service runs as LocalSystem, which can bind the privileged UDP ports
  // (traps 162, syslog 514, TFTP 69), so these are left at their defaults.
  env: [
    { name: 'PORT', value: process.env.PORT || '3000' }
  ]
});

svc.on('install', () => {
  console.log('Service installed. Starting it...');
  svc.start();
});
svc.on('alreadyinstalled', () => {
  console.log('The service is already installed. Use uninstall-service.bat first to reinstall.');
});
svc.on('start', () => {
  console.log('SBS Management Tool service is running.');
  console.log('Open the dashboard at http://localhost:' + (process.env.PORT || '3000') + ' (or run open-ui.bat),');
  console.log('then add your switches and credentials there - the service stores them and keeps collecting across reboots.');
});
svc.on('error', (e) => {
  console.error('Service error:', e && e.message ? e.message : e);
});

console.log('Installing the SBS Management Tool Windows service...');
svc.install();
