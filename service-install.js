/**
 * Install SBS Management Tool as a Windows service via node-windows.
 *
 * Run by install-service.bat (as Administrator). The service runs server.js
 * headless, auto-starts on boot, and restarts on failure - so collection
 * happens with no user logged in and survives a reboot (SERVER-STANDARD §9).
 * node-windows is only needed to create/remove the service; the running
 * service does not depend on it.
 *
 * It runs as LocalService, not LocalSystem: an account with no rights over
 * the rest of the machine. Windows lets any account bind the receivers' UDP
 * ports (69, 162, 514), so LocalService loses nothing the app uses; the one
 * thing it needs is write access to this folder, granted here before the
 * service first starts. SBS_SERVICE_ACCOUNT=LocalSystem keeps the old
 * account. node-windows creates services as LocalSystem, so the account is
 * changed with sc.exe after the install.
 *
 * LocalService gets rights on this folder only, so the folder must not sit
 * inside a user's profile (Desktop, Documents, Downloads): Node cannot start
 * a script below a folder its account cannot read, and the service dies with
 * "finished with 1" (service-location.js has the detail). The install stops
 * before creating anything when it finds that, and says where to move to.
 * After starting the service it checks the dashboard answers, and prints the
 * service's own error log when it does not.
 *
 * Files stay in the install directory (__dirname): server.js, the vault key and
 * state.enc, history.json, and logs/. vault.js and the others are __dirname-
 * based, so the service and an interactive run resolve the SAME files.
 */

const path = require('path');
const http = require('http');
const { execFileSync } = require('child_process');
const { userProfileFolder, daemonErrorTail } = require('./service-location');

const PORT = process.env.PORT || '3000';
const KEEP_LOCAL_SYSTEM = /^localsystem$/i.test(process.env.SBS_SERVICE_ACCOUNT || '');

// Before anything is created: LocalService cannot run from inside a profile.
const profile = KEEP_LOCAL_SYSTEM ? null : userProfileFolder(__dirname);
if (profile) {
  console.error('');
  console.error('This folder is inside the user profile ' + profile + ':');
  console.error('  ' + __dirname);
  console.error('The service runs as the LocalService account, which cannot open that');
  console.error('profile, so it would stop as soon as it started. Nothing was installed.');
  console.error('');
  console.error('Move the whole folder somewhere outside C:\\Users, for example');
  console.error('  C:\\sbs-management-tool');
  console.error('and run install-service.bat again from there. Your saved switches, key,');
  console.error('history and logs move with the folder.');
  console.error('If a service from this folder is already installed, run');
  console.error('uninstall-service.bat here first.');
  console.error('');
  process.exit(1);
}

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
  // Port / receiver ports can be overridden here if the defaults clash.
  // Windows has no privileged ports, so the receivers (traps 162, syslog
  // 514, TFTP 69) keep their defaults under either account.
  env: [
    { name: 'PORT', value: PORT }
  ]
});

// LocalService's well-known SID, so the grant works whatever the language of
// Windows (the account's name is translated, the SID is not).
const LOCAL_SERVICE_SID = '*S-1-5-19';
// node-windows registers the service under its id plus ".exe".
const SERVICE_NAME = svc.id + '.exe';

/**
 * Move the new service from LocalSystem to LocalService. First give
 * LocalService modify rights on this folder and everything in it, including
 * a vault key, state.enc and logs an earlier run left here, so the service
 * can read and keep writing them. Returns the account the service will run
 * as, saying plainly if it could not be changed.
 */
function useLocalService() {
  if (KEEP_LOCAL_SYSTEM) {
    console.log('SBS_SERVICE_ACCOUNT=LocalSystem: keeping the LocalSystem account.');
    return 'LocalSystem';
  }
  try {
    execFileSync('icacls', [__dirname, '/grant', LOCAL_SERVICE_SID + ':(OI)(CI)M', '/T', '/C', '/Q'], { stdio: 'inherit' });
    execFileSync('sc.exe', ['config', SERVICE_NAME, 'obj=', 'NT AUTHORITY\\LocalService', 'password=', ''], { stdio: 'inherit' });
    return 'LocalService';
  } catch (e) {
    console.error('Could not switch the service to LocalService (' + e.message + ').');
    console.error('It will run as LocalSystem, as earlier versions did.');
    return 'LocalSystem';
  }
}

svc.on('install', () => {
  const account = useLocalService();
  console.log('Service installed (account: ' + account + '). Starting it...');
  svc.start();
});
svc.on('alreadyinstalled', () => {
  console.log('The service is already installed. Use uninstall-service.bat first to reinstall.');
  process.exitCode = 1;
});
/**
 * Resolve true once the dashboard answers on PORT (any HTTP status counts:
 * the server is up), false after `seconds` without an answer.
 */
function waitForDashboard(seconds) {
  const deadline = Date.now() + seconds * 1000;
  return new Promise((resolve) => {
    const attempt = () => {
      const req = http.get({ host: '127.0.0.1', port: PORT, path: '/', timeout: 2000 }, (res) => {
        res.resume();
        resolve(true);
      });
      req.on('timeout', () => req.destroy());
      req.on('error', () => {
        if (Date.now() >= deadline) resolve(false);
        else setTimeout(attempt, 1000);
      });
    };
    attempt();
  });
}

svc.on('start', async () => {
  console.log('Service started. Checking the dashboard answers...');
  if (await waitForDashboard(30)) {
    console.log('SBS Management Tool service is running.');
    console.log('Open the dashboard at http://localhost:' + PORT + ' (or run open-ui.bat),');
    console.log('then add your switches and credentials there - the service stores them and keeps collecting across reboots.');
    return;
  }
  console.error('');
  console.error('The service started, but the dashboard did not answer on port ' + PORT + ' within 30 seconds.');
  const tail = daemonErrorTail(__dirname);
  if (tail) {
    console.error('The last lines the service wrote to its error log (daemon\\*.err.log):');
    console.error(tail.replace(/^/gm, '  '));
  } else {
    console.error('See daemon\\*.err.log and logs\\app.log in this folder, and Windows Event Viewer > Application.');
  }
  process.exitCode = 1;
});
svc.on('error', (e) => {
  console.error('Service error:', e && e.message ? e.message : e);
  process.exitCode = 1;
});

console.log('Installing the SBS Management Tool Windows service...');
svc.install();
