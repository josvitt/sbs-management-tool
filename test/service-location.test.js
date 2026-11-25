'use strict';
// The Windows service's install-location check and its error-log reader
// (service-location.js). Pure path logic, so it runs on any OS.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { userProfileFolder, daemonErrorTail } = require('../service-location');

const env = { PUBLIC: 'C:\\Users\\Public', SystemDrive: 'C:', USERPROFILE: 'C:\\Users\\Administrator' };

test('a folder on an Administrator Desktop is inside that profile', () => {
  assert.equal(
    userProfileFolder('C:\\Users\\Administrator\\Desktop\\sbs-management-tool-1.2.0', env),
    'C:\\Users\\Administrator');
});

test('any profile under the Users folder counts, whatever the case', () => {
  assert.equal(userProfileFolder('c:\\users\\joe\\Downloads\\app', env), 'c:\\users\\joe');
  assert.equal(userProfileFolder('C:\\Users\\Public\\app', env), 'C:\\Users\\Public');
});

test('folders outside the Users folder are fine', () => {
  assert.equal(userProfileFolder('C:\\sbs-management-tool', env), null);
  assert.equal(userProfileFolder('D:\\Apps\\sbs-management-tool', env), null);
  assert.equal(userProfileFolder('C:\\UsersData\\sbs', env), null);
  assert.equal(userProfileFolder('C:\\Users', env), null);
});

test('without %PUBLIC% the Users folder comes from %SystemDrive%', () => {
  assert.equal(userProfileFolder('D:\\Users\\ops\\Desktop\\app', { SystemDrive: 'D:' }), 'D:\\Users\\ops');
  assert.equal(userProfileFolder('C:\\Users\\ops\\Desktop\\app', { SystemDrive: 'D:' }), null);
});

test('a profile kept outside the Users folder is caught through %USERPROFILE%', () => {
  const e = { PUBLIC: 'C:\\Users\\Public', USERPROFILE: 'E:\\Profiles\\admin' };
  assert.equal(userProfileFolder('E:\\Profiles\\admin\\Desktop\\app', e), 'E:\\Profiles\\admin');
});

test('daemonErrorTail returns the end of the newest daemon err log', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sbs-svc-'));
  assert.equal(daemonErrorTail(dir), '');
  fs.mkdirSync(path.join(dir, 'daemon'));
  const old = path.join(dir, 'daemon', 'old.err.log');
  fs.writeFileSync(old, 'stale\n');
  fs.utimesSync(old, new Date(1000), new Date(1000));
  fs.writeFileSync(path.join(dir, 'daemon', 'sbsmanagementtool.err.log'),
    'line 1\r\n\r\nError: EPERM: operation not permitted, lstat \'C:\\Users\\Administrator\\Desktop\'\r\n');
  fs.writeFileSync(path.join(dir, 'daemon', 'sbsmanagementtool.out.log'), 'not this\n');
  assert.equal(daemonErrorTail(dir, 1), 'Error: EPERM: operation not permitted, lstat \'C:\\Users\\Administrator\\Desktop\'');
  assert.equal(daemonErrorTail(dir).split('\n').length, 2);
});
