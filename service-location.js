'use strict';

/**
 * Where the Windows service can run from, and what it said when it would not
 * start. Used by service-install.js; nothing here acts on load.
 *
 * Why a user's profile folder will not do: the service runs as LocalService
 * (SERVER-STANDARD §9). service-install.js gives that account rights on the
 * app folder, but not on the folders above it, and a profile such as
 * C:\Users\Administrator (with its Desktop, Documents and Downloads) is open
 * only to its owner, Administrators and SYSTEM. When Node starts a script it
 * resolves the script's real path by lstat-ing every folder on the way down
 * (fs.realpathSync); the first one LocalService cannot read fails with EPERM,
 * and node.exe exits with code 1 before the app runs a line. The service
 * wrapper then logs only "Child process ... finished with 1". That is the
 * failure of 1.2.0 installed on the Desktop.
 *
 * So the installer refuses any folder under the Users folder and asks for one
 * outside it (C:\sbs-management-tool), rather than widening the rights on
 * somebody's profile.
 */

const fs = require('fs');
const path = require('path');

const win = path.win32;

/**
 * The Users folder holding every profile: the parent of %PUBLIC%
 * (C:\Users\Public), else %SystemDrive%\Users.
 */
function usersRoot(env) {
  if (env.PUBLIC) return win.dirname(win.resolve(env.PUBLIC));
  return win.join((env.SystemDrive || 'C:') + '\\', 'Users');
}

/**
 * If `dir` is inside the Users folder, or inside the current user's profile
 * wherever that lives, return that profile's folder (e.g.
 * "C:\Users\Administrator"); otherwise null. Case-insensitive, as Windows
 * paths are.
 */
function userProfileFolder(dir, env = process.env) {
  const target = win.resolve(dir);
  const roots = [usersRoot(env)];
  if (env.USERPROFILE) roots.push(win.dirname(win.resolve(env.USERPROFILE)));
  for (const root of roots) {
    const rel = win.relative(root.toLowerCase(), target.toLowerCase());
    if (!rel || rel.startsWith('..') || win.isAbsolute(rel)) continue;
    const first = rel.split('\\')[0];
    // The profile's folder in its original spelling.
    return target.slice(0, win.join(root, first).length);
  }
  return null;
}

/**
 * The last `count` lines the service's Node process wrote to stderr: the
 * newest daemon\*.err.log that node-windows' wrapper keeps in the app folder.
 * Empty when there is none.
 */
function daemonErrorTail(appDir, count = 20) {
  const dir = path.join(appDir, 'daemon');
  let newest = null;
  try {
    for (const name of fs.readdirSync(dir)) {
      if (!/\.err\.log$/i.test(name)) continue;
      const file = path.join(dir, name);
      const mtime = fs.statSync(file).mtimeMs;
      if (!newest || mtime > newest.mtime) newest = { file, mtime };
    }
    if (!newest) return '';
    const lines = fs.readFileSync(newest.file, 'utf8').split(/\r?\n/).filter((l) => l.trim());
    return lines.slice(-count).join('\n');
  } catch (e) {
    return '';
  }
}

module.exports = { userProfileFolder, daemonErrorTail };
