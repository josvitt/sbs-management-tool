'use strict';

/**
 * Who may talk to this server: the ONE check, shared by every HTTP route and
 * the WebSocket upgrade (governing rule 3).
 *
 * The dashboard is opened from any PC on the network, so the server listens
 * on every interface and this does NOT restrict which machine connects. It
 * stops two browser-borne attacks that need no network access of their own:
 *
 * 1. Cross-site requests. Any web page open in a browser on the LAN can send
 *    requests to http://<this-pc>:3000 and open a WebSocket to it. A browser
 *    attaches an Origin header to those; when it names a different site than
 *    the one being asked, the request is refused. Requests with no Origin
 *    (curl, scripts, plain same-origin GETs) are not browser cross-site
 *    requests and pass.
 *
 * 2. DNS rebinding. A hostile page can point its own domain name at this PC
 *    and then read responses as "same origin". Its requests still carry that
 *    foreign name in the Host header, so only names that mean this machine
 *    are accepted: any IP address, localhost, this computer's own name (and
 *    <name>.<domain>), plus whatever SBS_ALLOWED_HOSTS lists
 *    (comma-separated) for an alias such as a DNS CNAME.
 */

const os = require('os');
const net = require('net');

function hostOnly(hostHeader) {
  const h = String(hostHeader || '').trim().toLowerCase();
  if (!h) return '';
  if (h.startsWith('[')) return h.slice(1, h.indexOf(']') > 0 ? h.indexOf(']') : undefined);  // [v6]:port
  const colon = h.lastIndexOf(':');
  return colon > -1 && h.indexOf(':') === colon ? h.slice(0, colon) : h;   // name:port, not bare v6
}

function extraAllowed() {
  return String(process.env.SBS_ALLOWED_HOSTS || '')
    .split(',').map((x) => x.trim().toLowerCase()).filter(Boolean);
}

function isAllowedHost(hostHeader) {
  const host = hostOnly(hostHeader);
  if (!host) return false;
  if (net.isIP(host)) return true;
  if (host === 'localhost' || host.endsWith('.localhost')) return true;
  const me = os.hostname().toLowerCase();
  if (host === me || host.startsWith(me + '.')) return true;
  return extraAllowed().includes(host);
}

// An Origin, when present, must name the same host:port the request was sent to.
function isSameOrigin(originHeader, hostHeader) {
  if (originHeader === undefined) return true;
  try {
    return new URL(String(originHeader)).host.toLowerCase() === String(hostHeader || '').toLowerCase();
  } catch (e) {
    return false;   // "null" (sandboxed frames, file://) or garbage
  }
}

/** Why a request is refused, or null when it may proceed. */
function refusal(headers) {
  if (!isAllowedHost(headers.host)) {
    return 'Host "' + hostOnly(headers.host) + '" is not a name for this server. ' +
      'Open the dashboard by IP address or this computer\'s name, or add the name to SBS_ALLOWED_HOSTS.';
  }
  if (!isSameOrigin(headers.origin, headers.host)) {
    return 'Cross-site request refused (Origin ' + headers.origin + ').';
  }
  return null;
}

/** Express middleware. `log` is injected so this module stays dependency-free. */
function middleware(log) {
  return (req, res, next) => {
    const why = refusal(req.headers);
    if (!why) return next();
    log.warn('guard', 'Request refused', { method: req.method, path: req.path, ip: req.ip, reason: why });
    res.status(403).type('text/plain').send(why);
  };
}

/** For WebSocketServer's verifyClient option. */
function verifyClient(log) {
  return (info) => {
    const why = refusal(info.req.headers);
    if (why) log.warn('guard', 'WebSocket refused', { ip: info.req.socket.remoteAddress, reason: why });
    return !why;
  };
}

module.exports = { middleware, verifyClient, refusal, isAllowedHost, isSameOrigin, hostOnly };
