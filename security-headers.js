'use strict';

/**
 * Browser security headers on every response: the ONE place they are set.
 *
 * The page is entirely same-origin: its scripts, styles and data come from
 * this server, and its only other connection is the terminal WebSocket back
 * to the same host. So the policy allows exactly that and nothing else:
 *
 * - scripts only from this server, never inline or eval'd: an injected
 *   <script> or onclick= cannot run even if markup ever slips through;
 * - styles from this server plus inline style attributes, which the page and
 *   app.js use throughout for layout (style="display:none", el.style.x);
 * - images from this server, data: (the topology PNG export) and blob:;
 * - fetch/EventSource/WebSocket only back to the host the page came from;
 * - no framing by any other page (clickjacking), no plugins, no <base>
 *   rewriting, forms post only here, no referrer leaked.
 */

function contentSecurityPolicy(host) {
  // 'self' covers ws: to the same host in current browsers; the explicit
  // ws:// entry keeps older ones working. host has already passed the
  // request guard, so it is an IP, localhost, or this machine's name.
  const ws = host ? ' ws://' + host + ' wss://' + host : '';
  return [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "font-src 'self' data:",
    "connect-src 'self'" + ws,
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'"
  ].join('; ');
}

function middleware() {
  return (req, res, next) => {
    res.set({
      'Content-Security-Policy': contentSecurityPolicy(req.headers.host),
      'X-Frame-Options': 'DENY',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
      'Cross-Origin-Opener-Policy': 'same-origin',
      'Cross-Origin-Resource-Policy': 'same-origin',
      'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()'
    });
    next();
  };
}

module.exports = { middleware, contentSecurityPolicy };
