'use strict';

/**
 * Saved credentials stay on the server. The ONE place that decides what of
 * the saved state a browser may see, and how a request that names a saved
 * switch gets that switch's secrets.
 *
 * What is a secret here: an SNMP community string, the SNMPv3 auth and priv
 * keys, and the SSH password. Everything else about a switch (host, port,
 * version, v3 username and methods, SSH username) is not.
 *
 * - publicState(state)   the saved state as it leaves the server: every
 *   secret removed, a `saved` flag per secret in its place, and an `id` per
 *   switch so the browser can refer to it.
 * - mergeForSave(incoming, stored)  a browser that never held a secret sends
 *   it back empty; the stored one is kept. A secret it does send (the user
 *   typed a new one) replaces the stored one. Switches are matched by id,
 *   else by SNMP host:port.
 * - resolveTarget(target, state)    an SNMP target from the browser with a
 *   secret missing gets it from the saved switch it names (target.ref, the
 *   switch id), else from the saved switch with the same host:port.
 * - resolveSsh(conn, state)          the same for the SSH password.
 */

const crypto = require('crypto');

const present = (v) => v !== undefined && v !== null && v !== '';
const snmpKey = (t) => t && t.host ? String(t.host).trim().toLowerCase() + ':' + (Number(t.port) || 161) : null;
const newId = () => crypto.randomBytes(8).toString('hex');

function stripTarget(t) {
  if (!t) return { target: t, saved: {} };
  const target = { ...t };
  const saved = {};
  delete target.ref;
  if (present(target.community)) saved.community = true;
  delete target.community;
  if (target.v3) {
    target.v3 = { ...target.v3 };
    if (present(target.v3.authKey)) saved.authKey = true;
    if (present(target.v3.privKey)) saved.privKey = true;
    delete target.v3.authKey;
    delete target.v3.privKey;
  }
  return { target, saved };
}

/** The saved state with every secret removed and a `saved` map in its place. */
function publicState(state) {
  if (!state || !Array.isArray(state.switches)) return state;
  return {
    ...state,
    switches: state.switches.map((sw) => {
      const { target, saved } = stripTarget(sw.target);
      let ssh = sw.ssh;
      if (ssh) {
        ssh = { ...ssh };
        if (present(ssh.password)) saved.sshPassword = true;
        delete ssh.password;
      }
      return { ...sw, target: sw.target ? target : sw.target, ssh, saved };
    })
  };
}

function findSaved(state, { id, key }) {
  const list = (state && Array.isArray(state.switches)) ? state.switches : [];
  if (id) {
    const byId = list.find((sw) => sw && sw.id === id);
    if (byId) return byId;
  }
  if (key) return list.find((sw) => sw && snmpKey(sw.target) === key) || null;
  return null;
}

// Fill each missing secret of `into` (a target) from `from` (a saved target).
function fillTarget(into, from) {
  if (!into || !from) return into;
  const out = { ...into };
  if (!present(out.community) && present(from.community)) out.community = from.community;
  if (out.v3 && from.v3) {
    out.v3 = { ...out.v3 };
    if (!present(out.v3.authKey) && present(from.v3.authKey)) out.v3.authKey = from.v3.authKey;
    if (!present(out.v3.privKey) && present(from.v3.privKey)) out.v3.privKey = from.v3.privKey;
  }
  return out;
}

/** The state to store: incoming switches, with stored secrets kept where none was sent. */
function mergeForSave(incoming, stored) {
  return incoming.map((sw) => {
    if (!sw || typeof sw !== 'object') return sw;
    const prior = findSaved(stored, { id: sw.id, key: snmpKey(sw.target) });
    const out = { ...sw, id: sw.id || (prior && prior.id) || newId() };
    delete out.saved;
    if (out.target) {
      out.target = { ...out.target };
      delete out.target.ref;
      if (prior && prior.target) out.target = fillTarget(out.target, prior.target);
    }
    if (out.ssh && prior && prior.ssh && !present(out.ssh.password) && present(prior.ssh.password) &&
        String(out.ssh.username || '') === String(prior.ssh.username || '')) {
      out.ssh = { ...out.ssh, password: prior.ssh.password };
    }
    return out;
  });
}

/** An SNMP target with any missing secret filled from the saved switch it names. */
function resolveTarget(target, state) {
  if (!target || typeof target !== 'object') return target;
  const prior = findSaved(state, { id: target.ref, key: snmpKey(target) });
  const out = prior && prior.target ? fillTarget(target, prior.target) : { ...target };
  delete out.ref;
  return out;
}

/**
 * The SSH password for a connect message that left it out: from the saved
 * switch named by `ref`, else the one whose SSH host, port and username match.
 */
function resolveSsh(msg, state) {
  if (!msg || present(msg.password)) return msg;
  const list = (state && Array.isArray(state.switches)) ? state.switches : [];
  const host = String(msg.host || '').trim().toLowerCase();
  const port = Number(msg.port) || 22;
  const user = String(msg.username || '');
  const match = (sw) => sw && sw.ssh && present(sw.ssh.password) &&
    String(sw.ssh.username || '') === user &&
    String(sw.ssh.host || (sw.target && sw.target.host) || '').trim().toLowerCase() === host &&
    (Number(sw.ssh.port) || 22) === port;
  const byRef = msg.ref ? list.find((sw) => sw && sw.id === msg.ref && match(sw)) : null;
  const hit = byRef || list.find(match);
  return hit ? { ...msg, password: hit.ssh.password } : msg;
}

module.exports = { publicState, mergeForSave, resolveTarget, resolveSsh };
