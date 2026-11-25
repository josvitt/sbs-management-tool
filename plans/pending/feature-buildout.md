# Build out the missing and half-built features

Source: the feature-gap audit of v1.6.0 (`reviews/feature-gaps.md` in the project
files), plus the 19 suggestions in the earlier design review. Dashboard sign-in is
out of scope (Joe, 25 Nov 2026).

Every phase is one pull request and one GitHub release (project rule). Each one
bumps `package.json`, adds `release-notes/v<version>.md` in plain language, and
follows `docs/MODULE-STANDARD.md` and `docs/SERVER-STANDARD.md`. Governing rules 5
and 6 apply to every new write: read the MIB entry and a row the switch itself
made before encoding a write, and never call something "unsupported" from an
error alone.

Verification for every phase:

- `npm test` (offline, includes the replay of the recorded C1300).
- `npm run build`, then a browser check of each new or changed panel against the
  recorded switch at 1600 px and 390 px wide.
- A **supervised switch test** on 192.168.98.253: a script records the current
  state, makes each new write, reads it back, restores the recorded state and
  ends with `RESTORED OK`. It never saves the config. Phases 4 and 5 also need a
  reboot test (below).

## Phases

### Phase 1: Finish what is half-built (v1.7.0)
Verified when: tests pass, and the switch test proves that routed mode, IPv4
addressing and the switchport undo work on .253 and restore cleanly.

#### Step 1.1: Hold collection while a write runs (Size: S)
- `/api/snmp/set` and every server write route hold that switch's collector (no
  scheduled or trap-triggered collection starts until the write and its settle
  time end). Collections already running are waited for first.
- Files: `collector.js`, `routes/snmp.js`, `routes/ports.js`, `routes/snmp-config.js`,
  `routes/aaa.js`, `routes/opc.js`, `routes/streams.js`; `SERVER-STANDARD.md` §3.
- Test seam: collector `_internals` with a counting SNMP stub.
- Blocked by: none

#### Step 1.2: Undo a failed switchport change (Size: S)
- `applySwitchportConfig` records the port's mode, VLANs and IPv4 address first,
  stops at the first failed step, and restores the recorded state, the same way
  port channels do. It reports "changed and restored" or "restore failed, check
  the port", never a silent half-change.
- Files: `public/src/07-ports.js`, `public/src/15-ipv4-addressing.js`.
- Test seam: new `test/switchport-write.test.js` with a stubbed `snmpSetResult`.
- Blocked by: none

#### Step 1.3: Offline tests for the untested writes (Size: M)
- Plan builders and SET sequences for ports, VLANs, port channels, IPv4, AAA and
  syslog setup are covered against the varbinds the switch accepted in earlier
  live tests.
- Files: `test/*.test.js`.
- Blocked by: 1.2

#### Step 1.4: Record the newer panels from .253 (Size: S)
- A read-only recording adds ACL, route table, SNMP configuration, capture and
  flash data to `test/fixtures/live/`, scrubbed like the existing one. The replay
  test covers those panels. The request counts in the v1.6.0 notes are replaced
  with measured ones. The same read-only check runs on .254 (the "Example"
  community works again, Joe, 25 Nov 2026).
- Blocked by: none

#### Step 1.5: Supervised routed and IPv4 test on .253 (Size: S)
- Covers routed mode, address add and delete, DHCP, a static route, a DNS
  server, and an undo after a forced failure.
- Blocked by: 1.1, 1.2

#### Step 1.6: Small fixes (Size: XS)
- Clear counters uses the port's own bit, not ifIndex. Remove the orphan
  comments in `07-ports.js`.
- Blocked by: none

### Phase 2: Design review (v1.8.0)
Verified when: all 19 findings are fixed or already fixed (each one checked
against v1.7.0 first, because v1.4.x touched some areas), and
`MODULE-STANDARD.md` Part A carries the four standard changes as decided below.
Do this before the new panels, so they're built in the corrected look.

- Step 2.1: The standard changes (A2 warning color, A2 and A5 button colors, A3
  label case and scale, A6 focus and motion). Size: S. Blocked by: none.
- Step 2.2: The P1 fixes (status colors, enum codes as words, temperature, Cancel
  button, tab underline). Size: M. Blocked by: 2.1.
- Step 2.3: The P2 and P3 fixes. Size: M. Blocked by: 2.1.
- Step 2.4: A whole-app conformance sweep (rule 8). Size: S. Blocked by: 2.2, 2.3.

### Phase 3: Config restore, reboot and firmware (v1.9.0)
Verified when: on .253 a saved config version is restored to startup and a
reboot brings it up running that version, and an image is uploaded, set as the
next boot image and booted.

- Step 3.1: Reboot now, or schedule a reboot (`rlRebootDelay`, with `rndAction`
  reset(1) as the fallback for "now"), with confirm text that names the switch.
  Size: S. (The plan first named `rlManualReboot`; the MIB shows it is
  read-only and only says whether the last restart was orderly.)
- Step 3.2: Restore a config-history version to the startup config over the
  built-in TFTP server (`rlCopyTable`, TFTP to startup), then offer a reboot.
  The diff against the running config shows first. Size: M. Blocked by: 3.1.
- Step 3.3: Firmware: show the active and inactive images. Upload an image file
  from the browser, have the switch pull it over TFTP, set the next boot image,
  then reboot now or later. TFTP size cap raised for images only. Size: M.
  Blocked by: 3.1.

### Phase 4: System settings (v1.10.0)
A new **System** panel.
- Step 4.1: Clock, time zone, summer time and SNTP servers (`rlSntpConfig*`,
  `rlTimeZone`). Size: S.
- Step 4.2: Local user accounts: list, add, change password and privilege,
  delete (`rlAAALocalUser*`). The account the app signs in with over SSH cannot
  be deleted. Size: S.
- Step 4.3: Management access: Telnet, SSH, HTTP and HTTPS on or off
  (`rlTelnetEnable`, `rlSsh*`, `rlEmWebHttpEnable`, ...), and the management ACL
  (`rlMngInf*`). It refuses to turn off the protocol the app is using. Size: M.
- Step 4.4: Create SNMPv3 users over SNMP only (D4). Probe `usmUserCloneFrom`; if the switch refuses every SNMP route, report that with the MIB evidence and leave it out. Size: M.

### Phase 5: Ports and PoE (v1.11.0)
New tabs in the port popout. Each list has a summary column in Interfaces.
- Step 5.1: PoE on or off, priority and power limit
  (`pethPsePortAdminEnable`, `pethPsePortPowerPriority`, `rlPethPsePortPowerLimit`). Size: S.
- Step 5.2: Port security, MAC limit and action (`swIfLock*`). Size: S.
- Step 5.3: Storm control (`rlStormCtrl*`). Size: S.
- Step 5.4: Cable test (`rlPhyTest*`). Size: S.
- Step 5.5: Err-disable recovery causes and interval (`rlErrdisableRecovery*`),
  and showing why a port was disabled. Size: S.
- Step 5.6: LLDP and CDP on or off, per port and globally
  (`lldpPortConfigAdminStatus`, `rlCdp*`), and EEE (`rlEee*`). Size: S.
- Step 5.7: A new **Port mirroring** panel: SPAN sessions, source ports and
  direction, and the destination port (`rlSpan*`). Size: S.

### Phase 6: Spanning tree writes (v1.12.0)
- Step 6.1: Mode and bridge priority, globally and per VLAN or instance. Size: S.
- Step 6.2: Per port: cost, priority, edge (PortFast) and BPDU guard
  (`rldot1dStpPortBpduGuard*`). Size: S.

### Phase 7: Access lists (v1.13.0)
- Step 7.1: More IPv4 protocols: ICMP type and code, any protocol number, and
  port ranges. Size: S.
- Step 7.2: MAC ACLs. Size: M.
- Step 7.3: IPv6 ACLs. Size: M. Blocked by: 7.1.

### Phase 8: Multicast and switching security (v1.14.0)
A new **Switching security** panel.
- Step 8.1: IGMP snooping, globally and per VLAN, with the group table
  (`rlIgmpSnoop*`). Size: S.
- Step 8.2: DHCP snooping and trusted ports (`rlIpDhcpSnoop*`). Size: S.
- Step 8.3: ARP inspection (`rlIpArpInspect*`). Size: S. Blocked by: 8.2.

### Phase 9: Alerts outside the dashboard (dropped, D7)
- Step 9.1: An **Alerts** section in Settings: an SMTP server (password stored
  in the vault) and an optional webhook. A test-send button. Size: M.
- Step 9.2: The server sends an alert when a switch becomes unreachable or
  recovers, a new critical alert appears, or the config changes. Repeats are
  held back: the same alert at most once an hour. Size: S. Blocked by: 9.1.

### Phase 10: IPv6 addressing (v1.15.0)
A new **IPv6 Addressing** panel, built like IPv4 Addressing.
- Step 10.1: Addresses on VLAN and routed interfaces, including autoconfig and
  link-local. Size: M.
- Step 10.2: Default gateway, static routes and IPv6 DNS servers. Size: S.

### Phase 11: QoS (v1.16.0)
A new **QoS** panel.
- Step 11.1: QoS mode and the trust mode (CoS or DSCP). Size: S.
- Step 11.2: Rate limits and shaping per port. Size: S.
- Step 11.3: CoS and DSCP to queue maps (read, then edit). Size: M.

### Phase 12: One change on many switches (dropped, D8)
- Step 12.1: Pick saved switches and a change: add or remove a VLAN, SNTP
  servers and time zone, a local user, or the syslog server. Size: M.
- Step 12.2: A preview per switch, then apply in turn, with each switch's result
  and the undo for that switch. It stops at the first failure unless you choose
  to continue. Size: M. Blocked by: 12.1, and the phase that owns each change.

## Decision log
| # | Decision | Chosen option | Why |
| --- | --- | --- | --- |
| D1 | Dashboard sign-in | Not built | Joe, 25 Nov 2026 |
| D2 | One PR and release per phase | Merge and release without asking once tests and the switch test pass | Joe, 25 Nov 2026 |
| D3 | Switch tests | Write tests on .253 gi1/0/4, restored and never saved; reboots of .253 announced first | Joe, 25 Nov 2026 |
| D4 | Everything over SNMP | No CLI writes at all. SNMPv3 user creation is built only if an SNMP route works (`usmUserCloneFrom` or `rlUsmUserExt`) | Joe, 25 Nov 2026 |
| D5 | Design standard changes | Separate warning color; green apply, blue secondary, red destructive, no amber or violet buttons; sentence-case labels, no 9.5px; one focus ring and reduced motion | Joe, 25 Nov 2026 |
| D6 | Config restore target | Restore to startup, then offer a reboot | Joe, 25 Nov 2026 |
| D7 | Alerts outside the dashboard | Not built for now (Phase 9 dropped) | Joe, 25 Nov 2026 |
| D8 | Changes on many switches | Not built for now (Phase 12 dropped) | Joe, 25 Nov 2026 |
| D9 | QoS scope | Trust mode, rate limits, queue maps; no policy maps | Joe, 25 Nov 2026 |
| D10 | Where the new features go | Panels: System, Switching security, Port mirroring, IPv6 Addressing, QoS; per-port settings as popout tabs | Joe, 25 Nov 2026 |

## Not yet specified
- Phase 3: the exact OIDs for the active and next boot image. Fog: read the
  rlCopy and image MIB entries and a switch-made row at pickup.
- Phase 4.4: whether `usmUserCloneFrom` works on this firmware. A probe answers
  this; it is not a question for Joe.
- Phase 11: which QoS tables the C1300 actually populates. Probe at pickup.

## Always / Never
- Always: SNMP first; a confirm on every write that is hard to undo; the
  collector held during writes (from Phase 1); offline tests for each write's
  SET plan; plain-language release notes.
- Never: dashboard sign-in; saving the config during a switch test; a switch
  test without Joe's typed approval; driving the CLI for any write (D4); alerts and multi-switch changes (D7, D8).

## Progress
| Phase | Status |
| --- | --- |
| 1 Half-built | Done (v1.7.0): switch test 31/31 on .253, recordings of .253 and .254 |
| 2 Design review | Done (v1.8.0): words not codes, warning color, button colors, focus ring, temperature fix |
| 3 Restore, reboot, firmware | Reboot, next boot image and image list proven on .253. Restore held back: the switch drops an `aaa` block from a config copied into startup. Firmware install proven (65.7 MB in 121 s). Shipped in v1.9.0. |
| 4 System | Not started |
| 5 Ports and PoE | Not started |
| 6 Spanning tree | Not started |
| 7 Access lists | Not started |
| 8 Switching security | Not started |
| 9 Alerts | Dropped (D7) |
| 10 IPv6 | Not started |
| 11 QoS | Not started |
| 12 Many switches | Dropped (D8) |
