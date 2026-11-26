# Switch Notes — How Catalyst 1200/1300 behaves, and what the code does about it

These are facts about the switches (SNMP agent, MIBs, CLI) that the code relies
on. Most were found on a real switch rather than a mock. Each one names the
file that handles it, so you can check it before you change that code.

How the server and the panels are built is in `SERVER-STANDARD.md` and
`MODULE-STANDARD.md`. This document covers only switch behaviour.

## SNMP walks

- **Walks are bounded in our own code** (`boundedWalk`, `snmp-core.js`).
  net-snmp's own walk asks GETBULK for 20 repetitions. At the end of a subtree
  the agent keeps producing successors past it, into unrelated objects, and
  Catalyst firmware can then log
  `%SNMP-D-MAXOIDSINKEYREACHED: too many oids in key for variable NN`.
  `boundedWalk` uses 10 repetitions, discards anything outside the base OID
  and stops there. It also caps rows and OID depth, and stops an agent that
  does not advance. Several columns can share one GETBULK stream, with the
  boundary and caps applied to each column (`SERVER-STANDARD.md` §1a). `mode: 'next'` (on `/api/snmp/walk`) walks one GETNEXT at
  a time, which never reads past the boundary.
- **A walk returns a table column by column.** So a row cap cuts off whole
  columns, not the last rows. This is why the spanning-tree per-port state is
  fetched by exact instance and never walked (below).
- **Counter64 arrives as a raw big-endian buffer** from net-snmp. It is always
  decoded as a number. A "printable text" check would turn some counters
  into strings like `2xY`.

## Interfaces and VLANs

- **Use `rlifPresentTable`, not `ifTable`.** Since firmware 4.1.9.85 it lists
  only interfaces that are physically present. `ifTable` also lists stack
  slots with no unit fitted. Interfaces reporting `notPresent(6)` are dropped
  wherever they come from.
- **A VLAN interface is listed among the ports,** named after its VLAN id.
  It is folded into that VLAN's row rather than shown as a port.
- **VLAN membership comes from `dot1qVlanCurrentTable`** (the operational
  view). The static table is read only for names: switches fill Current even
  when Static is sparse. Membership is a `PortList` bitmap per VLAN. It is
  inverted into per-port Untagged and Tagged columns, and tagged is worked
  out as egress minus untagged, which is what `show vlan` prints.
- **Different tables use different indexes.** CDP is indexed by ifIndex,
  LLDP by `timeMark.localPort.index`, and the forwarding database by
  `vlan.mac` with a *bridge port* number. All are resolved to interface
  names. A MAC in an index is read from its last six sub-identifiers, so it
  works whether or not the agent puts a length prefix first.
- **C1300X firmware may not fill the vendor per-port counters** its MIB
  defines. The reader tries the vendor columns first and falls back to the
  standard `ifXTable`/`ifTable` ones (`SERVER-STANDARD.md` §10).

## Routed ports, addresses and routes (`07-ports.js`, `15-ipv4-addressing.js`)

Proven on a C1300 (gi1/0/4, 25 Nov 2026, `scripts/switch-test.js`):

- **"no switchport" is `vlanSwitchPortModeCategory` = 2** and switchport is 1.
  The switch refuses an address on the port (InconsistentValue) for about
  2 seconds after the category changes, so writes that follow it wait 2.5 s.
- **An address is one `rsIpAddrTable` PDU:** status active(1), ifIndex and
  mask. invalid(2) removes it. The DHCP client is `rlDhcpClActionStatus`:
  createAndGo(4) on, destroy(6) off.
- **A static route's type is `rlIpStaticRouteType` remote(3).** That MIB
  numbers the types reject(1), local(2), remote(3), not like the standard
  `ipCidrRouteType`. The switch refuses 4 with WrongValue. A route through a
  next hop on a port with no link is accepted.
- **Nameservers are added in `rlDnsResConfigSbeltInetTable` and deleted from
  the DNS client v2 servers table,** whose row the switch makes for each one.

## Reboot and firmware (`switch-maint.js`, `26-maint.js`)

Proven on a C1300 (25 Nov 2026, firmware 4.1.9.92, `scripts/switch-test-maint.js`):

- **A reboot is `rlRebootDelay` (TimeTicks).** Setting 360000 schedules one in
  an hour, and reading it back gives the time left. Setting 4294967295 cancels
  it, and that is also what it reads when nothing is scheduled.
  `rlManualReboot` is not a control: it is read-only and says whether the
  last restart was orderly.
- **The next boot image is `rndActiveSoftwareFileAfterReset.<unit>`**,
  image1(1) or image2(2). It reads back at once. The running one is
  `rndActiveSoftwareFile.<unit>`, read-only.
- **The switch pulls a file from the app with an `rlCopyTable` row:** source
  tftp(3) with the app's address and a file name, source type other(1),
  destination local(1) on unit 1 with the file type, `createAndGo` in one PDU.
  The row is gone when the copy ends.
- **A configuration copied into startup this way is not stored as sent.** A
  143-line startup copied back into itself came back as 138 lines: two stray
  `!` comment lines and a block of an `aaa ...` line, `!` and `exit` were
  dropped. Doing it again gives the same result. So restoring a stored
  version to startup is held back until it is known which lines the switch
  drops and why.
- **The images are listed in `rndImageInfoTable`, one row per unit,** with a
  name, version and build date and time column for each slot. The name is a
  full path such as `flash://system/images/<file>.bin`.
- **A firmware install is the same copy with file type image(8).** A 65.7 MB
  image took 121 s. The switch writes it to the slot it is not running,
  stores it under the TFTP file name it was offered, and makes that slot
  the next boot image by itself.
- **Reading startup back over TFTP can stall right after a copy into it.**
  Twice the upload sat at uploadInProgress until the app gave up; a later
  read worked.

## System settings (`switch-system.js`, `27-system.js`)

Read from a C1300 (25 Nov 2026, firmware 4.1.9.92):

- **Never read the local user table in bulk.** `rlAAALocalUserTable`
  (101.79.17.1) keeps the password hash in column 2 and its salt in column
  10, right after the name. A GETBULK on the name column runs on into them.
  The app walks the privilege column (3) one GETNEXT at a time, which stops
  on the row status column (4), and reads name, lock state and failed
  logins with a GET per user. The index is the name, length first.
- **SNTP servers are indexed by address type, length and address**
  (`rlSntpConfigServerInetTable`, 101.92.2.2.17.1). Host names are type
  dns(16), so the switch's defaults read as `16.12.pool.ntp.org` and so on.
  Status (column 6) can say down(4) for every server while the clock says
  synchronizedBySntp: `rlSntpTimeSinceLastSync` tells how stale it is.
- **The time zone reads as `00:00`, without a sign,** in `rlTimeZone`.
  The clock (`rndTimeSyncManagedDateTime`) reads as ddmmyyhhmmss.
- **Written and read back over SNMP (25 Nov 2026, `scripts/switch-test-system.js`):**
  the time zone (`rlTimeZone` "+01:30" reads back "01:30", with
  `rlTimeZoneCode`), the clock (`rndTimeSyncManagedDateTime`, then
  `rlClockStatus` reads manuallySet), SNTP on and off
  (`rlSntpUnicastAdminState`), Telnet on and off, and a user's privilege
  (column 3) and deletion (column 4 destroy).
- **No form of adding an SNTP server was taken.** In
  `rlSntpConfigServerInetTable` a new row is refused with InconsistentValue
  as createAndGo with or without `polled`, and as createAndWait; so is a
  createAndGo in the older IPv4 table (101.92.2.2.12). It is not a limit:
  with one of the five servers removed, adding is still refused, and so is
  adding the removed server back. Destroying a row works. Not yet tried:
  createAndGo with `polled` and `rlSntpServerInetKeyIdentifier` (0) together.
  The app keeps the server list read-only, since a removal could not be
  undone.
- **No form of creating a user or setting a password was taken.** Privilege
  and createAndGo without a password: InconsistentValue. With the password
  in the same PDU as plain text (with or without hash method SHA-512):
  WrongValue on the password. With "$" and the clear text (the MIB's
  form a): CommitFailed, and the row is created anyway, without a usable
  password, so it must be removed. Changing a password on an existing row
  the same ways: CommitFailed. Not yet tried: the "#" encrypted form and
  `rlAAALocalUserPasswordVerificationAndSettingTable` (101.79.68).
  The app does not add users or set passwords.
- **Summer time start and end are 14-byte strings** whose layout the parsed
  MIB description does not give in full, so the app shows summer time but
  does not set it yet.
- **The SSH server's switches are enable(1)/disable(2), not TruthValue;**
  Telnet, HTTP and HTTPS are TruthValue.

## Spanning tree (`health.js`)

- **`dot1dStpVersion` can't be trusted on its own.** Firmware reports `rstp`
  while actually running Rapid-PVST, and some builds don't implement the
  object at all. So the small per-instance tables (`rlBrgPvstOperVlanTable`,
  `rldot1sMstpInstanceTable`) are always walked. If they are populated, that
  mode is in use, whatever the scalar says. The scalar only breaks ties and
  names plain STP/RSTP. When the two disagree, the panel says so.
- **Under Rapid-PVST, `dot1dStpPortTable` shows every port disabled.** It is
  shown only when the switch runs plain STP or RSTP.
- **Per-port state is fetched by exact instance in batched GETs, not walked.**
  It is indexed by instance and bridge port. On one real switch that was
  980 varbinds instead of 33,920. The fetch is capped at 1,200 instances, and
  anything beyond that is reported as missing.
- **Ghost ports.** A C1300 answers for every bridge port in its ifIndex space,
  about 424 of them with roughly 50 real interfaces. Since v1.5.0, per-port
  tables everywhere are read only for interfaces that exist, for the same
  reason. Rows are kept only for
  interfaces in `rlifPresentTable` that have a state or role.
- **A port's role alone is not enough.** Disabled ports, and slots that don't
  exist, can still report "designated". Whether a port is participating is
  decided by its state.
- **The two families of timers use different units.** BRIDGE-MIB timers are
  in hundredths of a second (`Timeout`). The vendor per-VLAN and per-instance
  timers are in whole seconds.
- **Bridge IDs** are a 2-byte priority followed by the MAC. The low 12 bits of
  the priority carry the VLAN or instance (`32769 = 32768 + 1`). To match a
  root bridge to a neighbour's chassis id, compare only the last 6 bytes.

## Fetching configuration (`config-fetch.js`, `tftp.js`)

- **No MIB object returns the config as text.** The app creates an
  `rlCopyTable` row that makes the switch upload the file to the app's
  built-in TFTP server. This needs SNMP write access.
- **Row creation differs by firmware.** Three RowStatus forms are tried in
  order: single-PDU `createAndGo`, then `createAndGo` and populate, then
  `createAndWait`, populate and `active`. The syslog collector write uses the
  same forms.
- **The address the switch uploads to is worked out per request** from the
  route to that switch (`localAddressFor`). A fixed address is wrong on a PC
  with more than one network.
- **The switch always uses UDP 69.** `TFTP_PORT` moves the receiver, but the
  switch can't be told to use another port. TFTP is cleartext and has no
  authentication, and a config contains secrets. So a received file is only
  written to disk encrypted, as a config-history version. File names can't
  be guessed, and the size and number of uploads are capped.
- **Diffs read from the saved config outwards.** `+` means running but not
  saved, which a reload would lose. A change inside an indented block prints
  the whole block, so you can see which interface it belongs to. The
  longest-common-subsequence diff trims the common start and end first. On a
  16,000-line pair that took it from 4.6 s to 5 ms.

## Syslog collector setup (`syslog-config.js`)

- **The firmware has three collector tables:** `snmpSyslogCollectorTable`
  (IETF draft), `rlsnmpSyslogCollectorTable` and
  `rlRegisteredLogsSyslogCollectorTable`. Which ones a build implements
  varies. All three are read, and a write is tried against each in turn. If
  you read only one, a switch that uses another looks unconfigured and then
  refuses the write.
- **The UDP port column is `Unsigned32`, not `INTEGER`.** Sending INTEGER
  gets `WrongType` on that one OID, which looks like a permissions problem.
  If a build refuses Unsigned32, the write is retried with INTEGER.
- **A new row takes the lowest free index** (1 to 8) in that table, so an
  existing row is never overwritten.

## Traps (`traps.js`)

- **Traps decide *when* to poll. They never replace polling.** Traps are UDP
  with no retransmission, and they arrive only if the switch was set up to
  send them, so a count kept from traps drifts. A trap triggers a re-read
  instead. Refreshes are combined and kept at least 10 seconds apart, so a
  flapping link can't cause a collection per flap.

## SNMPv3 (`snmp-crypto.js`)

- **net-snmp has no AES-192.** `snmp-crypto.js` adds it to the library's
  algorithm table at startup, and fails loudly if a library update changes
  those internals.
- **AES-192 and AES-256 need a longer key than SHA-1 produces, and there are
  two ways to extend it.** Reeder (used by Cisco) and Blumenthal (used by
  other vendors) don't work with each other. A mismatch looks exactly like a
  wrong password. Plain **AES-192/256** use Reeder. The Blumenthal versions
  are offered as separate choices.
- **DES is hidden on Node builds whose OpenSSL 3 has dropped it.** Otherwise
  it fails mid-request with "digital envelope routines::unsupported".
  `/api/snmp/v3-options` serves the list the server can actually use.
- **The security level comes from the auth and privacy choices**
  (`v3SecurityOf`). Privacy without authentication is refused.

## CLI and console (`routes/terminal.js`, `serial.js`, `public/tech-parse.js`)

- **Capturing `show tech-support`.** Paging is turned off first with
  `terminal datadump`, so the capture doesn't stop at a `More:` prompt. The
  output itself contains prompts, so the capture ends when the prompt
  reappears *after* the output goes quiet. If it goes quiet with no prompt,
  it returns what it has and says why.
- **Parsing a capture.** A table's dashed rule looks like a section banner,
  so a section name must contain a letter. `show vlan` and
  `show cdp neighbors` wrap long rows onto lines with an empty first column.
  Those lines are joined back to the row above.
- **Backspace on a console.** A terminal sends DEL (0x7f). A raw console line
  erases on BS (0x08), and Cisco accepts both, so DEL is translated to BS.
- **Close sessions like a person would.** Send `exit` so the switch logs a
  clean logout. Dropping the socket leaves the VTY line held until the
  switch's own timeout.
- **`serialport` is optional.** Without its prebuilt binaries the console
  feature is turned off and says why, and the rest of the app still runs.
  Listing ports on Linux needs `udevadm`.
- **Legacy SSH algorithms** are kept as fallbacks after the modern ones
  (`LEGACY_ALGORITHMS`), because some small-business firmware supports only
  older ones.
- **Writing config by driving the CLI is unreliable.** A console may be
  sitting at `User Name:`, not a prompt. Some devices treat CRLF as two key
  presses. The app reads switches over SNMP and leaves typing config to a
  person watching the output.

## Port features (`switch-ports.js`, `28-port-features.js`)

Proven on a C1300-24MGP-4X (4.1.9.92), with `scripts/switch-test-ports.js`
on an empty port, each change put back.

- **Most per-port tables carry a row for all 416 possible ifIndexes**
  (swIfTable, lldpPortConfigTable, cdpInterfaceTable, rlEeePortTable). A
  walk of five swIfTable columns took 523 requests and 25 s. The present
  front-panel ports come from `rlifPresentType` (type 6, ifIndex under 1000;
  1800 is the out-of-band port) and their rows are read by GET.
- **Storm control lives in `rlStormCtrlRateLimCfgTable` (V.77.12),** indexed
  ifIndex.traffic (broadcast 1, multicast all 4, unknown unicast 5). The
  older `rlStormCtrlTable` (V.77.8) is empty. Every switch-made row reads
  rate 0, unit 1, action 1. A rate of 10000 written to the rate column
  (Unsigned32) shows on the switch's web page as "10000 kbits/sec", so unit 1
  is kb/s. Only the rate is written; 0 turns it off.
- **PoE:** `pethPsePortAdminEnable`, `pethPsePortPowerPriority` and
  `rlPethPsePortPowerLimit` (mW) take a SET together.
- **Port security:** `swIfLockLimitationMode`, `swIfLockMaxMacAddresses` and
  `swIfLockAdminStatus` take a SET together.
- **LLDP, CDP and EEE per port, CDP for the switch, errdisable recovery
  causes and interval:** plain SETs of the column, proven.
- **Cable test:** `rlPhyTestSetType` = 2 (cable status, TDR) on a port with
  no link gave a result in about 30 s (`cableStatus`, units alaskaPhyStatus).
  On a linked gigabit port the results table also holds a VCT length
  (`cableLength`, units alaskaPhyLength, 0 to 4 meaning under 50 m to over
  140 m) and pair results that read `failed`, from earlier tests.
- **Mirroring:** the switch-made destination row reads ifIndex, span(1),
  monitor-only(1), RSPAN VLAN 1, active; its sources are indexed session,
  port(1), ifIndex with direction both(3). A new destination row (session 2)
  was refused with InconsistentValue on the row status in createAndGo and in
  createAndWait on the first run. On the second run `addMirror`, which now
  tries five forms in turn, made session 2 (port 5 to port 4), and it read
  back as the switch-made row does (RSPAN VLAN 1). Which form the switch
  took was not logged on that run; `addMirror` now returns it as `via`, with
  the refusals before it. Adding a port to an existing session (createAndGo
  on the source row with its direction) and taking it out (destroy) are
  proven, as is removing a session (sources, then the destination).

## Spanning tree (`switch-stp.js`, `29-stp-settings.js`)

Proven on a C1300-24MGP-4X (4.1.9.92) running Rapid PVST+, with
`scripts/switch-test-stp.js` on an empty port, each change put back.

- **Every bridge table carries a row for each possible port:** 424 rows in
  dot1dBasePortTable, dot1dStpPortTable, dot1dStpExtPortTable,
  rldot1dStpPortTable and rldot1dStpPortBpduGuardTable (bridge ports 1 to
  416 and 1000 to 1007). A walk of them took 750 requests and 34 s. The
  present ports come from `rlifPresentType` (Ethernet under 1000, port
  channels type 161) and their rows are read by GET. A bridge port's number
  is its ifIndex.
- **Plain SETs of the column, proven:** `rldot1dStpEnable`,
  `dot1dStpVersion` (rstp 2 and rpvst 8, each way), `dot1dStpPriority`,
  `dot1dStpPortPriority`, `dot1dStpPortEnable`, `dot1dStpPortAdminPathCost`
  (0 is automatic), `dot1dStpPortAdminEdgePort` (PortFast),
  `rldot1dStpPortAutoEdgePort` (on by default) and
  `rldot1dStpPortBpduGuardEnable`. Each is sent as its own SET, so a refusal
  names its column.
- **Per VLAN, not taken over SNMP.** `rlBrgPvstVlanTable` and
  `rlBrgPvstPortTable` are empty until a VLAN is configured. For VLAN 1 and
  port 4 the switch refused every form: the priority or cost column on the
  row as it is (NotWritable), createAndGo with the columns (NotWritable on
  the row status) and createAndWait then active (WrongValue on the row
  status). The app does not offer per-VLAN priority or cost; the panel says
  to set them on the switch's web page.
- **MSTP instances:** not tried (.253 runs PVST, so there was no switch-made
  `rldot1sMstpInstanceTable` row to encode from).

## Access lists (`14-acl.js`)

Encoded from rules the switch made itself from the CLI on .253 (sbs-ref-ip,
sbs-ref-v6, sbs-ref-mac) and .254 (DMZ, ISE-PREAUTH), read from the
recordings, and written back by `scripts/switch-test-acl.js`.

- **Three tables.** rlQosAclTable (88.7: name, type mac 1 / ip 2 / ipv6 3),
  rlQosAceTidxTable (88.31: action, type, eleven Tuple pointers in columns
  5 to 12 and 17 to 19) and rlQosTupleTable (88.5: type, Value1 INTEGER,
  Value2 octets). A rule is its tuples plus an ACE row pointing at them.
- **Each match has its own Tuple slot, and it depends on the rule type.**
  TCP and UDP: 1 protocol, 2 source, 3 source port or range start, 4
  destination, 5 destination port or range start, 6 source range end, 7
  destination range end, 8 TCP flags. ICMP has no ports, so its destination
  moves up: 3 destination, 4 type, 5 code. A plain IP or IPv6 rule: 1
  protocol number, 2 source, 4 destination. MAC: 1 source, 2 destination, 3
  VLAN. The app writes the same slots, and a failed edit puts a rule back in
  the slots it was read from.
- **Value encodings.** Protocol: one byte and ff (`2fff` is 47; ICMP for
  IPv6 is `3aff`). Addresses: value then wildcard, 1 bits ignored, for IPv4
  (4 + 4 bytes), IPv6 (16 + 16) and MAC (6 + 6). One port: Value1 is the
  port and Value2 `0000`. Ranges, ICMP type and code, and VLAN: Value1 is
  the number and Value2 is empty. TCP flags: value byte, then a don't-care
  byte.
- **Rule types.** ip 1, tcp 2, udp 3, icmp 7; ipv6 9, ipv6 tcp 10, ipv6 udp
  11, ipv6 icmp 13; mac 5. A rule naming a protocol number is a plain rule
  (type 1 or 9) with a protocol tuple.
- **Value1 reads with a thousands separator** in the display ("8,000"), so
  the app reads the raw number.
- **Binding.** rlQosIfPolicyTable: `rlQosIfAclIn`/`Out` hold an IPv4 or MAC
  list, `rlQosIfIpv6AclIn`/`Out` an IPv6 list. On .253 an IPv4 and an IPv6
  list bound together, and a MAC list bound alone (rlQosIfAclIn by itself).
  A MAC list sent in place of the IPv4 list, in the same SET that cleared
  the IPv6 column, was refused (WrongValue on rlQosIfAclIn); the panel then
  says to clear the port first and bind the MAC list on its own.
- **Proven** by `scripts/switch-test-acl.js` on .253, 32 of 32: every rule
  kind added, read back and edited, the bindings, and the lists deleted with
  no tuples left behind.
- **Not offered:** an Ethernet type on a MAC rule (the sample line was not
  taken by the switch, so there is no switch-made row to encode from), DSCP,
  IP precedence, CoS, and offset rules.

## Switching security (`switch-security.js`, `30-switch-security.js`)

Encoded from the settings made from the CLI on .253 for a test VLAN 999
(IGMP snooping and its querier, DHCP snooping, ARP inspection with the list
sbs-ref-arp, port gi1/0/4 trusted for both), read from the recording.

- **The snooping tables hold a row for every VLAN number.**
  rlIgmpSnoopQuerierVlanTable (55.2.12, indexed by VLAN) and
  rlIgmpMldSnoopVlanTable (55.5.5, indexed by address type 1 IPv4 / 2 IPv6
  and VLAN) answer for VLANs 1 to 4094 whether the VLAN exists or not. A walk
  stopped at the 600-row cap before VLAN 999 and took 860 requests, so the
  app reads them by GET for the VLANs in dot1qVlanStaticTable. The legacy
  rlIgmpSnoopVlanTable (55.2.7) and rlIgmpSnoopMembershipTable (55.2.11) are
  empty on a C1300; the 55.5 tables replace them.
- **Snooping and the querier are plain column SETs** on those rows:
  rlIgmpMldSnoopVlanEnable, RouterLearn and IsImmediateLeave; the querier's
  AdminEnable, AdminAddr (255.255.255.255 means the switch's own address on
  the VLAN), AdminVersionNumber (2 or 3) and ElectionEnable. Switch-wide:
  rlIgmpSnoopEnable, rlIgmpSnoopQuerierEnable and rlMldSnoopEnable.
- **DHCP snooping and ARP inspection keep a row only for what is set.** A
  VLAN with DHCP snooping on is a row in rlIpDhcpSnoopEnableVlanTable
  (112.1.12); a trusted port is a row in rlIpDhcpSnoopTrustedPortTable
  (112.1.13) and rlIpArpInspectTrustedPortTable (112.3.7). A VLAN with ARP
  inspection is a row in rlIpArpInspectEnableVlanTable (112.3.6) carrying
  the assigned list name. The app makes these rows with createAndGo and
  removes them with destroy, as the MIB says. An empty list name is refused
  (WrongLength on rlIpArpInspectAssignedListName), so the app clears a
  VLAN's list by destroying the row and making it again without one.
- **ARP lists** (rlIpArpInspectListTable, 112.3.5) are indexed by the list
  name as length and bytes, then the IP address; the MAC is an octet string
  column. A list exists while it has an entry.
- **The MAC check and the packet check are enable 1 / disable 2**, not
  TruthValue (rlIpDhcpSnoopVerifyMacAddress, rlIpDhcpSnoopFileEnable,
  rlIpArpInspectValidation). rlIpArpInspectLogInterval is Unsigned32, 0 to
  86400 seconds.
- **A static DHCP binding was not taken from the CLI.** Three forms of
  `ip dhcp snooping binding` (MAC with colons and with dots, expiry infinite
  and 3600) gave "Wrong number of parameters". The panel shows the bindings
  the switch learns and does not add them.
- **Walked octet strings arrive as hex text** ("10 00 00 00",
  "00:00:5E:00:53:23"); the reader turns them back into bytes for port lists
  and MACs.
- **Proven:** SWITCH_TEST_RESULT

## Port actions (`routes/ports.js`)

- **A PoE bounce makes the config "unsaved".** The bounce is two writes to
  the port's admin state, so the switch marks its config changed even though
  the port ends as it started. `rlPethPsePortReactivate` only recovers ports
  shut down by a hardware fault. So if the config was saved before the
  bounce, the app saves it again afterwards. If it was already unsaved, the
  app leaves it alone.

## MIB databases

`public/mib/oid-db.json` (C1200/C1300) and `oid-db-c1300x.json` (C1300X) are
generated from the official MIB archives. `public/mib/products.json` chooses
which file each product line uses. Both the browser and the server load the
same files. To regenerate one for a new firmware:

```bash
# 1. Parse a MIB set into a name -> OID map
python3 tools-parse-mibs.py path/to/MIBs_Cat1200_1300_x.y.z          # -> oid-map.json
# 2. Compact it into the database the app loads
python3 tools-compact-oiddb.py oid-map.json "C1300_MIBs_vX" public/mib/oid-db.json
```

The parser handles two traps in the MIB files:

- Inside a `SEQUENCE`, a column can be declared as `foo OBJECT IDENTIFIER,`.
  That looks like an assignment and used to swallow the next definition. A
  bare OID assignment must therefore have `::=` straight after `IDENTIFIER`.
- `DESCRIPTION` text sometimes contains an example assignment (rfc2668's
  `ifMauType`). String literals are blanked before assignments are matched.

The MIB says what the *files* define, not what a switch implements. An
unimplemented object comes back as `noSuchObject` or `noSuchInstance`.
