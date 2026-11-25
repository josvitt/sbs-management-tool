# SBS Management Tool — Cisco Catalyst 1200/1300 SSH + SNMP Client

A local web app for managing Catalyst 1200/1300 business switches: SSH
terminal sessions and SNMP queries, side by side as tabs, with the full
C1200/C1300 MIB set built in so you can query by name instead of by OID
number.

## Setup

1. Install [Node.js](https://nodejs.org) if you don't already have it.
2. Double-click **`start.bat`**.

First run installs dependencies (about a minute); later runs go straight
to starting the server, and your browser opens to `http://localhost:3000`
on its own. A console window titled "SBS Management Tool Server" stays open
while it runs — close it (or Ctrl+C) to stop.

Not on Windows? `npm install && npm start`, then open
`http://localhost:3000`.

### Run it unattended (as a service)

`start.bat` is the interactive way to run it. To have it collect from your
switches continuously — with no browser open and even after a reboot, before
anyone logs in — install it as a background service instead:

- **Windows:** right-click **`install-service.bat`** → *Run as administrator*.
  It installs a "SBS Management Tool" Windows service that starts on boot and
  runs with no window. Open the dashboard with **`open-ui.bat`** (or
  `http://localhost:3000`) and add your switches there — the service stores them
  encrypted and keeps collecting across reboots. Remove it with
  **`uninstall-service.bat`**.
- **Linux:** use the included `sbs-management-tool.service` systemd unit (see the
  comments at the top of that file).

The server does the health collection, alerting, and trap/syslog capture itself,
so the browser is only a viewer — closing it never stops collection. See
`docs/SERVER-STANDARD.md` for how that works.

## How it is organised

One **tab per switch**, draggable to reorder, with a **+** beside them.
Each switch has two sub-tabs, and what they are depends on whether the
switch exists yet.

**Before it does**, they are the kinds of credential - **SNMP**, **SSH**
and **Console** - so the first question is which one you are adding rather
than which page you want. SNMP is what the dashboard reads; SSH is needed
for `show tech-support` and the terminal; Console is the serial port.

**Once it responds**, they become **Overview** and **Settings**. Overview
is the dashboard. Settings is the same two credential forms, side by side,
for changing or adding either.

Everything else is an **overlay**, opened by the thing that produces it and
closing back to where you were: the tech-support viewer, the configuration
comparison, and the SSH terminal. None of them is a tab, because none of
them is a place you go - they are results you look at.

**Topology is a tab of its own**, first in the row and with no close
control. It is a view of the network in the same way each other tab is a
view of one switch, so it belongs in the same row and is reached the same
way; closing it would mean nothing, since there is nothing behind it to
close. It appears once there is a switch to draw and stays while any switch
exists - including ones whose tab has been closed, because that is where
they are found again.

The **MIB Explorer** and the **Log** remain buttons in the header: they are
tools that cover whatever you are looking at, not places you navigate to.

Tabs are named after **what the switch calls itself** once it says so. Two
switches on the same address but different ports would otherwise both read
as that address, which is no help when tabs are how you navigate; the
address moves to the tooltip. They cover
the working area while open because each is somewhere you go, not something
to read beside a dashboard.

### Quick actions

The Overview panel carries the things you come to a switch to *do*:

- **Collect tech-support** - runs the command and opens the viewer when it
  lands. The terminal is **cleared afterwards** and the switch nudged for a
  fresh prompt: several hundred kilobytes of capture leaves the cursor
  somewhere in the middle of a wall of text, and the output is safe in the
  viewer anyway. A new session always opens onto a clean screen, and
  **Clear** in the terminal toolbar does the same on demand - useful after
  any long command typed by hand. It works over **either transport**: the switch does not care which
  cable the characters arrive on, so the capture machinery does not either.
  With no session open it takes whichever route is set up - console first,
  for the same reason the CLI button prefers it - and fires by itself once
  that session is up. With neither, it takes you to Settings.
- **Download config** - fetched over TFTP and saved straight to disk. When
  the running and startup configurations differ it becomes two buttons, one
  for each; when they are identical there is only one thing to download, and
  a choice between two copies of the same file is a decision with no
  consequence.
- **CLI** - one way in to the command line. Which transport it uses is a
  detail of what has been set up, not a choice to make every time: the
  **console is preferred when both exist**, because it keeps working when
  the network path is the thing that is broken. With neither set up it goes
  to Settings and lights up both SSH and Console as the options they are,
  rather than failing quietly. The port
  belongs to the **switch**, not to the app: which cable goes to which
  device is exactly the thing worth remembering per switch, so it is stored
  with that switch's layout and comes back after a restart. A remembered
  port that is not currently plugged in is still shown, labelled *(not
  connected)*, rather than silently reverting to nothing.

The SSH session opened for a collection is **closed when the collection
finishes**, and closed the way a person would: `exit` is sent so the switch
tears down its own side and logs a clean logout, with the transport dropped
a moment later. Killing the socket outright leaves a dangling VTY line
until the switch's timeout expires. A session you opened as a terminal is
left alone.

### Comparing and saving the configuration

The **Config saved** metric is the entry point, and only when it says
**No**. Then it becomes clickable, and opens the comparison with the option
to save the running configuration. When it says Yes there is nothing to
compare and nothing to save, so it stays a plain reading rather than an
invitation to do busywork.

## Health dashboard

Health is a grid of panels. It opens with a default set covering the
things that matter on a Catalyst 1300 &mdash; overview, key metrics,
findings, power supplies, fans, sensors, stack, PoE and interfaces &mdash;
and grows automatically when a `show tech-support` capture is collected.
Panels with nothing to show are hidden rather than rendered empty.

### Editing the page

There is no separate SNMP tab: the dashboard *is* the query surface.

- **+ Add panel** takes any OID or MIB name, with autocomplete over the
  full 11,426-object database, and adds a panel showing it. **MIB
  Explorer** (below) can add one directly. Picking a
  table or a column of one selects WALK and queries from the base;
  picking a scalar selects GET and appends `.0`. That distinction is
  made from the MIB, not from the name &mdash; `rlifPresentName` reads like a
  scalar but lives under `rlifPresentEntry`, and asking for
  `rlifPresentName.0` returns nothing. A name that isn't in the MIB set is
  refused before it reaches the switch.
- The same dialog re-adds any built-in panel you have removed.
- **Drag a panel by its header** to reorder. To resize, drag its **right
  edge** for width, its **bottom edge** for height, or the **corner** for
  both; a badge shows the size as you drag. Three grab areas rather than
  one corner, because a 16px corner is hard to find and most panels start
  full width, so dragging it right does nothing - which reads as "resize is
  broken".
- Switch tabs can be **dragged to reorder**; the **+** button sits with
  them.
- The dashboard opens with **Details** and **Key metrics** showing and
  everything else minimised. Each is one click away, and a page that opens
  with eight tables is a page nobody reads. Expanding a panel paints it
  then - a folded panel builds no rows at all.
- **The whole header folds and unfolds a panel**, and only the **☰** grip
  starts a drag. The title is a line of text a few pixels tall inside a
  header three times that, so clicking just below the words did nothing -
  the app's fault rather than the operator's. With the whole header draggable the browser treated a press on the
  title as the beginning of a drag and suppressed the click that followed,
  which is why folding often took two attempts.
- Each panel header has **⟳** (refresh just this panel), **▾** (minimise
  to just the header), **✎** (edit, on OID panels) and **✕** (remove).
  A minimised panel stays minimised: it is remembered with the layout, and
  the grid closes over it rather than leaving a hole. **Clicking the title
  does the same thing** - a bigger target than the caret.
- **A panel whose contents do not fit is given its full height and moved to
  the bottom** - keeping, among the moved panels, the order the dashboard
  is meant to read in, so Spanning tree stays below Interfaces & VLANs
  rather than floating above it because it happened to overflow first.
  **Expanding a panel by hand never moves it**: a click on the title is a
  request to look at something, and having it jump to the bottom of the
  page mid-click is not what was asked for. It still gets its full height - so the page scrolls once instead of the page scrolling past
  a box that scrolls too. Scrolling inside a scroll is the worst way to
  read a table. A panel you have sized by hand is left exactly as you set
  it.

**⟳ refreshes only that panel**, and for most panels only its tables are
re-walked - refreshing Interfaces does not re-read a 1,500-entry
forwarding database. Overview, Key metrics and Findings describe the whole
switch, so for those there is nothing smaller to ask for and the button
does a full collection.

Layouts are saved per host on the server in `layouts.json` and restored on
reload. **Reset layout** returns to the defaults. This file holds
configuration only &mdash; panel positions, sizes, OIDs &mdash; never captured
device output or query results.

### Auto-refresh

The interval is editable (5&ndash;3600s, default 30) and the label counts
down &mdash; "Refreshing in 24s" &mdash; so it is obvious whether the page is
live or stale. Any refresh, manual or automatic, restarts the countdown,
and changing the interval applies immediately.

Auto-refresh re-reads everything. To update one panel on its own, use its
**⟳** button.

### The dashboard is SNMP only

Everything on the dashboard is live SNMP. A `show tech-support` capture is
a point-in-time text dump collected on demand, and mixing it in made it
ambiguous whether a panel was showing the switch now or an hour ago, so the
capture no longer feeds the dashboard at all.

| Panel | Source |
| --- | --- |
| Interfaces & VLANs | `rlifPresentTable` + `pethPsePortTable` + `dot1qVlanCurrentTable` |
| Sessions & authentication | this app's sessions, `rlSecSdMngSessionsTable`, `rlSshServerSessionInetTable`, `rlTelnetUsersTable`, `rldot1xAuthMultiSessionStatsTable`, `rldot1xLockedCientsTable` |
| Connected devices | `cdpCacheTable` + `lldpRemTable` + `dot1qTpFdbTable` |
| MAC address table | `dot1qTpFdbTable` + `dot1dBasePortTable` |
| Hardware | inventory, supplies, fans, sensors and stack in one panel |
| Spanning tree | `dot1dStp*` plus the MSTP or PVST family in use |
| Configuration | `rlCopyTable` (see below) |

These tables index themselves by things nobody thinks in, so the values are
resolved before display:

- **Interfaces reporting `notPresent(6)`** are dropped wherever the list
  came from. That status means the interface is not physically there - a
  slot the switch describes but has no hardware for - which is not the same
  as a port that is down.
- **Interfaces, PoE and VLANs are one table.** They all describe the same
  physical ports: what the port is doing, what it is powering, and what it
  carries. The switch reports VLAN membership per VLAN, as a bitmap of
  ports; looking at a port you want the other direction, so the bitmaps are
  inverted once into a per-port index and shown as **Untagged** and
  **Tagged** columns - a trunk reads `1` and `10-12, 20` rather than
  needing four VLAN rows cross-referenced by eye. The VLAN table follows
  underneath: the columns answer "what is this port in", the table answers
  "what is in this VLAN".
- **A VLAN interface is not a port.** The switch lists its VLAN interfaces
  in the same table as its ports, named after the VLAN id, so VLAN 10
  appeared twice on screen: once as a "port" called `10` and once as VLAN
  10. They are the same thing seen twice, so the interface is folded into
  the VLAN row it belongs to - as an **Interface** column carrying its
  state - and dropped from the port list.
- **A badge with nothing in it is just a coloured box.** An interface with
  no PoE gets an empty cell rather than an empty pill implying a state it
  does not have. The PoE columns
  appear only on a switch that has PoE, and the budget sits above the table
  it applies to. A PoE row with no matching interface still gets a line
  rather than disappearing.
- **Connected devices comes before spanning tree**, because what is
  attached is the more common question and it is the context for reading
  the topology.
- **Everything reachable through a port is one panel.** CDP and LLDP are
  two protocols describing the same neighbours, so they are one table with
  a column saying which spoke - a device running both would otherwise
  appear twice, in two panels, leaving you to work out it was one device.
  The forwarding database sits underneath: who announced themselves, then
  what has simply been seen.
- **Inventory leads the hardware panel**: what the box *is* comes before
  how it is doing.
- **The physical box is one panel.** Supplies, fans, sensors, the stack and
  the inventory are all answers to "what is in this switch and is it
  healthy", and as five separate panels they were five mostly-empty boxes.
  The stack section appears only when there is more than one unit - a
  single unit is not a stack, and saying so tells nobody anything the model
  number does not.
- **Inventory shows only hardware with an identity**: chassis, stack
  members, modules, transceivers. Ports, fans, supplies and sensors each
  have their own panel showing them in more useful form, and rows with no
  model, serial or revision identify nothing. Where `entPhysicalName` is
  just an index, the description is shown instead.
- **VLAN membership** comes from `dot1qVlanCurrentTable`, the operational
  view. The static table is consulted only for names: switches populate
  Current even when Static is sparse, and reading membership from Static
  showed every VLAN as having no ports. Membership arrives as `PortList`
  bit-per-port bitmaps. They are
  decoded to port numbers and collapsed into ranges (`1-4,24`), and the
  tagged set is derived as egress minus untagged - which is what
  `show vlan` prints and what neither bitmap gives you on its own.
- **CDP** is indexed by ifIndex, **LLDP** by `timeMark.localPort.index`,
  and the **forwarding database** by `vlan.macaddress` with a *bridge* port
  number rather than an ifIndex. All are resolved to interface names, so a
  neighbour shows as `gi1/0/2`, not `ifIndex 2`. The MAC is reconstructed
  from the last six sub-identifiers of the index, which works whether or
  not the agent length-prefixes it.

The larger walks are capped (`dot1qTpFdbTable` at 1500 rows, VLANs at 4096)
so one busy switch cannot stall the page.

## SNMPv3

Authentication and privacy are chosen independently; the security level is
derived from the two rather than being a third setting to get wrong
(`authPriv` with privacy set to None is a contradiction the user should
never have to resolve). Password fields appear only for the methods
actually in use, and privacy without authentication is refused with an
explanation rather than a failed request.

| Authentication | Privacy |
| --- | --- |
| None | None |
| MD5 | AES-128 |
| SHA (SHA-1) | AES-192 |
| SHA-224 | AES-256 |
| SHA-256 | AES-192 (Blumenthal key extension) |
| SHA-384 | AES-256 (Blumenthal key extension) |
| SHA-512 | |

Two things worth knowing:

**AES-192 is not in the SNMP library.** net-snmp ships AES-128 and two
AES-256 variants only, so AES-192 is registered into its algorithm table by
`snmp-crypto.js` at startup. If a future library version reshapes those
internals the app fails loudly on start rather than emitting packets the
switch silently rejects.

**AES-192 and AES-256 need key extension, and there are two schemes.** A
localised key from SHA-1 is 20 bytes, short of the 24 and 32 those ciphers
need. Reeder (used by Cisco) and Blumenthal (used by several other vendors)
extend it differently and are not interoperable. A mismatch looks exactly
like a wrong password, so both are offered explicitly; **AES-192** and
**AES-256** use the Cisco/Reeder scheme, and the Blumenthal entries are
there for anything else.

The menus are served from the backend (`/api/snmp/v3-options`) so the list
the UI offers is exactly the list the server can build a session for, and
ciphers are probed at startup: **DES is hidden entirely on Node builds
where OpenSSL 3 has dropped it**, because offering a method that cannot
work is worse than not offering it — the failure would otherwise surface
mid-request as an opaque "digital envelope routines::unsupported".

Verified against a live v3 agent across all 37 legal auth/privacy
combinations.

## The Configuration page

The **Configuration** page sits between Health and Tech-Support. One button,
**Fetch configurations**, pulls both the running and startup configs and
diffs them - fetching one without the other was never the interesting case.
The result is three views you can switch between freely: **Running**,
**Startup** and **Differences**. It opens on the differences when there are
any, and on the running config when the two match. It is a page rather than a dashboard panel because
fetching files is a task you go and do, and a config deserves the whole
viewport rather than a box to scroll past.

`show tech-support` is collected on its own page, next to the viewer that
reads it: it comes over SSH rather than SNMP, it is two orders of magnitude
larger, and it has a section browser the configs do not need.

Whatever has been fetched stays held and is selectable from the chips under
the buttons, so nothing is lost by looking at something else. Comparing
does not discard the configuration you were reading, switching between
Running, Startup, Differences and Tech-support costs nothing, and
**Compare** reuses copies already held rather than pulling them off the
switch again. Only **Refetch** goes back to the device. **Save this**
exports whichever document is on screen.

### Which way the differences read

The comparison is made **from the saved configuration outwards**, so `+` is
a line that is running but not saved - what a reload would lose - and `-` is
a line that is saved but no longer in effect. The other direction is
technically just as true and reads backwards every time, because the
question people arrive with is "what have I changed since I last saved".

### Reading the differences

A few lines of context is the wrong unit for a switch configuration.
`snmp trap link-status` added to two ports shows up as two identical
one-line changes, and three lines either side often does not reach the
`interface` header - so the diff tells you *what* changed and leaves you to
work out *where*, which is the part you needed.

Differences are stated **in terms of the running configuration**, because
that is the one being changed: a `+` is a line you added and have not
saved, a `-` is a line you removed that a reload would bring back.

A configuration is made of blocks: an unindented header with indented lines
under it. So a change inside a block prints **the whole block**, and the
header names the interface, the VLAN or the line it belongs to. Changes
that are themselves top-level keep the usual few lines of context.

The diff trims the **common head and tail** before running the
longest-common-subsequence table, which is quadratic in the input. Two
configurations from the same switch share nearly everything, so what
reaches the expensive part is the handful of lines that differ. On a
16,000-line pair that is the difference between 4,600 ms and 5 ms; a pair
where every line differs still finishes in about 30 ms.

**While the switch is being written to, the way out is removed** rather
than merely discouraged, and the header says why. Closing mid-save looks
like the save was abandoned, and the operator cannot tell that it was not -
the worst thing to be unsure about after pressing a button that overwrites
a configuration. The close returns when there is an answer to show.

### History

The **History** chip lists earlier running configurations of the switch,
newest first, with **View** and **Compare** on each. Compare shows what
changed from that version to the running configuration fetched on this
page, or to the newest stored version when none has been fetched.

A version is kept each time the running configuration's text changes,
starting with the first one the app sees. Copies come from the server's
background change check, which pulls the running config when the switch's
saved/unsaved flag flips, after a reboot and after a change made from this
app, and from fetching the running config here. So the history costs no
extra pull from the switch. A change made and saved entirely within one
30-second probe gap can be missed (docs/SERVER-STANDARD.md §5). Each
version is a file under `config-history/<switch>/`, encrypted with the same
key and passphrase rule as the saved state (`state.enc`). The newest 50 per
switch are kept; `SBS_CONFIG_HISTORY_KEEP` changes that and
`SBS_CONFIG_HISTORY_DIR` moves the folder.

### How it works

No MIB object returns configuration text, so the app drives `rlCopyTable`
to make the switch upload the file, and the TFTP server that receives it is
**built into this app** - there is nothing else to set up.

Requirements and caveats, none of which the app can paper over:

- **SNMP write access.** The copy is a row creation in `rlCopyTable`; a
  read-only community cannot do it. Row creation is not handled identically
  by all firmware, so three forms are tried in order (single-PDU
  `createAndGo`, then `createAndGo` followed by populate, then
  `createAndWait`/populate/`active`) before giving up.
- **The switch must reach this machine on UDP 69.** The destination address
  is worked out per request from the route to that switch rather than
  configured, because guessing is wrong on a multi-homed machine. On Linux,
  binding port 69 needs elevated privileges; `TFTP_PORT` can move it, though
  the switch will still try 69 unless it can be told otherwise.
- **TFTP is unauthenticated and cleartext**, and a running-config contains
  credentials and community strings. A received file reaches disk only
  encrypted, as a config history version (below); saving a readable copy
  is a deliberate act.

The **Compare** diff uses a longest-common-subsequence pass rather than a
line-by-line compare, so an inserted line does not report everything after
it as changed, and long unchanged runs are collapsed. It pairs with the
health page flagging that running differs from startup: the flag says
*that*, the diff says *what*.

## Performance

Measured against a mock 48-port switch with 52 interfaces, 64 VLANs and a
1,500-entry forwarding database, not guessed at:

| | Before | After |
| --- | --- | --- |
| Page weight, first load | 2.2 MB | 129 KB |
| Page weight, reload | 2.2 MB | ~1.5 KB of 304s |
| Health response on the wire | 432 KB | 24 KB |
| Varbinds per collection | 4,368 | 2,123 |
| One interface table walk | 2,080 varbinds, 287 ms | 364 varbinds, 52 ms |
| Dashboard re-render | 308 ms | 34 ms |
| Collection over a 4 ms-per-request link | 1,947 ms | 1,345 ms |

What changed, and why:

- **Only the columns that are shown are fetched.** Walking a table walks
  every column in it, and most carry far more than any panel uses -
  `rlifPresentTable` has forty and the Interfaces panel needs seven.
  Naming the columns turns one broad walk into a few narrow ones, which is
  fewer varbinds *and* fewer round trips, since each GETBULK response then
  fills with rows rather than with columns nobody asked for. Measured on
  one table: 2,080 varbinds and 287 ms became 364 and 52 ms. Small tables
  are still walked whole - a five-row table is not worth four walks.
- **The MIB database is fetched when something needs it.** It is 2 MB of
  JSON (315 KB compressed) and the dashboard never touches it: names are
  resolved server-side. Only the MIB Explorer and the add-panel
  autocomplete use it, so it loads when one of those is first opened.
  First paint went from 422 KB to 129 KB.
- **Assets revalidate instead of re-downloading.** The compression layer
  bypassed express's ETag handling, so every reload pulled the whole
  payload again. Cached bodies now carry an ETag and answer 304, making a
  reload a handful of header exchanges.
- **The terminal scrollback is 40,000 lines, not 500,000.** That was sized
  when captures landed in the terminal; they go to the viewer now, and a
  full `show tech-support` is under 8,000 lines.

- **Static assets and API responses are gzipped.** The MIB database alone
  is 2 MB of JSON fetched on every page load and compresses to 315 KB.
  Compressed bodies are built once and cached, since the files do not
  change while the server runs.
- **`display` is omitted when it would just repeat the value.** On a switch
  with a full forwarding database that was thousands of duplicated strings
  per refresh for no gain; readers fall back to the value.
- **Refreshing repaints panel bodies in place** instead of rebuilding the
  grid. This also fixed a real annoyance: scroll positions inside tables no
  longer jump to the top every 30 seconds.
- **Large tables render the first 250 rows** with a count and a *Show all*
  control, and rows go in through a document fragment so the browser lays
  out once rather than per row. The MAC table alone was 6,000 DOM cells.
- **Health walks run three at a time.** Each walk is many round trips, so
  on anything but a local switch the collection is latency-bound. The limit
  is deliberately low - six was only 6% faster than three, and a switch CPU
  that is already busy is exactly the one you are trying to measure.
  `SNMP_CONCURRENCY` overrides it.

One thing deliberately *not* changed: MIB Explorer search scans all 11,426
objects including their descriptions on every keystroke, which sounded
expensive but measures at 0-1 ms. It was left alone.

## Spanning tree

The panel is laid out the way `show spanning-tree` reads, because that is
the shape the information actually has.

### Working out which mode is running

`dot1dStpVersion` looks like the answer and is the wrong thing to trust on
its own. Catalyst 1200/1300 firmware will happily report **`rstp`** there
while actually running Rapid-PVST, and some builds do not implement the
object at all. Believing it meant the per-VLAN tables were never walked and
the page showed only the common instance - which reports every port
disabled, and is exactly the misleading view this panel exists to avoid.

So the small per-instance tables (`rlBrgPvstOperVlanTable` and
`rldot1sMstpInstanceTable`, one row per VLAN or instance) are **always**
walked, and the decision is made on evidence: if the switch is populating
per-VLAN or per-instance state, that is the family in use whatever the
scalar claims. The version scalar only breaks ties and names the plain
STP/RSTP cases, where there is no per-instance table to find. Only the
heavy per-port tables are conditional.

When the two disagree the panel says so rather than quietly overriding the
switch - *"Rapid-PVST / PVST · the switch reports "rstp (2)""*, with a line
naming the evidence the decision was based on. When no per-instance tables
are populated at all, it says that too, so an empty result is
distinguishable from a lookup that never happened.

### Per VLAN, or per instance

Under Rapid-PVST or PVST the real state is **per VLAN**; under MSTP it is
per instance. Each gets its own card carrying what the CLI prints: the root
ID as priority and address, whether **this switch is the root** (derived by
comparing the root's address with our own bridge address, which is the same
comparison the switch makes), the root port and path cost when it is not,
the bridge priority, the timers, and the topology-change count.

Below each card are the ports **actually participating**, decided on the
port's **state**, not its role. Role alone is not enough: switches report
"designated" against ports that are disabled, and even against slots that
do not physically exist, which is self-contradictory - a disabled port has
no role. The CLI agrees, showing an idle port as `Dsbl Dsbl` and marking
activity in the Sts column. Each listed port shows role, state, cost,
priority, edge status and BPDU counters. Disabled ports are counted but not listed, and an
instance with nothing participating says so in a line rather than in a
table of nothing.

This matters more than it sounds. On the switch this was built against, the
CLI prints 180 port rows across five VLANs; six of them are doing anything.
The panel shows those six.

### The common instance

`dot1dStpPortTable` is shown **only when it is the answer** - that is, when
the switch is running plain STP or RSTP, where it is the main port list.

Under a per-VLAN or per-instance mode it is left out entirely, along with
its hidden-row note. On a real Rapid-PVST switch it reports every port
disabled, and a table of misleading values plus an explanation of why they
are misleading is still a table of misleading values. The per-VLAN cards
are the state.

### Fetching the per-port state

The per-port tables are indexed instance-by-port, so five VLANs across 424
bridge ports is over two thousand rows of sixteen columns. They are **not
walked**. A walk returns a table column by column, so any row limit
truncates whole *columns* rather than trailing rows - the cap was being
spent inside the two index columns, every row came back carrying an index
and nothing else, and the panel concluded that no port was participating
anywhere.

The VLANs (or MST instances) are already known, and so are the bridge ports
that map to real interfaces, so the exact instances are fetched by name in
batched GETs. On the switch this was built against that is **980 varbinds
instead of 33,920**, and never a partial column. Very large VLAN counts are
capped at 1,200 instances, and the shortfall is reported rather than
silently dropped.

### Details that were worth the effort

- **Bridge IDs are decoded**, not dumped as hex: `80 00 24 d7 9c e8 b6 ca`
  becomes `32768  24:D7:9C:E8:B6:CA`, and where the low twelve bits carry a
  VLAN or instance the panel splits it out: `32769 (32768 + 1)`.
- **Timers carry their real units.** The BRIDGE-MIB scalars are `Timeout`,
  hundredths of a second, and read as `max age 2,000` raw. The *vendor*
  per-VLAN and per-instance timers are documented in whole seconds, so the
  same conversion turned a 2-second hello into `0.02 sec`. Each family is
  now handled on its own terms and both read as the CLI does: `hello 2 sec
  · max age 20 sec · forward delay 15 sec`.
- **Bridge ports resolve to interface names.** These tables are indexed by
  bridge port, like the forwarding database, so `24` becomes `tw1/0/24`.
- **Ghost ports are dropped.** A real C1300 answers for **424 bridge
  ports** when about 50 interfaces exist - every slot in its ifIndex space,
  including stack members that are not fitted. Rows are kept only for
  interfaces present in `rlifPresentTable`, and only when they carry a state
  or role. The count of what was hidden, and why, is shown in the panel.

### Findings

A port reporting state `broken`; ports blocked for an inconsistency (read
from both the vendor `rlBrgPvstInconsistencyPortTable` and the standard
Cisco `stpxInconsistencyTable`); and a topology change within the last five
minutes, since churn usually means a link is flapping. Being the root
bridge is reported as information, since an access switch winning the
election generally means the intended root is misconfigured or gone.

## Syslog

A switch only tells you about an event *as it happens* over syslog - the
SNMP log tables are a snapshot and a tech-support capture is a text dump.
The collector runs **inside this app**, so a switch can be pointed at it
with nothing else to install.

The **Syslog** panel sits directly under Key metrics and **updates live** -
messages appear as the switch sends them, with no refresh. That is a
server-sent event stream rather than polling: one-way, text-based, needing
no protocol of its own, and the browser reconnects by itself if the link
drops. A badge shows whether the stream is connected.

Arriving lines are inserted into the table already on screen rather than
repainting the panel, so a chatty switch does not make the page flicker or
fight whatever you are reading, and each new line flashes briefly so an
arrival is noticeable. The severity filter and search apply to arriving
messages too, not just to what was already there.

The panel shows what has arrived from that switch, with severity decoded
from the PRI header and the `%FACILITY-S-MNEMONIC` marker pulled
out of the body - so `%LINK-W-Down: gi1/0/5` lists as `LINK-W-Down` with
the message `gi1/0/5`. Both RFC 3164 and RFC 5424 framing are parsed, and a
message with no PRI header falls back to the severity letter in the
mnemonic. Filter by severity, or search the text.

Messages are held **in memory only**, in a bounded ring of 2,000 per
source. Log lines routinely carry usernames, addresses and topology detail,
and persisting them by default would be a decision you did not make.

### Detecting and configuring

The panel does not just show messages - it shows whether the plumbing
exists, because a log view that is silently empty because nobody pointed
the switch at it is worse than useless. It reads
`snmpSyslogCollectorTable` and compares the entries with the address this
machine is reachable on from that switch (worked out per request from the
route, since guessing is wrong on a multi-homed machine).

- **Not configured** - it says so, and offers to add itself. That writes to
  the switch, so it names the address and port and asks first. You choose
  the severity threshold. Afterwards the table is re-read so the panel
  proves the change rather than asserting it.
- **Configured but silent** - if the collector points at a different port
  than the receiver is listening on, that is named outright: it is the
  likeliest reason for a configured-but-quiet switch.
- **Logging globally disabled** - `rlSyslogGlobalEnable` is checked, and
  turned on as part of configuring, since a collector row alone would be a
  silent no-op.
- **Receiving without a matching row** - reported as an observation rather
  than a fault; the messages may be relayed or sent from another address on
  the same device.

Catalyst 1200/1300 firmware carries **three** collector tables: the IETF
draft one it inherits (`snmpSyslogCollectorTable`) and two vendor tables
(`rlsnmpSyslogCollectorTable`, `rlRegisteredLogsSyslogCollectorTable`).
Which of them a given build actually implements varies, so all three are
read and a write is attempted against each in turn. Reading all three
matters as much as writing: a switch that keeps its collectors in a vendor
table would otherwise look unconfigured, and then refuse the write. The
panel names the table each collector came from.

Row creation uses the same three RowStatus forms tried elsewhere, and the
index comes from the agent's own next-available hint where implemented,
otherwise the lowest free slot, so an occupied row is never overwritten.

The UDP port column is **`Unsigned32`**, not `INTEGER` - `SyslogUdpPort`
resolves to Unsigned32 in the IETF draft MIB, and
`rlRegisteredLogsSyslogCollectorUdpPort` says so directly. Sending it as
INTEGER is what makes a switch answer `WrongType` on exactly that OID while
every other column is accepted, which reads like a permissions problem and
is not one. If a build disagrees, the write is retried with INTEGER before
moving on.

When no table accepts the entry the error lists **what each one returned**,
OID by OID, and points at the CLI equivalent - "check your credentials" is
no help when the credentials are known to be read/write.

Binding UDP 514 needs elevated privileges on Linux; `SYSLOG_PORT` moves it,
and whatever port is in use is what the switch gets configured with. A bind
failure is reported in the panel rather than being fatal - everything else
still works.

## MIB Explorer

Finding the right object among 11,426 of them is the awkward part of using
SNMP on this platform, so the explorer is built around finding rather than
browsing.

- **Search covers names, OIDs and descriptions.** Name matches outrank
  description matches, so searching `fan` puts the fan objects first
  rather than everything that merely mentions fans. Description search is
  what makes plain-English lookup work: searching *"packets per second"*
  surfaces `rlSctCpuRate`, whose name gives no hint of what it does.
  Multiple words all have to match, somewhere.
- **Filters** narrow by access (readable / writable), by shape
  (scalar / table column / table) and by tree (vendor or standard MIB-II).
  Shape is decided from the MIB tree, not the name &mdash; `rlifPresentName`
  reads like a scalar but is a column of `rlifPresentEntry`.
- **Detail** shows access, syntax, units, defining MIB file, the full
  DESCRIPTION and any enumeration values, plus parent, children and
  siblings so you can walk the tree. Sibling navigation is usually how you
  find the column you actually wanted.
- **Add as panel** puts the object straight onto the active switch's
  dashboard with the right operation chosen (GET at `.0` for a scalar,
  WALK from the base for a table or column), which is the reason you were
  looking it up. **Copy OID** is there for use elsewhere.

## The Tech-Support viewer

**Collect tech-support** lives on this page, alongside the viewer that
reads the result. If no SSH session is open the request is remembered, you
are taken to the SSH tab for credentials, and the command fires by itself
once the shell is ready - then you land back here with the capture loaded.

The viewer opens on **Full output** - the entire
capture, all 58 sections of it - because opening on the first section shows
you the command echo, which tells you nothing. The left rail lists **Full
output**, then **Key sections**, then **All output**. Selecting a section
shows any fixed-width tables in it parsed into real columns with the raw
text below. Search filters the rail, reports per-section hit counts and
highlights matches. **Save capture** downloads the raw text.

Paging is disabled before the command runs (`terminal datadump`) so the
capture does not stall on a `More:` prompt. Completion is detected by the
device prompt reappearing *after* the output goes quiet - tech-support
prints intermediate prompts inside its own output, so a prompt alone is not
enough. If the stream idles without a prompt the capture still returns what
it has, flagged with the reason, rather than hanging until the 15-minute cap.

Two parsing details that real captures depend on:

- A table's dashed rule looks exactly like a section banner, so a section
  name must contain a letter. Without that guard every table becomes a
  phantom section.
- Rows wrap. `show vlan` continues its port list on following lines with an
  empty VLAN column, and `show cdp neighbors` wraps the Platform field the
  same way. Those continuation lines are folded back into the row above,
  otherwise a VLAN's port list is truncated at the first line.

Verified against a real 7,968-line capture from a stacked C1300-24MGP-4X:
58 sections, 28 ports, 5 VLANs, 2 CDP and 2 LLDP neighbours.

## MIB support

`public/mib/oid-db.json` is generated from the official Catalyst
1200/1300 MIB archive (`C1300_MIBs_V4_1_9_85`, 185 files) and contains
**11,426 resolved OIDs** — the vendor tree under the Cisco Small
Business root `1.3.6.1.4.1.9.6.1.101`, plus the standard MIB-II tree.
Both the browser and the server load the same file, so there is one
source of truth.

Two parser correctness notes, since they affected real OIDs:

- Inside a `SEQUENCE` block a column can be *declared* as
  `foo OBJECT IDENTIFIER,`. That looks like an OID assignment, and
  parsing it as one consumed the next real definition in the file. This
  is why `ifIndex` and `rlifPresentIndex` were originally absent while
  `ifSpecific` and `rlifPresentSpecific` carried their OIDs.
- MIB `DESCRIPTION` prose sometimes contains a literal example
  assignment (rfc2668's `ifMauType` documents
  `unknownMauType OBJECT IDENTIFIER ::= { 0 0 }`), which hijacked the
  enclosing object's own assignment.

Both are handled now: bare OID assignments must have `::=` immediately
after `IDENTIFIER`, and string literals are blanked before assignments
are matched. Together these corrected 34 OIDs and recovered 39 names
that were previously missing.

What this gives you:

- **Query by name.** Type `sysName.0`, `rlPethPsePortTable`, or
  `rlCpuUtilDuringLastMinute.0` instead of numeric OIDs. Numeric OIDs
  still work exactly as before, and the two can be mixed.
- **Autocomplete.** Typing in the OID box searches all 11,391 names and
  shows the resolved OID, access level (read-only / read-write / …) and
  syntax for each match. Arrow keys and Enter select; picking a scalar
  appends `.0`, picking a table leaves the base for walking.
- **Named results.** Responses are labelled with the MIB name they map
  to, using longest-prefix matching so instance suffixes survive —
  `1.3.6.1.4.1.9.6.1.101.108.1.1.6.1.5` displays as
  `rlPethPsePortPowerLimit.1.5`.
- **Clear errors.** A misspelled name is rejected up front
  ("Unknown MIB name: …") rather than being sent to the switch as
  garbage.

### Interfaces: rlifPresentTable, not ifTable

The 4.1.9.85 release notes add `rlifPresentTable`, which reports only
interfaces physically present in the stack. The standard `ifTable` also
lists interfaces that do not exist — for example units that are not
currently stack members — so polling it in a stacked deployment returns
rows for hardware that isn't there.

The interface presets therefore use the vendor table:

- **Interfaces (present only)** → walks `rlifPresentName`
- **Interface Status (present)** → walks `rlifPresentOperStatus`
- **Interface Detail (present)** → walks the whole `rlifPresentTable`

`ifTable` is still available under Standard MIB-II (**ifTable (all, incl.
absent)**) for comparison or for firmware older than 4.1.9.85. Walking it
— by preset or by typing any `if*` OID — displays an inline note pointing
at the present-only equivalent. It's an advisory, not a block.

### Walk safety (MAXOIDSINKEYREACHED)

Walks are bounded in this client rather than delegated to the SNMP
library. `net-snmp`'s built-in walk issues GETBULK with
`maxRepetitions: 20`; at the end of a subtree the agent still has to
produce the remaining repetitions, so it keeps generating successors
*past* the requested subtree and into unrelated variables. On Catalyst
1200/1300 firmware that can make the switch log:

```
%SNMP-D-MAXOIDSINKEYREACHED: too many oids in key for variable 38,
key = IP_Applications.DNS_client.maximum_number_of_pending_msgs
```

The bounded walk in `snmp-core.js` keeps GETBULK's speed but enforces the
subtree boundary locally: anything outside the base OID is discarded and
the walk stops rather than asking for more. It also lowers
`maxRepetitions` to 10, caps total rows, guards against OID depth blowing
up, and detects an agent that fails to advance (which would otherwise
loop forever).

If a switch still complains, tick **Compatibility walk (GETNEXT)** in the
query bar. That drops to one GETNEXT at a time, which never speculates
beyond the boundary. It is slower but maximally conservative; both modes
were verified to return identical data.



Grouped into standard MIB-II (System Info, Interface Names / Status /
Aliases, VLANs, Inventory, standard PoE) and Catalyst 1200/1300 specific
(CPU Utilisation, PoE Ports, Fans, Power Supplies, Stack Units). Presets
reference MIB names, not hardcoded numbers, so they read as
documentation.

### Regenerating for a different firmware

`tools-parse-mibs.py` is the generator. Point it at an unpacked MIB
archive and it rewrites the database:

```bash
# Step 1 - parse a MIB set into a name -> OID map:
python3 tools-parse-mibs.py path/to/MIBs_Cat1200_1300_x.y.z      # -> oid-map.json
# Step 2 - compact that into the DB the app loads:
python3 tools-compact-oiddb.py oid-map.json "C1300_MIBs_vX" public/mib/oid-db.json
```

The app ships **per-product** MIB databases, chosen by `public/mib/products.json`
(the product registry, read by both the browser and the server): C1200 and
C1300 share `oid-db.json` (their MIB sets are identical); C1300X uses
`oid-db-c1300x.json` (it adds OSPF/PTP and renumbers the 802.3bt PoE table).
Regenerate a product's DB by running the two steps above against that product's
MIB set and writing to its file. The MIB Explorer has a product picker, and the
connected switch's line is detected from its model string (`products.js`).

It resolves names iteratively (a MIB can anchor onto a parent defined in
another file) and prints spot-checks plus a count of anything it could
not resolve. On the shipped 4.1.9.85 archive it resolves all but one
entry — `null ::= { ccitt 0 }`, which is a CCITT root nothing references.

## Reading the output

Results are formatted using the MIB definition behind each OID rather than
dumped raw.

**Values are decoded.** The database carries 2,482 enumerations and 353
UNITS clauses (pulled from inline `INTEGER {...}` bodies and from the
TEXTUAL-CONVENTIONs objects reference, such as `TruthValue` and
`IANAifType`), so:

| Raw | Shown as |
| --- | --- |
| `2` (rlifPresentOperStatus) | `down (2)` |
| `5` (rlEnvMonSupplyState) | `notPresent (5)` |
| `6` (rlifPresentType) | `ethernetCsmacd (6)` |
| `e4 4e 2d 4a c3 2d` | `E4:4E:2D:4A:C3:2D` |
| `60761302` (TimeTicks) | `7d 0h 46m 53.02s  (60,761,302 ticks)` |
| `1000000000` (Speed) | `1 Gbps  (1,000,000,000)` |
| `4294967295` (Speed) | `unknown (use HighSpeed)` |
| empty OctetString | `(empty)` |

**Counter64 is read as a number.** net-snmp returns 64-bit counters as raw
big-endian buffers. Rendering those as text — which is what a
printable-ASCII check does — turns `0x32 0x78 0x59` into the string `2xY`
instead of `3,307,609`. Counters are now always decoded as integers, so
octet and packet counts are correct rather than mojibake.

**Tables are pivoted.** A walk returns one column at a time: every row's
column 1, then every row's column 2, and so on. For `rlifPresentTable`
that is 41 separate runs of values you would have to reassemble by eye.
Results are instead grouped into one row per instance index, with columns
across the top, a frozen index column, and the shared name prefix stripped
from headers (`rlifPresentOperStatus` → `OperStatus`, with the full name on
hover). A table's own index column is dropped when it just repeats the row
key. Rows sort numerically, so index 1800 lands after 52 rather than after
17.

Three shapes are recognised automatically:

- **scalars** (every instance `.0`, e.g. System Info) → object/value list
- **tables** (many columns × many indexes) → pivoted grid
- **single-column walks** (e.g. `rlifPresentName`) → index/value pairs

Every block has a **Show raw OIDs** toggle for the flat OID/type/value list.

## Saving output

SSH sessions have a **Save** button that downloads the terminal transcript
with ANSI control codes stripped and backspaces resolved, so a prompt
redraw like `\x1b[1;32mcore-350\x1b[0m#\x1b[K` saves as plain
`core-350#` rather than visible `[K` junk. The live terminal still
receives raw bytes and renders colour normally.

Nothing else is written to disk automatically. The only file the app
maintains on its own is `layouts.json` (dashboard configuration) and
`logs/app.log` (connection metadata for troubleshooting the tool).

## Layout

A saved layout never hides a panel that did not exist when it was saved:
anything missing is inserted where it belongs in the default order, and
panels this version no longer knows about are dropped. Rearranging the
dashboard between releases should not mean losing the new parts of it.


The window is locked to the viewport: exactly one scroll region is
active at a time (the terminal's own scrollback, the SNMP results list,
or the log panel), and the page itself never scrolls. This is verified
by an automated check that measures `scrollWidth`/`scrollHeight` against
client size at 1280px, 380px and 300px wide, with up to ten tabs open
and the log panel showing.

The log panel is an overlay rather than a column, so opening it never
widens the layout or pushes content off-screen.

## Sessions and authentication

Who is on the switch, and who has been let onto the network through it.
Three sources answer that, and the panel keeps them apart because they mean
different things:

- **This app** - the SSH and console sessions this process is holding, how
  long they have been open, and whether one is mid-capture. A console
  session is worth knowing about because it is a physical port: "why can I
  not open the console" is usually answered by "because this tab already
  has it".
- **The switch's own view** - `rlSecSdMngSessionsTable` lists everyone
  logged in with their privilege level and whether the channel is secure;
  `rlSshServerSessionInetTable` adds the peer address and negotiated
  cipher, and `rlTelnetUsersTable` any unencrypted sessions.
- **802.1x** - authenticated hosts with username, MAC, method (EAPOL, MAC
  or web), assigned VLAN and session age, from
  `rldot1xAuthMultiSessionStatsTable`, and clients the switch has locked
  out after failed attempts, which also raise a finding: a locked-out
  client is a person who cannot work, or a device quietly off the network.

MACs are decoded out of the table index and ports resolved to their
interface names, as everywhere else.

## Events: syslog and traps together

Syslog tells you what a switch decided to write down; a trap is the switch
interrupting you. A link going down, a fan failing, a topology change or a
failed authentication arrives within a second of happening, where a poll
would not notice until its next pass.

The receiver listens on UDP 162 (`TRAP_PORT` to override; ports below 1024
need elevation on Linux) and starts with the app, because a trap that
arrives while nobody is looking is exactly the one worth having kept. Held
in memory, per source, 1,000 deep - traps are a running commentary, not an
archive, and an app that writes them to disk becomes one that has to be
pruned.

Each trap is decoded through the MIB database, so the panel reads

    linkDown   ifIndex.3 = 3 . ifOperStatus.3 = down (2) . ifName.3 = gi1/0/3

rather than a row of numbers. Severity comes from the notification's own
name - anything that says a thing failed, went down or was denied is
coloured - because a switch does not label its traps. They stream in live,
like syslog.

Syslog and traps answer the same question over two transports - one is what
the switch wrote down, the other what it interrupted us about - so they are
**one panel**, merged by time with a column saying which arrived how.
Keeping them apart meant reading two lists to reconstruct one sequence.

Point a switch at the receiver with `snmp-server host <address> traps
version 2c <community>`.

### Traps drive refreshes; they do not replace polling

A trap is a good reason to go and look, and a bad thing to believe. It is
UDP with no retransmission, and it only arrives if somebody configured the
switch to send it - so a figure maintained *from* traps drifts silently the
first time one is dropped, and is simply absent on a switch nobody has set
up. "Interfaces up" counted from linkUp and linkDown would be wrong in
exactly the situation where it matters.

So polling stays the source of truth and traps decide **when** to poll. A
linkDown triggers a re-read within a second or two instead of waiting out
the refresh interval, which is where the saving actually is: the interval
can be long precisely because anything urgent announces itself.

Traps that change a derived figure - links, PoE, environment, topology,
restarts - trigger a full re-read, because "5 of 8 up", the PoE total and
the findings are computed from the whole picture rather than one table.
Ones that only fill a single table re-read that table. Refreshes are
coalesced and floored at ten seconds apart, so a flapping link cannot turn
into a collection per flap.

## Topology

**The button only appears once a switch has been collected from.** A button
that opens an empty page teaches people the feature is empty, which is a
hard first impression to undo. Closing the last switch lands on the
topology rather than a blank credentials form - the picture is kept and
labelled *No switches open* rather than cleared, since closing the tabs you
were looking at should not delete the diagram you were looking at.

The same picture a show-tech viewer draws, built from what SNMP has
already reported rather than from an uploaded capture. **Topology** in the
header opens it. Every input is data the dashboard collects anyway:

| Source | What it gives the picture |
| --- | --- |
| CDP and LLDP | who is attached to which port |
| Interface table | speed, admin and operational state |
| VLAN membership | access or trunk, and on which VLAN |
| Spanning tree | the root bridge, port roles, blocked links |
| PoE | which links are powering something |
| MAC table | hosts that announce nothing at all |

Every switch open in a tab is a device on the diagram; the neighbours they
report become nodes too, drawn dimmer and labelled **not polled** because
nothing is asking them anything. Nodes drag, the canvas pans and zooms,
and the diagram exports as a PNG.

**Layered by distance from the root bridge**, which is the shape a network
engineer already has in their head: root at the top, access at the bottom,
endpoints fanned beneath the switch they hang off. Tiers are worked out
over the links that actually carry traffic, so a **blocked** link does not
decide the shape - but a switch reachable only over one is still placed
beside its peer rather than exiled to the bottom, and its link is nudged
clear of the endpoint fan instead of drawn straight through it.

Nodes are keyed on the **tab**, not the address. Two switches can share an
address - different ports through a jump host, the same address behind NAT
- and keying on the host alone silently merges them into one node, which is
worse than drawing them twice.

### What it works out

- **Access or trunk** from VLAN membership rather than any single object:
  one untagged VLAN and nothing else is an access port, a spread of tagged
  VLANs is a trunk.
- **The root bridge, ignoring VLANs that carry nothing.** A switch can be
  the root for a VLAN that is shut down or that no port is in - true, and
  useless. Placing it at the top of the diagram on that basis describes a
  network that does not exist. So per-VLAN spanning tree decides it, and a
  VLAN counts only when its switch interface is up and at least one port is
  a member. When a switch is root solely for idle VLANs the notes say so by
  name, because otherwise the diagram and the CLI disagree with no
  explanation.
- **Which way is up, when the root cannot be identified.** With CDP alone a
  neighbour gives a name but no MAC, so the root bridge often cannot be
  matched to a node. The spanning tree's **root port** still says which way
  the root is, and the switch it points at goes to the top.
- **The root bridge**, matched across switches. A bridge identifier is a
  two-byte priority followed by the MAC, so only the last six bytes are
  compared - otherwise it never matches the chassis id a neighbour reports.
  CDP's device id is a *name* and LLDP's chassis id is an *address*; they
  are kept in separate fields for the same reason.
- **Hosts with nothing to say.** A workstation runs neither CDP nor LLDP,
  so ports with a learned MAC and no neighbour become endpoints, named by
  their manufacturer. A port with several MACs behind it is drawn as one
  node saying how many, because it is a link to something that switches
  rather than a host.
- **One-sided adjacencies.** A link reported by both ends is confirmed; one
  reported by a single end is drawn dashed and counted in the notes.

**Closing a tab puts a switch away; it does not throw it out.** A tab is a
place to look at a switch, not the switch itself - so the session stays up,
the layout and history survive, and the switch is still on the diagram,
marked *tab closed - click to reopen*. Double-click it, or use the button
in the inspector, and the tab comes back exactly as it was: no reconnecting
and no re-collecting. Auto-refresh pauses while nobody is watching; the
30-second probe keeps going, because it is one small packet and it is what
keeps the diagram honest.

**Closing the last tab lands here**, rather than dropping you into a blank
credentials form: this is the one view that is about the network rather
than about a single switch, and it is where the closed ones are waiting.

The diagram **opens at half the size that would fill the pane**, and is
never magnified past natural size: a picture fitted edge to edge leaves no
sign that anything is beyond it, and the first thing anyone does with a
topology is drag it about.

Two filters:

- **Endpoints** - phones, access points, cameras and hosts on access
  ports, including the ones known only by an address learned on a port,
  since a workstation runs neither CDP nor LLDP and that is the only trace
  of it. **Off by default**: on a full switch they outnumber everything
  else and bury the thing most people opened the page to see, which is how
  the switches connect to each other. Hiding them gives their space back
  too, so the switches are not spread apart by a fan that is not drawn.
- **Switches not polled** - neighbours this app is not talking to, drawn
  from what the polled switches say about them.

**Links to a neighbour on a port that is down are always drawn**, marked
`down` and greyed. That is a failed or unplugged uplink, which is exactly
what a diagram is for; putting it behind a switch meant the one picture
that would have shown the fault did not.

Focus VLAN narrows everything to one VLAN. Clicking anything opens an
inspector: for a link, both port names, speed, mode, VLANs, spanning-tree
state and PoE; for a switch, its summary, every neighbour and everything
attached, and a button that jumps to its tab.

## Connecting to a switch that is not set up yet

SSH or console access with no SNMP credentials is a common starting point:
the switch cannot be polled *yet*. Dropping straight into a terminal
assumes that is what was wanted, so the app says what the situation is,
offers the terminal, offers to take SNMP credentials, and **builds the
commands that would make the switch pollable** from fields you fill in -
username, group, the two passphrases, location, contact, source interface -
so what gets copied is yours rather than a template with placeholders left
in it. Placeholders are why copied examples get pasted wrong. A passphrase
the switch would refuse for being too short is called out before you paste
it, not after.

The block **starts with `configure`**, so it can be pasted straight at an
enabled prompt without typing anything first.

**The engine-ID command is not in the paste unless you ask for it.**
`snmp-server engineid local default` asks to confirm *twice* - once that the
engine ID must be unique, and again that changing it removes the SNMPv3
users bound to it. A pasted block has no answer for either, so the
following lines get consumed as the answers and the command aborts, taking
the next command with it. Worse, agreeing regenerates the engine ID,
which **deletes the SNMPv3 users already on the switch**, since users are
bound to it. Tick the box and both `Y` answers are included in the block -
if a firmware only asks once, the spare `Y` is refused as an unknown command
and nothing else is affected; leave it and the command is omitted, which is right for any switch
whose engine ID has already been set.

The offer depends on **intent, not on transport**. A terminal opens when
somebody asked for one: the CLI button, or reconnecting a session. Coming
from a credentials form means setting the switch up, so what happens next
is decided by whether there is anything to poll.

### Why the app does not run those commands for you

It used to, and the attempt is instructive. Driving a CLI blind means
knowing where the session already is, and a console is not necessarily at a
prompt - it may be at `User Name:`, in which case the first line of
configuration is typed into the username field, the second into the
password field, and the rest scrolls past as garbage while the switch
reports an authentication failure. Line endings matter too: a device that
acts on both CR and LF sees CRLF as two key presses and submits an empty
line after every command, which at a login means the blank becomes the
password and the real password is typed at the username prompt.

Both were fixed, and both were only found because a real switch behaved
differently from every mock. That is the point: the ways a terminal session
can be in an unexpected state are not bounded by what you thought to
handle, and the failure mode is a half-configured switch. Showing the
commands is honest about where the boundary is - this app reads switches
reliably, and writing configuration through a terminal is a job for a
person watching the output.

## Asking for the CLI once

Asking for a terminal when no credentials exist used to mean choosing a
serial port, landing back on the dashboard, and asking for the terminal a
second time - the app had the credentials by then but had forgotten *why*
they were being entered. The request is now held until a session actually
comes up, and the terminal opens by itself.

## Asking for the CLI gets you the CLI

Clicking **CLI** on a switch with no SSH or console set up takes you to the
credentials, as it must - but the request is remembered. Filling in either
form leads **straight to the terminal**, rather than back to the dashboard
to click CLI a second time. The first click having been a waste of the
operator's time was the whole complaint.

## Console or SSH, without leaving the CLI

The terminal carries a **Console / SSH** switch. They are two routes to the
same switch and which one is usable changes - a switch being rebooted
answers on the console long before it answers on the network - so moving
between them is one click rather than a trip through two forms. Whichever
is live is highlighted; one with no credentials is disabled and says so
when hovered.

**Connect again** returns on the transport you were using. Sending a
console session to the SSH credentials form is how "reconnect" came to look
like "the console is broken": nothing was wrong with the console, the
button simply went somewhere else.

### A session is only live if both ends agree

An open socket is not a working session. When a serial device disappeared -
cable pulled, adapter reset - the port closed but **the socket stayed
open**, so the app went on believing it had a console: the switch showed it
as live, and reconnecting did nothing because there appeared to be nothing
to reconnect. That is the state that read as "the console is broken", and
it was the app's bookkeeping rather than the hardware.

Now a console that closes or fails to open **ends the session**, and the
browser treats liveness as *socket open* **and** *far end not reported
gone*. Verified by pulling the device out from under a live session: the
switch stops claiming anything is connected, offers to connect again, and
recovers as soon as the port is back.

## One session per switch tab

Opening a session while one is already open used to do nothing at all on
some paths - no terminal, no reconnection, no message, which is
indistinguishable from a broken button. Connecting to a console you already
have now shows it, because that is the only thing the request can mean.
Connecting to anything else closes the current session first and waits for
it to go before claiming the port: a serial port is exclusive, and a second
session from one tab leaves the first holding hardware nobody can see any
more.

This is one path for both transports. The console form used to differ from
the SSH form because each had grown its own connect logic, which is how the
gap appeared at all.

## Console (serial)

A switch that will not answer on the network still answers on its console
port, which is exactly when you most need to talk to it: no address yet, a
bad VLAN, a locked-out management interface. **Backspace** is translated on the way to a console. A terminal sends DEL
(0x7f) for the key; an SSH shell has a line discipline that understands
that, but a raw console line does not - the Catalyst CLI erases on BS
(0x08). Cisco accepts both, so the translation is safe and fixes the case
where the key appeared to do nothing.

A console session is a full peer of an SSH one: the terminal, the
`show tech-support` capture with its paging suppression and prompt
detection, and the idle timeout all work the same way, because they are the
same code with one function deciding where the bytes go. Pick a **serial
port** and a **baud rate** (115200 first, since that is the current default; 9600 is
what older units ship with) and it opens in the same terminal, over the
same WebSocket, with the same capture machinery behind it - only the
transport differs.

The port list comes from the machine, not from a text box: a dropdown you
have to guess at is worse than none. On Windows each entry carries the
friendly name alongside `COM3`.

`serialport` is an **optional dependency**. It ships prebuilt binaries for
Windows and macOS, but a machine without them should lose the console
feature rather than fail to start, so the require is guarded and the reason
is shown on the form. Listing ports on Linux needs `udevadm`; when it is
missing that is reported rather than swallowed, because an empty list and a
broken list mean different things.

## Rates, not just totals

A counter is cumulative since boot, so on a switch that has been up for
months a non-zero error total is close to guaranteed and says nothing about
now: it could be a cable failing this minute or one bad hour last March.

The server keeps the previous collection per switch - just the error
counters, in memory - so findings can report what is **still climbing**:
*"Error counters still rising on 1 interface(s) in the last 6s: gi1/0/3
(+42)"*. The first collection after a restart has nothing to compare
against, so it reports totals and says so rather than pretending to know a
rate.

The reachability probe carries a few numbers as well as the uptime - CPU,
PoE draw, saved state - still one PDU of four varbinds. Those samples build
an hour of history per switch, drawn as **sparklines** under the CPU, PoE
and CPU-input-rate cards: the value says where you are, the line says
whether you are going anywhere. A flat line is drawn flat rather than as
amplified noise, and a line needs three samples before it is drawn at all -
two points are a segment, not a trend.

**CPU input rate leads with the rate now**, and carries the **5 and 60
minute peaks** in the smaller line beneath - each with its unit and its
window, since "5 min peak 9" reads as two numbers with no way to tell which
is which. Bursts are what hurt a control
plane and the instant you happen to look is rarely one of them, so the
peaks earn their place - but the current value is what the card is for. The
60 minute figure is only printed when it differs from the 5 minute one.

**The history outlives the tab, and the browser.** Samples go to the app,
which writes them to `history.json` beside the code - plain JSON, because
numbers about your own equipment are not secrets and you should be able to
read them with any tool. Kept at full resolution for a day, then thinned to
one point per five minutes for a week and one per hour beyond that: a year
of one switch is about 13,000 samples and two thirds of a megabyte,
measured rather than guessed.

**Sampling continues when a switch's tab is closed.** The tab is a place to
look at a switch, not the thing doing the looking, and a gap in a graph
because nobody happened to be watching is exactly the gap you want back.

**Every reading is a point on the graph**, and hovering anywhere reads out
the exact value and when it was taken, in a label that follows the cursor -
a reading you have to go and look for is a reading you read less often. The pointer snaps to the nearest
reading rather than needing to hit a dot: at one-pixel spacing you cannot
aim at a dot, but you can always aim at a moment. Past a few hundred
readings the dots are drawn smaller so they do not merge into a band and
swallow the line - still every reading, just not shouting.

**Clicking a metric card opens its full history** - the sparkline answers
"is this moving", the graph answers "when did it start" and "is today
unusual". Ranges from an hour to everything recorded, with the peak and
when it happened, the average and the lowest, and a CSV of exactly what is
on screen. The y-axis starts at zero, so 40% against 45% does not look like
a doubling.

The headline figures on the CPU, PoE and input-rate cards come from the
**newest reading**, not from the last collection. The probe keeps reading
every 30 seconds, so a card painted only from collection data sits still
while the graph underneath it moves, and looks stuck.

Every reading becomes a point, whether it came from the 30-second probe or
from a collection you asked for: a manual refresh is as real a sample as
one taken on a timer, and dropping it would leave visible gaps. Points are
spaced **by the clock rather than by sample number**, so a burst of manual
refreshes cannot stretch a few seconds across half the graph and make a
quiet hour look eventful. All three lines take their colour from the same
good/warning/critical scale as the value above them.

## Port actions

Two changes are worth making from a dashboard, and both are on the
interface row they act on:

- **Bounce PoE** power-cycles the port - off, three seconds, on - which is
  how a wedged phone, camera or access point gets rebooted. It is the
  commonest physical-layer fix there is, and otherwise means finding a CLI
  or walking to a rack.

  A power cycle is two writes to the port's admin state, so the switch
  marks its configuration dirty even though the port ends up exactly as it
  started. There is no cleaner action to use instead -
  `rlPethPsePortReactivate` only recovers ports disabled by a hardware
  fault - so the app **tidies up after itself**: if the configuration was
  saved before the bounce, it is saved again afterwards, and the operator
  sees nothing amiss. If it was *already* unsaved, nothing is saved -
  committing somebody else's pending changes is not ours to do - and the
  comparison view explains the flag if anyone goes looking.
- **Shut / No shut** sets `ifAdminStatus`.

Both write to the switch, so both confirm first with the port named, and
both re-read the port afterwards and refresh the panel: the page shows what
happened rather than assuming it worked.

**Shutting an uplink is how you lose contact with the switch you are
administering**, so a port that faces a CDP or LLDP neighbour, or carries
the spanning-tree path to the root, says so in the confirmation - *"gi1/0/8
faces core-sw, and carries the spanning-tree path to the root - shutting it
may cut off this switch."* Both reasons are given when both apply, because
either alone is less useful.

## Watching the switch

Two separate things run on timers, and they are deliberately different
sizes.

**Auto-refresh** re-reads everything and is off by default. **A
reachability probe** runs every 30 seconds regardless: one GET of
`sysUpTime`, about as small as SNMP gets. The question "is this switch
still there" should not cost a full collection to answer, so it does not.

When the probe stops getting answers the switch tab and the Overview
sub-tab both go red and the toolbar says *not answering SNMP* - stale data
is not health, so an unreachable switch overrides whatever the last
collection concluded. When it answers again, the dashboard refreshes
itself. The uptime the probe returns doubles as a reboot detector: an
uptime lower than the previous one means the switch restarted between
probes, which is worth noticing and free to notice.

**Sessions close themselves.** A session opened only to run a capture is
closed when the capture finishes - an SSH one with a clean logout, a
console one by handing the port back, since it is physical hardware someone
else may want. Beyond that, five minutes with no input closes an SSH or
console session, gracefully, the same way the disconnect button does. A
session left open is a VTY line held on the switch for nothing, and on a
console it is a serial port nobody else can use. A running capture counts
as activity - `show tech-support` prints for minutes with nobody typing,
and killing that would be perverse. `SESSION_IDLE_MS` overrides the five
minutes.

## What is remembered, and how

The app puts itself back as it was: the switches you had open, their SNMP
targets, SSH credentials and console ports. An app that restores your
switches and then asks for the community string has not restored anything,
so the credentials are part of it.

They are **encrypted at rest** with AES-256-GCM in `state.enc`, with the
key in `.state-key` beside it, both written 0600. What that protects
against is the realistic set of accidents: the folder gets backed up,
synced to cloud storage, committed to a repository, or copied to a
colleague. Plain text loses to all of those.

What it does **not** protect against is somebody who already has your OS
account and can read both files - and nothing stored unattended can,
because the app has to start without you there to type anything. That is
the trade, and Settings states it in those words rather than saying
"securely".

For the stronger version, set **`SWITCH_CONSOLE_PASSPHRASE`**. The key is
then derived from it with scrypt and never written to disk, so the file is
worthless without the passphrase - at the cost of supplying it whenever the
app starts. A wrong passphrase, a missing key file or a tampered file all
end the same way: the app says it cannot read the saved state and starts
fresh, rather than guessing.

**Forget this switch** on a switch's Settings page drops that one from the
saved set - the card lives on a switch, so clearing every saved switch from
it would be a surprise. The switch stays open; using it again saves it
again.

## A note on the palette

Every surface comes from three values - the page, a panel, and the inset
used for cards and nested boxes - and **depth runs one way**: the page is
darkest, a panel sits a step above it, anything nested inside a panel a
step above that. It used to run page, then panel lighter, then a card
*darker than the page it was printed on*, so nesting did not read as
depth and a dashboard of folded panels looked striped.

Two things had been quietly breaking that. The Overview panel painted a
tinted background *inside* a panel that already had one, making it a
visibly different shade from every other panel; the severity is now shown
as a left accent and on the badge instead. And the page never declared
`color-scheme: dark`, so the browser drew scrollbars, `select` controls and
autofill in its light-mode palette - flat neutral greys with no green in
them, against a page that is entirely green-black. Both are fixed, and the
rendered page now uses no colour outside the palette.

## Error logging

Connection attempts, SSH/SNMP errors and disconnects are logged with
timestamps to the server console and to `logs/app.log`. This is metadata
only — host, username, error text — never session content or query
results. Passwords, community strings and v3 auth/privacy keys are
redacted on both sides before anything is written.

The **Log** button (top right) opens the same stream in the browser, and
forwards any client-side JavaScript error to the server so both ends land
in one file.

## Security

**The dashboard can only be opened on the PC the app runs on**
(`http://localhost:3000`). The web server listens on the loopback address
only; other machines on the network cannot connect to it. The receivers the
switches send to (TFTP, syslog, traps) still listen on every interface, as
they must.

To open the dashboard to other PCs again, set `SBS_BIND=0.0.0.0` (or one of
this PC's addresses). Be aware that **it has no sign-in and no TLS**: anyone
who can reach port 3000 could then use it, read the saved switch credentials
and change switch configuration.

What it does protect against:

- **Other websites.** A web page open in a browser on this PC cannot call
  the API or open the SSH/console WebSocket: a request whose `Origin` is a
  different site is refused (`request-guard.js`).
- **Browser hardening.** Every response carries a Content-Security-Policy
  (scripts only from this server, nothing inline), refuses to be framed by
  another page, and sends no referrer (`security-headers.js`).
- **DNS rebinding.** Requests must be addressed to an IP address,
  `localhost`, or this computer's own name. If you open the dashboard
  through another DNS name (an alias), add it to `SBS_ALLOWED_HOSTS`,
  comma-separated, e.g. `SBS_ALLOWED_HOSTS=sbs.example.lan`.
- **Saved passwords stay on the server.** Once a switch is saved, the page
  never receives its community string, SNMPv3 keys or SSH password again:
  Settings shows those fields as *saved — leave blank to keep*, and the
  server fills them in when it talks to the switch. Typing a new value
  replaces the saved one.
- **SSH host keys.** The first time the app connects to a switch over SSH it
  remembers the switch's host key (`known-hosts.json`). If a later
  connection presents a different key, it is refused and Settings shows the
  old and new fingerprints with a **Trust the new key** button: expected
  after replacing a switch or regenerating its key, and otherwise a sign
  that something is impersonating it.
- **Secrets in logs and responses.** Passwords, community strings, SNMPv3
  keys and RADIUS/TACACS keys are redacted at any depth in `logs/app.log`,
  SET values are not logged, and collector snapshots never return
  credentials.
- **Flooding the receivers.** TFTP uploads are capped in size
  (`TFTP_MAX_BYTES`, default 256 MB) and number (`TFTP_MAX_TRANSFERS`, 16),
  config uploads use unguessable names, and syslog/traps keep at most
  `SBS_MAX_STREAM_SOURCES` (256) distinct senders.

`npm test` runs the offline tests for these controls.

## Notes

- Saved switches and their credentials are kept encrypted in `state.enc`
  (see `vault.js` and `docs/SERVER-STANDARD.md` §7). They are never stored
  in the browser.
- `routes/terminal.js` offers modern SSH algorithms first and keeps legacy key
  exchange and cipher suites as fallbacks, since Cisco small-business
  switches may not support modern-only sets. See `LEGACY_ALGORITHMS`.
- SNMP uses [net-snmp](https://www.npmjs.com/package/net-snmp). Each
  request opens a short-lived session and closes it — SNMP is
  connectionless, so there's no persistent state to manage.
- xterm.js is vendored in `public/vendor/xterm/`, so the UI works offline
  and on locked-down networks.
- See **Security** below for who can reach the dashboard and what is
  protected.
- The MIB database describes what the *MIB files* define. Whether a
  given OID is implemented depends on your switch model and firmware;
  unimplemented objects will come back as `noSuchObject` /
  `noSuchInstance`, which the UI shows per row.
