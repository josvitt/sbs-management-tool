# Server Standard — Collection & Persistence

The companion to `MODULE-STANDARD.md`. That document is the single source of
truth for the **client** (how a panel paints, refreshes, writes, and looks);
this one is the single source of truth for the **server side** — how the app
collects from switches on its own, and what it keeps on disk.

The governing rules in `MODULE-STANDARD.md §0` apply here unchanged (never
theorize; use a helper or create and document one; survey before adding and
reconcile after; an error is not evidence of impossibility; read what the
system actually has). This document is their application to the server, and,
like the module standard, it is **derived from the code that already exists** —
`collector.js`, `events.js`, `rotate.js`, the shared collection/probe paths in
`collection.js`, `snmp-core.js`, the routes under `routes/`, and `history.js`. Nothing here is aspirational.

---

## 0. The core principle — collection is the server's job, not the browser's

The app must behave the same whether or not a browser is open. A browser is a
**viewer**; it never drives collection. The authoritative poll loop runs on the
server, on a wall-clock cadence, against every saved switch, and persists what
changed. Closing the tab, switching devices, or the OS throttling a background
tab's timers must not change what the app collects or when.

This is the rule the old architecture broke: a browser `setInterval` drove
collection, so a backgrounded tab (whose timers the browser clamps to ~once a
minute) stretched a 5-minute poll to 5 hours. Any future work that reintroduces
a browser-driven collection loop is a regression against this principle.

---

## 1. The one collection path — `collectHealthFor` (collection.js)

There is exactly **one** function that builds an SNMP session, walks a switch,
and keeps the per-switch rate baseline: `collectHealthFor(target, { mode, only })`.
Both the HTTP handler (`POST /api/health`) and the server-side collector call
it. This is governing rule 4 (survey/reconcile) made concrete: there is no
second, parallel poller. A change to how collection works is made in this one
place and both callers inherit it.

- It throws on a session-build failure; it does **not** throw merely because a
  switch is unreachable — `health.collect` is resilient and returns a partial
  result with empty tables (see §3). The session is always closed (`finally`).
- `previous` (the per-switch `lastCollection` cache) turns error counters into
  rates; it is keyed by `host:port`.

## 2. The reachability probe — `probeSwitch` (collection.js)

`probeSwitch(target)` is a single-PDU GET of sysUpTime, CPU, PoE, the
config-saved flag, and cpu-pps. It never rejects; it resolves
`{ reachable, uptime, cpu, poeW, cpuPps, configSaved, ms, error? }`. It is shared
by `POST /api/ping` and the collector.

**Why a probe gates every collection.** `health.collect` returns a partial even
against a dead host, so "collect failed" is *not* a reachability signal. The
probe is. And a full collection is dozens of sequential walks; firing that at a
host that isn't answering wastes a long series of timeouts. So the collector
**probes first**: unreachable → record the event and stop (one PDU spent);
reachable → run the full collection. Reboot and the config-saved flag are read
from the probe (cheap, and available even when the subsequent full collect
comes back partial).

## 3. The collector — `collector.js` (the loop + change detection)

`collector.js` owns the **loop** and the **change detection**, and owns **no
SNMP or vault wiring** — everything that touches a switch or the vault is
injected (`probe`, `collect`, `fetchConfig`, `loadSwitches`), exactly as
`config-fetch.js` takes an injected session builder. This keeps the scheduler
testable without a switch (see `MODULE-STANDARD §0.2`: correctness over time —
there is an offline harness) and prevents a circular require back into
`server.js`.

**Two cadences (this matters for the metric graph).** Each switch has a
self-rescheduling per-switch timer that ticks at the fast metric cadence
`METRIC_PROBE_MS` (default **30 s**). Every tick does the cheap single-PDU
`probe` — reachability, reboot, the config-saved flag, and a CPU/PoE/cpu-pps
history sample. This is the fine-grained pulse the graph needs, and it is as
cheap as the old browser ping. **Additionally**, when a switch's own interval
has elapsed (the per-switch interval, default 300 s via `COLLECT_INTERVAL_MS`),
that same tick also runs the **full collection** — every table, `buildAlerts`,
the temperature and fan-state readings, and the config gate — and refreshes the
snapshot. So metrics land every ~30 s while the heavy walk stays at 300 s.

Collapsing these into one cadence is the mistake to avoid: sampling metrics only
on the full collection makes the graph 10× coarser (the Stage-2 regression this
restores); running the full walk every 30 s breaches §B5a. Keep them split. A
switch's first tick runs a full collection immediately (`lastFullAt` is 0), and
a manual nudge forces one (`opts.full`). Ticks are staggered at startup
(`COLLECT_PACE_MS`) so N switches don't fire at once, and the in-flight guard
means a switch is never polled twice at once.

**Saved-switch changes.** `reload()` (called from `PUT /api/state`) prunes a
removed switch's timer/snapshot/state and schedules a new switch's first tick
soon (~0.8 s) so it starts collecting promptly. The per-switch interval is read
live each tick, so an interval change takes effect on the next tick with no
rescheduling.

**Per-switch snapshot cache.** The latest result per switch
(`{ at, host, target, data?, probe?, error? }`) is held in memory and served by
`GET /api/collector/snapshot` and summarised by `GET /api/collector/status`.
This is what a browser reads instead of walking the switch itself (Stage 2).

**Manual refresh = `nudge(target)`.** Polls one switch out of cycle and returns
its fresh snapshot (`POST /api/collect/now`). The browser's "Refresh" nudges the
server to poll now; it does not walk the switch directly — the single polling
authority stays on the server.

### 3b. The client is a viewer (Stage 2 cutover)

The browser no longer walks the switch on a timer. The contract:

- **Periodic refresh** (the auto countdown) calls `syncView(s)` → `GET
  /api/collector/snapshot` and renders it. No switch contact. If the tab is
  backgrounded and its timer is throttled, only the VIEW lags; the server keeps
  collecting, so data integrity never depends on the browser.
- **Manual Refresh** and **first open** call `syncView(s, { nudge: true })` →
  `POST /api/collect/now`, so the user gets an immediate fresh poll — through
  the server, which stays the single polling authority.
- **The 30s probe** reads reachability from `GET /api/collector/status` and
  refreshes the metric graph from `GET /api/history`. It does not ping the
  switch, and the browser no longer POSTs history (the collector persists it).
- **Writes, on-demand module loads, and trap-driven reactive refreshes stay
  live** (`snmpSet`, `refreshTables`, `loadHealth`) — they are user/event
  initiated and must reflect at once (MODULE-STANDARD §B6); they are small,
  bounded bursts, not a periodic loop. The one-shot credential check at connect
  (`/api/ping`) also stays.
- `applyFullHealth(s, body)` is the single render path, used identically by a
  live `loadHealth` and by a snapshot `syncView`.

A future change must not reintroduce a browser-driven periodic switch walk; add
to the server collector instead.

### 3a. The SNMP cost budget still governs (MODULE-STANDARD §B5a)

Each switch still sees only its own full walk once per interval — the same
traffic the periodic walk always was, so the per-switch ~100 pps budget is
unchanged. The pacing gap paces the **server's fan-out** across switches, not
any one switch's load. `onDemand` modules (snmpcfg / flash / capture) are
**never** collected by the loop — they stay lazy and browser-only, by the same
rule. The collector reproduces exactly the scope of the old periodic walk
(families a/b), which is also exactly the scope `buildAlerts` reads, so
unattended alerting needs nothing the loop doesn't already gather.

## 4. The event log — `events.js`

An **event** records what changed and when — distinct from `app.log` (what the
*app* did) and from the metric history (numbers over time). It is what a
returning operator reads to see what happened while no browser was open.

Storage: one rotating JSONL file per switch under `logs/events/<host>.log` via
the shared `rotate` helper. API: `record(host, event)` and
`recent(host, { limit, type, since, generations })`; served by `GET /api/events`.

Event types the collector emits:

| type | when | key fields |
|---|---|---|
| `reachability` | probe fails / recovers | `state: down\|up`, `error?` |
| `reboot` | sysUpTime went backwards | `fromTicks`, `toTicks` |
| `alert` | a `buildAlerts` alert appears / disappears | `state: raised\|cleared`, `severity`, `area`, `message` |
| `config-change` | gated running-config content diff (see §5) | `hash`, `previousHash`, `bytes` |

**Alert identity must be churn-free.** Alert messages carry live numbers
("CPU at 85%"), so raised/cleared is diffed on a **signature** that blanks the
numbers (`area + '|' + message.replace(/\d+(\.\d+)?/g,'#')`), kept per switch in
`state.alertSigs`. Without this, every cycle would clear-and-raise the same
ongoing alert as its number ticked. A new feature that adds alerts inherits this
automatically; do not diff on the raw message.

## 5. Gated config content-diff (the expensive-pull rule)

A running-config pull is **not** a cheap read: `config-fetch.js` drives an
`rlCopyTable` row that TFTPs the whole config to the app's embedded server and
waits for completion — seconds, and a flash/CPU operation on the switch. Pulling
it every cycle would breach §B5a on its own. So the pull is **gated**:

- **Cheap per-cycle signals decide whether to pull:** the config-saved flag
  (`rlRunningCDBequalToStartupCDB`, read on the ~30s probe) flipping in either
  direction (the fast probe sets `configTripPending` on a flip); a reboot; or no
  baseline hash yet.
- **The pull + SHA-256 decide whether content changed:** on a trip, fetch the
  running-config, hash it, compare to the stored hash, emit `config-change` on a
  difference, and store the new hash. A min-gap (`CONFIG_PULL_MIN_GAP_MS`,
  default 60 s) debounces a flapping flag so repeated trips don't repeatedly
  TFTP.

**No config-change trap or OID exists on this platform (evidenced, §0.5).** The
full C1200/1300 MIB set was searched: the only config-state objects are
`rlRunningCDBequalToStartupCDB` (the saved/unsaved TruthValue we use) and
`rlStartupCDBChanged` (whether *startup* changed across the last two reboots —
not a live running signal). There is **no** running-config change counter,
timestamp, or notification — unlike enterprise IOS (CISCO-CONFIG-MAN-MIB:
`ccmHistoryRunningLastChanged`, `ccmCLIRunningConfigChanged`). The only
config-related traps are `rlCopyFinished`/`rlCopyFailed`, which fire on ANY copy
— **including the app's own config pulls** — so they are deliberately NOT used as
a change signal: keying on them makes every pull re-arm the gate and pull again
every interval forever (`trapSuggestsConfigChange` matches only a genuine
running-config-changed notification, which this platform never sends).

**Known blind spot, stated plainly:** a change made *and saved* entirely within
one ~30s probe gap leaves the saved flag unsaved→saved across that gap and can be
missed; an edit left unsaved, or one that straddles a probe, is caught. Closing
the save-within-30s case would need either a genuine config-change trap (absent
here) or distinguishing the app's own copy traps from an external
running→startup save by the copy index — a possible future enhancement.

## 6. Persistence helpers

- **`rotate.writeFileAtomic(file, data, { mode })`** — the ONE way a
  whole-file store reaches disk (`state.enc`, `history.json`,
  `layouts.json`): temp file, fsync, rename, so a crash mid-write can never
  leave a truncated file. Unlike `appendLine` it throws; callers report the
  failure in their own words. A new whole-file store uses it, never a bare
  `fs.writeFileSync`.
- **`rotate.js`** — the ONE size-capped append-with-rotation helper. `<file>`
  rolls to `<file>.1` … `<file>.<keep>` at `maxBytes`. Every on-disk store uses
  it; nothing re-implements rotation (§0.3). Appends are synchronous and
  best-effort — a logging store must never crash the app.
- **`logger.js`** — redacts credential fields (`SECRET_KEY`: passwords,
  passphrases, `community`, `key`, `authKey`/`privKey`, secrets, tokens) at
  **any depth** before a line is written, so a caller can log a whole target.
  SET requests log OID and type only, never the value. A new credential field
  name is added to `SECRET_KEY`, not redacted at the call site.
- **`logger.js`** — `app.log` now rotates through `rotate` (`LOG_MAX_BYTES`,
  `LOG_KEEP`); it was previously unbounded.
- **`source-limit.js`** — the ONE cap on how many distinct senders the
  unsolicited receivers keep (`SBS_MAX_STREAM_SOURCES`, default 256). Both
  `syslog.js` and `traps.js` admit through it; past the limit a NEW source is
  dropped (logged once a minute) and known sources are untouched. It bounds
  memory and the per-host files below against spoofed UDP.
- **traps / syslog** — received notifications are persisted to rotating per-host
  stores under `logs/traps/<host>.log` and `logs/syslog/<host>.log` by an
  always-on subscriber in `routes/streams.js`, in addition to the in-memory ring buffers
  and SSE streams (which are unchanged).
- **`history.js`** — the time-series gained `temp` (max sensor °C, from
  `summary.maxTempC`) and `fan` (worst fan-state code: 0 unknown · 1 ok ·
  2 warning · 3 critical, from `fans[].rlEnvMonFanState`) alongside
  `cpu`/`poeW`/`cpuPps`. The store is key-agnostic, so only the allowed-key list
  changed; thinning/retention are unchanged.

## 7. Credentials across reboot (the unattended requirement)

Collection with no human present requires the vault to decrypt itself at boot,
so the deployment uses **on-disk key mode** (`.state-key`), not a passphrase
(which cannot be typed unattended). The trade is stated in `vault.js`: anyone
who can read both vault files on the host can decrypt the stored switch
credentials. Both files live in the install directory (`__dirname`-based), so
they survive a reboot and a service launch. The KDF salt is a fixed constant and
**must never change** (see `vault.js`) or existing state becomes unreadable.

**An unreadable vault is never overwritten.** If `state.enc` cannot be
decrypted (wrong or missing key file), the UI starts fresh; the next save
first renames the old file to `state.enc.unreadable-<time>`, so it can be
recovered once the right `.state-key` is back.

Packaging: `.state-key` and `state.enc` are machine-local secrets and are
**never** included in a distributed build (they regenerate on first run).

## 8. Adding a new server-side collected thing — checklist

1. Does the data ride the existing full walk (families a/b)? Then it is already
   collected; read it from the snapshot. Only add a walk if genuinely missing,
   and weigh it against §B5a.
2. New periodic SNMP cost goes through **`collectHealthFor`**, never a new
   poller. A heavy/rare pull is gated by a cheap signal (the §5 pattern), never
   run every cycle.
3. A new persisted record is either an **event** (`events.record`) or a
   **metric** (`history.append`) — not a new bespoke file. Any new on-disk store
   rotates via **`rotate`**.
4. A new change-detection comparison keeps its "previous" in the collector's
   per-switch `state`, and uses a churn-free signature if the compared text
   carries live numbers (§4).
5. Document the addition here (§0.3).

## 9. Running as a service (unattended deployment)

The collector runs with no browser; to run with no logged-in user either, the
app installs as a service.

**Windows** (`install-service.bat` → `service-install.js`, via `node-windows`):

- Runs `server.js` headless under **LocalSystem**, auto-starts on boot, and
  restarts on failure. LocalSystem can bind the privileged UDP ports the
  receivers use (traps 162, syslog 514, TFTP 69) and 3000 — the same privilege
  the interactive run had.
- `node-windows` is installed **on demand** by `install-service.bat`, not
  carried in `package.json`, so a normal interactive install (`start.bat`) stays
  lean. It is needed only to create/remove the service; the running service does
  not depend on it.
- The batch files require Administrator (service creation does) and say so.
- `start.bat` is retained for interactive runs; `open-ui.bat` opens the
  dashboard (the service has no window of its own).

**Linux**: `sbs-management-tool.service` (systemd) is the equivalent — headless,
boot-start, restart-on-failure, with documented options for the privileged
receiver ports (root, `CAP_NET_BIND_SERVICE`, or high ports).

**Credentials workflow (important).** Credentials are entered through the **web
UI against the running service**, never by editing files. The service process
(LocalSystem on Windows) then owns the vault key and `state.enc` in the install
directory, so there is no file-ownership split between an interactive user run
and the service. Combined with on-disk key mode (§7), this is what lets
collection start automatically after a reboot with no human present. Pick one
run mode (service **or** interactive) and stay with it; switching means the
other identity may not be able to read a vault the first one wrote.

**Install location.** The `.bat`/unit resolve the app directory themselves
(`%~dp0` / `WorkingDirectory`), so any stable folder works — but not the Desktop
(the service and the vault key live there). All app files are `__dirname`-based,
so the service and an interactive run resolve the same vault, history and logs.

## 10. Products & MIB sets (per-product support)

The app supports three switch lines, and they are **not** the same at the MIB
level — so "what does this product support" is answered from the MIB where the
MIB expresses it, and from the switch at runtime where it does not.

**What the MIBs actually say** (compared directly, `tools-parse-mibs.py` →
`tools-compact-oiddb.py`):

- **C1200 and C1300 ship a byte-identical MIB set** (`MIBs_Cat1200_1300`). The
  MIB cannot tell them apart; their difference (PoE, routing scale, …) is
  datasheet/runtime, not MIB.
- **C1300X has its own, newer set**: it adds **OSPF/OSPFv3** (~840 OIDs) and
  **PTP** (~11), and **renumbers the 802.3bt PoE table** (`rlPethPseBtPort*`
  moved `…101.151` → `…101.108`). Every one of the ~360 OID names the app
  currently uses is present and identically numbered in all three, so today's
  features work everywhere; the renumbering only matters if a future feature
  uses the BT-PoE table, which is why resolution is product-aware.

**The registry** `public/mib/products.json` is the single source of truth (read
by the browser and by `products.js` on the server): each line's label, its MIB
DB file, the model-string `match` prefixes (tested most-specific-first so
`C1300X` beats `C1300`), and the MIB-proven `features` (ospf/ptp = C1300X only).

**Per-product MIB DBs.** `public/mib/oid-db.json` is the C1200/C1300 set (kept
as-is); `public/mib/oid-db-c1300x.json` is the C1300X set, generated by the same
two-step pipeline. The MIB Explorer picks the DB by product; a browser never
mixes two products' OIDs.

**Detection + override.** `products.detect(strings)` identifies the line from
the switch's model strings (sysDescr, stack product id, inventory model name);
`collect()` sets `health.product = { line, label, features, detected }`. The
old `detectModel` is C1300-only and stays for the PoE datasheet lookup, but the
product line comes from `products.detect`, which covers all three. A per-switch
manual override (chosen design) supplies the line when detection returns null.

**Gating is hybrid (the MIB can't do it alone).** Because the MIB is a family
superset (it lists OIDs a given C1200 may not actually run) and can't separate
C1200 from C1300, feature support is decided two ways, and both are wired into
the ONE visibility check (`renderSwitch`'s panel filter), not a parallel path:

- **Runtime half (already the model):** each built-in panel's existing `needs(s)`
  predicate hides it when its data is absent (no PoE ports, no VLANs, no
  neighbours, …). That is real per-unit evidence and needs nothing new.
- **MIB half (added):** a panel may declare a `mibFeature` (e.g. `ospf`, `ptp`);
  `productSupports(s, def)` shows it only on a product whose registry `features`
  prove that capability. A panel with no `mibFeature` is common to all three
  lines and always passes the MIB gate. No current panel is OSPF/PTP, so nothing
  is hidden today — correct, since every current module uses the common OID set
  — and the gate is ready for a product-specific module (an OSPF panel) to be
  added C1300X-only just by tagging it.

**Defined-in-MIB is not populated-by-device (prefer-then-fallback).** The
clearest live example: the C1300X MIB *defines* the vendor `rlifPresentTable`
per-port counters, but the 4.10.3.26 firmware returns `noSuchInstance` for them
(confirmed on the wire) and populates the standard `ifXTable`/`ifTable` counters
instead. So where an OID may be unimplemented on some line, the reader lists its
variants in preference order and uses the first the switch actually answers
(`PORT_COUNTERS` → `fetchPortCounters`): vendor first (C1200/C1300), standard
next (C1300X). This is the runtime half of the hybrid applied at the OID level —
no product branching; the switch decides.

**Effective product + override.** `effectiveProduct(s)` is the manual override
if set, else the detected line, else the registry default. The per-switch
override is a control in the Details panel, persisted in saved state
(`productOverride`), and it drives both the feature gate and the Explorer
default. The Details panel also surfaces the line and its MIB-proven features,
so "C1300X supports OSPF/PTP; C1200/C1300 do not" is visible, not just internal.

## 11. Shared request and SNMP paths (the server's own helpers)

**Where server code lives.** `server.js` only wires things together: it
builds the app (`web.js`: the guard and every other middleware), registers
the route modules under `routes/` (one per feature, each
`module.exports = function register(app)`), attaches the terminal WebSocket
(`routes/terminal.js`), starts the receivers and the collector, and listens.
SNMP primitives live in `snmp-core.js`, the collection path in
`collection.js`. A new feature's routes go in their own `routes/<feature>.js`
and use those helpers; nothing new is added to `server.js` itself.

The server-side counterparts of `MODULE-STANDARD §B8`. Each is the one place
its concern lives; a new route or caller uses it rather than re-implementing it.

| Concern | Helper | Why it exists |
|---|---|---|
| Where the dashboard listens | `SBS_BIND` in server.js | `127.0.0.1` by default: only the PC the app runs on can open it (the owner's choice, in place of a sign-in). `SBS_BIND=0.0.0.0` re-opens LAN access and logs a warning. The UDP receivers are separate sockets and always listen on every interface. |
| Browser security headers | `security-headers.js` | Sets CSP (`script-src 'self'`, inline style attributes allowed, connections only back to the page's host), `frame-ancestors 'none'`/X-Frame-Options, nosniff, no referrer. A page change that needs an inline script or another origin changes this policy here, deliberately. |
| Who may call the server | `request-guard.js` (`middleware`, `verifyClient`) | Runs before every HTTP request and on the WebSocket upgrade. It does NOT decide which machine connects (`SBS_BIND` does); it refuses a browser request whose `Origin` is another site, and any `Host` that is not an IP, `localhost`, this computer's name, or a name in `SBS_ALLOWED_HOSTS` (DNS rebinding). |
| JSON varbinds → net-snmp SET | `mapSetVarbinds(varbinds)` (snmp-core.js) | Every SET path (the `/api/snmp/set` route, snmp-config's bundle, the OPC/AAA/flash step runners) converts through it: numeric types, `valueHex` → Buffer with an even-length check, anything else unchanged. There were three copies, only some handling `valueHex`. |
| Walking a subtree | `boundedWalk(session, base, opts, onDone)` (snmp-core.js) | The ONE walk: subtree boundary, advance check, pacing (§B5a), row/depth caps, and a per-request watchdog (`SNMP_STEP_WATCHDOG_MS`, 12 s) so a reply net-snmp never delivers ends the walk instead of hanging it. `raw: true` returns untouched varbinds for snmp-config (`boundedWalkRaw` is that, with its 4000-row / depth-64 limits). |
| SNMPv3 security level | `v3SecurityOf(v3)` (snmp-core.js) | One derivation of auth/priv method and level, used to build the session and to judge whether a shared key would travel in cleartext, so the two cannot disagree. |
| Saved secrets | `credentials.js` (`publicState`, `mergeForSave`, `resolveTarget`, `resolveSsh`) | Community strings, v3 keys and SSH passwords of a saved switch never leave the server. `GET /api/state` returns them removed, with a `saved` flag and a switch `id`; `PUT /api/state` keeps a stored secret the browser sent back empty; a middleware in `web.js` fills a request's `target` from the saved switch (`target.ref` = id, else host:port) before any route sees it, and the terminal does the same for the SSH password. A secret the user types always wins. A new route that takes `req.body.target` inherits this; a new secret field is added here. |
| A snapshot leaving the server | `publicSnapshot(snap)` (routes/monitoring.js) | The collector keeps the full target to poll with; responses carry it through `redactTarget`. |

Offline tests for these and the persistence helpers live in `test/` and run
with `npm test` (node:test, no extra dependency). A new control gets a test
that is red when the control is removed, paired with a test that the
legitimate request still passes.
