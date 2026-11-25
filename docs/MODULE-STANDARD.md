# App Standard — Behavior & Visual Design

The single source of truth for how this app is built and how it looks. Backend
structure and visual structure are one system: the behavioral rules (how a panel
paints, refreshes, writes) and the visual rules (tokens, type, components) are
designed to reinforce each other, so a correctly-built module is automatically a
correctly-styled one and vice versa.

Everything here is **derived from the code that already exists** — the working
modules (VLANs, Connected, Hardware, Auth, Interfaces) and `public/styles.css`.
Nothing here is aspirational invention; it documents the real system and makes it
the rule.

**Where frontend code lives.** The browser loads one script, `public/app.js`,
which is **generated**: `scripts/build-app.js` joins the feature files in
`public/src/` (`01-core.js` … `24-init.js`, in name order) inside the single
function scope they share, so every function still sees every other and nothing
is global. Edit `public/src/`, then run `npm run build`; never edit `app.js` by
hand (`npm test` fails when the two differ). A new module goes in its own
numbered file, or the file of the feature it extends. Order matters only for
top-level statements that run while the page loads (constants read at load,
event wiring, start-up in `24-init.js`): a file may use at load time only what
an earlier file, or an earlier line of its own, declares.

---

## 0. Governing rules (apply to every change, always)

1. **Never theorize.** Decisions come from (a) this standard, (b) logs the user has
   shared, and (c) existing code already written for this app. When a cause is not
   yet known, find it in those three sources — read the MIB, read the log, read the
   working module — rather than guessing. A fix shipped on a guess is not a fix.

2. **Time is not the constraint; correctness is.** The goal is a full-featured,
   fully-optimized app. It is always acceptable to spend longer to get a thing
   right — to audit, to verify against a working module, to test — rather than ship
   something plausible.

3. **Use a helper, or create and document one.** Every change uses the applicable
   shared helper (§B8). If no helper fits, that is a signal: write the helper, use
   it, and document in this standard *why it exists and what it owns*. Never inline a
   one-off that re-implements something a helper does (or should do). The recurring
   bugs in this app came from hand-rolling instead of reusing — scroll bounce,
   spinner-finishing-early, stale scalars — every one was a helper that existed or
   should have.

4. **Survey before adding; reconcile after.** No code is added in isolation. Before
   writing a new function, refresh path, table render, write flow, or data shape,
   FIRST search the codebase for what already exists in that space, and decide
   deliberately among three outcomes — never defaulting to the first:
   (a) **reuse** an existing helper as-is;
   (b) **extend** an existing helper so it covers the new case too (preferred over a
       new parallel thing — one generalized tool beats two similar ones);
   (c) **add** a new helper *only* when (a) and (b genuinely do not fit, and then
       document why in this standard.
   Adding is the last resort, not the first move. A new thing that duplicates or
   parallels existing code is a defect even if it works — `routingRefresh` was first
   written as a parallel reimplementation of `refreshTables` and had to be collapsed
   into it; that round-trip is the cost of adding-before-surveying.

   The survey is not one-directional. New code changes the context of old code: when
   an addition reveals that existing code was doing a thing the long way, or
   inconsistently, or would now duplicate the new helper, the existing code is
   updated in the same change to match — the codebase is left MORE consistent than
   before, never with a new pattern bolted alongside an old one. "It works and I
   didn't touch the old code" is not success if the old code should now use the new
   helper. Concretely, every change answers, in the commit's reasoning:
   - What existing code occupies this space? (search first — grep the helpers, read
     the working module, check §B8.)
   - Does this duplicate or parallel any of it? If so, stop and reuse/extend instead.
   - Does adding this mean existing code *should* now change to use it? If so, change
     it in the same pass.
   - Is the codebase more uniform after this change than before? If not, it is not done.

   **Conform-first, as its own commit.** When a new feature must be built on top of
   existing code that violates the standard (e.g. a write editor that predates
   `runButtonAction` and hand-rolls its button lifecycle), do NOT add the feature to
   the non-conformant code — that entrenches the violation and leaves the module
   split between two patterns. Instead: (1) conform the existing code as an isolated,
   separately-verified change, then (2) build the feature on the now-conformant base.
   Bundling the conversion and the feature into one blob makes both untestable and
   hides which change broke what. The interfaces-settings editor was converted to
   `runButtonAction` on its own before the Voice VLAN per-port toggle was added to it,
   exactly so the conversion could be verified against the existing speed/duplex edits
   before new behavior rode on top. The extra round-trip is the cost of not shipping a
   feature welded to a standard violation.

5. **An error is not evidence of impossibility.** A rejection from the switch (or
   any tool) tells you *this specific attempt failed*, never *this cannot be done*.
   Before concluding a negative ("the firmware does not support X", "this isn't
   writable", "the table is read-only"), the authoritative source must be exhausted:
   read the actual MIB object (SYNTAX, MAX-ACCESS, the entry DESCRIPTION, the INDEX),
   not the compiled summary; compare against a case that *works* (the host-map delete
   worked on the same firmware the sbelt delete failed on — that alone disproved a
   blanket "firmware can't delete"); and, when the source says the action should
   work but it does not, say exactly that — "the MIB supports this; the switch
   rejects it; cause unknown" — rather than inventing a limitation. In this project
   "firmware limit" was asserted twice from a `CommitFailed` error before the MIB was
   ever read; both times it was wrong until a probe or a re-read corrected it. A
   negative conclusion is a claim that needs the same evidence as a positive one.

6. **Read what the system actually has before encoding what you think it wants.**
   When a write targets a structure with an index, a format, or an encoding, and a
   real instance of that structure exists (a row the switch created, a working
   example, a file on disk), read and decode THAT first and match it exactly —
   before hand-rolling the format from a spec or from memory. The DNS index was
   guessed as flat ASCII for several rounds and rejected every time; one look at a
   switch-created row showed it was DNS wire format, and matching the real bytes
   fixed it immediately. The authoritative format is the one the system is already
   using, not the one the documentation implies.

7. **Apply the rules before the first attempt, not after it fails.** The failure
   mode these rules keep catching is not ignorance of the rule — it is applying it
   reactively: shipping a plausible first attempt, then doing the survey / the MIB
   read / the helper-reuse only when a log comes back wrong. Rules 1–6 are a
   pre-flight checklist, not a debugging procedure. Before writing a change, run
   them: Is there a helper (3)? Have I surveyed for duplication and reconciled
   existing code (4)? Am I about to conclude a negative without exhausting the source
   (5)? Is there a real instance whose format I should match (6)? The cost of the
   checklist is minutes; the cost of skipping it has been most of this project's
   rounds. "It compiled and looks right" is the start of verification, not the end.

8. **Conformance is audited across the whole app, not just per change.** Per-change
   conformance (rule 4) is necessary but not sufficient: it only touches code a
   change happens to visit, so non-conformant code that no feature touches persists
   indefinitely — which is exactly how 11 write buttons kept the pre-`runButtonAction`
   lifecycle long after the Standard named `runButtonAction` the rule, and how a 12th
   write button (the Clear-counters button, which hand-rolled its lifecycle with
   `flashButtonOk` directly rather than `beginApply`, so a `beginApply`-only grep
   missed it) went uncounted until a whole-app sweep found it. So conformance is also
   a *standing, whole-app* check, run as its own task (not folded into a feature):
   grep every write button's lifecycle — searching for ALL the markers (`beginApply`,
   `flashButtonOk`, manual `disabled = true` on a write), not just one — plus every
   panel's load/refresh mechanism and every table's render path against the Standard,
   and list the deviations. A claim that the app "conforms
   to the Standard" means this sweep was actually run and its deviations fixed or
   logged — not that the modules in active development look right. When the Standard
   changes, the sweep re-runs against the new rule.

---

# PART A — VISUAL DESIGN

## A1. Philosophy

A dense, calm, terminal-grade instrument. It is a monospace, dark, green-on-black
console for reading switch state at a glance and acting on it precisely. The visual
language serves comprehension density, not decoration: small type, tight spacing,
one accent per meaning, and motion only to confirm that something changed.

The look follows the structure. A panel is a bordered box a step above the page; a
section within it is announced by an amber rule; data is a table; a status is a
pill; an action is a bordered button that fills on hover. Because every module is
built from the same behavioral parts (§B), it inherits the same visual parts for
free — that is the point of unifying the two.

## A2. Tokens (the only colors/dimensions a module may use)

All defined on `:root` in `styles.css`. A module **never** hard-codes a hex value or
a pixel dimension that a token covers — it uses the token, so a global change
propagates.

Surfaces (depth reads in one direction: page → panel → nested):
- `--bg: #0c1210` — the page, darkest.
- `--panel: #111a17` — a panel, one step above the page.
- `--panel-2: #16211c` — content nested inside a panel, one step above that.
- `--panel-border: #22332c` — every panel/section/control border.

Text:
- `--text: #d7e5dd` — primary reading text.
- `--muted: #7c9488` — secondary/notes/labels.

Accents — **each color carries one meaning; do not use a color against its meaning**:
- `--amber: #e8a33d` — **structure & headings**. Section titles, table headers,
  panel heads, form-section titles. Amber is the "this is a label/heading" color.
  It is never an action color.
- `--green: #4fd88a` — **action & healthy**. Add/apply buttons, the primary `.btn`,
  the "good/ON/active" pill. Green is "do this" and "this is well".
- `--red: #e2604f` — **danger & critical**. Delete/destroy buttons, the "crit" pill,
  error states.
- `--blue: #5fb3e8` — **informational / a distinct secondary action** (`.btn-blue`,
  e.g. a form's primary Add inside a modal where green is the row control).
- `--violet: #b08bf0` — **special/rare** category (used sparingly, ~5 places).
- There is a parallel `--t-*` palette scoped to the topology view only; outside
  topology, use the palette above.

Type & chrome:
- `--mono: "IBM Plex Mono", …` — the ONLY font. Everything is monospace.
- `--header-h: 46px`, `--tabbar-h: 42px` — fixed chrome heights.

## A3. Typography scale (use these sizes; do not introduce new ones)

Monospace throughout. The established scale (by frequency in the app):
- **10px** — section titles, panel heads, table headers, pills, `card-sub` notes.
  Uppercase + `letter-spacing: 0.1em` for titles/heads.
- **10.5–11px** — buttons (`tbl-add-btn`, `tbl-act-btn`), small controls.
- **11.5px** — table cell data (`data-table td`), the primary `.btn`.
- **12px** — form field labels.
- **13px** — form inputs, banners.
- **14px** — body base.
- Larger (15–22px) is reserved for headline figures (e.g. `poe-used`).

Rules: titles/headers/pills are **uppercase with letter-spacing**; body and table
data are not. Never bold for emphasis in prose — hierarchy comes from size, color,
and the amber rule, not weight.

## A4. Spacing & shape

- **Radius scale**: `3px` (default — pills, `.btn`, chips), `4px` (buttons, flashed
  cells), `5px` (panels, inputs). Larger radii (6–8px) exist for banners only. Use
  the smallest that fits the component class.
- **Panel padding**: `.panel-body`/`.scroll-body` own their padding (10–14px); a
  module does not add its own outer padding.
- **Section rhythm**: `.section-title` carries `margin: 16px 0 7px` and a
  `1px solid var(--panel-border)` bottom rule. Sections are separated by this rule,
  not by blank space or boxes.
- **Control spacing**: an add-control row is `.tbl-add { margin: 8px 0 14px }`.

## A5. Component vocabulary (build modules from these — do not invent new markup)

Each maps to a CSS class that already exists. A module composes these; if a needed
component does not exist, add it to `styles.css` as a reusable class (and note it
here), never as inline styles on a one-off node.

- **Section title** — `el('div','section-title', title)` with an optional
  `el('span','st-note', note)` for a count/subtitle. Amber, uppercase, ruled.
- **Status pill** — `el('span','pill '+variant, label)` where variant is
  `good|warn|crit|idle`. The semantic status indicator; color = meaning (A2).
- **Note / subtext** — `el('div','card-sub', text)`. Muted 10px; for empty states
  ("No routes reported.") and secondary info.
- **Data table** — always via `mountKeyedTable` (§B3). Renders `.data-table` with
  amber headers and 11.5px cells. Never hand-build a `<table>`.
- **Add control** — `addControl(label, onClick)` → a green `.tbl-add-btn` in a
  `.tbl-add` row. The standard "add a thing" affordance at the top of an editable
  section.
- **Row action** — `actGroup([...])` + `actBtnConfirm(label, fn, variant, title)`.
  A muted bordered button that colors to its variant (`danger` → red) on intent.
  The standard per-row Delete/edit affordance.
- **Primary/secondary buttons** — `.btn` (green, full-width, uppercase) and variants
  `.btn-blue/.btn-danger/.btn-amber/.btn-violet`; `.btn-small` for inline. Color by
  meaning (A2).
- **Form** — a modal via `openTabbedPopout(s, title, tabs, [])`; inside, group with
  `formSection(title)` (amber ruled title) and lay out fields with `field(label,
  control)` (`.snmp-field`: stacked label + input).
- **Change flash** — `flashValue(node)` adds `.value-changed` (a 1.7s settle
  animation) so a value that just changed is felt. Used for inline edits.

## A6. Motion & feedback

Motion exists only to confirm change, never to decorate:
- A value that changed flashes once (`value-settle`, 1.7s).
- A button action spins, then shows ✓ Done briefly, then reverts — owned entirely
  by `runButtonAction` (§B6). A module never writes its own spinner/done logic.
- Hover transitions on buttons are 0.12s fill. Nothing else animates.

## A7. Layout & scroll

- The grid is 12 columns; a panel spans some columns (`span: 12` full width).
- The dashboard scrolls in `.scroll-body`; a panel body scrolls in `.panel-body`.
  **Scroll position is sacred** — any repaint preserves it (§B5). A module never
  calls `scrollIntoView`, never sets `scrollTop` to a computed value, and never
  calls `reflowTallPanels` from a refresh (it fights scroll preservation).
- Wide content (tables) scrolls within its own container; the page body never
  scrolls sideways.
- The page is dark-only (`color-scheme: dark`); never introduce a light-mode value.

---

# PART B — BEHAVIOR

The behavioral rules. Because the visual components (Part A) are produced *by* these
helpers, following Part B yields correct visuals automatically.

## B1. Module families

There are three, by how their data is sourced. All three obey the same VISUAL rules
(Part A) and the same WRITE rules (§B6) — those are universal. They differ only in
the data/refresh mechanism (§B4–§B5), and §B2–§B3 (keyed paint + `mountKeyedTable`)
apply fully only to families (a) and (b).

**(a) Health-data panels** — render from tables in the periodic SNMP walk (summary,
metrics, hardware, interfaces, auth, connected, stp). A `case` in `paintBuiltin`.
Read-mostly; any writes follow §B6.

**(b) Keyed write modules** — data from `health.js` tables (some `onDemand`), refresh
via `refreshTables`, tables via `mountKeyedTable`, reconcile in place. Dedicated
paint fn dispatched before the switch. **routing, vlans.** This is the preferred
pattern for any NEW interactive module, and §B2–§B6 describe it in full.

**(c) Self-managed config modules** — **snmpcfg, capture, flash.** These own their
data pipeline: a dedicated server endpoint (`/api/snmp-config`, `/api/flash`,
`/api/capture`), their own loader (`loadSnmpPanel`, …) and their own repaint, loaded
lazily (on first open, then refreshed on the normal cycle and in place on write) —
NOT through `health.js`/`refreshTables`/`mountKeyedTable`.

**When family (c) is justified — the two tests.** A module earns family (c) only if
it meets AT LEAST ONE of these, and the choice is documented:
1. **Computed/server-side data.** The data is not a flat SNMP table the client can
   walk — it is a computed view that joins many tables or runs a probe/check on the
   server (snmpcfg's VACM model: a "community" row is synthesized from the Cisco
   community table + VACM security-to-group + access + view tree; plus an
   access-level probe and a target-integrity check — imperative diagnostics, not
   reads). A client-side join of flat walks does NOT qualify — see the ACL note.
2. **Periodic cost too high for the health timer.** Loading the module's data costs
   enough SNMP PDUs that putting it on the periodic walk would breach the pps budget
   (see §B5a). snmpcfg's load is ~35 walks over large VACM/per-port tables ≈ a ~100
   pps *burst* — on its own at the whole budget, and it would recur every cycle
   whether or not the panel is open. So snmpcfg MUST stay lazy; "load like the other
   modules on the periodic walk" is not an option for it, by the pps rule, not by
   preference.

A NEW module prefers family (b). It uses family (c) only when it passes a test above,
and then it still behaves identically to a keyed panel (loads lazily but refreshes on
the cycle, writes refresh in place — never a whole-module reload). Being "self-managed"
describes only WHERE the fetch lives; it is never visible to the user as different
behaviour.

**ACL is NOT family (c) — it is a keyed panel (b).** Its three tables
(`QOS_ACL.name/aceTidx/tuple`) are plain `getbulk` walks, its join is purely
client-side, and its load costs ~6 PDUs (~12-packet burst — negligible). It fails
both family-(c) tests: the data is flat-walkable and the cost is trivial. So ACL's
tables are declared in `health.js` and the existing client-side join moves, intact,
into its paint function (reading `h.aclNames/h.aclAces/h.aclTuples` instead of its
own `apiPost` walks). Having multiple tables/sections in one panel is NOT a reason
for family (c): routing and vlans are keyed panels with 5+ tables each. The only
family-(c) criteria are the two tests above.

**Why the self-managed PATTERN lives in helpers, not in `health.js`.** It is
tempting to teach `health.js` to produce computed/joined views so family (c)'s data
could run through it too. Do NOT: the defining trait of `health.js` is "runs
periodically for everyone", and the defining constraint of a genuine family-(c)
module (snmpcfg) is "must NOT run periodically" (test 2) — those are incompatible,
and snmpcfg's probe/check logic is imperative, not a declarative view producer. The
reuse benefit — a standard way to do "fetch several things, compute, render several
sections, refresh one in place on write" — is delivered through the family-(c)
helpers (`selfManagedRender`, `selfManagedReload`, per-section reload like
`reloadSnmpSection`, `plainTable`), which a future computed-view module composes.
Reuse comes from the helpers; it does not come from moving server-computed logic
onto the periodic timer.

Even so, family (c) shares the RENDER and REFRESH machinery through two helpers, so
it is not a separate world — only its data source differs:

- **Tables** — a self-managed module renders every *interactive or reconciling* data
  table with `plainTable(s, cols, rows)` (a thin keyed-render wrapper: `rows` are
  arrays of cells, each cell a string or a DOM node such as an `actGroup`), NOT a
  hand-built `<table>`. This gives it the same cell-diffing, styling, and action-cell
  handling as the keyed panels. The scope is tables with rows the user acts on or
  that re-render on a refresh (ACL rules, SNMP users/communities, flash files,
  captures). A handful of read-only, one-shot or live-append display tables
  elsewhere — the tech-support parse output, the OID results grid, the syslog stream,
  the dot1x trap matrix, the SNMP view grid — deliberately stay as hand-built
  `<table>` elements: they already carry the shared `data-table` class (so they are
  visually consistent), nothing reconciles them, and the cell-diffing/action-cell
  machinery buys them nothing while the conversion carries risk. `plainTable` is the
  rule for interactive/reconciling tables; a purely static display table may use
  `data-table` directly. The engine's own `<table>` inside `keyedTable` is the source
  of the pattern, not an instance of it.
- **Refresh** — a self-managed module's render runs inside `selfManagedRender(s,
  renderFn)`, which captures scroll before `renderFn` clears+rebuilds and restores it
  after (standard A7), so a rebuild never jumps the page. Its loader is awaited via
  `selfManagedReload(s, loaderFn)` (or simply by returning the async loader's
  promise), so a write's `runButtonAction` `settle` holds the spinner until the
  reload has actually repainted — the same guarantee `refreshTables` gives family (b).

Obligations, then: VISUAL rules (Part A) in full; WRITE rules (§B6) in full
(`snmpSet`/`snmpSetResult`, `runButtonAction`, `markConfigDirty`, shared index
helpers); tables via `plainTable`; refresh wrapped in `selfManagedRender` and awaited
so the spinner holds. The only thing family (c) does differently from (b) is *where
the rows come from* — never *how they are rendered or how scroll/spinners behave*.

**A write refreshes ONLY the section it changed, never the whole module.** A
whole-module reload (re-fetching every section) on a single create/delete is the
family-(c) failure mode: snmpcfg's reload was 6 serial fetches for one community
change. Each section renders into a stable wrapper node kept on the module's state;
a write's `settle` re-fetches and re-renders just that section's wrapper
(`reloadSnmpSection(s, which)` is the pattern — re-fetch one section's data, replace
its wrapper via `selfManagedRender`, optionally refresh a dependent section like a
target-integrity banner). This matches how a keyed panel reconciles only the tables
whose data changed. A full reload is allowed only as a cold-start fallback (the panel
hasn't rendered its wrappers yet).

## B2. The paint function contract

Signature `paintXPanel(s, body, p)` — always take `p` if the module has keyed tables
(`mountKeyedTable` needs it).

Observe the reconcile guard `s._ktReconcile`:
- **false** (full paint): clear the body, build all scaffolding (section titles,
  add-controls, static text, and the stable containers for any scalar-driven
  status — see below).
- **true** (in-place reconcile): do NOT clear, do NOT rebuild scaffolding. Only
  re-mount keyed tables (they diff themselves) and refresh the **contents** of the
  stable scalar containers.

Concentrate the guard: build a `section()`/`scaffold()` helper and an
`emptyNote()` helper and call those, rather than sprinkling `if (!s._ktReconcile)`
across the function. (A module using the guard a dozen times is scattering
scaffolding and will drift; VLANs uses it ~3 times.)

**Scalar-driven status that can change (pills, toggles whose label depends on a
scalar):** build the container ONCE under the guard, keep a handle on `p`
(`p._xStatus`), and refresh its contents on EVERY pass (including reconcile) in
place. Do NOT rebuild it (that is a structural change → forces a full repaint →
scroll jump), and do NOT leave it reconcile-skipped (then it never updates after a
write). This is the pattern that fixed the routing L3/DNS status pills.

Skeleton:

```js
function paintXPanel(s, body, p) {
  if (!s._ktReconcile) clear(body);
  const h = s.health;
  if (!h) { if (!s._ktReconcile) body.appendChild(el('div','card-sub','Waiting for data…')); return; }

  if (!s._ktReconcile) ensureXLoaded(s);            // §B4, on-demand modules only

  const dv = (c, fb) => (c == null ? (fb !== undefined ? fb : '')
    : (c.display != null ? c.display : (c.value !== undefined ? c.value : c)));

  const section = (title, note, addLabel, onAdd) => {
    if (s._ktReconcile) return;
    const st = el('div','section-title', title);
    if (note) st.appendChild(el('span','st-note', note));
    body.appendChild(st);
    if (addLabel && s.target) body.appendChild(addControl(addLabel, onAdd));
  };
  const emptyNote = (msg) => { if (!s._ktReconcile) body.appendChild(el('div','card-sub', msg)); };

  // scalar-driven status: stable container built once, contents refreshed always
  if (!s._ktReconcile) { section('Status'); p._xStatus = el('div','card-sub'); body.appendChild(p._xStatus); }
  if (p._xStatus) { clear(p._xStatus); p._xStatus.appendChild(el('span','pill '+(ok?'good':'idle'), ok?'ON':'OFF')); }

  // a data section:
  section('Things', rows.length + ' items', 'Add thing', () => openThingForm(s));
  if (rows.length) body.appendChild(mountKeyedTable(s, p, 'things', COLS, rows, opts));
  else emptyNote('No things.');
}
```

## B3. Tables — always `mountKeyedTable`

Never hand-build a `<table>`. `mountKeyedTable(s, p, id, cols, rows, opts)`:
- `id` stable per table; `rows` are `{ key, cells }` with a stable `key`.
- cells: `{ v }` text · `{ cellNode }` built node (action group) · `{ pill:true, v }`
  status pill. Action cells carry a `sig` so the diff distinguishes them.
- `opts.pageSize` paginates; the engine preserves the current page across reconciles.
- Reconcile-aware: called identically on full paint and reconcile.

**Placement — ALWAYS place a keyed table with `mountInto(container, s, p, id, cols,
rows, opts)`, never `container.appendChild(mountKeyedTable(...))`.**
On a reconcile, `mountKeyedTable` reconciles the existing table node in place and
returns it; re-appending that already-attached node MOVES it to the end of the
container. A panel with more than one keyed table that does a non-structural in-place
reconcile (same table set, same columns, only row data changed) therefore piles every
table at the bottom, detached from its section title — the routing-panel "tables jump
to the bottom" bug. `mountInto` appends only when the node is not already in the
container, leaving an in-place-reconciled node where it sits; for a single-table panel
it is a harmless no-op append.

This rule is universal (not "multi-table only") because the vulnerability is easy to
misjudge: the condition is *(keyed panel) × (>1 table) × (a non-structural reconcile
fires)*, and the last two are not obvious at the call site. `interfaces` looks
single-table (`ports`) but also mounts `channels`; `auth`'s session tables reconcile
in place even though its radius/tacacs tables are in `PANEL_FULL_REPAINT_TABLES`;
`hardware` and `connected` are multi-table and only *looked* safe because their data
rarely changes. Using `mountInto` everywhere removes the judgment call — a table is
always placed correctly regardless of how its panel reconciles. All keyed panels in
the app use it.

## B4. On-demand loading (tables NOT in the periodic walk)

Large/rare tables are marked `onDemand` in `health.js` and loaded once per visit via
a guarded helper (the Connected/MAC pattern):

```js
function ensureXLoaded(s) {
  if (s._xFetching || !s.target) return;
  if (Date.now() - (s._xFetchedAt || 0) < 30000) return;   // once per visit
  s._xFetching = true;
  xRefresh(s).then(() => { s._xFetching = false; }, () => { s._xFetching = false; });
}
```
Guard with BOTH an in-flight flag and a 30s timestamp (without the timestamp an
empty result re-fetches every repaint and thrashes the switch). The fetch goes
through the module refresh (§B5), never a bespoke `fetch`.

**Raw table mode — for a panel that joins several subtrees itself.** A normal health
table is *pivoted* into one row per index with named columns. A panel that builds its
rows by joining multiple subtrees with pointer indirection (the ACL panel: header →
ACEs → tuple values) reads the *un-pivoted* walk rows instead (`{ index, column,
value, display }`). Declare such a table with `raw: true` (and `oid`, or `oids` for a
list of subtrees to walk and concatenate); `health.js` then returns the raw walk rows
and the panel's existing join reads them unchanged. This is how ACL became a keyed
panel (B1b) without rewriting its join: its three tables (`aclNames/aclAces/
aclTuples`) are `raw` + `onDemand`, synced to the panel via pointers. Use `raw` only
when a panel genuinely joins subtrees itself; a single flat table uses the normal
pivoted form.

## B5. Refresh — ALWAYS delegate to `refreshTables`

A module NEVER hand-rolls its data refresh. Wrap `refreshTables(s, tables)` — the one
canonical path — which provides, for free: scroll preservation (`scrollKeeper`),
defer-when-busy (coalesces against an in-flight walk/write), in-place reconcile of
every panel whose `PANEL_TABLE_DEPS` include a changed table (scroll-preserving
`repaintPanel` fallback), and a promise that resolves only after the UI reflects the
change (so a button can spin until then).

```js
const X_TABLES = ['tableA','tableB', 'scalars'];   // include 'scalars' if any
                                                    // status reads from a scalar
function xRefresh(s) {
  if (!s.target) return Promise.resolve();
  s._xFetchedAt = Date.now();                       // keep ensureXLoaded from double-firing
  return refreshTables(s, X_TABLES);
}
```
Register the module: add it to `KEYED_PANELS` (reconcile in place) and to
`PANEL_TABLE_DEPS` (so `refreshTables` knows to reconcile it, including `scalars` if
any status is scalar-driven). Do NOT call `reflowTallPanels` from a refresh —
`refreshTables` handles layout; an extra reflow fights scroll preservation. (Reflow
belongs only in the one-shot on-demand loader's first populate, as Connected does.)

**If a status reads from a scalar, `X_TABLES` MUST include `'scalars'`** — otherwise
the write succeeds but the UI never re-reads the scalar and the status goes stale
(the DNS-toggle bug).

## B5a. The SNMP cost budget (pps)

The app must not raise the switch's CPU input rate by more than **~100 pps**. Every
periodic walk and every panel load spends SNMP PDUs against that budget, so what goes
on the periodic timer is a cost decision, not just a correctness one.

- **Averaged vs burst.** Averaged over the refresh interval (default 300s) almost
  anything is cheap. The constraint is the **burst**: a load fires all its PDUs in a
  ~1–2s window, and that spike is what approaches the budget. Estimate a load as
  `walks × PDUs-per-walk × 2 (req+resp)` landing in ~2s. A flat table of a few rows is
  ~1 PDU; a getbulk over a 400-port table is several. ACL ≈ 6 PDUs ≈ a 12-packet
  burst (noise); snmpcfg ≈ 35 walks over large tables ≈ a ~100 pps burst (the whole
  budget, by itself).
- **This decides family placement (§B1).** If a module's data is cheap to walk, it
  belongs on the periodic cycle (family a/b). If its load is a large burst, it stays
  lazy (family c, test 2) — loaded on first open, refreshed on the cycle only while
  open, and never added to the always-on walk. Do not "make it load like the other
  modules" if that puts a heavy burst on every refresh for data the user may not be
  viewing.
- **Large tables are `onDemand`.** A big table (the full route table, a per-port walk
  a panel rarely needs) is marked `onDemand` in `health.js` and loaded once per visit
  (§B4), not on every periodic walk — the same budget discipline inside a keyed panel.
- **Writes re-read the minimum.** A write settles by refreshing only the affected
  table(s)/section (§B5, §B6), never the whole panel or a full re-walk — both for
  snappy UX and to keep write-time PDU bursts small.

## B6. Writes

- **Every SNMP write** → `snmpSet(s, vb)` (throws) or `snmpSetResult(s, vb)`
  (returns `{ok,body}`). Never a bespoke `fetch` to `/api/snmp/set`. One varbind or
  an array, sent as one atomic PDU.
- **Every write button** → `runButtonAction(btn, spec)`. It owns spinner → run →
  check `ok` → `onApplied` → `settle` (awaited) → ✓ Done / fail+restore, plus the
  minimum-visible-spin floor so a fast write still registers. `settle` MUST return
  the refresh promise so the spinner holds until the UI updates:

  ```js
  runButtonAction(btn, {
    failLabel: 'Delete route',
    run:       () => rowStatusDelete(s, STATUS_OID + '.' + index),
    ok:        (res) => res && res.ok && !(res.body && res.body.error),
    onApplied: () => markConfigDirty(s),
    settle:    () => xRefresh(s),          // returns the promise — not Promise.resolve(x())
  });
  ```
  The old hand-rolled lifecycle — `beginApply` / `flashButtonOk` / `resetApply` — is
  **deprecated and must not be used in new or edited code**; it predates
  `runButtonAction` and reimplements the same spinner/done/revert without the minSpin
  floor or a consistent settle. A write button that still uses it is a conformance
  deviation (rule 8). **Compose with a confirm** the established way — a two-tap
  confirm wraps a handler that calls `runButtonAction`:
  `withConfirm(btn, (e) => runButtonAction(e.currentTarget, { … }))` (what
  `actBtnConfirm` does, and the interface-settings and snmpcfg editors). A multi-field
  editor's `run` performs the whole ordered batch and returns `{ ok, failures }`; its
  `settle` does the computed re-read; detailed per-field errors may go to the form's
  own message line via `error` rather than a toast.
- **Row deletes** → `rowStatusDelete(s, statusOid)` — tries `destroy(6)`, falls back
  to `notInService(2)`→`destroy(6)`. **But first decide whether the row is
  deletable at all**, and gate the control rather than offering an action the switch
  will always reject. Two established cases:
  (a) a switch-owned row (a DHCP-learned DNS server, per its Owner column) is
      removed by changing DHCP, not SNMP;
  (b) the DNS-server (sbelt) table on this C1300 firmware rejects *every* documented
      delete path — direct `destroy`, `notInService`→`destroy`, clear-name+destroy,
      the Ext-owner teardown, and the standard-table destroy all return
      `CommitFailed` — even though the MIB says the row is deletable and the add path
      works. This was established by a delete-probe that tried each variant (rule 5:
      the negative was proven, not assumed), after reading both CISCOSB-dnscl.mib and
      rfc1612.mib. Both cases show a 🔒 with a reason instead of a Delete button.
- **Protect connectivity-critical writes.** A write that could sever the app's own
  SNMP path to the switch is locked, not merely confirmed — the same protection the
  management SVI/VLAN already has (`isManagementIf`). This covers deleting the
  default route or a route whose network contains the management IP
  (`routeDeleteRisk`), and by extension any future write that would tear down the
  interface, VLAN, or address carrying `s.target.host`. Lock the control with a
  visible reason rather than letting the user cut themselves off; a write the app
  cannot recover from is worse than a write the switch rejects. The routed-port
  mode follows this: a routed port holding the management address cannot be
  turned back into a switchport, and a port flagged as the uplink cannot be made
  routed (`buildSwitchportEditor`), each locked with the reason shown.
- **RowStatus creates** set the mandatory columns and `createAndGo(4)` in ONE PDU (a
  bare RowStatus set returns InconsistentValue).
- **`markConfigDirty(s)`** in `onApplied` for any running-config change, so the
  unsaved badge/banner update.
- **Index encoding** uses the shared helper matched to the MIB index type:
  - plain `IpAddress` index → `ipToOidIndex(ip)`
  - `InetAddress` index → `ipv4IndexV4(ip)` / `nameserverIndex(ip)`;
    decode with `inetIndexToIp(idx)`
  - `DnsNameAsIndex` (Cisco DNS tables) → `dnsNameIndex(name)` /
    `dnsNameIndexToStr(idx)` — DNS wire format (`<total-len>.<label-len><label>…0`),
    NOT flat ASCII. Verified against switch-created rows; a flat-ASCII encoding is
    rejected with NotWritable/NoCreation. Prefer the row's own `r.index` for a
    delete (authoritative) over re-encoding.
  - `InetAddress` column VALUE → `ipv4ToHex` / `hexToIpv4`
  Never hand-roll index math.

## B7. Registration checklist for a new module

1. `health.js`: add table walk(s); mark large ones `onDemand`; include any companion
   table needed to classify rows (e.g. an Owner table that says static vs dynamic).
2. `BUILTIN` panel list (`public/src/04-health.js`): `{ key, title, span, h, needs }`.
3. `paintBuiltin`: `if (key === 'x') { paintXPanel(s, body, p); return; }`.
4. `KEYED_PANELS.add('x')`.
5. `PANEL_TABLE_DEPS.x = [ ...tables..., 'scalars'? ]`.
6. Paint per §B2–§B3; loader per §B4; refresh per §B5; writes per §B6. Visuals come
   from the helpers (Part A) automatically.
7. Reuse index/enum helpers; never hand-roll.

## B8. Shared helpers index (the toolbox a module is built from)

| Concern | Helper |
|---|---|
| Full data refresh (scroll-safe, defer-safe) | `refreshTables(s, tables)` |
| Preserve scroll around a manual repaint | `scrollKeeper(s)` |
| Repaint one panel (scroll-preserved) | `repaintPanel(s, key)` |
| Reconcile one panel's keyed tables in place | `reconcilePanelInPlace(s, p)` |
| Build/diff a data table | `mountKeyedTable(s, p, id, cols, rows, opts)` |
| Place a table (multi-table panels) | `mountInto(container, s, p, id, cols, rows, opts)` |
| Render a table in a self-managed module | `plainTable(s, cols, rows)` |
| Preserve scroll around a self-managed rebuild | `selfManagedRender(s, renderFn)` |
| Await a self-managed loader (settle) | `selfManagedReload(s, loaderFn)` |
| Refresh one section in place (family c) | per-section reload, e.g. `reloadSnmpSection(s, which)` |
| ~~Old button lifecycle — REMOVED~~ | `beginApply` / `resetApply` deleted (no callers); `flashButtonOk` is now internal to `runButtonAction` only → always use `runButtonAction` |
| Wrap existing cell arrays as keyed rows | `keyedRowsFrom(cells, rows, keyFn)` |
| Write SNMP (throws) | `snmpSet(s, vb)` |
| Write SNMP (returns {ok,body}) | `snmpSetResult(s, vb)` |
| Delete a RowStatus row (with fallback) | `rowStatusDelete(s, statusOid)` |
| Button lifecycle (spinner→run→settle→done) | `runButtonAction(btn, spec)` |
| Show a line diff (`diffLines` result) | `diffPre(diff)` → `<pre class="diff">` |
| Read-only GET of an app API (throws on error) | `getJson(url)` |
| App-level window (not per switch) | a `.dialog-card` in its own overlay, like `#panel-dialog` and `#update-dialog` (25-updates.js) |
| Flash a changed value | `flashValue(node)` / `flashValues(nodes)` |
| Mark running-config dirty | `markConfigDirty(s)` |
| Section title + optional add-control | the module's `section()` (per §B2) |
| Add-control button | `addControl(label, onClick)` |
| Row action group / confirm button | `actGroup([...])`, `actBtnConfirm(...)` |
| Status pill | `el('span','pill '+variant, label)` |
| Modal form | `openTabbedPopout(s, title, tabs, [])`, `formSection`, `field` |
| A popout tab that exists only in some states | tab `{ hidden: true }` + the popout's `setTabVisible(tab, visible)` (the routed port's IPv4 tab) |
| Two-tap confirm only when the click is drastic | `withConfirm(btn, run, { when, confirmText })`: `when()` false runs on the first tap; `confirmText` may be a function naming what goes |
| IPv4 address of an L3 interface (VLAN SVI or routed port) | `buildSviEditor(s, iface, ifIndex, pane)`, `iface` = `vlanIface(vlan)` or `{ name, noun: 'port' }`; one editor, one management lock |
| IpAddress index ↔ | `ipToOidIndex` |
| InetAddress index ↔ | `ipv4IndexV4` / `nameserverIndex` / `inetIndexToIp` |
| DnsName/string index ↔ | `strToOidIndex` / `oidIndexToStr` |
| InetAddress value ↔ | `ipv4ToHex` / `hexToIpv4` |

When a change needs something not in this table, add the helper and add its row here
(governing rule 3).
