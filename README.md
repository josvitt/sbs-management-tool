# SBS Management Tool

A web app for managing Cisco Catalyst 1200, 1300 and 1300X business
switches. It runs on one PC and you use it in a browser at
`http://localhost:3000`. It talks to the switches over SNMP, SSH and the
serial console.

What it does:

- **A health dashboard per switch.** Each switch gets a tab with panels for
  details, key metrics with history graphs, interfaces, VLANs, connected
  devices, hardware, PoE, spanning tree, sessions and 802.1X, access lists,
  SNMP settings, flash files and packet capture. You can add your own panels
  for any MIB object.
- **Changes from the dashboard.** You can edit ports, VLANs, IP addresses,
  port channels, AAA servers, ACLs and the SNMP setup. You can also bounce PoE
  and shut or enable ports. Every write asks you to confirm when it is hard to
  undo.
- **Configuration.** It fetches the running and startup configs, shows the
  differences, saves running to startup, and keeps a history of past
  versions.
- **Events.** It receives syslog and SNMP traps from the switches and shows
  them live.
- **Topology.** It draws a diagram of how the switches and devices connect.
- **A terminal.** You get SSH or console (serial) access, and a viewer for
  `show tech-support` output.
- **A MIB Explorer.** You can search the full Catalyst MIB set by name,
  number or description.

Collection runs on the server, so closing the browser does not stop it.

## Install

1. Download the newest release from the
   [Releases page](https://github.com/josvitt/sbs-management-tool/releases/latest)
   (*Source code (zip)*) and unpack it. Or clone the repository with
   `git clone https://github.com/josvitt/sbs-management-tool.git`.
2. Install [Node.js](https://nodejs.org) (version 22 or newer).
3. Double-click **`start.bat`**.

The first run installs dependencies, which takes about a minute. Then your
browser opens the dashboard. A console window titled "SBS Management Tool
Server" stays open while the app runs. Close it, or press Ctrl+C, to stop
the app.

Not on Windows? Run `npm install && npm start`, then open
`http://localhost:3000`.

## Run it as a service (recommended)

A service keeps collecting from your switches with no browser open, and it
starts again after a reboot, before anyone logs in.

**Windows**

1. Put the app folder **outside `C:\Users`**, for example
   `C:\sbs-management-tool`. It cannot go on the Desktop or in Documents or
   Downloads. The service's account cannot open those folders, so the
   installer stops and tells you to move it.
2. Right-click **`install-service.bat`** and choose *Run as administrator*.
3. Open the dashboard with **`open-ui.bat`** (or `http://localhost:3000`)
   and add your switches there.

The service is called "SBS Management Tool". It runs with no window under
Windows' limited **LocalService** account. To remove it, run
**`uninstall-service.bat`** as administrator.

**Linux:** use the `sbs-management-tool.service` systemd unit. The comments
at the top of that file give the setup steps.

Pick one way of running it, either the service or `start.bat`, and keep to
it. Saved switches belong to the account that saved them.

## Updates

The **Updates** button (top right) shows the installed version and the
newest release with its notes. The app checks once a day and shows a green
**NEW** badge when a release is out. It never installs on its own. You
click **Install**.

Updates come from this public repository, so **no GitHub account or token
is needed**.

GitHub allows about 60 update checks an hour from one internet address
without a token. That is plenty for one PC. If many PCs share one address
and the Updates window says the hourly limit is used up, you can paste an
optional token into the Updates window: on GitHub, go to Settings →
Developer settings → Fine-grained tokens → Generate new token, and choose
*Public repositories (read-only)* with no permissions. It is stored
encrypted and only ever sent to GitHub.

**Install** downloads and checks the new version first, then restarts the
app. Your saved switches, logs, history and layouts are kept. If the new
version doesn't start properly, the app goes back to the old one by itself.
After an update you can also choose **Go back** until the next update. The
PC needs to reach `api.github.com`, `codeload.github.com` and
`registry.npmjs.org`.

When the app runs as a service, the service restarts it. `start.bat` also
restarts it. With plain `npm start`, start it again yourself.

## Pointing your switches at it

The app has its own receivers, so you don't need to install anything else.

| Receiver | Port (UDP) | Used for |
| --- | --- | --- |
| TFTP | 69 | fetching and backing up configs |
| Syslog | 514 | the Events panel |
| SNMP traps | 162 | the Events panel, and quicker refreshes |

The Events panel can set up syslog on a switch for you. For traps, run
`snmp-server host <this PC's address> traps version 2c <community>` on the
switch. Fetching configs needs an SNMP community or user with write access.
On Linux, ports below 1024 need the systemd unit's permission or root.

## Security

- **Only this PC can open the dashboard.** The web server listens on
  `localhost` only. The receivers above listen on every network interface,
  because the switches have to reach them.
- **There is no sign-in and no HTTPS.** If you open the dashboard to other
  PCs with `SBS_BIND=0.0.0.0`, anyone who can reach port 3000 can use it,
  see the saved switches and change their configuration.
- **Saved credentials are encrypted** in `state.enc`. The key is kept in
  `.state-key` in the same folder. This protects a copied or backed-up folder,
  but not someone who can already log in to this PC. For stronger protection,
  set `SBS_PASSPHRASE`. The key then comes from the passphrase and is never
  written to disk, but you must supply the passphrase every time the app
  starts.
- **Other websites and DNS tricks are blocked.** A page from another site
  can't call the app. If you open the dashboard by a DNS alias, add the
  alias to `SBS_ALLOWED_HOSTS`.
- **SSH host keys are checked.** If a switch's key changes, the app refuses
  to connect until you confirm the new key in Settings.
- **Passwords are kept out of the logs.**

## Settings

You don't need to change any of these. Set them as environment variables.

| Variable | Default | What it does |
| --- | --- | --- |
| `PORT` | 3000 | Dashboard port |
| `SBS_BIND` | `127.0.0.1` | Address the dashboard listens on |
| `SBS_ALLOWED_HOSTS` | | Extra host names allowed to open the dashboard, comma-separated |
| `SBS_PASSPHRASE` | | Derive the vault key from a passphrase instead of `.state-key` (`SWITCH_CONSOLE_PASSPHRASE` also works) |
| `TFTP_PORT`, `SYSLOG_PORT`, `TRAP_PORT` | 69, 514, 162 | Receiver ports |
| `SNMP_MAX_RPS` | 100 | Most SNMP requests per second sent to one switch |
| `SESSION_IDLE_MS` | 300000 | Close an idle SSH or console session after this long |
| `SBS_CONFIG_HISTORY_KEEP` | 50 | Config versions kept per switch |
| `SBS_UPDATE_TOKEN` | | Optional GitHub token, used instead of one saved in the Updates window |

Collection timing and other tuning settings are described in
[docs/SERVER-STANDARD.md](docs/SERVER-STANDARD.md).

## Files it keeps

All of these are in the app folder. None of them are replaced by an update.

| File | Contents |
| --- | --- |
| `state.enc`, `.state-key` | Saved switches and credentials (encrypted) |
| `config-history/` | Past running configs (encrypted) |
| `history.json` | Metric history for the graphs |
| `layouts.json` | Dashboard layout per switch |
| `known-hosts.json` | Trusted SSH host keys |
| `logs/` | The app log (connections and errors only, never session content), the event log, and received syslog and traps |
| `updates/` | Update settings, downloads, the previous version and the optional token |

## Development

- The browser code is in `public/src/`, one file per feature.
  `npm run build` joins it into `public/app.js`, which the page loads.
- `npm test` runs the tests. They include a replay of a real
  C1300-24MGP-4X with private details removed (`test/fixtures/live/`).
  GitHub runs them on every push and pull request.
- **Releases:** every merge to `main` is published as a GitHub release. In
  the pull request, bump `version` in `package.json` and add
  `release-notes/v<version>.md` in plain language. If you merge without them,
  the release gets the next patch number and notes generated from the pull
  request titles.

## Other documents

- [docs/SERVER-STANDARD.md](docs/SERVER-STANDARD.md) covers how the server
  works: collection, events, storage, the service, product support, shared
  helpers and self-update.
- [docs/MODULE-STANDARD.md](docs/MODULE-STANDARD.md) covers how the dashboard
  panels are built: visual design, behaviour and the shared helpers.
- [docs/SWITCH-NOTES.md](docs/SWITCH-NOTES.md) covers how the Catalyst
  switches behave over SNMP and the CLI, and how the code handles that.
- `release-notes/` has what changed in each version.
