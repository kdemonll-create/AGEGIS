# AEGIS — Field Security Operations Suite

A self-contained, web-based suite for **travel-risk management and duty-of-care** —
keeping situational awareness on worldwide threats to your own travelers, planning and
briefing trips, working all-source reporting, and keeping open-source intelligence (OSINT)
shortcuts one tap away.

It ships in **one codebase with two deployment modes**:

| | Standalone | Secure |
|---|---|---|
| Setup | Open a file. Nothing to install. | `npm install && npm start` |
| Auth | Convenience lock (browser-local) | Real session login (httpOnly cookie, scrypt-hashed) |
| Storage | This browser only (`localStorage`) | Shared database — **MySQL** (PHP path), or JSON/Postgres/SQLite (Node path) |
| Best for | A single operator, offline, quick use | A team sharing the same records |

The same `.html` files power both. At startup the client probes `GET /api/status`:
if the AEGIS server answers, it runs in **secure** mode; otherwise it falls back to
**standalone**.

---

## What's inside

**Portal (`index.html`)** — login + launch point. Live mode indicator, active-threat and
personnel counters, and an **editable OSINT panel** (search, filter, add/edit/delete,
restore curated defaults).

**Apps**

- **Threat Watch (`threat-tracker.html`)** — Dashboard, threat log
  (severity / category / status), duty-of-care personnel roster with check-in status,
  regional risk tiers, and a dark GEOINT map (Leaflet) plotting threats, people, and
  regions. Includes nearby-threat correlation (haversine) and one-click geocoding.
- **Trip Command (`trip-command.html`)** — itinerary, lodging, budget, and trip map.
- **Analytic Workbench (`workbench.html`)** — operational all-source workbench:
  source grading (Admiralty/NATO), ICD 203 estimative language, entity & link analysis
  with **type icons** (person, organization, location, event, asset, vehicle, account),
  GEOINT with **automatic geocoding** (type an address or city and coordinates are filled
  in — on demand or on save), and Analysis of Competing Hypotheses. Starts empty; saves to
  the suite database.
- **Workbench · Training (`intel-workbench.html`)** — the same toolset as a teaching
  sandbox, preloaded with a fictional scenario. Kept deliberately self-contained: it
  stores its practice data locally in the browser, separate from live data.
- **Task List (`todo-list.html`)** — lightweight task & checklist tracker.
- **Security Feed (`feeds.html`)** — live open-source situational awareness, aggregating
  humanitarian, disaster, travel-advisory, health, and cyber sources into one filterable
  stream (secure mode; see below).

All apps except the training workbench start **empty** (no sample data) and persist to the
**suite database** in secure mode (browser storage in standalone mode).

**Settings (`settings.html`)** — organization/display config, classification banner text,
passphrase change, OSINT defaults, theme and language
switches, backup/restore, and deployment/DB info.

## Appearance & language

- **Light / dark theme.** Toggle from **Settings → Appearance & Language** or the ◐ button
  on the portal topbar. The whole console re-skins — including the GEOINT maps (light CARTO
  tiles) and the link-analysis chart. The Task List keeps its paper styling by design, and
  the training sandbox keeps its fixed dark look.
- **Español.** Switch the interface language in **Settings → Appearance & Language**. The
  translation layer is display-only and skips form controls entirely, so **stored data is
  never altered** — severities, statuses, and types remain consistent in the database while
  the UI shows Spanish. Coverage spans navigation, forms, buttons, and labels across all
  apps; long reference prose (Tradecraft Primer, license) remains in English.
- Both are **per-device preferences** stored in the browser, not in the shared database.

---

## Desktop edition (C++)

For offline or single-analyst use, AEGIS also ships as a **native C++ desktop
application** in [`desktop/`](desktop/). One self-contained executable embeds
the entire UI and a C++ backend (embedded HTTP server + JSON-document store),
opening in its own window (or your browser). No web server, PHP, or database
server required; data lives in a per-user file on the machine. It's single-user
and login-free (the OS account is the boundary), while this web edition keeps
full multi-user authentication. Build with CMake (`cmake -S desktop -B build &&
cmake --build build`) or the dependency-free `desktop/build.sh`; CPack produces
Windows/macOS/Linux installers. See [`desktop/README.md`](desktop/README.md).

## Deploy from a website (cPanel / shared hosting) — recommended

Most shared hosting provides **Apache + PHP + MySQL**, so the suite ships with a
PHP backend (`api/`) that talks to your MySQL database. No Node required.

1. In your hosting control panel, confirm the MySQL database and user exist and the
   user is granted access to the database.
2. Edit **`api/config.php`** and set your database name, user, and password (the
   values you provided are already filled in; `host` defaults to `localhost`, which
   is correct on most cPanel hosts).
3. Upload the **entire suite to your document root** (e.g. `public_html/`) so that
   `index.html` and the `api/` folder sit at the site root. (The app calls `/api/...`
   at the root, so don't bury it in a subfolder.)
4. Visit your site. It auto-detects the PHP backend, runs in **secure** mode, and
   walks you through first-run admin setup. Tables are created automatically.

The included `.htaccess` routes `/api/*` to the PHP controller and blocks direct
access to `config.php`, the database, and the Node `server/` folder. **URL rewriting
is optional** — if your host has no `mod_rewrite` (LiteSpeed/Nginx) or `.htaccess` is
ignored, the suite automatically falls back to query-string routing
(`/api/index.php?__route=status`), which works on any PHP host. Serve the site over
**HTTPS** (standard on cPanel via AutoSSL).

> **Rotate your database password.** The password supplied during setup was shared
> in plain text, so treat it as exposed: change it in your control panel after the
> first successful deploy and update `api/config.php` (and `server/.env` if you use
> the Node path). `api/config.php` and `server/.env` are gitignored — never commit them.

> **One backend per database.** Use *either* the PHP backend *or* the Node server
> against a given database, not both — they manage the `users` table differently.
> Your threat / personnel / region / OSINT data is interchangeable between them.

### Test the database connection

Before (or after) deploying, confirm the credentials and reachability with the
included self-tests. Both connect, verify the schema, do a write/read/delete
round-trip on a throwaway key (your real data is untouched), and report.

- **PHP host:** upload the suite, then open `https://your-site/api/db-test.php`
  (or run `php api/db-test.php`). **Delete `api/db-test.php` afterward.**
- **Node host / your laptop:**

  ```bash
  cd server
  npm install
  node db-test.js                         # uses server/.env (host=localhost)
  node db-test.js --host 40.90.253.12      # test a remote DB by IP
  node db-test.js --host 40.90.253.12 --ssl  # if the provider requires TLS
  ```

**Connecting by IP (remote MySQL).** `localhost` only works when the app runs on
the *same* server as MySQL. To reach the database at `40.90.253.12` from anywhere
else, the host must allow it:

1. Authorize the **connecting machine's IP** for the user — on cPanel this is
   **Remote MySQL → Add Access Host** (or a `GRANT ... TO user@'client-ip'`).
2. Ensure **port 3306** is open in the server firewall.
3. Then set the host to `40.90.253.12` (Node: `DB_HOST` in `server/.env`;
   PHP: `AEGIS_DB_HOST` in `api/config.php`).

Exposing MySQL to the public internet widens your attack surface. Where possible,
host the app on the same box and keep `localhost`, or restrict 3306 to known IPs /
use an SSH tunnel or VPN. Managed/cloud MySQL (the `40.90.x` range looks like a
cloud provider) often **requires TLS** and a `user@server` login format — use
`--ssl` with the Node test to check.

---

## Option A — Standalone (no install)

1. Unzip the suite anywhere.
2. Open **`index.html`** in a modern browser (Chrome, Edge, Firefox, Safari).
3. On first launch, create a username + passphrase, then sign in.

Everything is stored in that browser. To move to another machine, use
**Settings → Data & Backup → Download Backup**, then restore the file on the other device.

> **Security note:** in standalone mode the login is a *convenience lock*, not a security
> boundary. Anyone with access to that browser profile can read the stored data. Use the
> secure server build (below) when you need real authentication or shared access.

A couple of features call external services from the browser: the map uses CARTO/Leaflet
tiles and the "Locate" buttons use OpenStreetMap's Nominatim geocoder, so those need
internet access. Everything else works offline.

---

## Option B — Node server (alternative, for Node-capable hosts)

Requirements: **Node.js 18+**.

```bash
cd server
cp .env.example .env        # optional but recommended — set SESSION_SECRET
npm install
npm start
```

Then open **http://localhost:3000** and complete first-run admin setup (creating the first
account locks the setup endpoint).

The server serves the whole suite, enforces login on every protected page and data API, and
stores all records in a database.

### Database — "convenient" by default

- **JSON file (default).** Zero configuration and **zero dependencies** — a single file is
  created at `server/data/aegis.json`. Nothing to install or run, and `npm install` never
  needs a compiler. This is the recommended starting point for one operator or a small team.
- **MySQL / MariaDB (optional).** For the same database used by the PHP path, set in
  `server/.env`:

  ```ini
  DB_DRIVER=mysql
  DB_HOST=localhost
  DB_NAME=your_database_name
  DB_USER=your_database_user
  DB_PASSWORD=your_database_password
  ```

  (`mysql2` is a pure-JS driver — `npm install` needs no compiler.)
- **PostgreSQL (optional).** For larger / networked, multi-user deployments, set in
  `server/.env`:

  ```ini
  DB_DRIVER=postgres
  DATABASE_URL=postgres://user:password@host:5432/aegis
  # PGSSL=true        # if your provider requires SSL
  ```

  Restart the server; tables are created automatically.
- **SQLite (optional).** If you specifically want a single-file SQL database, set
  `DB_DRIVER=sqlite`. This uses `better-sqlite3`, a **native module**: `npm install` will
  fetch a prebuilt binary for common platforms, or fall back to compiling (which needs a
  build toolchain). If it can't load, AEGIS automatically falls back to the JSON driver.

### Server configuration (`server/.env`)

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `3000` | Listen port |
| `SESSION_SECRET` | random | Signs session cookies. **Set this** or logins reset on restart. |
| `COOKIE_SECURE` | `false` | Set `true` when served over HTTPS |
| `DB_DRIVER` | `json` | `json`, `mysql`, `postgres`, or `sqlite` |
| `JSON_FILE` | `server/data/aegis.json` | JSON db file path |
| `SQLITE_FILE` | `server/data/aegis.db` | SQLite file path (sqlite driver) |
| `DB_HOST`/`DB_NAME`/`DB_USER`/`DB_PASSWORD` | — | MySQL/MariaDB connection (mysql driver) |
| `DATABASE_URL` | — | Postgres connection string |
| `PGSSL` | `false` | Postgres SSL |

Generate a secret:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

> **Deploy behind HTTPS** for any real use (a reverse proxy such as Caddy/Nginx, or your
> platform's TLS), and set `COOKIE_SECURE=true`. The bundled server has no built-in TLS.

---

## Moving data between modes

Backups are portable JSON. Export from one mode (**Settings → Download Backup**) and import
in the other (**Restore — merge** or **replace all**). A backup contains your display
config and all threat / personnel / region / OSINT records.

---

## OSINT links

The portal ships with ~18 curated public sources (e.g. US State Dept & UK FCDO advisories,
ReliefWeb, ACLED, GDACS, WHO outbreak news, USGS earthquakes, FlightRadar24, MarineTraffic,
GDELT, Bellingcat). All are freely editable — add your own, re-categorize, or restore the
defaults from the portal or Settings. Links open in a new tab; AEGIS does not proxy or
fetch them.

---

## Security

In **secure (server) mode** the suite applies defense-in-depth appropriate to a small
team deployment:

- **Real authentication** — server-verified login, passwords stored only as scrypt
  (Node) or `password_hash`/bcrypt (PHP) hashes; the session cookie is `HttpOnly`,
  `SameSite=Lax`, and `Secure` over HTTPS.
- **Session hardening** — the session ID is regenerated on login to prevent fixation.
- **Brute-force throttling** — repeated failed logins are rate-limited with progressive
  lockout (per-IP).
- **CSRF mitigation** — state-changing API calls must be `application/json`, which
  same-origin scripts can send but cross-site forms cannot; combined with `SameSite`
  cookies this blocks classic CSRF.
- **Security headers** — `Content-Security-Policy`, `X-Frame-Options: DENY`
  (clickjacking), `X-Content-Type-Options: nosniff`, `Referrer-Policy`,
  `Permissions-Policy`, and HSTS over HTTPS. Directory listing is disabled and the
  credentials/database files are blocked from the web.
- **Gating** — protected pages and every data API require a session; secrets live only
  in `api/config.php` / `server/.env` (both gitignored).

**Security Feed.** The aggregator fetches a **fixed, server-side allowlist** of reputable
sources (ReliefWeb, GDACS, UN humanitarian news, US travel advisories, WHO outbreaks, CISA
cyber). Clients never supply URLs, so there is no SSRF surface; results are cached ~10
minutes server-side. It runs in secure mode only — a browser cannot fetch cross-origin RSS
directly, so the standalone build shows the curated source links to open manually instead.

Always serve over **HTTPS** in production (standard on cPanel via AutoSSL) and keep
`COOKIE_SECURE=true`. In **standalone mode** the login is a convenience lock only — see
below.

---

## License

Released under the **AEGIS Non-Commercial & Ethical-Use License** (see `LICENSE.md`).
In short: free for non-commercial use — personal, family-safety, educational, research,
journalism, humanitarian, and not-for-profit — provided it is **not** used for any illegal
or unethical purpose (no unlawful surveillance, stalking, targeting, discrimination, or
harm). Commercial/business use requires separate written permission. Provided with no
warranty. This is a source-available license, intentionally not OSI open-source because it
restricts field of use and purpose.

---

## Scope & honest limitations

- **Threat / personnel tracking is defensive** — built for duty of care toward your own
  people (where they are, who needs a check-in, what's happening near them), who have
  consented to that protection. It is not a targeting tool, and the license forbids such
  use.
- **Data persistence.** Threat Watch, Trip Command, the operational Analytic Workbench,
  the Task List, the portal, and Settings all save to the shared database in secure mode.
  The **training** workbench (`intel-workbench.html`) is the deliberate exception: it keeps
  its practice scenario in the local browser, separate from live data.
- **Standalone mode login is a convenience lock, not a security boundary** — anyone with
  access to that browser profile can read the local data. Use the secure server for real
  protection.
- The bundled server is a straightforward Express/PHP app suitable for small teams. For
  larger deployments add database backups and your own user-management policy.

---

## Project layout

```
aegis/
├─ index.html              Portal (login + launcher + OSINT)
├─ threat-tracker.html     Threat Watch
├─ trip-command.html       Trip Command
├─ workbench.html          Analytic Workbench (operational, DB-backed)
├─ intel-workbench.html    Workbench · Training (local sandbox, seeded)
├─ todo-list.html          Task List
├─ feeds.html              Security Feed (OSINT aggregator)
├─ settings.html           Configuration + About/License
├─ LICENSE.md              Non-Commercial & Ethical-Use License
├─ .htaccess               Apache: route /api -> PHP, headers, protect secrets
├─ assets/
│  ├─ aegis-common.css     Shared design system
│  ├─ aegis-common.js      Shared runtime (mode detect, auth, store, OSINT, feeds, theme, backup)
│  ├─ aegis-i18n.js        Spanish UI translation layer
│  ├─ logo.png             Global Response Team emblem
│  └─ favicon.png
├─ api/                    PHP + MySQL backend (website path)
│  ├─ index.php            API front controller (auth, throttle, collections)
│  ├─ config.php           DB credentials (gitignored — fill in/rotate)
│  ├─ config.example.php   Template
│  └─ db-test.php          Connectivity self-test (delete after use)
└─ server/                 Node backend (alternative path)
   ├─ server.js
   ├─ db.js                JSON / MySQL / Postgres / SQLite abstraction
   ├─ db-test.js           Connectivity self-test
   ├─ package.json
   ├─ .env / .env.example  Config (.env gitignored)
   └─ data/                (created at runtime — JSON/SQLite db file)
```
