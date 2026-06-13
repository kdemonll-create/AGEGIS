/* ============================================================================
   AEGIS — Field Security Operations Suite
   Secure backend (Express + session auth + database)
   ----------------------------------------------------------------------------
   Run:   npm install   &&   npm start
   Then open http://localhost:3000  — the suite auto-detects "secure" mode and
   walks you through first-run admin setup.

   What "secure" gives you over the standalone build:
     • Real session authentication (httpOnly cookie), not a browser convenience
       lock. Unauthenticated users cannot reach protected pages or any data API.
     • Server-side scrypt-hashed passwords.
     • A real shared database (SQLite by default, Postgres optional) so multiple
       operators see the same threat / personnel / region / OSINT records.
   ============================================================================ */
'use strict';

try { require('dotenv').config(); } catch (e) { /* dotenv optional */ }

var path = require('path');
var crypto = require('crypto');
var express = require('express');
var session = require('express-session');
var db = require('./db');

var PORT = parseInt(process.env.PORT || '3000', 10);
var STATIC_DIR = path.join(__dirname, '..');           // the suite root (one level up)
var COLLECTIONS = db.COLLECTIONS;

var DEFAULT_CONFIG = {
  suiteName: 'AEGIS',
  orgName: 'Field Security Operations',
  classification: 'Unclassified // Internal Use // Personnel Protection',
  operatorInitials: '',
  homeRegion: ''
};

/* ---------------------------------------------------------------------------
   password hashing — Node built-in scrypt (no native deps)
   stored hash format:  scrypt key (hex);  salt + N kept in their own columns
   --------------------------------------------------------------------------- */
var SCRYPT_N = 16384, SCRYPT_R = 8, SCRYPT_P = 1, KEYLEN = 64;
function scrypt(pass, saltHex, N) {
  return new Promise(function (resolve, reject) {
    crypto.scrypt(String(pass), Buffer.from(saltHex, 'hex'),
      KEYLEN, { N: N || SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P, maxmem: 64 * 1024 * 1024 },
      function (err, dk) { if (err) reject(err); else resolve(dk.toString('hex')); });
  });
}
async function hashPassword(pass) {
  var salt = crypto.randomBytes(16).toString('hex');
  var hash = await scrypt(pass, salt, SCRYPT_N);
  return { salt: salt, hash: hash, n: SCRYPT_N };
}
async function verifyPassword(pass, user) {
  var hash = await scrypt(pass, user.salt, user.n || SCRYPT_N);
  var a = Buffer.from(hash, 'hex'), b = Buffer.from(user.hash, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

/* --------------------------------------------------------------------------- */
var app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);   // honor X-Forwarded-* when hosted behind a reverse proxy / HTTPS terminator

// --- security headers (applied to every response) ---
app.use(function (req, res, next) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'geolocation=(self), camera=(), microphone=()');
  res.setHeader('Content-Security-Policy',
    "default-src 'self'; " +
    "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; " +
    "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com; " +
    "font-src 'self' https://fonts.gstatic.com; " +
    "img-src 'self' data: https:; " +
    "connect-src 'self' https://nominatim.openstreetmap.org; " +
    "frame-ancestors 'none'; base-uri 'self'; form-action 'self'");
  if (process.env.COOKIE_SECURE === 'true') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  next();
});

// --- CSRF mitigation: state-changing API calls must be JSON (browsers can't send
// application/json cross-origin without a CORS preflight, which same-origin cookies fail).
// Combined with SameSite=Lax cookies this blocks classic cross-site form CSRF. ---
app.use('/api', function (req, res, next) {
  if (['POST', 'PUT', 'DELETE', 'PATCH'].indexOf(req.method) >= 0) {
    var ct = (req.headers['content-type'] || '');
    if (ct.indexOf('application/json') < 0) return res.status(415).json({ error: 'Expected application/json.' });
  }
  next();
});

app.use(express.json({ limit: '4mb' }));

var SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
if (!process.env.SESSION_SECRET) {
  console.warn('[aegis] SESSION_SECRET not set — using a random secret (sessions reset on restart).');
  console.warn('[aegis] Set SESSION_SECRET in server/.env for persistent logins.');
}
app.use(session({
  name: 'aegis.sid',
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.COOKIE_SECURE === 'true',   // set true when served over HTTPS
    maxAge: 1000 * 60 * 60 * 12                       // 12h
  }
}));

function requireAuth(req, res, next) {
  if (req.session && req.session.user) return next();
  res.status(401).json({ error: 'Authentication required.' });
}
function validColl(req, res, next) {
  if (COLLECTIONS.indexOf(req.params.coll) < 0) return res.status(400).json({ error: 'Unknown collection.' });
  next();
}
async function effectiveConfig() {
  var cfg = await db.getConfig();
  return Object.assign({}, DEFAULT_CONFIG, cfg || {});
}

/* ============================ API: auth / status ========================== */

// Public — drives client mode auto-detection.
app.get('/api/status', async function (req, res, next) {
  try {
    var count = await db.userCount();
    res.json({
      mode: 'secure',
      driver: db.driver,
      configured: count > 0,
      user: (req.session && req.session.user) || null,
      config: count > 0 ? await effectiveConfig() : null
    });
  } catch (e) { next(e); }
});

// Public — first-run admin creation only (locked once an account exists).
app.post('/api/setup', async function (req, res, next) {
  try {
    if ((await db.userCount()) > 0) return res.status(403).json({ error: 'Setup already completed.' });
    var user = String((req.body && req.body.user) || '').trim();
    var pass = String((req.body && req.body.pass) || '');
    if (user.length < 3) return res.status(400).json({ error: 'Username must be at least 3 characters.' });
    if (pass.length < 6) return res.status(400).json({ error: 'Passphrase must be at least 6 characters.' });
    var h = await hashPassword(pass);
    await db.createUser({ username: user, salt: h.salt, hash: h.hash, n: h.n });
    if (!(await db.getConfig())) await db.setConfig(DEFAULT_CONFIG);
    res.json({ ok: true });
  } catch (e) { next(e); }
});

// Simple in-memory login throttle: progressive lockout per IP after repeated failures.
var loginFails = {};
function throttleKey(req) { return (req.ip || 'unknown'); }
function throttleCheck(req) {
  var k = throttleKey(req), e = loginFails[k];
  if (e && e.until && Date.now() < e.until) return Math.ceil((e.until - Date.now()) / 1000);
  return 0;
}
function throttleFail(req) {
  var k = throttleKey(req), e = loginFails[k] || { n: 0 };
  e.n++; if (e.n >= 5) e.until = Date.now() + Math.min(15 * 60e3, (e.n - 4) * 30e3);
  loginFails[k] = e;
}
function throttleReset(req) { delete loginFails[throttleKey(req)]; }

app.post('/api/login', async function (req, res, next) {
  try {
    var wait = throttleCheck(req);
    if (wait) return res.status(429).json({ error: 'Too many attempts. Try again in ' + wait + 's.' });
    var user = String((req.body && req.body.user) || '').trim();
    var pass = String((req.body && req.body.pass) || '');
    var row = await db.getUser(user);
    if (!row || !(await verifyPassword(pass, row))) { throttleFail(req); return res.status(401).json({ error: 'Invalid credentials.' }); }
    throttleReset(req);
    req.session.regenerate(function (err) {
      if (err) return next(err);
      req.session.user = row.username;
      req.session.save(function (err2) {
        if (err2) return next(err2);
        res.json({ ok: true, user: row.username });
      });
    });
  } catch (e) { next(e); }
});

app.post('/api/logout', function (req, res) {
  if (req.session) req.session.destroy(function () {});
  res.clearCookie('aegis.sid');
  res.json({ ok: true });
});

app.get('/api/me', requireAuth, function (req, res) { res.json({ user: req.session.user }); });

app.post('/api/change-pass', requireAuth, async function (req, res, next) {
  try {
    var oldPass = String((req.body && req.body.oldPass) || '');
    var newPass = String((req.body && req.body.newPass) || '');
    if (newPass.length < 6) return res.status(400).json({ error: 'New passphrase must be at least 6 characters.' });
    var row = await db.getUser(req.session.user);
    if (!row || !(await verifyPassword(oldPass, row))) return res.status(403).json({ error: 'Current passphrase is incorrect.' });
    var h = await hashPassword(newPass);
    await db.updateUserPass(row.username, h.salt, h.hash, h.n);
    res.json({ ok: true });
  } catch (e) { next(e); }
});

/* ============================ API: config ================================= */
app.get('/api/config', requireAuth, async function (req, res, next) {
  try { res.json(await effectiveConfig()); } catch (e) { next(e); }
});
app.put('/api/config', requireAuth, async function (req, res, next) {
  try {
    var next_ = Object.assign({}, DEFAULT_CONFIG, req.body || {});
    await db.setConfig(next_);
    res.json(next_);
  } catch (e) { next(e); }
});

/* ============================ API: collections =========================== */
app.get('/api/collections/:coll', requireAuth, validColl, async function (req, res, next) {
  try { res.json(await db.listItems(req.params.coll)); } catch (e) { next(e); }
});
app.post('/api/collections/:coll', requireAuth, validColl, async function (req, res, next) {
  try {
    var obj = req.body || {};
    if (!obj.id) obj.id = req.params.coll[0] + '_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
    res.json(await db.upsertItem(req.params.coll, obj));
  } catch (e) { next(e); }
});
app.put('/api/collections/:coll', requireAuth, validColl, async function (req, res, next) {
  try {
    var items = (req.body && req.body.items) || [];
    if (!Array.isArray(items)) return res.status(400).json({ error: 'Body must be { items: [...] }.' });
    await db.replaceItems(req.params.coll, items);
    res.json({ ok: true, count: items.length });
  } catch (e) { next(e); }
});
app.delete('/api/collections/:coll/:id', requireAuth, validColl, async function (req, res, next) {
  try { await db.removeItem(req.params.coll, req.params.id); res.json({ ok: true }); } catch (e) { next(e); }
});

/* ============================ API: security feeds ======================== */
// Curated, server-side allowlist (prevents SSRF — clients can't supply URLs).
var FEED_SOURCES = [
  { key: 'reliefweb', name: 'ReliefWeb', url: 'https://reliefweb.int/updates/rss.xml' },
  { key: 'gdacs', name: 'GDACS Disasters', url: 'https://www.gdacs.org/xml/rss.xml' },
  { key: 'unhum', name: 'UN Humanitarian', url: 'https://news.un.org/feed/subscribe/en/news/topic/humanitarian-aid/feed/rss.xml' },
  { key: 'state', name: 'US Travel Advisories', url: 'https://travel.state.gov/_res/rss/TAsTWs.xml' },
  { key: 'who', name: 'WHO Outbreaks', url: 'https://www.who.int/feeds/entity/csr/don/en/rss.xml' },
  { key: 'cisa', name: 'CISA Cyber', url: 'https://www.cisa.gov/cybersecurity-advisories/all.xml' }
];
var feedsCache = { at: 0, data: null };
function feedStrip(s) {
  return (s || '')
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'").replace(/&apos;/g, "'").replace(/&amp;/g, '&')
    .replace(/\s+/g, ' ').trim();
}
function feedTag(block, name) {
  var m = block.match(new RegExp('<' + name + '[^>]*>([\\s\\S]*?)<\\/' + name + '>', 'i'));
  return m ? m[1] : '';
}
function parseFeed(xml, src) {
  var isAtom = /<feed[\s>]/i.test(xml) && !/<rss[\s>]/i.test(xml);
  var blocks = xml.split(isAtom ? /<entry[\s>]/i : /<item[\s>]/i).slice(1);
  var out = [];
  blocks.forEach(function (b) {
    var title = feedStrip(feedTag(b, 'title'));
    var link = '';
    if (isAtom) { var lm = b.match(/<link[^>]*href="([^"]+)"/i); link = lm ? lm[1] : ''; }
    else link = feedStrip(feedTag(b, 'link'));
    var date = feedStrip(feedTag(b, isAtom ? 'updated' : 'pubDate'));
    var desc = feedStrip(feedTag(b, isAtom ? 'summary' : 'description')).slice(0, 240);
    if (title) out.push({ source: src.name, sourceKey: src.key, title: title, link: link, date: date, summary: desc });
  });
  return out.slice(0, 15);
}
async function fetchFeed(src) {
  try {
    var ctrl = new AbortController(); var t = setTimeout(function () { ctrl.abort(); }, 7000);
    var r = await fetch(src.url, { signal: ctrl.signal, headers: {
      'User-Agent': 'AEGIS-FieldSecurity/1.0 (+duty-of-care)',
      'Accept': 'application/rss+xml, application/atom+xml, application/xml, text/xml, */*'
    } });
    clearTimeout(t);
    if (!r.ok) return [];
    return parseFeed(await r.text(), src);
  } catch (e) { return []; }
}
app.get('/api/feeds', requireAuth, async function (req, res, next) {
  try {
    if (feedsCache.data && Date.now() - feedsCache.at < 10 * 60e3) return res.json(feedsCache.data);
    var all = [];
    for (var i = 0; i < FEED_SOURCES.length; i++) all = all.concat(await fetchFeed(FEED_SOURCES[i]));
    all.sort(function (a, b) { return (Date.parse(b.date) || 0) - (Date.parse(a.date) || 0); });
    var out = {
      fetched: new Date().toISOString(),
      sources: FEED_SOURCES.map(function (s) { return { key: s.key, name: s.name, url: s.url }; }),
      items: all.slice(0, 120)
    };
    feedsCache = { at: Date.now(), data: out };
    res.json(out);
  } catch (e) { next(e); }
});

// Any other /api/* → JSON 404 (so the client never gets HTML where it expects JSON)
app.use('/api', function (req, res) { res.status(404).json({ error: 'Not found.' }); });

/* ============================ static (gated) ============================= */
// Never serve the server folder (source, .env, db files).
app.use(function (req, res, next) {
  if (req.path === '/server' || req.path.indexOf('/server/') === 0) return res.status(404).end();
  next();
});

// Protected HTML pages require a session; bounce to the portal (which shows login).
var PROTECTED_PAGES = ['/threat-tracker.html', '/settings.html', '/workbench.html', '/feeds.html',
  '/todo-list.html', '/trip-command.html', '/intel-workbench.html'];
app.use(function (req, res, next) {
  if (req.method === 'GET' && PROTECTED_PAGES.indexOf(req.path) >= 0 &&
      !(req.session && req.session.user)) {
    return res.redirect('/');
  }
  next();
});

app.use(express.static(STATIC_DIR, { extensions: ['html'], index: 'index.html' }));
app.get('/', function (req, res) { res.sendFile(path.join(STATIC_DIR, 'index.html')); });

/* ============================ errors ===================================== */
app.use(function (err, req, res, next) {
  console.error('[aegis]', err && err.stack ? err.stack : err);
  if (res.headersSent) return next(err);
  res.status(500).json({ error: 'Server error.' });
});

/* ============================ boot ======================================= */
db.init().then(function () {
  app.listen(PORT, function () {
    console.log('============================================================');
    console.log('  AEGIS secure server running');
    console.log('  URL      : http://localhost:' + PORT);
    console.log('  DB driver: ' + db.driver + (db.location ? '  (' + db.location + ')' : ''));
    console.log('  Open the URL above to complete first-run setup.');
    console.log('============================================================');
  });
}).catch(function (e) {
  console.error('[aegis] Failed to initialize database:', e.message);
  console.error('[aegis] Check your DB settings in server/.env:');
  console.error('[aegis]   • mysql    → DB_HOST / DB_NAME / DB_USER / DB_PASSWORD');
  console.error('[aegis]   • postgres → DATABASE_URL');
  console.error('[aegis] (On shared hosting the DB host is usually "localhost".)');
  process.exit(1);
});
