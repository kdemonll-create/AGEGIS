/* ============================================================================
   AEGIS — database connectivity self-test (Node)
   ----------------------------------------------------------------------------
   Verifies that the MySQL/MariaDB settings in server/.env actually work:
   connects, confirms server version, creates the AEGIS tables if missing,
   performs a write -> read -> delete round-trip on a throwaway key (it does
   NOT touch your real threat/personnel/region/OSINT data), and reports.

   Run from a machine that can reach the database:

       cd server
       npm install            # if you haven't already (installs mysql2)
       node db-test.js                       # uses server/.env
       node db-test.js --host 40.90.253.12   # override host (remote DB)
       node db-test.js --host 40.90.253.12 --ssl   # if the provider requires TLS

   No credentials are printed. Safe to run repeatedly.
   ============================================================================ */
'use strict';
try { require('dotenv').config(); } catch (e) {}

function arg(name) { var i = process.argv.indexOf('--' + name); return i >= 0 ? (process.argv[i + 1] || true) : null; }
var useSsl = !!arg('ssl');

var cfg = {
  host: arg('host') || process.env.DB_HOST || 'localhost',
  port: parseInt(arg('port') || process.env.DB_PORT || '3306', 10),
  database: arg('db') || process.env.DB_NAME,
  user: arg('user') || process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  connectTimeout: 8000
};
if (useSsl) cfg.ssl = { rejectUnauthorized: false };

var mysql;
try { mysql = require('mysql2/promise'); }
catch (e) { console.error('✗ mysql2 is not installed. Run "npm install" in the server/ folder first.'); process.exit(1); }

function ok(m) { console.log('  \u2713 ' + m); }
function step(m) { console.log('\u2022 ' + m); }

(async function () {
  console.log('AEGIS database self-test');
  console.log('  host : ' + cfg.host + ':' + cfg.port);
  console.log('  db   : ' + (cfg.database || '(unset)'));
  console.log('  user : ' + (cfg.user || '(unset)') + (useSsl ? '   [TLS on]' : ''));
  console.log('------------------------------------------------------------');
  if (!cfg.database || !cfg.user) {
    console.error('✗ DB_NAME and DB_USER must be set (server/.env or --db/--user). Aborting.');
    process.exit(1);
  }

  var conn;
  var t0 = Date.now();
  try {
    step('Connecting…');
    conn = await mysql.createConnection(cfg);
    ok('Connected in ' + (Date.now() - t0) + ' ms');

    var ver = (await conn.query('SELECT VERSION() v'))[0][0].v;
    ok('Server version: ' + ver);

    step('Ensuring AEGIS tables exist…');
    await conn.query('CREATE TABLE IF NOT EXISTS users (username VARCHAR(64) PRIMARY KEY, salt VARCHAR(64) NOT NULL, hash VARCHAR(255) NOT NULL, n INT NOT NULL DEFAULT 16384, created VARCHAR(40) NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');
    await conn.query('CREATE TABLE IF NOT EXISTS config (k VARCHAR(64) PRIMARY KEY, v MEDIUMTEXT NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');
    await conn.query('CREATE TABLE IF NOT EXISTS items (coll VARCHAR(64) NOT NULL, id VARCHAR(64) NOT NULL, data MEDIUMTEXT NOT NULL, updated VARCHAR(40) NOT NULL, PRIMARY KEY (coll, id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');
    ok('Tables present (users, config, items)');

    step('Write \u2192 read \u2192 delete round-trip (throwaway key, no real data touched)…');
    var id = 'probe_' + Date.now().toString(36);
    var payload = JSON.stringify({ id: id, ts: Date.now(), note: 'aegis self-test' });
    await conn.query('INSERT INTO items (coll,id,data,updated) VALUES (?,?,?,?) ON DUPLICATE KEY UPDATE data=VALUES(data)',
      ['_selftest', id, payload, new Date().toISOString()]);
    var read = (await conn.query('SELECT data FROM items WHERE coll=? AND id=?', ['_selftest', id]))[0];
    if (!read.length || JSON.parse(read[0].data).id !== id) throw new Error('read-back mismatch');
    await conn.query('DELETE FROM items WHERE coll=?', ['_selftest']);
    ok('Round-trip succeeded and cleaned up');

    var counts = {};
    for (var tbl of ['users', 'config', 'items']) {
      counts[tbl] = (await conn.query('SELECT COUNT(*) c FROM ' + tbl))[0][0].c;
    }
    ok('Row counts — users:' + counts.users + '  config:' + counts.config + '  items:' + counts.items);

    console.log('------------------------------------------------------------');
    console.log('\u2705 PASS — the database is reachable and fully functional for AEGIS.');
    if (counts.users === 0) console.log('   (No admin yet — open the site to complete first-run setup.)');
    await conn.end();
    process.exit(0);
  } catch (e) {
    console.log('------------------------------------------------------------');
    console.error('\u274C FAIL — ' + e.code + (e.code ? ': ' : '') + e.message);
    var hints = {
      ETIMEDOUT: 'Host/port unreachable. Check the IP, that port 3306 is open in the firewall, and that the DB allows remote connections.',
      ECONNREFUSED: 'Nothing is listening on that host:port, or the firewall is blocking it.',
      ER_ACCESS_DENIED_ERROR: 'Username/password rejected, OR this client IP is not authorized. On cPanel add your IP under "Remote MySQL".',
      ER_HOST_NOT_PRIVILEGED: 'This client host is not allowed to connect. Authorize it under "Remote MySQL" / GRANT host.',
      ER_DBACCESS_DENIED_ERROR: 'User exists but lacks rights on this database. Grant the user access to the database.',
      ENOTFOUND: 'Host name could not be resolved. Check DB_HOST.',
      HANDSHAKE_NO_SSL_SUPPORT: 'Server requires TLS — re-run with --ssl.',
      ER_NOT_SUPPORTED_AUTH_MODE: 'Auth plugin mismatch — the DB user may use caching_sha2; mysql2 supports it, but some managed hosts need TLS (try --ssl).'
    };
    if (hints[e.code]) console.error('   Hint: ' + hints[e.code]);
    else console.error('   Hint: if this is a managed/cloud MySQL, it often requires TLS — try --ssl.');
    try { if (conn) await conn.end(); } catch (x) {}
    process.exit(2);
  }
})();
