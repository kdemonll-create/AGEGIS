/* ============================================================================
   AEGIS secure backend — database abstraction
   ----------------------------------------------------------------------------
   ONE interface, THREE drivers, chosen by env DB_DRIVER:

     • json     (DEFAULT) — a single self-contained JSON file with atomic writes.
                            ZERO external dependencies, zero native build, zero
                            services to run. Installs and runs anywhere Node does.
                            Ideal for a single operator or a small team.
     • postgres           — node-postgres (pg). Point DATABASE_URL at any Postgres
                            instance for a networked, multi-user database.
     • sqlite             — better-sqlite3. A classic single-file SQL database.
                            Opt-in: it is a NATIVE module, so it must be able to
                            install a prebuilt binary or compile on your machine.

   Every method is async so server.js treats all drivers identically.

   Logical model (driver-agnostic):
     users  : { username, salt, hash, n, created }
     config : a single object
     items  : per-collection arrays of { id, ... }   (threats/personnel/regions/osint)
   ============================================================================ */
'use strict';

var DRIVER = (process.env.DB_DRIVER || 'json').toLowerCase();
var COLLECTIONS = ['threats','personnel','regions','osint','tasks','trips','itinerary','hotels','budget','iw_entries','iw_entities','iw_rels','iw_ach'];

/* ---------------------------------------------------------------------------
   JSON file implementation (default) — no dependencies
   --------------------------------------------------------------------------- */
function makeJson() {
  var fs = require('fs');
  var path = require('path');
  var file = process.env.JSON_FILE || path.join(__dirname, 'data', 'aegis.json');
  var dir = path.dirname(file);
  var state = { users: [], config: null, items: {} };
  COLLECTIONS.forEach(function (c) { state.items[c] = []; });
  var writing = Promise.resolve();

  function load() {
    try {
      if (fs.existsSync(file)) {
        var raw = JSON.parse(fs.readFileSync(file, 'utf8'));
        state.users = raw.users || [];
        state.config = raw.config || null;
        state.items = raw.items || state.items;
        COLLECTIONS.forEach(function (c) { if (!state.items[c]) state.items[c] = []; });
      }
    } catch (e) { console.error('[aegis] could not read JSON db, starting fresh:', e.message); }
  }
  // Serialize writes; write to a temp file then rename (atomic on same fs).
  function persist() {
    writing = writing.then(function () {
      return new Promise(function (resolve, reject) {
        var tmp = file + '.tmp';
        fs.writeFile(tmp, JSON.stringify(state, null, 2), function (err) {
          if (err) return reject(err);
          fs.rename(tmp, file, function (e2) { e2 ? reject(e2) : resolve(); });
        });
      });
    }).catch(function (e) { console.error('[aegis] db write failed:', e.message); });
    return writing;
  }

  function init() { fs.mkdirSync(dir, { recursive: true }); load(); return Promise.resolve(); }

  return {
    driver: 'json',
    location: file,
    init: init,
    userCount: function () { return Promise.resolve(state.users.length); },
    getUser: function (username) {
      var u = state.users.find(function (x) { return x.username.toLowerCase() === String(username).toLowerCase(); });
      return Promise.resolve(u || null);
    },
    createUser: function (u) {
      state.users.push({ username: u.username, salt: u.salt, hash: u.hash, n: u.n, created: new Date().toISOString() });
      return persist();
    },
    updateUserPass: function (username, salt, hash, n) {
      var u = state.users.find(function (x) { return x.username.toLowerCase() === String(username).toLowerCase(); });
      if (u) { u.salt = salt; u.hash = hash; u.n = n; }
      return persist();
    },
    getConfig: function () { return Promise.resolve(state.config); },
    setConfig: function (obj) { state.config = obj; return persist(); },
    listItems: function (coll) { return Promise.resolve((state.items[coll] || []).slice()); },
    upsertItem: function (coll, obj) {
      var arr = state.items[coll] || (state.items[coll] = []);
      var i = arr.findIndex(function (x) { return x.id === obj.id; });
      if (i >= 0) arr[i] = obj; else arr.push(obj);
      return persist().then(function () { return obj; });
    },
    removeItem: function (coll, id) {
      state.items[coll] = (state.items[coll] || []).filter(function (x) { return x.id !== id; });
      return persist();
    },
    replaceItems: function (coll, arr) { state.items[coll] = (arr || []).slice(); return persist(); },
    close: function () { return writing; }
  };
}

/* ---------------------------------------------------------------------------
   SQLite implementation (opt-in) — better-sqlite3 (native module)
   --------------------------------------------------------------------------- */
function makeSqlite() {
  var Database = require('better-sqlite3');
  var path = require('path');
  var fs = require('fs');
  var file = process.env.SQLITE_FILE || path.join(__dirname, 'data', 'aegis.db');
  fs.mkdirSync(path.dirname(file), { recursive: true });
  var db = new Database(file);
  db.pragma('journal_mode = WAL');

  function init() {
    db.exec(
      'CREATE TABLE IF NOT EXISTS users (' +
      '  username TEXT PRIMARY KEY, salt TEXT NOT NULL, hash TEXT NOT NULL,' +
      '  n INTEGER NOT NULL DEFAULT 16384, created TEXT NOT NULL);' +
      'CREATE TABLE IF NOT EXISTS config (k TEXT PRIMARY KEY, v TEXT NOT NULL);' +
      'CREATE TABLE IF NOT EXISTS items (' +
      '  coll TEXT NOT NULL, id TEXT NOT NULL, data TEXT NOT NULL,' +
      '  updated TEXT NOT NULL, PRIMARY KEY (coll, id));'
    );
    return Promise.resolve();
  }
  return {
    driver: 'sqlite',
    location: file,
    init: init,
    userCount: function () { return Promise.resolve(db.prepare('SELECT COUNT(*) c FROM users').get().c); },
    getUser: function (username) {
      return Promise.resolve(db.prepare('SELECT * FROM users WHERE lower(username)=lower(?)').get(username) || null);
    },
    createUser: function (u) {
      db.prepare('INSERT INTO users (username,salt,hash,n,created) VALUES (?,?,?,?,?)')
        .run(u.username, u.salt, u.hash, u.n, new Date().toISOString());
      return Promise.resolve();
    },
    updateUserPass: function (username, salt, hash, n) {
      db.prepare('UPDATE users SET salt=?, hash=?, n=? WHERE lower(username)=lower(?)').run(salt, hash, n, username);
      return Promise.resolve();
    },
    getConfig: function () {
      var row = db.prepare('SELECT v FROM config WHERE k=?').get('main');
      return Promise.resolve(row ? JSON.parse(row.v) : null);
    },
    setConfig: function (obj) {
      db.prepare('INSERT INTO config (k,v) VALUES (?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v')
        .run('main', JSON.stringify(obj));
      return Promise.resolve();
    },
    listItems: function (coll) {
      return Promise.resolve(db.prepare('SELECT data FROM items WHERE coll=?').all(coll)
        .map(function (r) { return JSON.parse(r.data); }));
    },
    upsertItem: function (coll, obj) {
      db.prepare('INSERT INTO items (coll,id,data,updated) VALUES (?,?,?,?) ' +
        'ON CONFLICT(coll,id) DO UPDATE SET data=excluded.data, updated=excluded.updated')
        .run(coll, obj.id, JSON.stringify(obj), new Date().toISOString());
      return Promise.resolve(obj);
    },
    removeItem: function (coll, id) {
      db.prepare('DELETE FROM items WHERE coll=? AND id=?').run(coll, id); return Promise.resolve();
    },
    replaceItems: function (coll, arr) {
      var tx = db.transaction(function (list) {
        db.prepare('DELETE FROM items WHERE coll=?').run(coll);
        var ins = db.prepare('INSERT INTO items (coll,id,data,updated) VALUES (?,?,?,?)');
        var now = new Date().toISOString();
        list.forEach(function (o) { ins.run(coll, o.id, JSON.stringify(o), now); });
      });
      tx(arr || []); return Promise.resolve();
    },
    close: function () { db.close(); return Promise.resolve(); }
  };
}

/* ---------------------------------------------------------------------------
   Postgres implementation (opt-in) — pg
   --------------------------------------------------------------------------- */
function makePostgres() {
  var Pool = require('pg').Pool;
  var pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.PGSSL === 'true' ? { rejectUnauthorized: false } : undefined
  });
  async function init() {
    await pool.query('CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, salt TEXT NOT NULL, hash TEXT NOT NULL, n INTEGER NOT NULL DEFAULT 16384, created TEXT NOT NULL)');
    await pool.query('CREATE TABLE IF NOT EXISTS config (k TEXT PRIMARY KEY, v TEXT NOT NULL)');
    await pool.query('CREATE TABLE IF NOT EXISTS items (coll TEXT NOT NULL, id TEXT NOT NULL, data TEXT NOT NULL, updated TEXT NOT NULL, PRIMARY KEY (coll, id))');
  }
  return {
    driver: 'postgres',
    location: (process.env.DATABASE_URL || '').replace(/:[^:@/]+@/, ':****@'),
    init: init,
    userCount: async function () { return (await pool.query('SELECT COUNT(*)::int c FROM users')).rows[0].c; },
    getUser: async function (username) {
      return (await pool.query('SELECT * FROM users WHERE lower(username)=lower($1)', [username])).rows[0] || null;
    },
    createUser: async function (u) {
      await pool.query('INSERT INTO users (username,salt,hash,n,created) VALUES ($1,$2,$3,$4,$5)',
        [u.username, u.salt, u.hash, u.n, new Date().toISOString()]);
    },
    updateUserPass: async function (username, salt, hash, n) {
      await pool.query('UPDATE users SET salt=$1, hash=$2, n=$3 WHERE lower(username)=lower($4)', [salt, hash, n, username]);
    },
    getConfig: async function () {
      var r = await pool.query('SELECT v FROM config WHERE k=$1', ['main']);
      return r.rows[0] ? JSON.parse(r.rows[0].v) : null;
    },
    setConfig: async function (obj) {
      await pool.query('INSERT INTO config (k,v) VALUES ($1,$2) ON CONFLICT (k) DO UPDATE SET v=EXCLUDED.v', ['main', JSON.stringify(obj)]);
    },
    listItems: async function (coll) {
      return (await pool.query('SELECT data FROM items WHERE coll=$1', [coll])).rows.map(function (x) { return JSON.parse(x.data); });
    },
    upsertItem: async function (coll, obj) {
      await pool.query('INSERT INTO items (coll,id,data,updated) VALUES ($1,$2,$3,$4) ON CONFLICT (coll,id) DO UPDATE SET data=EXCLUDED.data, updated=EXCLUDED.updated',
        [coll, obj.id, JSON.stringify(obj), new Date().toISOString()]);
      return obj;
    },
    removeItem: async function (coll, id) { await pool.query('DELETE FROM items WHERE coll=$1 AND id=$2', [coll, id]); },
    replaceItems: async function (coll, arr) {
      var client = await pool.connect();
      try {
        await client.query('BEGIN');
        await client.query('DELETE FROM items WHERE coll=$1', [coll]);
        var now = new Date().toISOString();
        for (var i = 0; i < (arr || []).length; i++) {
          await client.query('INSERT INTO items (coll,id,data,updated) VALUES ($1,$2,$3,$4)',
            [coll, arr[i].id, JSON.stringify(arr[i]), now]);
        }
        await client.query('COMMIT');
      } catch (e) { await client.query('ROLLBACK'); throw e; } finally { client.release(); }
    },
    close: async function () { await pool.end(); }
  };
}

/* ---------------------------------------------------------------------------
   MySQL / MariaDB implementation (opt-in) — mysql2 (pure JS, no native build)
   The right choice for typical shared / cPanel hosting that provides MySQL.
   --------------------------------------------------------------------------- */
function makeMysql() {
  var mysql = require('mysql2/promise');
  var pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT || '3306', 10),
    database: process.env.DB_NAME,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    waitForConnections: true,
    connectionLimit: 5,
    charset: 'utf8mb4'
  });
  async function q(sql, params) { var r = await pool.query(sql, params || []); return r[0]; }
  async function init() {
    await q('CREATE TABLE IF NOT EXISTS users (username VARCHAR(64) PRIMARY KEY, salt VARCHAR(64) NOT NULL, hash VARCHAR(255) NOT NULL, n INT NOT NULL DEFAULT 16384, created VARCHAR(40) NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');
    await q('CREATE TABLE IF NOT EXISTS config (k VARCHAR(64) PRIMARY KEY, v MEDIUMTEXT NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');
    await q('CREATE TABLE IF NOT EXISTS items (coll VARCHAR(64) NOT NULL, id VARCHAR(64) NOT NULL, data MEDIUMTEXT NOT NULL, updated VARCHAR(40) NOT NULL, PRIMARY KEY (coll, id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');
  }
  return {
    driver: 'mysql',
    location: (process.env.DB_USER || '') + '@' + (process.env.DB_HOST || 'localhost') + '/' + (process.env.DB_NAME || ''),
    init: init,
    userCount: async function () { return (await q('SELECT COUNT(*) c FROM users'))[0].c; },
    getUser: async function (username) {
      var rows = await q('SELECT * FROM users WHERE LOWER(username)=LOWER(?)', [username]);
      return rows[0] || null;
    },
    createUser: async function (u) {
      await q('INSERT INTO users (username,salt,hash,n,created) VALUES (?,?,?,?,?)',
        [u.username, u.salt, u.hash, u.n, new Date().toISOString()]);
    },
    updateUserPass: async function (username, salt, hash, n) {
      await q('UPDATE users SET salt=?, hash=?, n=? WHERE LOWER(username)=LOWER(?)', [salt, hash, n, username]);
    },
    getConfig: async function () {
      var rows = await q('SELECT v FROM config WHERE k=?', ['main']);
      return rows[0] ? JSON.parse(rows[0].v) : null;
    },
    setConfig: async function (obj) {
      await q('INSERT INTO config (k,v) VALUES (?,?) ON DUPLICATE KEY UPDATE v=VALUES(v)', ['main', JSON.stringify(obj)]);
    },
    listItems: async function (coll) {
      var rows = await q('SELECT data FROM items WHERE coll=?', [coll]);
      return rows.map(function (r) { return JSON.parse(r.data); });
    },
    upsertItem: async function (coll, obj) {
      await q('INSERT INTO items (coll,id,data,updated) VALUES (?,?,?,?) ON DUPLICATE KEY UPDATE data=VALUES(data), updated=VALUES(updated)',
        [coll, obj.id, JSON.stringify(obj), new Date().toISOString()]);
      return obj;
    },
    removeItem: async function (coll, id) { await q('DELETE FROM items WHERE coll=? AND id=?', [coll, id]); },
    replaceItems: async function (coll, arr) {
      var conn = await pool.getConnection();
      try {
        await conn.beginTransaction();
        await conn.query('DELETE FROM items WHERE coll=?', [coll]);
        var now = new Date().toISOString();
        for (var i = 0; i < (arr || []).length; i++) {
          await conn.query('INSERT INTO items (coll,id,data,updated) VALUES (?,?,?,?)',
            [coll, arr[i].id, JSON.stringify(arr[i]), now]);
        }
        await conn.commit();
      } catch (e) { await conn.rollback(); throw e; } finally { conn.release(); }
    },
    close: async function () { await pool.end(); }
  };
}

var impl;
try {
  if (DRIVER === 'mysql' || DRIVER === 'mariadb') impl = makeMysql();
  else if (DRIVER === 'postgres' || DRIVER === 'pg') impl = makePostgres();
  else if (DRIVER === 'sqlite') impl = makeSqlite();
  else impl = makeJson();
} catch (e) {
  console.error('[aegis] DB driver "' + DRIVER + '" failed to load: ' + e.message);
  console.error('[aegis] Falling back to the built-in JSON driver.');
  impl = makeJson();
}

impl.COLLECTIONS = COLLECTIONS;
module.exports = impl;
