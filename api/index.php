<?php
/* ============================================================================
   AEGIS — Field Security Operations Suite
   PHP + MySQL backend (front controller)
   ----------------------------------------------------------------------------
   This is the "website deployment" path for typical shared hosting (cPanel /
   Apache + PHP + MySQL). It implements EXACTLY the same JSON API the suite's
   JavaScript already auto-detects, so the same .html files work unchanged:

     GET  /api/status                     -> { mode, driver, configured, user, config }
     POST /api/setup        {user,pass}   -> first-run admin only (then locks)
     POST /api/login        {user,pass}
     POST /api/logout
     GET  /api/me
     POST /api/change-pass  {oldPass,newPass}
     GET  /api/config
     PUT  /api/config       {...}
     GET    /api/collections/:coll
     POST   /api/collections/:coll        {obj}            (upsert; server assigns id)
     PUT    /api/collections/:coll        {items:[...]}    (replace all)
     DELETE /api/collections/:coll/:id

   Credentials live in config.php (gitignored). Tables are created on first run.
   ============================================================================ */

require __DIR__ . '/config.php';

@ini_set('display_errors', '0');
error_reporting(E_ALL);

/* ---- session (same-origin cookie auth) ---- */
$https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
      || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https');
session_set_cookie_params([
  'lifetime' => 0,
  'path' => '/',
  'httponly' => true,
  'samesite' => 'Lax',
  'secure' => $https,
]);
session_name('aegis_sid');
session_start();

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
header('Permissions-Policy: geolocation=(self), camera=(), microphone=()');
header("Content-Security-Policy: frame-ancestors 'none'; base-uri 'self'");
if ($https) header('Strict-Transport-Security: max-age=31536000; includeSubDomains');

// CSRF mitigation: state-changing calls must be JSON (same-origin XHR only).
if (in_array($_SERVER['REQUEST_METHOD'], ['POST', 'PUT', 'DELETE', 'PATCH'], true)) {
    $ct = $_SERVER['CONTENT_TYPE'] ?? ($_SERVER['HTTP_CONTENT_TYPE'] ?? '');
    if (stripos($ct, 'application/json') === false) {
        http_response_code(415); echo json_encode(['error' => 'Expected application/json.']); exit;
    }
}

function client_ip() { return $_SERVER['REMOTE_ADDR'] ?? 'unknown'; }

// Fetch a URL server-side (cURL preferred, file_get_contents fallback).
function aegis_fetch($url) {
    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true, CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_TIMEOUT => 8, CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_USERAGENT => 'AEGIS-FieldSecurity/1.0 (+duty-of-care)',
        ]);
        $d = curl_exec($ch); $code = curl_getinfo($ch, CURLINFO_HTTP_CODE); curl_close($ch);
        return ($d && $code >= 200 && $code < 400) ? $d : null;
    }
    $ctx = stream_context_create(['http' => ['timeout' => 8, 'header' => 'User-Agent: AEGIS-FieldSecurity/1.0']]);
    $d = @file_get_contents($url, false, $ctx);
    return $d ?: null;
}

const COLLECTIONS = ['threats','personnel','regions','osint','tasks','trips','itinerary','hotels','budget','iw_entries','iw_entities','iw_rels','iw_ach'];
$DEFAULT_CONFIG = [
  'suiteName' => 'AEGIS',
  'orgName' => 'Field Security Operations',
  'classification' => 'Unclassified // Internal Use // Personnel Protection',
  'operatorInitials' => '',
  'homeRegion' => '',
];

/* ---- helpers ---- */
function respond($data, $code = 200) { http_response_code($code); echo json_encode($data); exit; }
function fail($msg, $code) { respond(['error' => $msg], $code); }
function body() {
  $raw = file_get_contents('php://input');
  $j = json_decode($raw, true);
  return is_array($j) ? $j : [];
}
function require_auth() { if (empty($_SESSION['user'])) fail('Authentication required.', 401); }

/* ---- database ---- */
function db() {
  static $pdo = null;
  if ($pdo) return $pdo;
  try {
    $dsn = 'mysql:host=' . AEGIS_DB_HOST . ';port=' . AEGIS_DB_PORT
         . ';dbname=' . AEGIS_DB_NAME . ';charset=utf8mb4';
    $pdo = new PDO($dsn, AEGIS_DB_USER, AEGIS_DB_PASS, [
      PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
      PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
      PDO::ATTR_EMULATE_PREPARES => false,
    ]);
  } catch (Throwable $e) {
    fail('Database connection failed. Check api/config.php credentials and host.', 500);
  }
  $pdo->exec('CREATE TABLE IF NOT EXISTS users (
      username VARCHAR(64) PRIMARY KEY,
      pass VARCHAR(255) NOT NULL,
      created VARCHAR(40) NOT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');
  $pdo->exec('CREATE TABLE IF NOT EXISTS config (
      k VARCHAR(64) PRIMARY KEY,
      v MEDIUMTEXT NOT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');
  $pdo->exec('CREATE TABLE IF NOT EXISTS items (
      coll VARCHAR(64) NOT NULL,
      id VARCHAR(64) NOT NULL,
      data MEDIUMTEXT NOT NULL,
      updated VARCHAR(40) NOT NULL,
      PRIMARY KEY (coll, id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');
  return $pdo;
}
function user_count() { return (int) db()->query('SELECT COUNT(*) c FROM users')->fetch()['c']; }
function get_user($u) {
  $st = db()->prepare('SELECT * FROM users WHERE LOWER(username)=LOWER(?)');
  $st->execute([$u]); $r = $st->fetch(); return $r ?: null;
}
function get_config() {
  $st = db()->prepare('SELECT v FROM config WHERE k=?'); $st->execute(['main']);
  $r = $st->fetch(); return $r ? json_decode($r['v'], true) : null;
}
function set_config($obj) {
  $st = db()->prepare('INSERT INTO config (k,v) VALUES (?,?) ON DUPLICATE KEY UPDATE v=VALUES(v)');
  $st->execute(['main', json_encode($obj)]);
}
function effective_config() {
  global $DEFAULT_CONFIG; $c = get_config();
  return array_merge($DEFAULT_CONFIG, is_array($c) ? $c : []);
}
function list_items($coll) {
  $st = db()->prepare('SELECT data FROM items WHERE coll=?'); $st->execute([$coll]);
  $out = [];
  foreach ($st->fetchAll() as $row) { $out[] = json_decode($row['data'], true); }
  return $out;
}
function upsert_item($coll, $obj) {
  $st = db()->prepare('INSERT INTO items (coll,id,data,updated) VALUES (?,?,?,?)
                       ON DUPLICATE KEY UPDATE data=VALUES(data), updated=VALUES(updated)');
  $st->execute([$coll, $obj['id'], json_encode($obj), gmdate('c')]);
  return $obj;
}
function remove_item($coll, $id) {
  $st = db()->prepare('DELETE FROM items WHERE coll=? AND id=?'); $st->execute([$coll, $id]);
}
function replace_items($coll, $arr) {
  $pdo = db(); $pdo->beginTransaction();
  try {
    $del = $pdo->prepare('DELETE FROM items WHERE coll=?'); $del->execute([$coll]);
    $ins = $pdo->prepare('INSERT INTO items (coll,id,data,updated) VALUES (?,?,?,?)');
    $now = gmdate('c');
    foreach ($arr as $o) { $ins->execute([$coll, $o['id'], json_encode($o), $now]); }
    $pdo->commit();
  } catch (Throwable $e) { $pdo->rollBack(); throw $e; }
}
function valid_coll($c) { return in_array($c, COLLECTIONS, true); }

/* ---- routing ----
   Route is resolved in priority order so this works with OR without rewrite:
     1. ?__route=...        (set by .htaccess rewrite)
     2. /api/index.php/foo  (PATH_INFO style — works with no rewrite at all)
     3. /api/foo            (clean URL via rewrite that preserves REQUEST_URI)   */
$method = $_SERVER['REQUEST_METHOD'];
if (isset($_GET['__route'])) {
  $route = $_GET['__route'];
} elseif (!empty($_SERVER['PATH_INFO'])) {
  $route = $_SERVER['PATH_INFO'];
} else {
  $uri = parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH);
  $pos = strpos($uri, '/api/');
  $route = ($pos === false) ? '' : substr($uri, $pos + 5);
}
$route = preg_replace('#^index\.php/?#', '', $route); // tolerate /api/index.php/<route>
$route = trim($route, '/');
$parts = $route === '' ? [] : explode('/', $route);
$head = $parts[0] ?? '';

try {
  /* ---- public: status ---- */
  if ($head === 'status' && $method === 'GET') {
    $configured = user_count() > 0;
    respond([
      'mode' => 'secure',
      'driver' => 'mysql',
      'configured' => $configured,
      'user' => $_SESSION['user'] ?? null,
      'config' => $configured ? effective_config() : null,
    ]);
  }

  /* ---- public: first-run setup ---- */
  if ($head === 'setup' && $method === 'POST') {
    if (user_count() > 0) fail('Setup already completed.', 403);
    $b = body();
    $u = trim($b['user'] ?? ''); $p = (string) ($b['pass'] ?? '');
    if (strlen($u) < 3) fail('Username must be at least 3 characters.', 400);
    if (strlen($p) < 6) fail('Passphrase must be at least 6 characters.', 400);
    $st = db()->prepare('INSERT INTO users (username,pass,created) VALUES (?,?,?)');
    $st->execute([$u, password_hash($p, PASSWORD_DEFAULT), gmdate('c')]);
    global $DEFAULT_CONFIG; if (!get_config()) set_config($DEFAULT_CONFIG);
    respond(['ok' => true]);
  }

  /* ---- public: login (with throttle) ---- */
  if ($head === 'login' && $method === 'POST') {
    $b = body();
    $u = trim($b['user'] ?? ''); $p = (string) ($b['pass'] ?? '');
    $tkey = 'ip_' . substr(hash('sha256', client_ip()), 0, 24);
    // read throttle record
    $tst = db()->prepare('SELECT data FROM items WHERE coll=? AND id=?');
    $tst->execute(['_throttle', $tkey]);
    $trow = $tst->fetch(); $tr = $trow ? json_decode($trow['data'], true) : ['n' => 0, 'until' => 0];
    if (!empty($tr['until']) && time() < $tr['until']) {
      fail('Too many attempts. Try again in ' . ($tr['until'] - time()) . 's.', 429);
    }
    $row = get_user($u);
    if (!$row || !password_verify($p, $row['pass'])) {
      usleep(400000); // slow brute force
      $tr['n'] = ($tr['n'] ?? 0) + 1;
      if ($tr['n'] >= 5) $tr['until'] = time() + min(900, ($tr['n'] - 4) * 30);
      $ins = db()->prepare('INSERT INTO items (coll,id,data,updated) VALUES (?,?,?,?) ON DUPLICATE KEY UPDATE data=VALUES(data), updated=VALUES(updated)');
      $ins->execute(['_throttle', $tkey, json_encode($tr), gmdate('c')]);
      fail('Invalid credentials.', 401);
    }
    db()->prepare('DELETE FROM items WHERE coll=? AND id=?')->execute(['_throttle', $tkey]);
    session_regenerate_id(true);
    $_SESSION['user'] = $row['username'];
    respond(['ok' => true, 'user' => $row['username']]);
  }

  if ($head === 'logout' && $method === 'POST') {
    $_SESSION = []; session_destroy();
    respond(['ok' => true]);
  }

  if ($head === 'me' && $method === 'GET') {
    require_auth(); respond(['user' => $_SESSION['user']]);
  }

  if ($head === 'change-pass' && $method === 'POST') {
    require_auth();
    $b = body();
    $old = (string) ($b['oldPass'] ?? ''); $new = (string) ($b['newPass'] ?? '');
    if (strlen($new) < 6) fail('New passphrase must be at least 6 characters.', 400);
    $row = get_user($_SESSION['user']);
    if (!$row || !password_verify($old, $row['pass'])) fail('Current passphrase is incorrect.', 403);
    $st = db()->prepare('UPDATE users SET pass=? WHERE LOWER(username)=LOWER(?)');
    $st->execute([password_hash($new, PASSWORD_DEFAULT), $row['username']]);
    respond(['ok' => true]);
  }

  /* ---- config ---- */
  if ($head === 'config') {
    require_auth();
    if ($method === 'GET') respond(effective_config());
    if ($method === 'PUT') {
      global $DEFAULT_CONFIG;
      $next = array_merge($DEFAULT_CONFIG, body());
      set_config($next); respond($next);
    }
    fail('Method not allowed.', 405);
  }

  /* ---- collections ---- */
  if ($head === 'collections') {
    require_auth();
    $coll = $parts[1] ?? '';
    $id = $parts[2] ?? null;
    if (!valid_coll($coll)) fail('Unknown collection.', 400);

    if ($method === 'GET') respond(list_items($coll));

    if ($method === 'POST') {
      $obj = body();
      if (empty($obj['id'])) {
        $obj['id'] = substr($coll, 0, 1) . '_' . base_convert((string) time(), 10, 36)
                   . substr(bin2hex(random_bytes(3)), 0, 4);
      }
      respond(upsert_item($coll, $obj));
    }
    if ($method === 'PUT') {
      $b = body();
      $items = $b['items'] ?? null;
      if (!is_array($items)) fail('Body must be { items: [...] }.', 400);
      replace_items($coll, $items);
      respond(['ok' => true, 'count' => count($items)]);
    }
    if ($method === 'DELETE') {
      if ($id === null || $id === '') fail('Item id required.', 400);
      remove_item($coll, $id);
      respond(['ok' => true]);
    }
    fail('Method not allowed.', 405);
  }

  /* ---- security feeds (curated server-side allowlist) ---- */
  if ($head === 'feeds' && $method === 'GET') {
    require_auth();
    $sources = [
      ['key' => 'reliefweb', 'name' => 'ReliefWeb', 'url' => 'https://reliefweb.int/updates/rss.xml'],
      ['key' => 'gdacs', 'name' => 'GDACS Disasters', 'url' => 'https://www.gdacs.org/xml/rss.xml'],
      ['key' => 'unhum', 'name' => 'UN Humanitarian', 'url' => 'https://news.un.org/feed/subscribe/en/news/topic/humanitarian-aid/feed/rss.xml'],
      ['key' => 'state', 'name' => 'US Travel Advisories', 'url' => 'https://travel.state.gov/_res/rss/TAsTWs.xml'],
      ['key' => 'who', 'name' => 'WHO Outbreaks', 'url' => 'https://www.who.int/feeds/entity/csr/don/en/rss.xml'],
      ['key' => 'cisa', 'name' => 'CISA Cyber', 'url' => 'https://www.cisa.gov/cybersecurity-advisories/all.xml'],
    ];
    $cacheFile = sys_get_temp_dir() . '/aegis_feeds_cache.json';
    if (is_file($cacheFile) && (time() - filemtime($cacheFile) < 600)) {
      $c = @file_get_contents($cacheFile);
      if ($c) { echo $c; exit; }
    }
    $items = [];
    foreach ($sources as $src) {
      $xml = aegis_fetch($src['url']);
      if (!$xml) continue;
      $prev = libxml_use_internal_errors(true);
      $feed = simplexml_load_string($xml);
      libxml_use_internal_errors($prev);
      if (!$feed) continue;
      $entries = [];
      if (isset($feed->channel->item)) $entries = $feed->channel->item;
      elseif (isset($feed->entry)) $entries = $feed->entry;
      elseif (isset($feed->item)) $entries = $feed->item;
      $n = 0;
      foreach ($entries as $it) {
        if ($n++ >= 15) break;
        $title = trim((string) $it->title);
        $link = '';
        if (isset($it->link['href'])) $link = (string) $it->link['href'];
        elseif (isset($it->link)) $link = (string) $it->link;
        $date = (string) ($it->pubDate ?? $it->updated ?? $it->published ?? '');
        $desc = trim(strip_tags((string) ($it->description ?? $it->summary ?? '')));
        if (function_exists('mb_substr') && mb_strlen($desc) > 240) $desc = mb_substr($desc, 0, 240) . '…';
        if ($title) $items[] = ['source' => $src['name'], 'sourceKey' => $src['key'], 'title' => $title, 'link' => $link, 'date' => $date, 'summary' => $desc];
      }
    }
    usort($items, function ($a, $b) { return (strtotime($b['date']) ?: 0) - (strtotime($a['date']) ?: 0); });
    $out = [
      'fetched' => gmdate('c'),
      'sources' => array_map(function ($s) { return ['key' => $s['key'], 'name' => $s['name'], 'url' => $s['url']]; }, $sources),
      'items' => array_slice($items, 0, 120)
    ];
    $json = json_encode($out);
    @file_put_contents($cacheFile, $json);
    echo $json; exit;
  }

  respond([
    'error' => 'Not found.',
    '_debug' => [
      'parsed_route' => $route,
      'method' => $method,
      'REQUEST_URI' => $_SERVER['REQUEST_URI'] ?? null,
      'PATH_INFO' => $_SERVER['PATH_INFO'] ?? null,
      'SCRIPT_NAME' => $_SERVER['SCRIPT_NAME'] ?? null,
      'QUERY_STRING' => $_SERVER['QUERY_STRING'] ?? null
    ]
  ], 404);
} catch (Throwable $e) {
  fail('Server error.', 500);
}
