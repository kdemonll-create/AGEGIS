<?php
/* ============================================================================
   AEGIS — database connectivity self-test (PHP)
   ----------------------------------------------------------------------------
   Confirms that api/config.php credentials work against your MySQL database.
   Connects, prints server version, ensures the AEGIS tables, performs a
   write -> read -> delete round-trip on a throwaway key (does NOT touch your
   real data), and reports.

   Use it ONE of two ways:
     • Browser:   https://your-site/api/db-test.php
     • CLI:       php api/db-test.php

   SECURITY: delete this file after you've confirmed the connection works.
   It prints no credentials, but it does reveal that the DB is reachable.
   ============================================================================ */

header('Content-Type: text/plain; charset=utf-8');
require __DIR__ . '/config.php';

function line($s) { echo $s . "\n"; }

line('AEGIS database self-test (PHP)');
line('  host : ' . AEGIS_DB_HOST . ':' . AEGIS_DB_PORT);
line('  db   : ' . AEGIS_DB_NAME);
line('  user : ' . AEGIS_DB_USER);
line('------------------------------------------------------------');

try {
    $dsn = 'mysql:host=' . AEGIS_DB_HOST . ';port=' . AEGIS_DB_PORT
         . ';dbname=' . AEGIS_DB_NAME . ';charset=utf8mb4';
    $t0 = microtime(true);
    $pdo = new PDO($dsn, AEGIS_DB_USER, AEGIS_DB_PASS, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_TIMEOUT => 8,
    ]);
    line(sprintf('  \xE2\x9C\x93 Connected in %d ms', (int) ((microtime(true) - $t0) * 1000)));

    $ver = $pdo->query('SELECT VERSION() v')->fetch(PDO::FETCH_ASSOC)['v'];
    line('  \xE2\x9C\x93 Server version: ' . $ver);

    line('• Ensuring AEGIS tables exist…');
    $pdo->exec('CREATE TABLE IF NOT EXISTS users (username VARCHAR(64) PRIMARY KEY, pass VARCHAR(255) NOT NULL, created VARCHAR(40) NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');
    $pdo->exec('CREATE TABLE IF NOT EXISTS config (k VARCHAR(64) PRIMARY KEY, v MEDIUMTEXT NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');
    $pdo->exec('CREATE TABLE IF NOT EXISTS items (coll VARCHAR(64) NOT NULL, id VARCHAR(64) NOT NULL, data MEDIUMTEXT NOT NULL, updated VARCHAR(40) NOT NULL, PRIMARY KEY (coll, id)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');
    line('  \xE2\x9C\x93 Tables present (users, config, items)');

    line('• Write -> read -> delete round-trip (throwaway key)…');
    $id = 'probe_' . base_convert((string) time(), 10, 36);
    $st = $pdo->prepare('INSERT INTO items (coll,id,data,updated) VALUES (?,?,?,?) ON DUPLICATE KEY UPDATE data=VALUES(data)');
    $st->execute(['_selftest', $id, json_encode(['id' => $id, 'note' => 'aegis self-test']), gmdate('c')]);
    $rd = $pdo->prepare('SELECT data FROM items WHERE coll=? AND id=?');
    $rd->execute(['_selftest', $id]);
    $row = $rd->fetch(PDO::FETCH_ASSOC);
    if (!$row || json_decode($row['data'], true)['id'] !== $id) throw new Exception('read-back mismatch');
    $pdo->prepare('DELETE FROM items WHERE coll=?')->execute(['_selftest']);
    line('  \xE2\x9C\x93 Round-trip succeeded and cleaned up');

    $counts = [];
    foreach (['users', 'config', 'items'] as $t) {
        $counts[$t] = (int) $pdo->query("SELECT COUNT(*) c FROM `$t`")->fetch(PDO::FETCH_ASSOC)['c'];
    }
    line('  \xE2\x9C\x93 Row counts — users:' . $counts['users'] . '  config:' . $counts['config'] . '  items:' . $counts['items']);

    line('------------------------------------------------------------');
    line("\xE2\x9C\x85 PASS — the database is reachable and fully functional for AEGIS.");
    if ($counts['users'] === 0) line('   (No admin yet — open the site to complete first-run setup.)');
    line('');
    line('Reminder: delete api/db-test.php now that the test has passed.');
} catch (Throwable $e) {
    line('------------------------------------------------------------');
    line("\xE2\x9D\x8C FAIL — " . $e->getMessage());
    line('   Common causes:');
    line('   • "Access denied" — wrong user/password, OR this client IP is not');
    line('     authorized. On cPanel add the connecting IP under "Remote MySQL".');
    line('   • "not allowed to connect" — host not GRANTed for this user.');
    line('   • timeout/refused — wrong host/IP, port 3306 closed, or remote');
    line('     access disabled (the DB only accepts localhost connections).');
    line('   • managed/cloud MySQL may require TLS and a user@server login format.');
}
