<?php
declare(strict_types=1);
require __DIR__ . '/../vendor/autoload.php';
use Magebean\Engine\{Context, ScanDeadline, ScanDeadlineExceeded};
use Magebean\Engine\Collectors\{BoundedSourceInventory, CollectionSession};
use Magebean\Engine\Checks\LinuxWorkerObservationCheck;
$root = sys_get_temp_dir() . '/magebean-backlog-collection-' . bin2hex(random_bytes(8));
mkdir($root . '/app/code', 0777, true); mkdir($root . '/.magebean'); mkdir($root . '/proc/123', 0777, true);
$count = 0;
$assert = static function(bool $ok, string $message) use (&$count): void { $count++; if (!$ok) throw new RuntimeException($message); };
$session = new CollectionSession(); $collector = new BoundedSourceInventory($session); $ctx = new Context($root, '');
$args = ['paths' => ['app/code'], 'include_ext' => ['php']];
try {
    file_put_contents($root . '/app/code/policy.php', '<?php return 1;');
    $session->begin(); $initial = $collector->collect($ctx, $args);
    $assert($initial['complete'] && $initial['files_read'] === 1, 'First active snapshot collects actual source');
    file_put_contents($root . '/app/code/policy.php', '<?php return 2;');
    $cached = $collector->collect($ctx, $args + ['kind' => 'native_unserialize']);
    $assert($cached['files'][0]['content'] === '<?php return 1;', 'Different policy kinds share same active source scope snapshot');
    $assert($session->stats()['hits'] === 1, 'Scope-sharing produces one collection cache hit');
    $different = $collector->collect($ctx, ['paths' => ['app/code'], 'include_ext' => ['phtml']]);
    $assert(!$different['complete'], 'Different extension scope has distinct inventory');
    $session->end(); $fresh = $collector->collect($ctx, $args);
    $assert($fresh['files'][0]['content'] === '<?php return 2;', 'End clears cached source contents');
    file_put_contents($root . '/app/code/policy.php', '<?php return 3;');
    $assert($collector->collect($ctx, $args)['files'][0]['content'] === '<?php return 3;', 'Standalone calls remain fresh');
    $session->begin(); $assert($collector->collect($ctx, $args)['files'][0]['content'] === '<?php return 3;', 'New scan captures a fresh snapshot'); $session->end();
    $now = 0.0; $clock = static function() use (&$now): float { return $now; };
    $deadline = new ScanDeadline(1.0, $clock); $session->begin($deadline);
    $collector->collect($ctx, $args); $now = 2.0; $expired = false;
    try { $collector->collect($ctx, $args); } catch (ScanDeadlineExceeded) { $expired = true; }
    $assert($expired, 'Expired global deadline prevents cached inventory reuse'); $session->end();
    $checkpointCount = 0; $now = 0.0; $deadline = new ScanDeadline(1.0, $clock);
    $session->begin($deadline, static function() use (&$checkpointCount, &$now): void { if (++$checkpointCount >= 2) $now = 2.0; });
    $expired = false; try { $collector->collect($ctx, $args); } catch (ScanDeadlineExceeded) { $expired = true; }
    $assert($expired && $checkpointCount >= 2, 'Active traversal checks shared global deadline cooperatively'); $session->end();
    $fields = array_fill(0, 20, '0'); $fields[0] = 'S'; $fields[19] = '500';
    file_put_contents($root . '/proc/123/stat', '123 (php-fpm8.4) ' . implode(' ', $fields));
    file_put_contents($root . '/proc/123/cmdline', "php-fpm: pool store\0");
    symlink('/usr/sbin/php-fpm8.4', $root . '/proc/123/exe');
    file_put_contents($root . '/.magebean/php-fpm-workers.json', json_encode(['schema_version' => 1, 'workers' => [['pid' => 123, 'pool' => 'store', 'start_ticks' => '500']]]));
    $worker = new LinuxWorkerObservationCheck($ctx, $root . '/proc');
    file_put_contents($root . '/proc/123/maps', '');
    $assert($worker->xdebugModulesAbsent([])[0] === null, 'Empty worker maps cannot prove absence of Xdebug');
    file_put_contents($root . '/proc/123/maps', " \n\t");
    $assert($worker->xdebugModulesAbsent([])[0] === null, 'Whitespace maps remain collection gap');
    file_put_contents($root . '/proc/123/maps', "0000-1111 r-xp 0 00:00 1 /usr/lib/php/opcache.so\n");
    $assert($worker->xdebugModulesAbsent([])[0] === true, 'Positive complete verified maps support scoped absence result');
    echo "Automation backlog collection: $count assertions passed\n";
} finally {
    $session->end();
    foreach (['stat', 'cmdline', 'exe', 'maps'] as $name) if (file_exists($root . '/proc/123/' . $name) || is_link($root . '/proc/123/' . $name)) unlink($root . '/proc/123/' . $name);
    unlink($root . '/.magebean/php-fpm-workers.json'); unlink($root . '/app/code/policy.php');
    rmdir($root . '/proc/123'); rmdir($root . '/proc'); rmdir($root . '/.magebean'); rmdir($root . '/app/code'); rmdir($root . '/app'); rmdir($root);
}
