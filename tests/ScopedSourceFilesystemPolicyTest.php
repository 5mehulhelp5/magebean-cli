<?php
declare(strict_types=1);
require __DIR__ . '/../vendor/autoload.php';
use Magebean\Engine\Checks\FilesystemCheck;
use Magebean\Engine\Checks\Families\CodeQueryChecks;
use Magebean\Engine\Context;
$root = sys_get_temp_dir() . '/magebean-scoped-policy-' . bin2hex(random_bytes(8));
mkdir($root); mkdir($root . '/app'); mkdir($root . '/pub');
$count = 0;
$assert = static function (bool $condition, string $message) use (&$count): void { $count++; if (!$condition) throw new RuntimeException($message); };
$grep = static fn() => new CodeQueryChecks(new Context($root, ''));
$fs = new FilesystemCheck(new Context($root, ''));
$args = ['paths' => ['app'], 'strict_scope' => true];
try {
    file_put_contents($root . '/app/safe.php', '<?php /* $_GET */ $x = \'$_POST\'; return $x;');
    $assert($grep()->grep($args)[0] === true, 'Comments and literal strings are not direct superglobals');
    file_put_contents($root . '/app/bad.php', '<?php return $_GET["q"];');
    $assert($grep()->grep($args)[0] === false, 'Actual direct reference fails with file and line');
    unlink($root . '/app/bad.php');
    file_put_contents($root . '/app/invalid.php', '<?php return [;');
    $assert($grep()->grep($args)[0] === null, 'Malformed PHP cannot pass bounded token scan');
    unlink($root . '/app/invalid.php');
    $assert($grep()->grep(['strict_scope' => true, 'paths' => ['absent']])[0] === null, 'Missing source is collection gap');
    chmod($root . '/app', 0555); chmod($root . '/app/safe.php', 0444);
    $assert($fs->codeDirsReadonly(['strict_scope' => true, 'dirs' => ['app']])[0] === true, 'Read-only subtree passes');
    chmod($root . '/app/safe.php', 0644);
    $assert($fs->codeDirsReadonly(['strict_scope' => true, 'dirs' => ['app']])[0] === false, 'Owner write bit violates precise mode policy');
    $assert($fs->codeDirsReadonly(['strict_scope' => true, 'dirs' => ['absent']])[0] === null, 'Missing code path cannot pass');
    $assert($fs->logsReportsNotInWebroot(['strict_scope' => true])[0] === true, 'No physical forbidden paths passes');
    mkdir($root . '/pub/var'); mkdir($root . '/pub/var/log');
    $assert($fs->logsReportsNotInWebroot(['strict_scope' => true])[0] === false, 'Physical log directory fails');
    rmdir($root . '/pub/var/log'); rmdir($root . '/pub/var');
    mkdir($root . '/var'); mkdir($root . '/var/log'); symlink($root . '/var/log', $root . '/pub/exposed');
    $assert($fs->logsReportsNotInWebroot(['strict_scope' => true])[0] === false, 'Renamed log symlink fails');
    unlink($root . '/pub/exposed');
    $assert($fs->logsReportsNotInWebroot(['strict_scope' => true, 'webroot' => 'absent'])[0] === null, 'Missing webroot cannot pass');
    if (function_exists('posix_geteuid') && posix_geteuid() !== 0) {
        chmod($root . '/app/safe.php', 0000);
        $assert($grep()->grep($args)[0] === null, 'Unreadable PHP cannot pass token scan');
        chmod($root . '/app/safe.php', 0644);
        mkdir($root . '/generated'); mkdir($root . '/generated/code'); mkdir($root . '/generated/metadata');
        file_put_contents($root . '/generated/code/a.php', '<?php return [];');
        file_put_contents($root . '/generated/metadata/a.php', '<?php return [];');
        chmod($root . '/generated/code/a.php', 0000);
        $assert($fs->diCompiled([])[0] === null, 'Unreadable generated PHP cannot satisfy readable artifact policy');
        chmod($root . '/generated/code/a.php', 0644); unlink($root . '/generated/code/a.php'); unlink($root . '/generated/metadata/a.php');
        rmdir($root . '/generated/code'); rmdir($root . '/generated/metadata'); rmdir($root . '/generated');
        file_put_contents($root . '/composer.json', '{}'); file_put_contents($root . '/composer.lock', '{}');
        chmod($root . '/composer.lock', 0000);
        $composer = new \Magebean\Engine\Checks\Families\ComposerPolicyChecks(new Context($root, ''));
        $assert($composer->lockIntegrity([])[0] === null, 'Unreadable existing lock is collection failure, not confirmed invalid-lock finding');
        chmod($root . '/composer.lock', 0644); unlink($root . '/composer.lock'); unlink($root . '/composer.json');
        chmod($root . '/pub', 0000);
        $assert($fs->logsReportsNotInWebroot(['strict_scope' => true])[0] === null, 'Unreadable webroot cannot pass placement scan');
        chmod($root . '/pub', 0755);
    }
    echo "Scoped source/filesystem policy: $count assertions passed\n";
} finally {
    chmod($root . '/app', 0755); chmod($root . '/app/safe.php', 0644);
    unlink($root . '/app/safe.php'); rmdir($root . '/app'); rmdir($root . '/pub'); rmdir($root . '/var/log'); rmdir($root . '/var'); rmdir($root);
}
