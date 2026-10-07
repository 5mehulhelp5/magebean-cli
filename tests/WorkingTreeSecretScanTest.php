<?php
declare(strict_types=1);
require __DIR__ . '/../vendor/autoload.php';
use Magebean\Engine\Checks\GitHistoryCheck;
use Magebean\Engine\Context;
$root = sys_get_temp_dir() . '/magebean-working-tree-' . bin2hex(random_bytes(8));
mkdir($root);
$check = new GitHistoryCheck(new Context($root, ''));
$args = ['patterns' => ['AKIA[0-9A-Z]{16}']];
$count = 0;
$assert = static function (bool $condition, string $message) use (&$count): void {
    $count++;
    if (!$condition) throw new RuntimeException($message);
};
try {
    file_put_contents($root . '/safe.php', '<?php return [];');
    $result = $check->workingTreeScan($args);
    $assert($result[0] === true, 'Clean deployed tree without .git passes');
    $assert($result[2]['history_required'] === false, 'History explicitly outside scope');
    $assert($check->secretScan($args)[0] === null, 'Historical requirement still requires history');
    $secret = 'AKIA' . str_repeat('A', 16);
    file_put_contents($root . '/secret.php', $secret);
    $result = $check->workingTreeScan($args);
    $assert($result[0] === false, 'Matching working-tree secret fails');
    $assert(!str_contains(json_encode($result), $secret), 'Secret never appears in evidence');
    unlink($root . '/secret.php');
    $assert($check->workingTreeScan($args + ['paths' => ['missing']])[0] === null, 'Missing configured path cannot pass');
    file_put_contents($root . '/font.ttf', "\0" . str_repeat('x', 2 * 1024 * 1024));
    $assert($check->workingTreeScan($args)[0] === true, 'Oversized binary fonts are outside text scope, not coverage errors');
    unlink($root . '/font.ttf');
    file_put_contents($root . '/large.js', str_repeat('x', 1100000) . "\n" . $secret);
    $assert($check->workingTreeScan($args + ['max_file_bytes' => 16777216])[0] === false, 'Secret beyond old1MB cutoff is detected in expanded bounded text scope');
    unlink($root . '/large.js');
    file_put_contents($root . '/large.php', str_repeat('x', 2048));
    $assert($check->workingTreeScan($args + ['max_file_bytes' => 1024])[0] === null, 'Oversized text creates coverage gap');
    unlink($root . '/large.php');
    $assert($check->workingTreeScan(['patterns' => ['[']])[0] === null, 'Malformed pattern cannot pass');
    if (function_exists('posix_geteuid') && posix_geteuid() !== 0) {
        chmod($root . '/safe.php', 0000);
        $assert($check->workingTreeScan($args)[0] === null, 'Unreadable file cannot pass');
        chmod($root . '/safe.php', 0600);
    }
    echo "Working-tree secret scan: $count assertions passed\n";
} finally {
    foreach (glob($root . '/*') ?: [] as $file) { chmod($file, 0600); unlink($file); }
    rmdir($root);
}
