<?php
declare(strict_types=1);
require __DIR__ . '/../vendor/autoload.php';
use Magebean\Engine\Checks\GitHistoryCheck;
use Magebean\Engine\Checks\Families\PaymentSourceChecks;
use Magebean\Engine\Context;
$root = sys_get_temp_dir() . '/magebean-sensitive-pattern-' . bin2hex(random_bytes(8)); mkdir($root);
$count = 0;
$assert = static function (bool $condition, string $message) use (&$count): void { $count++; if (!$condition) throw new RuntimeException($message); };
$run = static function (array $command) use ($root): void {
    $p = proc_open($command, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, $root);
    if (!is_resource($p)) throw new RuntimeException('Cannot launch fixture Git');
    $output = stream_get_contents($pipes[1]); $error = stream_get_contents($pipes[2]); fclose($pipes[1]); fclose($pipes[2]);
    if (proc_close($p) !== 0) throw new RuntimeException($error . $output);
};
try {
    $run(['git', 'init', '-q']); $run(['git', 'config', 'user.name', 'Fixture']); $run(['git', 'config', 'user.email', 'fixture@example.invalid']);
    file_put_contents($root . '/old.txt', 'SECRET-1234'); $run(['git', 'add', 'old.txt']); $run(['git', 'commit', '-qm', 'fixture']);
    unlink($root . '/old.txt');
    $check = new GitHistoryCheck(new Context($root, ''));
    $result = $check->secretScan(['patterns' => ['SECRET-\d{4}'], 'exclude_dirs' => ['.git']]);
    $assert($result[0] === false && count($result[2]['git_history_findings']) === 1, 'PCRE digit syntax matches historical secret');
    $assert(!str_contains(json_encode($result), 'SECRET-1234'), 'Historical secret redacted');
    $payment = new PaymentSourceChecks(new Context($root, ''));
    $panMethod = new ReflectionMethod($payment, 'cardholderFilePanFindings');
    $findings = $panMethod->invoke($payment, $root . '/export.csv', '4111111111111111');
    $assert(count($findings) === 1, 'PAN-like observation retained');
    $assert(!str_contains(json_encode($findings), '4111111111111111'), 'Full PAN absent from structured evidence');
    $sensitiveMethod = new ReflectionMethod($payment, 'cardholderFileSensitiveFieldFindings');
    $findings = $sensitiveMethod->invoke($payment, $root . '/export.csv', 'cvv: 937', 'csv');
    $assert(count($findings) === 1 && !str_contains(json_encode($findings), '937'), 'CVV absent from structured evidence');
    echo "Sensitive pattern safety: $count assertions passed\n";
} finally {
    $cleanup = static function (string $path) use (&$cleanup): void { if (is_dir($path) && !is_link($path)) { foreach (scandir($path) as $child) if ($child !== '.' && $child !== '..') $cleanup($path . '/' . $child); rmdir($path); } else unlink($path); };
    $cleanup($root);
}
