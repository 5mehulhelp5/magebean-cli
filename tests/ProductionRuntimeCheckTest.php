<?php
declare(strict_types=1);
require __DIR__ . '/../vendor/autoload.php';

use Magebean\Engine\Checks\ProductionRuntimeCheck;
use Magebean\Engine\Context;

$root = sys_get_temp_dir() . '/mb-production-runtime-' . bin2hex(random_bytes(6));
mkdir($root . '/app/etc', 0777, true);
$n = 0;
$assert = static function (mixed $expected, array $actual, string $label) use (&$n): void {
    ++$n;
    if ($actual[0] !== $expected) throw new RuntimeException($label . ': ' . json_encode($actual));
};
$env = static function (array $value) use ($root): void { file_put_contents($root . '/app/etc/env.php', '<?php return ' . var_export($value, true) . ';'); };
$remove = static function (string $path) use (&$remove): void {
    if (is_link($path) || is_file($path)) { @chmod($path, 0644); unlink($path); return; }
    @chmod($path, 0755);
    foreach (new DirectoryIterator($path) as $entry) if (!$entry->isDot()) $remove($entry->getPathname());
    rmdir($path);
};
try {
    $check = new ProductionRuntimeCheck(new Context($root, ''));
    $assert(null, $check->uploadSignaturesAbsent([]), 'Missing upload root cannot pass');
    mkdir($root . '/pub/media', 0777, true);
    file_put_contents($root . '/pub/media/logo.svg', '<?xml version="1.0"?><svg/>');
    $assert(true, $check->uploadSignaturesAbsent([]), 'XML declaration is not a PHP tag');
    file_put_contents($root . '/pub/media/image.jpg', "JPEG\n<?php echo 'fixture';");
    $result = $check->uploadSignaturesAbsent([]);
    $assert(false, $result, 'PHP disguised as image is found without executing it');
    if (($result[2]['findings'][0]['line'] ?? null) !== 2 || str_contains(json_encode($result), "echo 'fixture'")) throw new RuntimeException('Evidence should report location without payload');
    unlink($root . '/pub/media/image.jpg');
    file_put_contents($root . '/pub/media/big.dat', str_repeat('x', 100));
    $assert(null, $check->uploadSignaturesAbsent(['max_file_bytes' => 32]), 'Oversized eligible content cannot disappear into PASS');
    $assert(null, $check->uploadSignaturesAbsent(['max_total_bytes' => 32]), 'Total byte budget does not certify unread inventory');
    unlink($root . '/pub/media/big.dat');
    symlink($root . '/app', $root . '/pub/media/linked');
    $assert(null, $check->uploadSignaturesAbsent([]), 'Unfollowed links are explicit coverage gaps');
    unlink($root . '/pub/media/linked');
    $assert(null, $check->uploadSignaturesAbsent(['max_entries' => 1, 'paths' => ['pub/media', 'app']]), 'Traversal budget does not certify an incomplete inventory');
    file_put_contents($root . '/pub/media/.htaccess', "AddHandler application/x-httpd-php .jpg\n");
    $assert(false, $check->uploadSignaturesAbsent([]), 'Upload handler override signature fails');
    unlink($root . '/pub/media/.htaccess');

    $env(['system' => ['default' => ['dev/debug/template_hints' => '0', 'dev/debug/template_hints_storefront' => 0, 'dev/translate_inline/active' => false]]]);
    $assert(true, $check->nativeDebugDefaultsDisabled([]), 'Resolved explicit native default settings off');
    $env(['system' => ['default' => ['dev/debug/template_hints' => '1']]]);
    $assert(false, $check->nativeDebugDefaultsDisabled([]), 'Known enabled debug fails despite other unresolved paths');
    $env([]);
    $assert(null, $check->nativeDebugDefaultsDisabled([]), 'Missing effective defaults never fabricated off');
    $assert(null, $check->integrationDebugDefaultsDisabled([]), 'Integration key policy is mandatory');
    $env(['system' => ['default' => ['payment/stripe/debug' => '0', 'payment/stripe/logging' => '1']]]);
    $assert(true, $check->integrationDebugDefaultsDisabled(['paths' => ['payment/stripe/debug']]), 'Audit logging does not masquerade as vendor debug');
    $env(['system' => ['default' => ['payment/stripe/debug' => 'unexpected']]]);
    $assert(null, $check->integrationDebugDefaultsDisabled(['paths' => ['payment/stripe/debug']]), 'Unknown flag representation is not falsey safe');

    $response = ['complete_headers' => true, 'status' => 200, 'headers' => ['x-content-type-options' => ['nosniff']]];
    $http = new ProductionRuntimeCheck(new Context($root, 'https://review.invalid'), static function () use (&$response): array { return $response; });
    $assert(true, $http->runtimeNosniff([]), 'One observed exact header passes');
    $response['headers'] = [];
    $assert(false, $http->runtimeNosniff([]), 'Missing header on collected 200 fails');
    $response['headers'] = ['x-content-type-options' => ['nosniff', 'nosniff']];
    $assert(null, $http->runtimeNosniff([]), 'Duplicate headers cannot establish unambiguous policy');
    $response['status'] = 302;
    $assert(null, $http->runtimeNosniff([]), 'Redirect is not an observed application 200');
    $response['status'] = 200;
    $csp = "script-src 'self'; connect-src 'self'; frame-src https://gateway.example; form-action 'self'; object-src 'none'; base-uri 'self'; report-to csp";
    $response['headers'] = ['content-security-policy' => [$csp]];
    $assert(null, $http->checkoutCspResponse([]), 'Homepage cannot silently substitute for checkout');
    $assert(true, $http->checkoutCspResponse(['path' => '/checkout/']), 'Complete explicit checkout response policy passes');
    $response['headers'] = ['content-security-policy-report-only' => [$csp]];
    $assert(false, $http->checkoutCspResponse(['path' => '/checkout/']), 'Report-only is not enforced CSP');
    $response['headers'] = ['content-security-policy' => [str_replace("script-src 'self'", "script-src * 'unsafe-inline'", $csp)]];
    $assert(false, $http->checkoutCspResponse(['path' => '/checkout/']), 'Wildcard/unsafe script policy fails explicit baseline');
    $response['headers'] = ['content-security-policy' => [$csp . "; script-src 'none'"]];
    $assert(null, $http->checkoutCspResponse(['path' => '/checkout/']), 'Duplicate CSP directives are not combined optimistically');
    $response['headers'] = ['content-security-policy' => [str_replace("script-src 'self'", 'script-src unsupportedgarbage', $csp)]];
    $assert(null, $http->checkoutCspResponse(['path' => '/checkout/']), 'Unsupported source syntax cannot pass');
    $response['final_url'] = 'https://outside.invalid/checkout/';
    $assert(null, $http->checkoutCspResponse(['path' => '/checkout/']), 'Off-origin response cannot supply evidence');
    unset($response['final_url']);
    $assert(null, $http->runtimeNosniff(['path' => '//outside.invalid']), 'Network-path references rejected');

    $pdo = new PDO('sqlite::memory:');
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->exec('CREATE TABLE authorization_role (role_id INTEGER, role_type TEXT)');
    $pdo->exec('CREATE TABLE authorization_rule (role_id INTEGER, resource_id TEXT, permission TEXT)');
    $pdo->exec("INSERT INTO authorization_role VALUES (1, 'G'), (2, 'U')");
    $pdo->exec("INSERT INTO authorization_rule VALUES (1, 'Magento_Backend::all', 'allow')");
    $acl = new ProductionRuntimeCheck(new Context($root, '', '', ['pdo' => $pdo]));
    $assert(null, $acl->directGlobalRolesApproved([]), 'Missing approval policy is not empty deny-all');
    $assert(true, $acl->directGlobalRolesApproved(['approved_role_ids' => [1]]), 'Real SELECT rows compared with explicit role policy');
    $assert(false, $acl->directGlobalRolesApproved(['approved_role_ids' => []]), 'Explicit deny-all detects direct grant');
    $pdo->exec("INSERT INTO authorization_rule VALUES (999, 'Magento_Backend::all', 'allow')");
    $assert(null, $acl->directGlobalRolesApproved(['approved_role_ids' => [1]]), 'Uncollected orphan rule prevents positive ACL conclusion');
    $pdo->exec('DELETE FROM authorization_rule');
    $assert(true, $acl->directGlobalRolesApproved(['approved_role_ids' => []]), 'Complete nonempty role inventory with no direct grants passes');

    $assert(null, $check->boundWorkerCodeReadonly([]), 'Unknown runtime identity cannot become mode-bit failure');
    $identityMethod = new ReflectionMethod(ProductionRuntimeCheck::class, 'processIdentity');
    $identity = $identityMethod->invoke($check, getmypid(), false);
    if (is_array($identity)) {
        // Test-only provider binds to this real unprivileged process; kernel access checks remain real.
        $worker = new ProductionRuntimeCheck(new Context($root, ''), null, static fn(int $pid): array => $identity);
        mkdir($root . '/code'); file_put_contents($root . '/code/fixture.php', '<?php // inert');
        chmod($root . '/code/fixture.php', 0444); chmod($root . '/code', 0555); chmod($root, 0555);
        $assert(true, $worker->boundWorkerCodeReadonly(['worker_pids' => [getmypid()], 'dirs' => ['code']]), 'Kernel denies writes in complete readonly tree');
        chmod($root . '/code/fixture.php', 0644); clearstatcache();
        $assert(false, $worker->boundWorkerCodeReadonly(['worker_pids' => [getmypid()], 'dirs' => ['code']]), 'Kernel allows actual code write for matched identity');
        $mismatch = $identity; $mismatch['uid']++;
        $other = new ProductionRuntimeCheck(new Context($root, ''), null, static fn(int $pid): array => $mismatch);
        $assert(null, $other->boundWorkerCodeReadonly(['worker_pids' => [getmypid()], 'dirs' => ['code']]), 'Different UID cannot use scanner access results');
        chmod($root, 0755);
    }
    echo "ProductionRuntimeCheckTest: {$n} assertions passed\n";
} finally { $remove($root); }
