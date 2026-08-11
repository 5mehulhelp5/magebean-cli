<?php
declare(strict_types=1);
require_once __DIR__ . '/../vendor/autoload.php';

use Magebean\Agent\InstallationMetadata;

function metadataAssert(bool $condition, string $message): void { if (!$condition) { fwrite(STDERR, "InstallationMetadataTest: {$message}\n"); exit(1); } }

$root = sys_get_temp_dir() . '/magebean-metadata-' . bin2hex(random_bytes(5));
mkdir($root . '/bin', 0777, true);
file_put_contents($root . '/composer.lock', json_encode(['packages' => [[
    'name' => 'magento/product-enterprise-edition',
    'version' => '2.4.8-p1',
]]], JSON_THROW_ON_ERROR));
file_put_contents($root . '/bin/magento', <<<'PHP'
#!/usr/bin/env php
<?php
if (($argv[1] ?? '') === 'config:show' && ($argv[2] ?? '') === 'web/secure/base_url') {
    echo "https://shop.example.com/\n";
    exit(0);
}
exit(1);
PHP);
chmod($root . '/bin/magento', 0755);

try {
    $metadata = (new InstallationMetadata())->detect($root);
    metadataAssert($metadata === [
        'store_url' => 'https://shop.example.com',
        'magento_version' => '2.4.8-p1',
        'magento_edition' => 'commerce',
    ], 'detected metadata did not match installation');
} finally {
    @unlink($root . '/bin/magento');
    @unlink($root . '/composer.lock');
    @rmdir($root . '/bin');
    @rmdir($root);
}

echo "InstallationMetadataTest: PASS\n";
