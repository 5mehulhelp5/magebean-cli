<?php

declare(strict_types=1);

require_once __DIR__ . '/../src/Engine/Context.php';
require_once __DIR__ . '/../src/Engine/Checks/MagentoCheck.php';

use Magebean\Engine\Checks\MagentoCheck;
use Magebean\Engine\Context;

function assertAsvs(bool $condition, string $message): void
{
    if (!$condition) {
        fwrite(STDERR, $message . "\n");
        exit(1);
    }
}

$root = sys_get_temp_dir() . '/magebean-asvs-' . bin2hex(random_bytes(6));
mkdir($root . '/app/etc', 0777, true);

$writePolicy = static function (int $minimum) use ($root): void {
    $config = [
        'system' => [
            'default' => [
                'admin' => [
                    'security' => [
                        'min_password_length' => $minimum,
                    ],
                ],
            ],
        ],
    ];
    file_put_contents(
        $root . '/app/etc/config.php',
        '<?php return ' . var_export($config, true) . ';'
    );
};

$check = new MagentoCheck(new Context($root, ''));

$writePolicy(8);
$passing = $check->adminPasswordPolicyStrong([
    'file' => 'app/etc/config.php',
    'base_path' => 'system.default.admin.security',
    'min_password_length' => 8,
]);
assertAsvs(($passing[0] ?? null) === true, 'ASVS minimum password length should pass at 8 characters');
assertAsvs(
    array_keys(array_filter($passing[2]['requirements'] ?? [], static fn(mixed $value): bool => $value !== null && $value !== false))
        === ['min_password_length'],
    'Default ASVS password check must not require lockout, expiry, or forced password changes'
);

$writePolicy(7);
$failing = $check->adminPasswordPolicyStrong([
    'file' => 'app/etc/config.php',
    'base_path' => 'system.default.admin.security',
    'min_password_length' => 8,
]);
assertAsvs(($failing[0] ?? null) === false, 'ASVS minimum password length should fail below 8 characters');

$controls = json_decode(
    (string)file_get_contents(__DIR__ . '/../src/Rules/controls/MB-C04.json'),
    true,
    512,
    JSON_THROW_ON_ERROR
);
$hsts = array_values(array_filter(
    $controls['rules'] ?? [],
    static fn(array $rule): bool => ($rule['id'] ?? '') === 'MB-R027'
))[0] ?? [];
foreach ($hsts['checks'] ?? [] as $entry) {
    assertAsvs(
        (int)($entry['args']['min_max_age'] ?? 0) === 31536000,
        'Every MB-R027 check must require an HSTS max-age of at least one year'
    );
}

unlink($root . '/app/etc/config.php');
rmdir($root . '/app/etc');
rmdir($root . '/app');
rmdir($root);

echo "AsvsCriteriaTest: PASS\n";
