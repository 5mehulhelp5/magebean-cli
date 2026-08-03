<?php

declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

use Magebean\Engine\Checks\ComposerCheck;
use Magebean\Engine\Context;
use Magebean\Engine\Cve\OsvSeverity;

function assertSeverity(
    string $expectedLabel,
    string $expectedScore,
    array $vulnerability,
    ?array $affected,
    string $case
): void {
    $actual = OsvSeverity::resolve($vulnerability, $affected);
    if ($actual['label'] !== $expectedLabel || $actual['score'] !== $expectedScore) {
        fwrite(STDERR, sprintf(
            "%s: expected %s/%s, got %s/%s\n",
            $case,
            $expectedLabel,
            $expectedScore,
            $actual['label'],
            $actual['score']
        ));
        exit(1);
    }
}

assertSeverity(
    'Critical',
    '9.8',
    ['severity' => [[
        'type' => 'CVSS_V3',
        'score' => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    ]]],
    null,
    'CVSS v3 vector'
);

assertSeverity(
    'High',
    '7.5',
    ['severity' => [[
        'type' => 'CVSS_V2',
        'score' => 'AV:N/AC:L/Au:N/C:P/I:P/A:P',
    ]]],
    null,
    'CVSS v2 vector'
);

assertSeverity(
    'Medium',
    '',
    ['database_specific' => ['severity' => 'HIGH']],
    ['database_specific' => ['severity' => 'MODERATE']],
    'affected package severity takes precedence'
);

assertSeverity(
    'Severity not published',
    '',
    ['id' => 'GHSA-example'],
    null,
    'missing severity'
);

$fixtureRoot = sys_get_temp_dir() . '/magebean-osv-severity-' . bin2hex(random_bytes(4));
mkdir($fixtureRoot, 0700, true);
file_put_contents($fixtureRoot . '/composer.lock', json_encode([
    'packages' => [[
        'name' => 'mtdowling/jmespath.php',
        'version' => '2.8.0',
    ]],
], JSON_THROW_ON_ERROR));
file_put_contents($fixtureRoot . '/osv.json', json_encode([
    'id' => 'CVE-2026-54133',
    'severity' => [[
        'type' => 'CVSS_V3',
        'score' => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    ]],
    'affected' => [[
        'package' => [
            'ecosystem' => 'Packagist',
            'name' => 'mtdowling/jmespath.php',
        ],
        'ranges' => [[
            'type' => 'ECOSYSTEM',
            'events' => [
                ['introduced' => '0'],
                ['fixed' => '2.9.1'],
            ],
        ]],
    ]],
], JSON_THROW_ON_ERROR));

try {
    $result = (new ComposerCheck(new Context($fixtureRoot, '', $fixtureRoot . '/osv.json')))
        ->auditOffline([]);
    $expectedOutput = 'mtdowling/jmespath.php@2.8.0 -> CVE-2026-54133'
        . ' (Critical · CVSS 9.8), fix >= 2.9.1';
    if (($result[0] ?? null) !== false || !str_contains((string)($result[1] ?? ''), $expectedOutput)) {
        fwrite(STDERR, "R049 integration output did not contain the normalized severity:\n"
            . (string)($result[1] ?? '') . "\n");
        exit(1);
    }
} finally {
    @unlink($fixtureRoot . '/osv.json');
    @unlink($fixtureRoot . '/composer.lock');
    @rmdir($fixtureRoot);
}

echo "OsvSeverityTest: PASS\n";
