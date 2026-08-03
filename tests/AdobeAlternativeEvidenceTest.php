<?php

declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

use Magebean\Engine\Checks\ComposerCheck;
use Magebean\Engine\Context;

function assertAdobeEvidence(bool $condition, string $message): void
{
    if (!$condition) {
        fwrite(STDERR, "AdobeAlternativeEvidenceTest: {$message}\n");
        exit(1);
    }
}

$check = new ComposerCheck(new Context(__DIR__, ''));
$method = new ReflectionMethod($check, 'applyAdobeFingerprintEvidence');
$method->setAccessible(true);

$response = [
    'status' => 'outdated',
    'missing_patches' => [
        [
            'advisory' => 'APSB-PACKAGE',
            'alternative_rules' => [[
                'type' => 'package_constraint',
                'package' => 'magento/magento-cloud-patches',
                'constraint' => '>=1.1.8',
                'label' => 'Cloud patches',
            ]],
        ],
        [
            'advisory' => 'APSB-IDENTIFIER',
            'alternative_rules' => [[
                'type' => 'patch_identifier',
                'pattern' => 'vuln-28982',
                'label' => 'Isolated patch',
            ]],
        ],
        [
            'advisory' => 'APSB-MISSING',
            'alternative_rules' => [],
        ],
    ],
    'satisfied_by_alternatives' => [],
];

$localEvidence = [
    'packages' => ['magento/magento-cloud-patches' => '1.1.9'],
    'patch_artifacts' => [[
        'path' => 'm2-hotfixes/VULN-28982.patch',
        'identifiers' => ['VULN-28982'],
        'applied' => true,
    ]],
];

$result = $method->invoke($check, $response, $localEvidence);
assertAdobeEvidence(count($result['missing_patches']) === 1, 'expected only the unmatched advisory to remain');
assertAdobeEvidence(($result['missing_patches'][0]['advisory'] ?? '') === 'APSB-MISSING', 'wrong advisory remained');
assertAdobeEvidence(isset($result['satisfied_by_alternatives']['APSB-PACKAGE']), 'package constraint was not matched locally');
assertAdobeEvidence(isset($result['satisfied_by_alternatives']['APSB-IDENTIFIER']), 'patch identifier was not matched locally');
assertAdobeEvidence(($result['status'] ?? '') === 'outdated', 'status must remain outdated while a patch is missing');

$fullySatisfied = $response;
array_pop($fullySatisfied['missing_patches']);
$fullySatisfied = $method->invoke($check, $fullySatisfied, $localEvidence);
assertAdobeEvidence($fullySatisfied['missing_patches'] === [], 'all alternatives should be satisfied');
assertAdobeEvidence(($fullySatisfied['status'] ?? '') === 'current', 'fully satisfied alternatives should mark status current');

$unappliedEvidence = $localEvidence;
$unappliedEvidence['patch_artifacts'][0]['applied'] = false;
$identifierOnly = $response;
$identifierOnly['missing_patches'] = [$response['missing_patches'][1]];
$identifierOnly = $method->invoke($check, $identifierOnly, $unappliedEvidence);
assertAdobeEvidence(count($identifierOnly['missing_patches']) === 1, 'an unapplied patch must not satisfy an alternative');

echo "AdobeAlternativeEvidenceTest: PASS\n";
