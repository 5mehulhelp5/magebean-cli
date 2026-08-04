<?php

declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

use Magebean\Engine\Checks\CheckRegistry;
use Magebean\Engine\Context;
use Magebean\Engine\ScanRunner;

function assertPciEvidenceOutput(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

$fixture = json_decode(
    (string) file_get_contents(__DIR__ . '/../docs/examples/pci-dss-2.2.2-evidence.example.json'),
    true,
    512,
    JSON_THROW_ON_ERROR
);
$temporaryRoot = sys_get_temp_dir() . '/magebean-pci-output-' . bin2hex(random_bytes(6));
if (!mkdir($temporaryRoot, 0700, true) && !is_dir($temporaryRoot)) {
    throw new RuntimeException('Unable to create PCI output test directory');
}
$evidencePath = $temporaryRoot . '/evidence.json';
$rule = [
    'id' => 'MB-TEST-PCI-2.2.2',
    'title' => 'Vendor default account evidence assessment',
    'control' => 'MB-C02',
    'severity' => 'high',
    'verification' => 'manual',
    'op' => 'all',
    'checks' => [
        [
            'name' => 'pci_vendor_default_accounts_evidence',
            'args' => ['paths' => ['evidence.json']],
        ],
        [
            'name' => 'human_manual_review_required',
            'args' => [
                'requirement' => 'PCI DSS 4.0.1 2.2.2',
                'review' => 'Confirm every in-scope component is inventoried; verify retained vendor default accounts changed their default password and unused vendor default accounts are disabled or removed.',
                'evidence_needed' => [
                    'Complete in-scope component inventory',
                    'Vendor documentation identifying default accounts',
                    'Account configuration exports or observations',
                    'Reviewer attestation',
                ],
            ],
        ],
    ],
];

$run = static function () use ($temporaryRoot, $rule): array {
    $context = new Context($temporaryRoot, '');
    return (new ScanRunner($context, ['rules' => [$rule]], null, CheckRegistry::fromContext($context)))->run();
};

try {
    file_put_contents($evidencePath, json_encode($fixture, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));
    $complete = $run();
    $completeFinding = $complete['findings'][0];
    assertPciEvidenceOutput($completeFinding['status'] === 'MANUAL_REVIEW', 'Evidence-complete hybrid rule must remain human verification required');
    assertPciEvidenceOutput($completeFinding['passed'] === null, 'Evidence-complete hybrid rule must not pass automatically');
    assertPciEvidenceOutput(str_contains($completeFinding['message'], 'Confirm every in-scope component'), 'Manual output must describe exactly what requires verification');
    assertPciEvidenceOutput(($completeFinding['detail'][0]['status'] ?? null) === 'PASS', 'Automated evidence detail should record structural completion');
    assertPciEvidenceOutput(($completeFinding['detail'][1]['status'] ?? null) === 'MANUAL_REVIEW', 'Human detail must remain mandatory');

    unlink($evidencePath);
    $missing = $run();
    $missingFinding = $missing['findings'][0];
    assertPciEvidenceOutput($missingFinding['status'] === 'MANUAL_REVIEW', 'Missing opt-in evidence must require human verification, not fail');
    assertPciEvidenceOutput(($missingFinding['detail'][0]['status'] ?? null) === 'UNKNOWN', 'Missing evidence detail must remain unknown');
    assertPciEvidenceOutput(($missingFinding['detail'][1]['status'] ?? null) === 'MANUAL_REVIEW', 'Missing evidence must retain specific human instruction');

    $unsafe = $fixture;
    $unsafe['accounts'][0]['observed_state'] = 'ENABLED';
    file_put_contents($evidencePath, json_encode($unsafe, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));
    $failed = $run();
    $failedFinding = $failed['findings'][0];
    assertPciEvidenceOutput($failedFinding['status'] === 'FAIL', 'Explicit unsafe evidence must override manual status');
    assertPciEvidenceOutput($failedFinding['passed'] === false, 'Explicit unsafe evidence must fail');
    assertPciEvidenceOutput(str_contains($failedFinding['message'], 'remains enabled'), 'Failure output must explain the explicit unsafe disposition');
    assertPciEvidenceOutput(($failed['summary']['failed'] ?? 0) === 1, 'Explicit unsafe evidence must count as failed');
} finally {
    if (is_file($evidencePath)) {
        unlink($evidencePath);
    }
    if (is_dir($temporaryRoot)) {
        rmdir($temporaryRoot);
    }
}

echo "PciEvidenceOutputSemanticsTest: PASS\n";
