<?php

declare(strict_types=1);

require_once __DIR__ . '/../src/Engine/Context.php';
require_once __DIR__ . '/../src/Engine/Checks/PciEvidenceCheck.php';

use Magebean\Engine\Checks\PciEvidenceCheck;
use Magebean\Engine\Context;

function assertPciEvidence(bool $condition, string $message): void
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
$temporaryRoot = sys_get_temp_dir() . '/magebean-pci-evidence-' . bin2hex(random_bytes(6));
if (!mkdir($temporaryRoot, 0700, true) && !is_dir($temporaryRoot)) {
    throw new RuntimeException('Unable to create PCI evidence test directory');
}
$evidencePath = $temporaryRoot . '/evidence.json';
$check = new PciEvidenceCheck(new Context($temporaryRoot, ''));

$runDocument = static function (array $document) use ($evidencePath, $check): array {
    file_put_contents($evidencePath, json_encode($document, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));
    return $check->vendorDefaultAccountsEvidence(['paths' => ['evidence.json']]);
};

try {
    $complete = $runDocument($fixture);
    assertPciEvidence(($complete[0] ?? null) === true, 'Complete evidence must pass structural and semantic validation');
    assertPciEvidence(($complete[2]['outcome'] ?? null) === 'EVIDENCE_COMPLETE', 'Complete evidence outcome mismatch');
    assertPciEvidence(($complete[2]['human_verification_required'] ?? null) === true, 'Complete evidence must retain human verification');
    assertPciEvidence(($complete[2]['credential_material_processed'] ?? null) === false, 'Validator must not process credentials');
    assertPciEvidence(str_contains((string) ($complete[1] ?? ''), 'does not attest compliance'), 'Complete message must reject compliance attestation');

    $unsafe = $fixture;
    $unsafe['accounts'][0]['observed_state'] = 'ENABLED';
    $unsafeResult = $runDocument($unsafe);
    assertPciEvidence(($unsafeResult[0] ?? null) === false, 'Explicitly enabled unused default account must fail');
    assertPciEvidence(($unsafeResult[2]['outcome'] ?? null) === 'FAIL', 'Unsafe evidence outcome mismatch');

    $unsafeCredential = $fixture;
    $unsafeCredential['accounts'][0]['intended_use'] = 'USED';
    $unsafeCredential['accounts'][0]['observed_state'] = 'ENABLED';
    $unsafeCredential['accounts'][0]['credential_state'] = 'DEFAULT_OR_UNCHANGED';
    assertPciEvidence(($runDocument($unsafeCredential)[0] ?? null) === false, 'Explicit unchanged default credential must fail');

    $incomplete = $fixture;
    $incomplete['accounts'][0]['classification'] = 'SUSPECTED_VENDOR_DEFAULT';
    $incomplete['accounts'][0]['human_verified'] = false;
    $incomplete['attestation']['manual_verification_complete'] = false;
    $incompleteResult = $runDocument($incomplete);
    assertPciEvidence(array_key_exists(0, $incompleteResult) && $incompleteResult[0] === null, 'Incomplete evidence must remain indeterminate');
    assertPciEvidence(($incompleteResult[2]['outcome'] ?? null) === 'HUMAN_VERIFICATION_REQUIRED', 'Incomplete evidence must require human verification');
    assertPciEvidence(str_starts_with((string) ($incompleteResult[1] ?? ''), '[MANUAL_REVIEW]'), 'Incomplete evidence must use manual-review semantics');

    $duplicate = $fixture;
    $duplicate['evidence'][] = $duplicate['evidence'][0];
    $duplicateResult = $runDocument($duplicate);
    assertPciEvidence(array_key_exists(0, $duplicateResult) && $duplicateResult[0] === null && ($duplicateResult[2]['outcome'] ?? null) === 'UNKNOWN', 'Duplicate evidence IDs must be unknown');

    $brokenReference = $fixture;
    $brokenReference['accounts'][0]['evidence_refs'][] = 'missing-evidence';
    $brokenResult = $runDocument($brokenReference);
    assertPciEvidence(array_key_exists(0, $brokenResult) && $brokenResult[0] === null && ($brokenResult[2]['outcome'] ?? null) === 'UNKNOWN', 'Broken evidence references must be unknown');

    $zeroAccounts = $fixture;
    $zeroAccounts['accounts'] = [];
    $zeroResult = $runDocument($zeroAccounts);
    assertPciEvidence(($zeroResult[0] ?? null) === true, 'Attested zero-account inventory may be evidence-complete');
    assertPciEvidence(($zeroResult[2]['accounts_seen'] ?? -1) === 0, 'Zero-account evidence count mismatch');
    assertPciEvidence(($zeroResult[2]['human_verification_required'] ?? null) === true, 'Zero-account evidence must not remove human verification');

    $forbidden = $fixture;
    $forbidden['accounts'][0]['password'] = 'must-never-appear';
    $forbiddenResult = $runDocument($forbidden);
    assertPciEvidence(array_key_exists(0, $forbiddenResult) && $forbiddenResult[0] === null && ($forbiddenResult[2]['outcome'] ?? null) === 'UNKNOWN', 'Credential fields must invalidate evidence');
    assertPciEvidence(!str_contains(json_encode($forbiddenResult, JSON_THROW_ON_ERROR), 'must-never-appear'), 'Credential value leaked into validator output');

    file_put_contents($evidencePath, '{invalid-json');
    $malformed = $check->vendorDefaultAccountsEvidence(['paths' => ['evidence.json']]);
    assertPciEvidence(array_key_exists(0, $malformed) && $malformed[0] === null && ($malformed[2]['outcome'] ?? null) === 'UNKNOWN', 'Malformed JSON must be unknown');

    unlink($evidencePath);
    $missing = $check->vendorDefaultAccountsEvidence(['paths' => ['evidence.json']]);
    assertPciEvidence(array_key_exists(0, $missing) && $missing[0] === null && ($missing[2]['reason'] ?? null) === 'evidence_file_missing', 'Missing evidence must be unknown, not fail');
} finally {
    if (is_file($evidencePath)) {
        unlink($evidencePath);
    }
    if (is_dir($temporaryRoot)) {
        rmdir($temporaryRoot);
    }
}

echo "PciEvidenceCheckTest: PASS\n";
