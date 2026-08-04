<?php

declare(strict_types=1);

function assertPciRequirement02(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

$root = dirname(__DIR__);
$review = json_decode((string) file_get_contents($root . '/src/Rules/standards/pci-dss-v4.0.1-requirement-02-review.json'), true, 512, JSON_THROW_ON_ERROR);
$registry = json_decode((string) file_get_contents($root . '/src/Rules/standards/pci-dss-v4.0.1.json'), true, 512, JSON_THROW_ON_ERROR);
$profile = json_decode((string) file_get_contents($root . '/src/Rules/profiles/pci-dss-v4.0.1.json'), true, 512, JSON_THROW_ON_ERROR);
$coverage = json_decode((string) file_get_contents($root . '/src/Rules/standards/pci-dss-v4.0.1-coverage.json'), true, 512, JSON_THROW_ON_ERROR);

$registryById = [];
foreach ($registry['requirements'] as $requirement) {
    $registryById[$requirement['id']] = $requirement;
}
$profileMappings = [];
foreach ($profile['rules'] as $rule) {
    foreach ($rule['mappings'] as $mapping) {
        $profileMappings[$mapping['requirement']][$rule['id']] = $mapping['coverage'];
    }
}
$coverageById = [];
foreach ($coverage['requirements'] as $requirement) {
    $coverageById[$requirement['id']] = $requirement['coverage'];
}

$expectedIds = ['2.2.2', '2.2.3', '2.2.4', '2.2.5', '2.2.6', '2.2.7'];
$entries = $review['requirements'] ?? [];
assertPciRequirement02(array_column($entries, 'requirement') === $expectedIds, 'Requirement 2 review must cover 2.2.2 through 2.2.7 in order');
assertPciRequirement02(($review['summary'] ?? null) === ['requirements_reviewed' => 6, 'reuse_existing_rules' => 2, 'new_rule_candidates' => 0, 'external_system_evidence' => 3, 'new_rules_added' => 1], 'Requirement 2 review summary is stale');

$index = [];
foreach ($entries as $entry) {
    $id = $entry['requirement'];
    $registryRequirement = $registryById[$id] ?? null;
    assertPciRequirement02($registryRequirement !== null, "Unknown reviewed requirement {$id}");
    assertPciRequirement02(($entry['source_pdf_page'] ?? null) === ($registryRequirement['source']['pdf_page'] ?? null), "Source page mismatch for {$id}");
    assertPciRequirement02(($entry['testing_methods'] ?? null) === ($registryRequirement['testing_methods'] ?? null), "Testing methods mismatch for {$id}");
    foreach (['criterion_summary', 'rationale', 'next_action'] as $field) {
        $value = (string) ($entry[$field] ?? '');
        assertPciRequirement02($value !== '' && preg_match('/[^\x00-\x7F]/', $value) !== 1, "{$field} must be non-empty English ASCII for {$id}");
    }
    $index[$id] = $entry;
}

assertPciRequirement02($index['2.2.2']['decision'] === 'IMPLEMENTED_HYBRID_RULE' && $index['2.2.2']['automation_model'] === 'HYBRID', '2.2.2 must be an implemented hybrid rule');
assertPciRequirement02($index['2.2.2']['existing_rules'] === ['MB-R371'], '2.2.2 must reference MB-R371');
assertPciRequirement02(($profileMappings['2.2.2'] ?? null) === ['MB-R371' => 'PARTIAL'], 'Profile mapping for 2.2.2 is missing');
foreach (['2.2.3', '2.2.4', '2.2.5'] as $id) {
    assertPciRequirement02($index[$id]['decision'] === 'EXTERNAL_SYSTEM_EVIDENCE', "{$id} must require external evidence");
}
assertPciRequirement02($index['2.2.6']['existing_rules'] === ['MB-R031', 'MB-R032', 'MB-R033', 'MB-R036'], 'Unexpected reused rules for 2.2.6');
assertPciRequirement02($index['2.2.7']['existing_rules'] === ['MB-R026', 'MB-R027', 'MB-R028'], 'Unexpected reused rules for 2.2.7');
assertPciRequirement02(($profileMappings['2.2.6'] ?? null) === ['MB-R031' => 'PARTIAL', 'MB-R032' => 'PARTIAL', 'MB-R033' => 'PARTIAL', 'MB-R036' => 'PARTIAL'], 'Profile mappings for 2.2.6 do not match review');
assertPciRequirement02(($profileMappings['2.2.7'] ?? null) === ['MB-R026' => 'PARTIAL', 'MB-R027' => 'SUPPORTING', 'MB-R028' => 'PARTIAL'], 'Profile mappings for 2.2.7 do not match review');
assertPciRequirement02(($coverageById['2.2.6'] ?? null) === 'PARTIAL' && ($coverageById['2.2.7'] ?? null) === 'PARTIAL', 'Reviewed reused criteria must have PARTIAL requirement coverage');

echo "PciDssRequirement02ReviewTest: PASS\n";
