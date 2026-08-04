<?php

declare(strict_types=1);

function assertPciCoverage(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

$root = dirname(__DIR__);
$matrix = json_decode((string) file_get_contents($root . '/src/Rules/standards/pci-dss-v4.0.1-coverage.json'), true, 512, JSON_THROW_ON_ERROR);
$registry = json_decode((string) file_get_contents($root . '/src/Rules/standards/pci-dss-v4.0.1.json'), true, 512, JSON_THROW_ON_ERROR);
$profile = json_decode((string) file_get_contents($root . '/src/Rules/profiles/pci-dss-v4.0.1.json'), true, 512, JSON_THROW_ON_ERROR);

$rank = ['UNMAPPED' => 0, 'SUPPORTING' => 1, 'PARTIAL' => 2, 'DIRECT' => 3];
$expectedEvidence = [];
foreach ($profile['rules'] ?? [] as $rule) {
    foreach ($rule['mappings'] ?? [] as $mapping) {
        $expectedEvidence[$mapping['requirement']][] = [
            'rule' => $rule['id'],
            'coverage' => $mapping['coverage'],
            'evidence_type' => $rule['evidence_type'],
            'rationale' => $mapping['rationale'],
        ];
    }
}

$registryById = [];
foreach ($registry['requirements'] ?? [] as $requirement) {
    $registryById[$requirement['id']] = $requirement;
}

$rows = $matrix['requirements'] ?? [];
$seen = [];
$coverageCounts = array_fill_keys(array_keys($rank), 0);
$principalCounts = [];

assertPciCoverage(($matrix['profile'] ?? null) === '../profiles/pci-dss-v4.0.1.json', 'Matrix profile link is invalid');
assertPciCoverage(($matrix['registry'] ?? null) === 'pci-dss-v4.0.1.json', 'Matrix registry link is invalid');
assertPciCoverage(str_contains((string) ($matrix['human_verification_policy'] ?? ''), 'mandatory'), 'Mandatory human-verification policy is missing');
assertPciCoverage(count($rows) === 280, 'Coverage matrix must contain all 280 requirements');

foreach ($rows as $row) {
    $id = (string) ($row['id'] ?? '');
    assertPciCoverage(isset($registryById[$id]) && !isset($seen[$id]), "Unknown or duplicate matrix requirement {$id}");
    $seen[$id] = true;
    $registryRequirement = $registryById[$id];
    foreach (['principal_requirement', 'objective_group', 'kind', 'entity_restriction', 'effective_from'] as $field) {
        assertPciCoverage(($row[$field] ?? null) === ($registryRequirement[$field] ?? null), "Registry metadata mismatch for {$id}: {$field}");
    }
    assertPciCoverage(($row['overlay'] ?? null) === ($registryRequirement['overlay'] ?? null), "Overlay mismatch for {$id}");
    assertPciCoverage(($row['human_verification_required'] ?? null) === true, "Human verification must be mandatory for {$id}");
    assertPciCoverage((string) ($row['gap_action'] ?? '') !== '', "Gap action missing for {$id}");

    $expected = $expectedEvidence[$id] ?? [];
    assertPciCoverage(($row['evidence'] ?? null) === $expected, "Evidence list mismatch for {$id}");
    $expectedCoverage = 'UNMAPPED';
    foreach ($expected as $evidence) {
        if ($rank[$evidence['coverage']] > $rank[$expectedCoverage]) {
            $expectedCoverage = $evidence['coverage'];
        }
    }
    assertPciCoverage(($row['coverage'] ?? null) === $expectedCoverage, "Strongest coverage mismatch for {$id}");
    $coverageCounts[$expectedCoverage]++;
    $principal = (string) $row['principal_requirement'];
    $principalCounts[$principal] ??= ['total' => 0, 'DIRECT' => 0, 'PARTIAL' => 0, 'SUPPORTING' => 0, 'UNMAPPED' => 0];
    $principalCounts[$principal]['total']++;
    $principalCounts[$principal][$expectedCoverage]++;
}

assertPciCoverage(count($seen) === count($registryById), 'Matrix does not cover the complete registry');
assertPciCoverage($coverageCounts === ['UNMAPPED' => 245, 'SUPPORTING' => 9, 'PARTIAL' => 25, 'DIRECT' => 1], 'Unexpected requirement-level coverage distribution');
assertPciCoverage(($matrix['summary']['coverage'] ?? null) === ['DIRECT' => 1, 'PARTIAL' => 25, 'SUPPORTING' => 9, 'UNMAPPED' => 245], 'Coverage summary is stale');
assertPciCoverage(($matrix['summary']['requirements_with_magebean_evidence'] ?? null) === 35, 'Evidence coverage total is stale');
assertPciCoverage(($matrix['summary']['human_verification'] ?? null) === ['required' => 280], 'Human-verification summary is stale');
assertPciCoverage(($matrix['summary']['by_principal_requirement'] ?? null) == $principalCounts, 'Principal-requirement summary is stale');

echo "PciDssCoverageMatrixTest: PASS\n";
