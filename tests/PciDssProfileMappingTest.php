<?php

declare(strict_types=1);

function assertPciMapping(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

$root = dirname(__DIR__);
$profile = json_decode((string) file_get_contents($root . '/src/Rules/profiles/pci-dss-v4.0.1.json'), true, 512, JSON_THROW_ON_ERROR);
$registry = json_decode((string) file_get_contents($root . '/src/Rules/standards/pci-dss-v4.0.1.json'), true, 512, JSON_THROW_ON_ERROR);
$registryIds = array_fill_keys(array_column($registry['requirements'] ?? [], 'id'), true);
$allowedCoverage = ['DIRECT', 'PARTIAL', 'SUPPORTING', 'HUMAN'];
$allowedEvidence = ['automated', 'hybrid', 'manual'];
$rules = $profile['rules'] ?? [];
$ruleIds = [];
$coverageCounts = array_fill_keys($allowedCoverage, 0);
$evidenceCounts = array_fill_keys($allowedEvidence, 0);
$mappingIndex = [];

assertPciMapping(($profile['registry'] ?? null) === '../standards/pci-dss-v4.0.1.json', 'Profile must link to its canonical registry');
assertPciMapping(count($rules) === 68, 'Audited PCI profile must contain 68 rules');

foreach ($rules as $rule) {
    $ruleId = (string) ($rule['id'] ?? '');
    assertPciMapping($ruleId !== '' && !isset($ruleIds[$ruleId]), "Duplicate or empty rule ID: {$ruleId}");
    $ruleIds[$ruleId] = true;
    $evidenceType = (string) ($rule['evidence_type'] ?? '');
    assertPciMapping(in_array($evidenceType, $allowedEvidence, true), "Invalid evidence type for {$ruleId}");
    $evidenceCounts[$evidenceType]++;
    $mappings = $rule['mappings'] ?? [];
    assertPciMapping($mappings !== [], "Mappings missing for {$ruleId}");
    assertPciMapping(array_column($mappings, 'requirement') === ($rule['requirements'] ?? null), "Legacy requirements differ from mappings for {$ruleId}");

    foreach ($mappings as $mapping) {
        $requirement = (string) ($mapping['requirement'] ?? '');
        $coverage = (string) ($mapping['coverage'] ?? '');
        $rationale = (string) ($mapping['rationale'] ?? '');
        assertPciMapping(isset($registryIds[$requirement]), "Unknown PCI DSS requirement {$requirement} on {$ruleId}");
        assertPciMapping(in_array($coverage, $allowedCoverage, true), "Invalid coverage {$coverage} on {$ruleId}");
        assertPciMapping($rationale !== '' && preg_match('/[^\x00-\x7F]/', $rationale) !== 1, "Rationale must be non-empty English ASCII for {$ruleId}");
        $coverageCounts[$coverage]++;
        $mappingIndex["{$ruleId}:{$requirement}"] = $coverage;
    }
}

foreach (['MB-R006', 'MB-R030', 'MB-R035', 'MB-R045'] as $excludedRule) {
    assertPciMapping(!isset($ruleIds[$excludedRule]), "{$excludedRule} must not be presented as PCI DSS evidence");
}

assertPciMapping($evidenceCounts === ['automated' => 64, 'hybrid' => 4, 'manual' => 0], 'Unexpected PCI evidence-type distribution');
assertPciMapping($coverageCounts === ['DIRECT' => 1, 'PARTIAL' => 58, 'SUPPORTING' => 35, 'HUMAN' => 0], 'Unexpected PCI mapping coverage distribution');
assertPciMapping(($profile['coverage_summary']['rules'] ?? null) === count($rules), 'Rule summary is stale');
assertPciMapping(($profile['coverage_summary']['evidence_types'] ?? null) === $evidenceCounts, 'Evidence summary is stale');
assertPciMapping(($profile['coverage_summary']['mappings'] ?? null) === $coverageCounts, 'Mapping summary is stale');
assertPciMapping(($mappingIndex['MB-R009:8.2.8'] ?? null) === 'DIRECT', 'Session timeout must map directly to 8.2.8');
assertPciMapping(($mappingIndex['MB-R023:6.2.4'] ?? null) === 'PARTIAL', 'SQL injection must map partially to secure engineering 6.2.4');
assertPciMapping(($mappingIndex['MB-R043:10.5.1'] ?? null) === 'PARTIAL', 'Log rotation must map partially to retention 10.5.1');
assertPciMapping(($mappingIndex['MB-R073:4.2.1'] ?? null) === 'PARTIAL', 'HTTPS-only endpoints must map partially to 4.2.1');
assertPciMapping(($mappingIndex['MB-R093:12.8.5'] ?? null) === 'SUPPORTING', 'Evidence checklist must support 12.8.5');
assertPciMapping(($mappingIndex['MB-R093:12.10.1'] ?? null) === 'SUPPORTING', 'Evidence checklist must support 12.10.1');
assertPciMapping(($mappingIndex['MB-R100:7.2.2'] ?? null) === 'PARTIAL', 'Admin role assignments must partially map to 7.2.2');
assertPciMapping(($mappingIndex['MB-R101:7.3.1'] ?? null) === 'SUPPORTING', 'Global ACL restriction must support 7.3.1');
assertPciMapping(($mappingIndex['MB-R007:8.4.1'] ?? null) === 'PARTIAL', 'Admin 2FA must partially map to 8.4.1');
assertPciMapping(($mappingIndex['MB-R042:10.3.2'] ?? null) === 'SUPPORTING', 'Public log protection must support 10.3.2');
assertPciMapping(($mappingIndex['MB-R371:2.2.2'] ?? null) === 'PARTIAL', 'Vendor default account evidence must partially map to 2.2.2');
assertPciMapping(($mappingIndex['MB-R031:2.2.6'] ?? null) === 'PARTIAL', 'Production mode must partially map to security parameters 2.2.6');
assertPciMapping(($mappingIndex['MB-R026:2.2.7'] ?? null) === 'PARTIAL', 'Admin HTTPS must partially map to encrypted administration 2.2.7');
assertPciMapping(($mappingIndex['MB-R027:2.2.7'] ?? null) === 'SUPPORTING', 'HSTS must only support encrypted administration 2.2.7');
$directMappings = array_filter($mappingIndex, static fn (string $coverage): bool => $coverage === 'DIRECT');
assertPciMapping($directMappings === ['MB-R009:8.2.8' => 'DIRECT'], 'Only the exact idle-timeout criterion may be classified DIRECT');

echo "PciDssProfileMappingTest: PASS\n";
