<?php

declare(strict_types=1);

function assertPci022Design(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

function collectPci022Keys(mixed $value, array &$keys): void
{
    if (!is_array($value)) {
        return;
    }
    foreach ($value as $key => $child) {
        if (is_string($key)) {
            $keys[] = strtolower($key);
        }
        collectPci022Keys($child, $keys);
    }
}

$root = dirname(__DIR__);
$schema = json_decode((string) file_get_contents($root . '/src/Rules/standards/pci-dss-v4.0.1-2.2.2-evidence.schema.json'), true, 512, JSON_THROW_ON_ERROR);
$design = json_decode((string) file_get_contents($root . '/src/Rules/standards/pci-dss-v4.0.1-requirement-02.2.2-design.json'), true, 512, JSON_THROW_ON_ERROR);
$example = json_decode((string) file_get_contents($root . '/docs/examples/pci-dss-2.2.2-evidence.example.json'), true, 512, JSON_THROW_ON_ERROR);
$review = json_decode((string) file_get_contents($root . '/src/Rules/standards/pci-dss-v4.0.1-requirement-02-review.json'), true, 512, JSON_THROW_ON_ERROR);
$triage = json_decode((string) file_get_contents($root . '/src/Rules/standards/pci-dss-v4.0.1-gap-triage.json'), true, 512, JSON_THROW_ON_ERROR);

assertPci022Design(($schema['$schema'] ?? null) === 'https://json-schema.org/draft/2020-12/schema', 'Unexpected evidence-schema dialect');
assertPci022Design(($schema['properties']['requirement']['const'] ?? null) === '2.2.2', 'Evidence schema must be restricted to requirement 2.2.2');
assertPci022Design(($schema['additionalProperties'] ?? null) === false, 'Evidence schema must reject unknown top-level fields');
assertPci022Design(($schema['$defs']['account']['additionalProperties'] ?? null) === false, 'Account evidence must reject unknown fields');
assertPci022Design(($schema['$defs']['component']['additionalProperties'] ?? null) === false, 'Component evidence must reject unknown fields');
assertPci022Design(($schema['$defs']['evidence']['additionalProperties'] ?? null) === false, 'Evidence references must reject unknown fields');

assertPci022Design(($design['implementation_status'] ?? null) === 'IMPLEMENTED', '2.2.2 implementation status is stale');
assertPci022Design(($design['proposed_rule_id'] ?? null) === 'MB-R371', 'Implemented rule ID must be MB-R371');
assertPci022Design(($design['evidence_type'] ?? null) === 'hybrid', '2.2.2 evidence must remain hybrid');
assertPci022Design(($design['maximum_mapping_coverage'] ?? null) === 'PARTIAL', '2.2.2 must never exceed PARTIAL mapping coverage');
assertPci022Design(($design['human_verification_required'] ?? null) === true, 'Human verification must remain mandatory');
assertPci022Design(array_column($design['outcomes'] ?? [], 'outcome') === ['FAIL', 'HUMAN_VERIFICATION_REQUIRED', 'UNKNOWN', 'EVIDENCE_COMPLETE'], 'Unexpected proposed outcome set');
assertPci022Design(($design['outcome_precedence'] ?? null) === ['UNKNOWN', 'FAIL', 'HUMAN_VERIFICATION_REQUIRED', 'EVIDENCE_COMPLETE'], 'Unsafe outcome precedence');
assertPci022Design(count($design['false_positive_boundaries'] ?? []) >= 8, 'False-positive boundaries are incomplete');

assertPci022Design(array_keys($example) === ($schema['required'] ?? []), 'Example top-level fields must exactly match the required evidence contract');
assertPci022Design(($example['schema_version'] ?? null) === 1 && ($example['requirement'] ?? null) === '2.2.2', 'Example contract identity is invalid');
assertPci022Design(($example['scope']['components'] ?? []) !== [], 'Example requires at least one scoped component');

$componentIds = array_column($example['scope']['components'], 'id');
$accountIds = array_column($example['accounts'], 'id');
$evidenceIds = array_column($example['evidence'], 'id');
assertPci022Design(count($componentIds) === count(array_unique($componentIds)), 'Duplicate component IDs in example');
assertPci022Design(count($accountIds) === count(array_unique($accountIds)), 'Duplicate account IDs in example');
assertPci022Design(count($evidenceIds) === count(array_unique($evidenceIds)), 'Duplicate evidence IDs in example');

foreach ($example['scope']['components'] as $component) {
    foreach ($component['evidence_refs'] as $reference) {
        assertPci022Design(in_array($reference, $evidenceIds, true), "Broken component evidence reference {$reference}");
    }
}
foreach ($example['accounts'] as $account) {
    assertPci022Design(in_array($account['component_id'], $componentIds, true), "Unknown account component {$account['component_id']}");
    foreach ($account['evidence_refs'] as $reference) {
        assertPci022Design(in_array($reference, $evidenceIds, true), "Broken account evidence reference {$reference}");
    }
}
foreach ($example['evidence'] as $evidence) {
    assertPci022Design(preg_match('/^[a-f0-9]{64}$/', (string) $evidence['sha256']) === 1, "Invalid evidence fingerprint {$evidence['id']}");
}

$exampleKeys = [];
collectPci022Keys($example, $exampleKeys);
foreach ($design['sensitive_data_policy']['forbidden'] ?? [] as $forbiddenKey) {
    assertPci022Design(!in_array(strtolower((string) $forbiddenKey), $exampleKeys, true), "Forbidden credential field in example: {$forbiddenKey}");
}

$review0222 = null;
foreach ($review['requirements'] ?? [] as $entry) {
    if (($entry['requirement'] ?? null) === '2.2.2') {
        $review0222 = $entry;
        break;
    }
}
assertPci022Design(($review0222['decision'] ?? null) === 'IMPLEMENTED_HYBRID_RULE', 'Requirement 2 review must record the implemented hybrid rule');
assertPci022Design(($review0222['design'] ?? null) === 'pci-dss-v4.0.1-requirement-02.2.2-design.json', 'Requirement 2 review must link to the design');

$triage0222 = null;
foreach ($triage['requirements'] ?? [] as $entry) {
    if (($entry['requirement'] ?? null) === '2.2.2') {
        $triage0222 = $entry;
        break;
    }
}
assertPci022Design($triage0222 === null, 'Implemented 2.2.2 must leave gap triage');

echo "PciDssRequirement022EvidenceDesignTest: PASS\n";
