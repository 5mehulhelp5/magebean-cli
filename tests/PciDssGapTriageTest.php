<?php

declare(strict_types=1);

function assertPciTriage(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

$root = dirname(__DIR__);
$triage = json_decode((string) file_get_contents($root . '/src/Rules/standards/pci-dss-v4.0.1-gap-triage.json'), true, 512, JSON_THROW_ON_ERROR);
$coverage = json_decode((string) file_get_contents($root . '/src/Rules/standards/pci-dss-v4.0.1-coverage.json'), true, 512, JSON_THROW_ON_ERROR);
$registry = json_decode((string) file_get_contents($root . '/src/Rules/standards/pci-dss-v4.0.1.json'), true, 512, JSON_THROW_ON_ERROR);

$unmapped = [];
foreach ($coverage['requirements'] ?? [] as $requirement) {
    if (($requirement['coverage'] ?? null) === 'UNMAPPED') {
        $unmapped[$requirement['id']] = true;
    }
}
$registryById = [];
foreach ($registry['requirements'] ?? [] as $requirement) {
    $registryById[$requirement['id']] = $requirement;
}

$allowedCategories = ['AUTOMATION_CANDIDATE', 'EXTERNAL_SYSTEM_EVIDENCE', 'CONTEXTUAL_APPLICABILITY', 'HUMAN_ONLY'];
$allowedPriorities = ['HIGH', 'MEDIUM', 'NONE'];
$categoryCounts = array_fill_keys($allowedCategories, 0);
$priorityCounts = array_fill_keys($allowedPriorities, 0);
$seen = [];
$index = [];

assertPciTriage(($triage['registry'] ?? null) === 'pci-dss-v4.0.1.json', 'Triage registry link is invalid');
assertPciTriage(($triage['coverage_matrix'] ?? null) === 'pci-dss-v4.0.1-coverage.json', 'Triage coverage link is invalid');
assertPciTriage(count($triage['requirements'] ?? []) === 245, 'All 245 unmapped requirements must be triaged');

foreach ($triage['requirements'] as $entry) {
    $id = (string) ($entry['requirement'] ?? '');
    assertPciTriage(isset($unmapped[$id]) && !isset($seen[$id]), "Unknown, mapped, or duplicate triage requirement {$id}");
    $seen[$id] = true;
    $registryRequirement = $registryById[$id];
    assertPciTriage(($entry['source_pdf_page'] ?? null) === ($registryRequirement['source']['pdf_page'] ?? null), "Source page mismatch for {$id}");
    assertPciTriage(($entry['testing_methods'] ?? null) === ($registryRequirement['testing_methods'] ?? null), "Testing methods mismatch for {$id}");
    assertPciTriage(($entry['entity_restriction'] ?? null) === ($registryRequirement['entity_restriction'] ?? null), "Entity restriction mismatch for {$id}");

    $category = (string) ($entry['category'] ?? '');
    $priority = (string) ($entry['priority'] ?? '');
    assertPciTriage(in_array($category, $allowedCategories, true), "Invalid category for {$id}");
    assertPciTriage(in_array($priority, $allowedPriorities, true), "Invalid priority for {$id}");
    assertPciTriage(in_array($entry['review_state'] ?? null, ['INITIAL_TRIAGE', 'CRITERION_REVIEWED', 'DESIGN_COMPLETE'], true), "Review state mismatch for {$id}");
    foreach (['objective', 'candidate_surface', 'rationale', 'next_action'] as $field) {
        $value = (string) ($entry[$field] ?? '');
        assertPciTriage($value !== '' && preg_match('/[^\x00-\x7F]/', $value) !== 1, "{$field} must be non-empty English ASCII for {$id}");
    }

    if ($category === 'AUTOMATION_CANDIDATE') {
        assertPciTriage(in_array($priority, ['HIGH', 'MEDIUM'], true), "Automation candidate {$id} requires engineering priority");
    } else {
        assertPciTriage($priority === 'NONE', "Non-automation entry {$id} must not imply engineering priority or PCI applicability");
    }
    if (($entry['overlay'] ?? null) !== null || $entry['entity_restriction'] === 'service_provider_only') {
        assertPciTriage($category === 'CONTEXTUAL_APPLICABILITY', "Conditional requirement {$id} must be triaged contextually");
    }

    $categoryCounts[$category]++;
    $priorityCounts[$priority]++;
    $index[$id] = $entry;
}

assertPciTriage(count($seen) === count($unmapped), 'Triage does not exactly match the unmapped requirement set');
assertPciTriage($categoryCounts === ['AUTOMATION_CANDIDATE' => 0, 'EXTERNAL_SYSTEM_EVIDENCE' => 121, 'CONTEXTUAL_APPLICABILITY' => 48, 'HUMAN_ONLY' => 76], 'Unexpected triage category distribution');
assertPciTriage($priorityCounts === ['HIGH' => 0, 'MEDIUM' => 0, 'NONE' => 245], 'Unexpected engineering priority distribution');
assertPciTriage(($triage['summary']['categories'] ?? null) === $categoryCounts, 'Triage category summary is stale');
assertPciTriage(($triage['summary']['automation_priority'] ?? null) === $priorityCounts, 'Triage priority summary is stale');
assertPciTriage(!isset($index['2.2.2']), 'Implemented Requirement 2.2.2 must leave gap triage');
assertPciTriage(($index['2.2.3']['category'] ?? null) === 'EXTERNAL_SYSTEM_EVIDENCE', 'Mixed primary functions 2.2.3 require external evidence');
assertPciTriage(!isset($index['2.2.6']) && !isset($index['2.2.7']), 'Mapped Requirement 2 criteria must leave gap triage');
assertPciTriage(($index['9.2.1']['category'] ?? null) === 'EXTERNAL_SYSTEM_EVIDENCE', 'Physical access criterion 9.2.1 should require external evidence');
assertPciTriage(($index['12.1.1']['category'] ?? null) === 'HUMAN_ONLY', 'Policy criterion 12.1.1 should be human-only');
assertPciTriage(($index['A1.1.1']['category'] ?? null) === 'CONTEXTUAL_APPLICABILITY', 'Appendix A1 criterion must be contextual');

echo "PciDssGapTriageTest: PASS\n";
