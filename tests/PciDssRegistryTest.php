<?php

declare(strict_types=1);

function assertPciRegistry(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

$root = dirname(__DIR__);
$registryPath = $root . '/src/Rules/standards/pci-dss-v4.0.1.json';
$schemaPath = $root . '/src/Rules/standards/pci-dss-v4.0.1.schema.json';
$profilePath = $root . '/src/Rules/profiles/pci-dss-v4.0.1.json';
$sourcePath = $root . '/docs/PCI-DSS-v4_0_1.pdf';

assertPciRegistry(is_file($registryPath), 'PCI DSS registry is missing');
assertPciRegistry(is_file($schemaPath), 'PCI DSS registry schema is missing');
assertPciRegistry(is_file($sourcePath), 'Official PCI DSS source PDF is missing');

$registry = json_decode((string) file_get_contents($registryPath), true, 512, JSON_THROW_ON_ERROR);
$schema = json_decode((string) file_get_contents($schemaPath), true, 512, JSON_THROW_ON_ERROR);
$requirements = $registry['requirements'] ?? [];
$groups = $registry['objective_groups'] ?? [];

assertPciRegistry(($schema['$schema'] ?? null) === 'https://json-schema.org/draft/2020-12/schema', 'Unexpected JSON Schema dialect');
assertPciRegistry(($registry['standard'] ?? null) === 'PCI DSS', 'Unexpected standard name');
assertPciRegistry(($registry['version'] ?? null) === '4.0.1', 'Unexpected PCI DSS version');
assertPciRegistry(count($requirements) === 280, 'Registry must contain 250 core and 30 additional requirements');
assertPciRegistry(count($groups) === 71, 'Registry must contain 63 core and 8 overlay objective groups');

$expectedCore = [1 => 19, 2 => 11, 3 => 29, 4 => 6, 5 => 13, 6 => 19, 7 => 12, 8 => 29, 9 => 27, 10 => 27, 11 => 21, 12 => 37];
$expectedOverlays = ['A1' => 7, 'A2' => 3, 'A3' => 20];
$actualCore = [];
$actualOverlays = [];
$ids = [];
$groupIds = array_column($groups, 'id');

foreach ($requirements as $requirement) {
    $id = (string) ($requirement['id'] ?? '');
    assertPciRegistry($id !== '' && !isset($ids[$id]), "Duplicate or empty requirement ID: {$id}");
    $ids[$id] = true;
    assertPciRegistry(in_array($requirement['objective_group'] ?? null, $groupIds, true), "Unknown objective group for {$id}");
    assertPciRegistry(($requirement['testing_methods'] ?? []) !== [], "Testing methods missing for {$id}");
    foreach ($requirement['testing_methods'] as $method) {
        assertPciRegistry(in_array($method, ['examine', 'interview', 'observe'], true), "Invalid testing method for {$id}: {$method}");
    }
    assertPciRegistry(preg_match('/^[a-f0-9]{64}$/', (string) ($requirement['source']['content_sha256'] ?? '')) === 1, "Invalid source fingerprint for {$id}");
    assertPciRegistry((int) ($requirement['source']['pdf_page'] ?? 0) >= 1 && (int) ($requirement['source']['pdf_page'] ?? 0) <= 397, "Invalid PDF page for {$id}");

    if (($requirement['kind'] ?? null) === 'core') {
        $principal = (int) ($requirement['principal_requirement'] ?? 0);
        $actualCore[$principal] = ($actualCore[$principal] ?? 0) + 1;
    } else {
        $overlay = (string) ($requirement['overlay'] ?? '');
        $actualOverlays[$overlay] = ($actualOverlays[$overlay] ?? 0) + 1;
    }
}

ksort($actualCore);
ksort($actualOverlays);
assertPciRegistry($actualCore === $expectedCore, 'Core requirement distribution does not match PCI DSS 4.0.1');
assertPciRegistry($actualOverlays === $expectedOverlays, 'Appendix requirement distribution does not match PCI DSS 4.0.1');

$profile = json_decode((string) file_get_contents($profilePath), true, 512, JSON_THROW_ON_ERROR);
foreach ($profile['rules'] ?? [] as $rule) {
    foreach ($rule['requirements'] ?? [] as $requirementId) {
        assertPciRegistry(isset($ids[$requirementId]), "PCI profile maps unknown requirement {$requirementId}");
    }
}

echo "PciDssRegistryTest: PASS\n";
