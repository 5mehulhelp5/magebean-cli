<?php

declare(strict_types=1);

namespace Magebean\Engine\Checks;

use DateTimeImmutable;
use Magebean\Engine\Context;
use Throwable;

final class PciEvidenceCheck
{
    private const FORBIDDEN_KEYS = ['password', 'password_hash', 'credential_value', 'secret', 'token', 'private_key', 'authentication_cookie'];

    public function __construct(private readonly Context $ctx)
    {
    }

    public function vendorDefaultAccountsEvidence(array $args): array
    {
        $paths = $args['paths'] ?? ['.magebean/pci/2.2.2-vendor-default-accounts.json', '.magebean/pci-2.2.2-evidence.json'];
        if (!is_array($paths) || $paths === []) {
            $paths = ['.magebean/pci/2.2.2-vendor-default-accounts.json'];
        }
        $selected = null;
        foreach ($paths as $path) {
            $candidate = $this->ctx->abs((string) $path);
            if (is_file($candidate)) {
                $selected = [(string) $path, $candidate];
                break;
            }
        }
        if ($selected === null) {
            return [null, '[UNKNOWN] PCI DSS 2.2.2 vendor default account evidence file not found', [
                'outcome' => 'UNKNOWN',
                'paths' => array_values(array_map('strval', $paths)),
                'reason' => 'evidence_file_missing',
                'human_verification_required' => true,
            ]];
        }

        [$relativePath, $absolutePath] = $selected;
        $content = @file_get_contents($absolutePath);
        if (!is_string($content)) {
            return $this->unknown($relativePath, ['Evidence file is unreadable.']);
        }
        try {
            $document = json_decode($content, true, 512, JSON_THROW_ON_ERROR);
        } catch (Throwable $exception) {
            return $this->unknown($relativePath, ['Invalid JSON: ' . $exception->getMessage()]);
        }
        if (!is_array($document)) {
            return $this->unknown($relativePath, ['Evidence document must be a JSON object.']);
        }

        $errors = $this->structuralErrors($document);
        if ($errors !== []) {
            return $this->unknown($relativePath, $errors);
        }

        $failures = [];
        $manualReasons = [];
        foreach ($document['accounts'] as $account) {
            $accountId = (string) $account['id'];
            $classification = (string) $account['classification'];
            $intendedUse = (string) $account['intended_use'];
            $observedState = (string) $account['observed_state'];
            $credentialState = (string) $account['credential_state'];
            if (empty($account['human_verified'])) {
                $manualReasons[] = "Account {$accountId} has not been human verified.";
            }
            if ($classification === 'SUSPECTED_VENDOR_DEFAULT') {
                $manualReasons[] = "Account {$accountId} still has suspected vendor-default classification.";
                continue;
            }
            if ($classification === 'CONFIRMED_NOT_VENDOR_DEFAULT') {
                continue;
            }
            if ($intendedUse === 'UNRESOLVED') {
                $manualReasons[] = "Account {$accountId} intended use is unresolved.";
                continue;
            }
            if ($observedState === 'UNKNOWN') {
                $manualReasons[] = "Account {$accountId} observed state is unknown.";
            }
            if ($intendedUse === 'USED') {
                if ($credentialState === 'DEFAULT_OR_UNCHANGED') {
                    $failures[] = "Confirmed used vendor default account {$accountId} retains a default or unchanged credential.";
                } elseif ($credentialState !== 'CHANGED_FROM_VENDOR_DEFAULT') {
                    $manualReasons[] = "Account {$accountId} changed-from-default credential state is not established.";
                }
                if ($observedState !== 'ENABLED') {
                    $manualReasons[] = "Used account {$accountId} is not observed as enabled.";
                }
            } elseif ($intendedUse === 'NOT_USED') {
                if ($observedState === 'ENABLED') {
                    $failures[] = "Confirmed unused vendor default account {$accountId} remains enabled.";
                } elseif (!in_array($observedState, ['DISABLED', 'REMOVED'], true)) {
                    $manualReasons[] = "Unused account {$accountId} is not proven disabled or removed.";
                }
            }
        }

        foreach (['scope_confirmed' => 'Scope confirmation is incomplete.', 'inventory_complete' => 'Vendor default account inventory is not attested complete.', 'manual_verification_complete' => 'Mandatory manual verification is incomplete.'] as $field => $message) {
            if (empty($document['attestation'][$field])) {
                $manualReasons[] = $message;
            }
        }
        $manualReasons = array_values(array_unique($manualReasons));
        $evidence = [
            'outcome' => $failures !== [] ? 'FAIL' : ($manualReasons !== [] ? 'HUMAN_VERIFICATION_REQUIRED' : 'EVIDENCE_COMPLETE'),
            'path' => $relativePath,
            'assessment_id' => (string) $document['assessment']['id'],
            'components_seen' => count($document['scope']['components']),
            'accounts_seen' => count($document['accounts']),
            'evidence_items_seen' => count($document['evidence']),
            'failures' => $failures,
            'manual_reasons' => $manualReasons,
            'human_verification_required' => true,
            'credential_material_processed' => false,
        ];
        if ($failures !== []) {
            return [false, 'PCI DSS 2.2.2 evidence contains unsafe vendor default account dispositions: ' . implode(' ', $failures), $evidence];
        }
        if ($manualReasons !== []) {
            return [null, '[MANUAL_REVIEW] PCI DSS 2.2.2 vendor default account evidence requires mandatory human verification: ' . implode(' ', $manualReasons), $evidence];
        }
        return [true, 'PCI DSS 2.2.2 evidence package is internally complete; independent human verification remains mandatory and Magebean does not attest compliance.', $evidence];
    }

    private function unknown(string $path, array $errors): array
    {
        return [null, '[UNKNOWN] PCI DSS 2.2.2 evidence is invalid: ' . implode(' ', array_slice($errors, 0, 5)), [
            'outcome' => 'UNKNOWN',
            'path' => $path,
            'errors' => $errors,
            'human_verification_required' => true,
            'credential_material_processed' => false,
        ]];
    }

    private function structuralErrors(array $document): array
    {
        $errors = [];
        $this->rejectUnexpectedKeys($document, ['schema_version', 'requirement', 'assessment', 'scope', 'accounts', 'evidence', 'attestation'], '$', $errors);
        $this->findForbiddenKeys($document, '$', $errors);
        foreach (['schema_version', 'requirement', 'assessment', 'scope', 'accounts', 'evidence', 'attestation'] as $field) {
            if (!array_key_exists($field, $document)) {
                $errors[] = "Missing required field $.{$field}.";
            }
        }
        if ($errors !== []) {
            return $errors;
        }
        if ($document['schema_version'] !== 1 || $document['requirement'] !== '2.2.2') {
            $errors[] = 'Evidence identity must use schema_version 1 and requirement 2.2.2.';
        }
        if (!is_array($document['assessment']) || !is_array($document['scope']) || !is_array($document['accounts']) || !is_array($document['evidence']) || !is_array($document['attestation'])) {
            $errors[] = 'Assessment, scope, accounts, evidence, and attestation must use their declared object or array types.';
            return $errors;
        }

        $assessment = $document['assessment'];
        $this->rejectUnexpectedKeys($assessment, ['id', 'generated_at', 'prepared_by'], '$.assessment', $errors);
        if (!$this->validId($assessment['id'] ?? null) || !$this->validTimestamp($assessment['generated_at'] ?? null)) {
            $errors[] = 'Invalid assessment identifier or timestamp.';
        }
        if (!is_array($assessment['prepared_by'] ?? null)) {
            $errors[] = 'Missing $.assessment.prepared_by object.';
        } else {
            $this->rejectUnexpectedKeys($assessment['prepared_by'], ['name', 'role'], '$.assessment.prepared_by', $errors);
            foreach (['name', 'role'] as $field) {
                if (!$this->nonEmptyString($assessment['prepared_by'][$field] ?? null)) {
                    $errors[] = "Invalid $.assessment.prepared_by.{$field}.";
                }
            }
        }

        $scope = $document['scope'];
        $this->rejectUnexpectedKeys($scope, ['entity_role', 'environment', 'components'], '$.scope', $errors);
        if (!in_array($scope['entity_role'] ?? null, ['MERCHANT', 'SERVICE_PROVIDER', 'MERCHANT_AND_SERVICE_PROVIDER'], true)) {
            $errors[] = 'Invalid $.scope.entity_role.';
        }
        if (!in_array($scope['environment'] ?? null, ['PRODUCTION', 'STAGING', 'DISASTER_RECOVERY', 'OTHER'], true)) {
            $errors[] = 'Invalid $.scope.environment.';
        }
        if (!is_array($scope['components'] ?? null) || $scope['components'] === []) {
            $errors[] = '$.scope.components must contain at least one component.';
            return $errors;
        }

        $evidenceIds = [];
        foreach ($document['evidence'] as $index => $item) {
            $path = "$.evidence[{$index}]";
            if (!is_array($item)) {
                $errors[] = "{$path} must be an object.";
                continue;
            }
            $this->rejectUnexpectedKeys($item, ['id', 'type', 'reference', 'collected_at', 'sha256'], $path, $errors);
            $id = $item['id'] ?? null;
            if (!$this->validId($id)) {
                $errors[] = "Invalid {$path}.id.";
            } elseif (isset($evidenceIds[$id])) {
                $errors[] = "Duplicate evidence id {$id}.";
            } else {
                $evidenceIds[$id] = true;
            }
            if (!in_array($item['type'] ?? null, ['CONFIGURATION_EXPORT', 'DATABASE_QUERY_RESULT', 'VENDOR_DOCUMENTATION', 'SCREENSHOT', 'OBSERVATION_RECORD', 'INTERVIEW_RECORD'], true)) {
                $errors[] = "Invalid {$path}.type.";
            }
            if (!$this->nonEmptyString($item['reference'] ?? null) || !$this->validTimestamp($item['collected_at'] ?? null)) {
                $errors[] = "Invalid {$path} reference or timestamp.";
            }
            if (!is_string($item['sha256'] ?? null) || preg_match('/^[a-f0-9]{64}$/', $item['sha256']) !== 1) {
                $errors[] = "Invalid {$path}.sha256.";
            }
        }

        $componentIds = [];
        foreach ($scope['components'] as $index => $component) {
            $path = "$.scope.components[{$index}]";
            if (!is_array($component)) {
                $errors[] = "{$path} must be an object.";
                continue;
            }
            $this->rejectUnexpectedKeys($component, ['id', 'name', 'type', 'vendor', 'product', 'in_scope', 'inventory_source', 'evidence_refs'], $path, $errors);
            $id = $component['id'] ?? null;
            if (!$this->validId($id)) {
                $errors[] = "Invalid {$path}.id.";
            } elseif (isset($componentIds[$id])) {
                $errors[] = "Duplicate component id {$id}.";
            } else {
                $componentIds[$id] = true;
            }
            if (!in_array($component['type'] ?? null, ['MAGENTO_APPLICATION', 'OPERATING_SYSTEM', 'DATABASE', 'WEB_SERVER', 'SECURITY_SERVICE', 'NETWORK_DEVICE', 'CLOUD_SERVICE', 'PAYMENT_APPLICATION', 'POS_TERMINAL', 'OTHER'], true)) {
                $errors[] = "Invalid {$path}.type.";
            }
            foreach (['name', 'vendor', 'product', 'inventory_source'] as $field) {
                if (!$this->nonEmptyString($component[$field] ?? null)) {
                    $errors[] = "Invalid {$path}.{$field}.";
                }
            }
            if (!is_bool($component['in_scope'] ?? null)) {
                $errors[] = "Invalid {$path}.in_scope.";
            }
            $this->validateReferences($component['evidence_refs'] ?? null, $evidenceIds, "{$path}.evidence_refs", $errors);
        }

        $accountIds = [];
        foreach ($document['accounts'] as $index => $account) {
            $path = "$.accounts[{$index}]";
            if (!is_array($account)) {
                $errors[] = "{$path} must be an object.";
                continue;
            }
            $this->rejectUnexpectedKeys($account, ['id', 'component_id', 'vendor', 'product', 'account_name', 'classification', 'intended_use', 'observed_state', 'credential_state', 'verification_methods', 'evidence_refs', 'human_verified', 'notes'], $path, $errors);
            $id = $account['id'] ?? null;
            if (!$this->validId($id)) {
                $errors[] = "Invalid {$path}.id.";
            } elseif (isset($accountIds[$id])) {
                $errors[] = "Duplicate account id {$id}.";
            } else {
                $accountIds[$id] = true;
            }
            if (!isset($componentIds[$account['component_id'] ?? null])) {
                $errors[] = "Unknown {$path}.component_id.";
            }
            foreach (['vendor', 'product', 'account_name'] as $field) {
                if (!$this->nonEmptyString($account[$field] ?? null)) {
                    $errors[] = "Invalid {$path}.{$field}.";
                }
            }
            if (!in_array($account['classification'] ?? null, ['CONFIRMED_VENDOR_DEFAULT', 'SUSPECTED_VENDOR_DEFAULT', 'CONFIRMED_NOT_VENDOR_DEFAULT'], true)) {
                $errors[] = "Invalid {$path}.classification.";
            }
            if (!in_array($account['intended_use'] ?? null, ['USED', 'NOT_USED', 'UNRESOLVED'], true)) {
                $errors[] = "Invalid {$path}.intended_use.";
            }
            if (!in_array($account['observed_state'] ?? null, ['ENABLED', 'DISABLED', 'REMOVED', 'UNKNOWN'], true)) {
                $errors[] = "Invalid {$path}.observed_state.";
            }
            if (!in_array($account['credential_state'] ?? null, ['CHANGED_FROM_VENDOR_DEFAULT', 'DEFAULT_OR_UNCHANGED', 'NOT_APPLICABLE', 'UNKNOWN'], true)) {
                $errors[] = "Invalid {$path}.credential_state.";
            }
            $methods = $account['verification_methods'] ?? null;
            if (!is_array($methods) || $methods === [] || count($methods) !== count(array_unique($methods))) {
                $errors[] = "Invalid {$path}.verification_methods.";
            } else {
                foreach ($methods as $method) {
                    if (!in_array($method, ['CONFIGURATION_EXPORT', 'DATABASE_QUERY', 'VENDOR_DOCUMENTATION', 'SYSTEM_OBSERVATION', 'PERSONNEL_INTERVIEW'], true)) {
                        $errors[] = "Invalid verification method on {$path}.";
                    }
                }
            }
            $this->validateReferences($account['evidence_refs'] ?? null, $evidenceIds, "{$path}.evidence_refs", $errors);
            if (!is_bool($account['human_verified'] ?? null)) {
                $errors[] = "Invalid {$path}.human_verified.";
            }
            if (array_key_exists('notes', $account) && !$this->nonEmptyString($account['notes'])) {
                $errors[] = "Invalid {$path}.notes.";
            }
        }

        $attestation = $document['attestation'];
        $this->rejectUnexpectedKeys($attestation, ['scope_confirmed', 'inventory_complete', 'manual_verification_complete', 'reviewed_by', 'reviewed_at', 'notes'], '$.attestation', $errors);
        foreach (['scope_confirmed', 'inventory_complete', 'manual_verification_complete'] as $field) {
            if (!is_bool($attestation[$field] ?? null)) {
                $errors[] = "Invalid $.attestation.{$field}.";
            }
        }
        if (!$this->nonEmptyString($attestation['reviewed_by'] ?? null) || !$this->validTimestamp($attestation['reviewed_at'] ?? null)) {
            $errors[] = 'Invalid attestation reviewer or timestamp.';
        }
        if (array_key_exists('notes', $attestation) && !$this->nonEmptyString($attestation['notes'])) {
            $errors[] = 'Invalid $.attestation.notes.';
        }
        return array_values(array_unique($errors));
    }

    private function validateReferences(mixed $references, array $known, string $path, array &$errors): void
    {
        if (!is_array($references) || $references === [] || count($references) !== count(array_unique($references))) {
            $errors[] = "Invalid {$path}.";
            return;
        }
        foreach ($references as $reference) {
            if (!$this->validId($reference) || !isset($known[$reference])) {
                $errors[] = "Broken evidence reference {$reference} at {$path}.";
            }
        }
    }

    private function rejectUnexpectedKeys(array $value, array $allowed, string $path, array &$errors): void
    {
        foreach (array_keys($value) as $key) {
            if (is_string($key) && !in_array($key, $allowed, true)) {
                $errors[] = "Unexpected field {$path}.{$key}.";
            }
        }
    }

    private function findForbiddenKeys(array $value, string $path, array &$errors): void
    {
        foreach ($value as $key => $child) {
            $childPath = is_string($key) ? "{$path}.{$key}" : "{$path}[{$key}]";
            if (is_string($key) && in_array(strtolower($key), self::FORBIDDEN_KEYS, true)) {
                $errors[] = "Forbidden credential field {$childPath}.";
            }
            if (is_array($child)) {
                $this->findForbiddenKeys($child, $childPath, $errors);
            }
        }
    }

    private function validId(mixed $value): bool
    {
        return is_string($value) && preg_match('/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/', $value) === 1;
    }

    private function nonEmptyString(mixed $value): bool
    {
        return is_string($value) && trim($value) !== '' && strlen($value) <= 500;
    }

    private function validTimestamp(mixed $value): bool
    {
        if (!is_string($value) || !str_contains($value, 'T')) {
            return false;
        }
        try {
            new DateTimeImmutable($value);
            return true;
        } catch (Throwable) {
            return false;
        }
    }
}
