<?php
declare(strict_types=1);
namespace Magebean\Engine;

/** Compiles legacy evidence mappings into one assessment definition per ASVS identity. */
final class RequirementCatalog
{
    public static function supports(array $profile): bool
    {
        return strtolower((string)($profile['standard']['id'] ?? '')) === 'owasp-asvs';
    }

    public static function compile(array $pack, array $profile, array $capabilities = [], bool $restrictToAvailable = false): array
    {
        if (!self::supports($profile)) return $pack;
        if (($profile['standard']['version'] ?? '') !== '5.0.0') throw new \RuntimeException('Unsupported ASVS requirement version.');
        $standard = json_decode((string)file_get_contents(__DIR__ . '/../Rules/standards/owasp-asvs-v5.0.0.json'), true, 512, JSON_THROW_ON_ERROR);
        $references = array_column($standard['requirements'], null, 'id');
        $nativeCatalog = json_decode((string)file_get_contents(__DIR__ . '/../Rules/requirements/asvs-v5.0.0.json'), true, 512, JSON_THROW_ON_ERROR)['implementations'];
        $assessmentLevel = (int)($profile['standard']['level'] ?? 0);
        if (!in_array($assessmentLevel, [1, 2, 3], true)) throw new \RuntimeException('Invalid ASVS assessment level.');
        $sources = []; $bundled = [];
        foreach ($pack['rules'] ?? [] as $rule) $sources[strtoupper((string)$rule['id'])] = $rule;
        foreach (RulePackLoader::loadAll()['rules'] as $rule) $bundled[strtoupper((string)$rule['id'])] = $rule;
        $definitions = []; $seen = [];
        foreach ($profile['requirement_coverage'] ?? [] as $coverage) {
            $reference = trim((string)($coverage['id'] ?? ''));
            if (!preg_match('/^\d+\.\d+\.\d+$/D', $reference) || isset($seen[$reference])) throw new \RuntimeException('Invalid or duplicate ASVS requirement identity: ' . $reference);
            if (!isset($references[$reference]) || $references[$reference]['level'] > $assessmentLevel) throw new \RuntimeException('ASVS requirement is not valid at this assessment level: ' . $reference);
            $seen[$reference] = true;
            $id = 'OWASP-ASVS:5.0.0:' . $reference;
            $native = isset($coverage['implementation']) ? ($nativeCatalog[$reference] ?? null) : null;
            if ($native !== null && $coverage['implementation'] !== $native['id']) throw new \RuntimeException('Invalid native requirement implementation identity.');
            if (isset($coverage['implementation']) && $native === null) throw new \RuntimeException('Unknown native requirement implementation.');
            if ($restrictToAvailable && array_intersect(array_keys($sources), $coverage['rules'] ?? []) === [] && ($native === null || !in_array($native['control'], $pack['controls'] ?? [], true))) continue;
            $groups = []; $sourceIds = []; $controls = []; $severity = 'low'; $active = false;
            foreach ($coverage['rules'] ?? [] as $sourceId) {
                $sourceId = strtoupper((string)$sourceId);
                $source = $sources[$sourceId] ?? null; $template = $source ?? $bundled[$sourceId] ?? null;
                $capability = $template['applicability']['capability'] ?? null;
                if ($capability !== null && !self::enabled($capabilities, (string)$capability)) continue;
                $active = true; $sourceIds[] = $sourceId;
                if ($template !== null) {
                    $controls[] = (string)$template['control'];
                    if (self::rank((string)$template['severity']) > self::rank($severity)) $severity = (string)$template['severity'];
                }
                $groups[] = $source === null
                    ? ['id' => $sourceId, 'op' => 'all', 'checks' => [], 'missing' => true]
                    : ['id' => $sourceId, 'op' => $source['op'] ?? 'all', 'checks' => $source['checks'] ?? [], 'missing' => false];
            }
            if ($native !== null) {
                $active = true; $controls[] = $native['control'];
                if (self::rank($native['severity']) > self::rank($severity)) $severity = $native['severity'];
                $groups[] = ['id' => $native['id'], 'op' => 'all', 'checks' => $native['checks'], 'missing' => false];
            }
            $requiredGroups = [];
            foreach ($groups as $group) {
                $human = []; $technical = [];
                foreach ($group['checks'] as $check) {
                    if (in_array($check['name'] ?? '', ['human_manual_review_required', 'manual_review'], true)) $human[] = $check;
                    else $technical[] = $check;
                }
                if ($technical !== [] || $group['missing']) { $group['checks'] = $technical; $requiredGroups[] = $group; }
                if ($human !== []) $requiredGroups[] = ['id' => $group['id'], 'op' => 'all', 'checks' => $human, 'missing' => false];
            }
            $groups = $requiredGroups;
            // Explicitly disabled contextual requirements are omitted; unmapped criteria remain gaps.
            if (!$active && ($coverage['rules'] ?? []) !== []) continue;
            $status = (string)($coverage['status'] ?? 'NOT_YET_COVERED');
            if (!in_array($status, ['AUTOMATED', 'PARTIALLY_AUTOMATED', 'MANUAL_REVIEW', 'CONTEXT_REQUIRED', 'NOT_YET_COVERED'], true)) throw new \RuntimeException('Unsupported requirement coverage status.');
            if ($native !== null && $status !== $native['coverage']) throw new \RuntimeException('Native evidence coverage must remain partial.');
            $manual = in_array($status, ['MANUAL_REVIEW', 'CONTEXT_REQUIRED'], true);
            $requirement = ['standard' => 'OWASP-ASVS', 'version' => '5.0.0', 'id' => $reference, 'level' => $references[$reference]['level']];
            $definitions[] = [
                'id' => $id, 'title' => $native['title'] ?? 'ASVS 5.0.0 requirement ' . $reference,
                'control' => (($availableControls = array_values(array_intersect($controls, $pack['controls'] ?? [])))[0] ?? $controls[0] ?? 'ASVS'), 'severity' => $severity,
                'verification' => $manual ? 'manual' : 'automated', 'op' => 'all',
                'assessment_level' => $assessmentLevel, 'requirement' => $requirement, 'requirements' => [$requirement],
                'legacy_rule_ids' => array_values(array_unique(array_map('strtoupper', $coverage['rules'] ?? []))), 'source_controls' => array_values(array_unique($controls)),
                'coverage' => $status,
                'checks' => [['name' => 'requirement_assessment', 'args' => [
                    'requirement' => $requirement, 'assessment_level' => $assessmentLevel, 'coverage' => $status,
                    'groups' => $groups, 'review' => (string)($coverage['note'] ?? ''),
                ]]],
                'profile' => ['id' => $profile['id'], 'title' => $profile['title'] ?? '', 'mapping' => ['mappings' => [['requirement' => $reference, 'coverage' => $status]]]],
            ];
        }
        if ($seen === []) throw new \RuntimeException('ASVS profile has no requirement coverage inventory.');
        $pack['rules'] = $definitions;
        $pack['controls'] = array_values(array_unique(array_column($definitions, 'control')));
        $pack['assessment_model'] = 'requirement-v1';
        return $pack;
    }

    private static function enabled(array $capabilities, string $name): bool
    {
        if (array_is_list($capabilities)) return in_array($name, $capabilities, true);
        return filter_var($capabilities[$name] ?? false, FILTER_VALIDATE_BOOLEAN);
    }

    private static function rank(string $severity): int
    {
        return ['low' => 0, 'medium' => 1, 'high' => 2, 'critical' => 3][$severity] ?? 0;
    }

    /** Explicit canonical selection has no implicit profile-level choice. */
    public static function forProfile(string $name, array $capabilities = []): array
    {
        $profile = ProfileLoader::loadBundled($name);
        return self::compile(ProfileLoader::apply(RulePackLoader::loadAll(), $profile, false, $capabilities), $profile, $capabilities);
    }
}
