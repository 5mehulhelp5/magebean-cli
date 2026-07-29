<?php

declare(strict_types=1);

namespace Magebean\Engine\Cve;

/**
 * Normalizes OSV severity metadata and calculates CVSS v2/v3 base scores.
 *
 * OSV stores CVSS scores as vector strings, not numeric values. Severity may
 * also be scoped to an affected package instead of the top-level advisory.
 */
final class OsvSeverity
{
    /**
     * @return array{label: string, score: string, vector: string, type: string}
     */
    public static function resolve(array $vulnerability, ?array $affected = null): array
    {
        $severityGroups = [];
        if (is_array($affected['severity'] ?? null)) {
            $severityGroups[] = $affected['severity'];
        }
        if (is_array($vulnerability['severity'] ?? null)) {
            $severityGroups[] = $vulnerability['severity'];
        }

        $unscoredVector = null;
        foreach ($severityGroups as $severityItems) {
            foreach ($severityItems as $severity) {
                if (!is_array($severity)) {
                    continue;
                }

                $type = strtoupper(trim((string)($severity['type'] ?? '')));
                $rawScore = trim((string)($severity['score'] ?? ''));
                if ($rawScore === '') {
                    continue;
                }

                $numericScore = self::numericScore($type, $rawScore);
                if ($numericScore !== null) {
                    return [
                        'label' => self::labelByScore($numericScore),
                        'score' => self::formatScore($numericScore),
                        'vector' => self::isCvssVector($rawScore) ? $rawScore : '',
                        'type' => $type,
                    ];
                }

                if (self::isCvssVector($rawScore) && $unscoredVector === null) {
                    $unscoredVector = ['vector' => $rawScore, 'type' => $type];
                }
            }
        }

        foreach ([
            $affected['database_specific']['severity'] ?? null,
            $affected['ecosystem_specific']['severity'] ?? null,
            $vulnerability['database_specific']['severity'] ?? null,
            $vulnerability['ecosystem_specific']['severity'] ?? null,
        ] as $qualitativeSeverity) {
            $label = self::normalizeLabel($qualitativeSeverity);
            if ($label !== null) {
                return [
                    'label' => $label,
                    'score' => '',
                    'vector' => $unscoredVector['vector'] ?? '',
                    'type' => $unscoredVector['type'] ?? '',
                ];
            }
        }

        if ($unscoredVector !== null) {
            return [
                'label' => 'Severity score unavailable',
                'score' => '',
                'vector' => $unscoredVector['vector'],
                'type' => $unscoredVector['type'],
            ];
        }

        return [
            'label' => 'Severity not published',
            'score' => '',
            'vector' => '',
            'type' => '',
        ];
    }

    private static function numericScore(string $type, string $rawScore): ?float
    {
        if (is_numeric($rawScore)) {
            $score = (float)$rawScore;
            return $score >= 0.0 && $score <= 10.0 ? $score : null;
        }

        if ($type === 'CVSS_V3' || str_starts_with($rawScore, 'CVSS:3.')) {
            return self::cvssV3Score($rawScore);
        }

        if ($type === 'CVSS_V2' || preg_match('/^(?:CVSS2#)?AV:/i', $rawScore) === 1) {
            return self::cvssV2Score($rawScore);
        }

        return null;
    }

    private static function cvssV3Score(string $vector): ?float
    {
        $metrics = self::parseVector($vector);
        $scope = $metrics['S'] ?? null;
        if (!in_array($scope, ['U', 'C'], true)) {
            return null;
        }

        $av = self::weight($metrics, 'AV', ['N' => 0.85, 'A' => 0.62, 'L' => 0.55, 'P' => 0.20]);
        $ac = self::weight($metrics, 'AC', ['L' => 0.77, 'H' => 0.44]);
        $ui = self::weight($metrics, 'UI', ['N' => 0.85, 'R' => 0.62]);
        $prWeights = $scope === 'C'
            ? ['N' => 0.85, 'L' => 0.68, 'H' => 0.50]
            : ['N' => 0.85, 'L' => 0.62, 'H' => 0.27];
        $pr = self::weight($metrics, 'PR', $prWeights);
        $confidentiality = self::weight($metrics, 'C', ['N' => 0.0, 'L' => 0.22, 'H' => 0.56]);
        $integrity = self::weight($metrics, 'I', ['N' => 0.0, 'L' => 0.22, 'H' => 0.56]);
        $availability = self::weight($metrics, 'A', ['N' => 0.0, 'L' => 0.22, 'H' => 0.56]);

        if (in_array(null, [$av, $ac, $ui, $pr, $confidentiality, $integrity, $availability], true)) {
            return null;
        }

        $impactSubScore = 1 - ((1 - $confidentiality) * (1 - $integrity) * (1 - $availability));
        $impact = $scope === 'U'
            ? 6.42 * $impactSubScore
            : 7.52 * ($impactSubScore - 0.029) - 3.25 * (($impactSubScore - 0.02) ** 15);
        if ($impact <= 0) {
            return 0.0;
        }

        $exploitability = 8.22 * $av * $ac * $pr * $ui;
        $baseScore = $scope === 'U'
            ? min($impact + $exploitability, 10.0)
            : min(1.08 * ($impact + $exploitability), 10.0);

        return self::roundUpOneDecimal($baseScore);
    }

    private static function cvssV2Score(string $vector): ?float
    {
        $metrics = self::parseVector(preg_replace('/^CVSS2#/i', '', $vector) ?? $vector);
        $av = self::weight($metrics, 'AV', ['L' => 0.395, 'A' => 0.646, 'N' => 1.0]);
        $ac = self::weight($metrics, 'AC', ['H' => 0.35, 'M' => 0.61, 'L' => 0.71]);
        $authentication = self::weight($metrics, 'AU', ['M' => 0.45, 'S' => 0.56, 'N' => 0.704]);
        $confidentiality = self::weight($metrics, 'C', ['N' => 0.0, 'P' => 0.275, 'C' => 0.66]);
        $integrity = self::weight($metrics, 'I', ['N' => 0.0, 'P' => 0.275, 'C' => 0.66]);
        $availability = self::weight($metrics, 'A', ['N' => 0.0, 'P' => 0.275, 'C' => 0.66]);

        if (in_array(null, [$av, $ac, $authentication, $confidentiality, $integrity, $availability], true)) {
            return null;
        }

        $impact = 10.41 * (1 - ((1 - $confidentiality) * (1 - $integrity) * (1 - $availability)));
        if ($impact <= 0) {
            return 0.0;
        }

        $exploitability = 20 * $av * $ac * $authentication;
        return round((((0.6 * $impact) + (0.4 * $exploitability) - 1.5) * 1.176), 1);
    }

    /** @return array<string, string> */
    private static function parseVector(string $vector): array
    {
        $metrics = [];
        foreach (explode('/', $vector) as $part) {
            if (!str_contains($part, ':')) {
                continue;
            }
            [$name, $value] = explode(':', $part, 2);
            $name = strtoupper(trim($name));
            $value = strtoupper(trim($value));
            if ($name !== '' && $value !== '') {
                $metrics[$name] = $value;
            }
        }
        return $metrics;
    }

    /**
     * @param array<string, string> $metrics
     * @param array<string, float> $weights
     */
    private static function weight(array $metrics, string $metric, array $weights): ?float
    {
        $value = $metrics[$metric] ?? null;
        return $value !== null && array_key_exists($value, $weights) ? $weights[$value] : null;
    }

    private static function normalizeLabel(mixed $severity): ?string
    {
        if (!is_string($severity)) {
            return null;
        }

        return match (strtolower(trim($severity))) {
            'critical' => 'Critical',
            'high', 'important' => 'High',
            'medium', 'moderate' => 'Medium',
            'low', 'minor', 'negligible' => 'Low',
            'none' => 'None',
            default => null,
        };
    }

    private static function labelByScore(float $score): string
    {
        return match (true) {
            $score >= 9.0 => 'Critical',
            $score >= 7.0 => 'High',
            $score >= 4.0 => 'Medium',
            $score > 0.0 => 'Low',
            default => 'None',
        };
    }

    private static function isCvssVector(string $score): bool
    {
        return str_starts_with(strtoupper($score), 'CVSS:')
            || preg_match('/^(?:CVSS2#)?AV:/i', $score) === 1;
    }

    private static function roundUpOneDecimal(float $value): float
    {
        return ceil(($value * 10) - 1.0e-9) / 10;
    }

    private static function formatScore(float $score): string
    {
        return number_format($score, 1, '.', '');
    }
}
