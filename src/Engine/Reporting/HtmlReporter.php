<?php

declare(strict_types=1);

namespace Magebean\Engine\Reporting;

final class HtmlReporter implements Reporter
{
    private string $tpl;

    public function __construct(string $tpl)
    {
        $this->tpl = $tpl;
    }

    public function write(array $result, string $outFile): void
    {
        $html = file_get_contents($this->tpl);

        // --- Summary inputs ---
        $sum = $result['summary'] ?? [];

        $completedRaw = $sum['completed']    ?? $result['completed']    ?? $sum['end']   ?? $result['end']
            ?? $sum['completed_at'] ?? $result['completed_at'] ?? null;
        $scanCompleted = $this->formatTsOrNow($completedRaw);

        $pathAudited = $sum['path'] ?? ($result['path'] ?? ($result['meta']['path'] ?? ($result['args']['path'] ?? '')));
        $pathEsc = htmlspecialchars((string)$pathAudited, ENT_QUOTES, 'UTF-8');

        $rulesPassed = (int)($sum['passed'] ?? 0);
        $rulesFailed = (int)($sum['failed'] ?? 0);
        $rulesTotal  = (int)($sum['total']  ?? ($rulesPassed + $rulesFailed));
        $rulesPct    = $rulesTotal > 0 ? round(($rulesPassed / $rulesTotal) * 100, 1) : 0.0;

        $sevCounts = ['Critical' => 0, 'High' => 0, 'Medium' => 0, 'Low' => 0];
        $rows = '';

        foreach ($result['findings'] ?? [] as $f) {
            $id       = htmlspecialchars((string)($f['id'] ?? ''), ENT_QUOTES, 'UTF-8');
            $control  = htmlspecialchars((string)($f['control'] ?? ''), ENT_QUOTES, 'UTF-8');
            $severity = htmlspecialchars((string)($f['severity'] ?? ''), ENT_QUOTES, 'UTF-8');
            $title    = htmlspecialchars((string)($f['title'] ?? ''), ENT_QUOTES, 'UTF-8');

            $passed = (bool)($f['passed'] ?? false);
            $status = $passed ? 'PASS' : 'FAIL';
            $statusClass = $passed ? 'status-pass' : 'status-fail';

            if (!$passed) {
                $sevKey = ucfirst(strtolower($f['severity'] ?? 'Low'));
                if (!isset($sevCounts[$sevKey])) {
                    $sevKey = 'Low';
                }
                $sevCounts[$sevKey]++;
            }

            $rows .= "<tr>"
                . "<td>{$id}</td>"
                . "<td>{$control}</td>"
                . "<td>{$severity}</td>"
                . "<td class=\"{$statusClass}\">{$status}</td>"
                . "<td>{$title}</td>"
                . "</tr>";
        }

        $findingsTotal = array_sum($sevCounts);


        $html = str_replace('{{summary}}', '', $html);
        $html = strtr($html, [
            '{{scan_completed}}'       => $scanCompleted,
            '{{path_audited}}'         => $pathEsc,

            '{{rules_total}}'          => (string)$rulesTotal,
            '{{rules_passed}}'         => (string)$rulesPassed,
            '{{rules_failed}}'         => (string)$rulesFailed,
            '{{rules_passed_percent}}' => (string)$rulesPct,

            '{{findings_critical}}'    => (string)$sevCounts['Critical'],
            '{{findings_high}}'        => (string)$sevCounts['High'],
            '{{findings_medium}}'      => (string)$sevCounts['Medium'],
            '{{findings_low}}'         => (string)$sevCounts['Low'],

            '{{findings_total}}'       => (string)$findingsTotal,
        ]);

        $html = str_replace('{{table}}', $rows, $html);
        file_put_contents($outFile, $html);
    }

    private function formatTsOrNow($ts): string
    {
        if ($ts instanceof \DateTimeInterface) {
            return $ts->format('Y-m-d H:i:s');
        }
        if (is_numeric($ts)) {
            return date('Y-m-d H:i:s', (int)$ts);
        }
        if (is_string($ts) && strtotime($ts)) {
            return date('Y-m-d H:i:s', strtotime($ts));
        }
        return date('Y-m-d H:i:s');
    }
}
