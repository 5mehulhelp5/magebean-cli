<?php
declare(strict_types=1);
namespace Magebean\Console;
use Magebean\Application;
use Magebean\Engine\ScanDiagnostic;
use Symfony\Component\Console\Helper\ProgressBar;
use Symfony\Component\Console\Output\OutputInterface;
final class ScanConsoleRenderer
{
    public function diagnostic(OutputInterface $out, ScanDiagnostic $diagnostic): void
    {
        $label = $diagnostic->level === 'plain' ? $diagnostic->label
            : '<' . $diagnostic->level . '>' . $diagnostic->label . '</' . $diagnostic->level . '>';
        $out->writeln($label . $diagnostic->detail);
    }

    public function renderPciAssessmentSummary(OutputInterface $out, array $pci): void
    {
        $summary = $pci['summary'] ?? [];
        $statuses = $summary['statuses'] ?? [];
        $requirements = (int)($summary['human_verification_required'] ?? $summary['requirements'] ?? 0);
        $out->writeln('');
        $out->writeln('<options=bold>PCI DSS 4.0.1 EVIDENCE READINESS</>');
        $out->writeln(sprintf('  Registry requirements requiring human confirmation: <fg=cyan;options=bold>%d</>', $requirements));
        $out->writeln(sprintf('  Technical findings: %d · Evidence collected, human confirmation pending: %d', (int)($statuses['TECHNICAL_FINDING'] ?? 0), (int)($statuses['EVIDENCE_COLLECTED_HUMAN_VERIFICATION_REQUIRED'] ?? 0)));
        $out->writeln(sprintf('  Applicability undetermined: %d · Not applicable, confirmation pending: %d', (int)($statuses['NOT_DETERMINED'] ?? 0), (int)($statuses['NOT_APPLICABLE'] ?? 0)));
        $actions = $pci['human_actions'] ?? [];
        if ($actions === []) {
            $out->writeln('  <comment>Detailed human actions are hidden; use --include-manual-review to list them.</comment>');
        } else {
            $out->writeln(sprintf('  <fg=cyan;options=bold>Human actions (%d)</>', count($actions)));
            foreach ($actions as $action) {
                $out->writeln(sprintf('    <fg=cyan>[%s]</> %s', (string)($action['requirement'] ?? ''), (string)($action['scope'] ?? '')));
            }
        }
        $out->writeln('<comment>This is evidence-readiness output, not PCI DSS certification or an attestation of compliance.</comment>');
    }

    public function renderRemoteMagentoInconclusive(
        OutputInterface $out,
        string $url,
        string $reason
    ): void {
        $safeUrl = \Symfony\Component\Console\Formatter\OutputFormatter::escape($url);
        $safeReason = \Symfony\Component\Console\Formatter\OutputFormatter::escape($reason);

        $out->writeln('');
        $out->writeln('<fg=magenta;options=bold>INCONCLUSIVE: MAGENTO 2 NOT CONFIRMED</>');
        $out->writeln(sprintf('Target: <fg=green>%s</>', $safeUrl));
        $out->writeln(sprintf('Reason: <comment>%s</comment>', $safeReason));
        $out->writeln('No remote audit rules were executed.');
        $out->writeln('');
    }

    public function renderPrettySummary(OutputInterface $out, array $result, string $path): void
    {
        $sum    = $result['summary'] ?? [];
        $total  = (int)($sum['total']  ?? 0);
        $passed = (int)($sum['passed'] ?? 0);

        $env      = strtoupper($this->detectMageMode($path));
        $isExternal = str_starts_with($path, 'URL:');
        $env = $isExternal ? 'EXTERNAL' : strtoupper($this->detectMageMode($path));
        $targetOption = $isExternal
            ? '--url=' . substr($path, 4) . ' '
            : '--path=' . escapeshellarg($path) . ' ';
        $phpShort = PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION;

        // Helpers
        $sevBadge = function (string $sev): string {
            $sev = strtoupper($sev);
            return match ($sev) {
                'CRITICAL' => '<fg=white;bg=red;options=bold>[CRITICAL]</>',
                'HIGH'     => '<fg=red;options=bold>[HIGH]</>',
                'MEDIUM'   => '<fg=yellow;options=bold>[MEDIUM]</>',
                'LOW'      => '<fg=blue;options=bold>[LOW]</>',
                default    => sprintf('[%s]', $sev),
            };
        };
        $envTag = function (string $env) {
            return match ($env) {
                'PRODUCTION' => '<fg=white;bg=green;options=bold>PRODUCTION</>',
                'DEVELOPER'  => '<fg=yellow;options=bold>DEVELOPER</>',
                'DEFAULT'    => '<fg=cyan>DEFAULT</>',
                'EXTERNAL'   => '<fg=blue;options=bold>EXTERNAL</>',
                default      => sprintf('<fg=magenta>%s</>', $env),
            };
        };

        // Header
        $out->writeln('');
        $out->writeln(sprintf('<fg=cyan;options=bold>Magebean CLI %s</>', Application::VERSION));
        $out->writeln(sprintf('Audit         Security Audit · Baseline %s', Application::BASELINE_VERSION));
        $out->writeln(sprintf('Target        <fg=green>%s</>', $path));
        $standard = (string)($result['meta']['standard'] ?? 'magebean');
        $profile = (array)($result['meta']['profile'] ?? []);
        $profileTitle = (string)($profile['title'] ?? $profile['id'] ?? 'Magebean Baseline');
        $out->writeln(sprintf('Profile ID    <info>%s</info>', strtoupper($standard)));
        $out->writeln(sprintf('Profile       <info>%s</info>', $profileTitle));
        $profileRulesTotal = (int)($result['meta']['profile_rules_total'] ?? $total);
        $profileManualRulesTotal = (int)($result['meta']['profile_manual_rules_total'] ?? 0);
        $manualRulesHidden = (int)($result['meta']['manual_rules_hidden'] ?? 0);
        $manualRulesIncluded = (bool)($result['meta']['manual_rules_included'] ?? false);
        $out->writeln(sprintf('Rules         <info>%d</info> / <info>%d</info> selected', $total, $profileRulesTotal));
        if ($manualRulesHidden > 0) {
            $out->writeln(sprintf('Manual rules  <fg=cyan;options=bold>%d not evaluated</> (use <info>--include-manual-review</info> to include)', $manualRulesHidden));
        } elseif ($manualRulesIncluded && $profileManualRulesTotal > 0) {
            $out->writeln(sprintf('Manual rules  <fg=cyan;options=bold>%d included</>', $profileManualRulesTotal));
        } else {
            $out->writeln('Manual rules  <comment>None in the current profile selection</comment>');
        }
        $out->writeln(sprintf('Environment   PHP <info>%s</info> · %s · <comment>%s</comment>', $phpShort, $envTag($env), date('Y-m-d H:i')));
        if ($isExternal) {
            $det = $result['meta']['detected'] ?? [];
            $detConf = (int)($det['confidence'] ?? 0);
            $detConfirmed = (bool)($det['confirmed'] ?? false);
            $detVersion = trim((string)($det['version'] ?? ''));
            $signals = (array)($det['signals'] ?? []);
            $overall = (int)($result['meta']['overall_confidence'] ?? 0);
            $tPct    = (int)($result['meta']['transport_success_percent'] ?? 0);
            $cPct    = (int)($result['meta']['coverage_percent'] ?? 0);
            $planned = (int)($result['meta']['planned_rules'] ?? 0);
            $execd   = (int)($result['meta']['executed_rules'] ?? 0);
            $detectionLabel = $detConfirmed
                ? '<info>Magento 2</info>'
                : '<comment>Magento 2 not confirmed</comment>';
            $out->writeln(sprintf('Detected: %s (confidence <comment>%d%%</comment>)', $detectionLabel, $detConf));
            $out->writeln($detVersion !== ''
                ? sprintf('Magento version: <info>%s</info>', $detVersion)
                : 'Magento version: <comment>not publicly exposed</comment>');
            $out->writeln(sprintf('Scan confidence: <info>%d%%</info> (detect %d, transport %d, coverage %d)', $overall, $detConf, $tPct, $cPct));
            if ($planned > 0) {
                $out->writeln(sprintf('Coverage: <info>%d/%d</info> rules (%d%%)', $execd, $planned, $cPct));
            }
            if (!empty($signals)) {
                $out->writeln('Signals:');
                foreach (array_slice($signals, 0, 6) as $s) {
                    $out->writeln('  - ' . $s);
                }
                if (count($signals) > 6) $out->writeln('  - …');
            }
            $out->writeln('');
        }
        $out->writeln('');

        // Findings requiring attention
        $attentionFindings = array_values(array_filter(
            ($result['findings'] ?? []),
            static fn(array $finding): bool => empty($finding['passed'])
        ));
        usort($attentionFindings, fn($a, $b) => $this->sevOrder($a['severity'] ?? 'Low') <=> $this->sevOrder($b['severity'] ?? 'Low'));
        $allFindings = array_values((array)($result['findings'] ?? []));
        usort($allFindings, fn($a, $b) => $this->sevOrder($a['severity'] ?? 'Low') <=> $this->sevOrder($b['severity'] ?? 'Low'));
        $inconclusiveFindings = array_values(array_filter(
            $attentionFindings,
            static fn(array $finding): bool => strtoupper((string)($finding['status'] ?? '')) === 'UNKNOWN'
        ));
        $confirmedFindings = array_values(array_filter(
            $attentionFindings,
            static fn(array $finding): bool => strtoupper((string)($finding['status'] ?? '')) === 'FAIL'
        ));
        $manualReviewFindings = array_values(array_filter(
            $attentionFindings,
            static fn(array $finding): bool => strtoupper((string)($finding['status'] ?? '')) === 'MANUAL_REVIEW'
        ));

        $sevCounts = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0];
        foreach ($confirmedFindings as $f) {
            $k = strtolower((string)($f['severity'] ?? 'low'));
            if (!isset($sevCounts[$k])) $k = 'low';
            $sevCounts[$k]++;
        }

        // Summary first, so the result remains visible even for long audits.
        $auditStatus = $confirmedFindings !== []
            ? '<fg=yellow;options=bold>AUDIT COMPLETE · ATTENTION REQUIRED</>'
            : ($manualReviewFindings !== []
                ? '<fg=cyan;options=bold>AUDIT COMPLETE · HUMAN REVIEW REQUIRED</>'
                : ($inconclusiveFindings !== []
                ? '<fg=magenta;options=bold>AUDIT COMPLETE · INCONCLUSIVE</>'
                : '<info>AUDIT COMPLETE</info>'));
        $out->writeln($auditStatus);
        $out->writeln('');
        $out->writeln(sprintf('  Passed                    <info>%d / %d</info>', $passed, $total));
        $out->writeln(sprintf('  Confirmed findings        <fg=yellow;options=bold>%d</>', count($confirmedFindings)));
        $out->writeln(sprintf('  Technical manual review   <fg=cyan;options=bold>%d</>', count($manualReviewFindings)));
        $out->writeln(sprintf('  Inconclusive              <fg=magenta;options=bold>%d</>', count($inconclusiveFindings)));
        if ($confirmedFindings !== []) {
            $out->writeln(sprintf(
                '  %sCritical %d</> · %sHigh %d</> · %sMedium %d</> · %sLow %d</>',
                '<fg=white;bg=red;options=bold>',
                $sevCounts['critical'],
                '<fg=red;options=bold>',
                $sevCounts['high'],
                '<fg=yellow;options=bold>',
                $sevCounts['medium'],
                '<fg=blue;options=bold>',
                $sevCounts['low'],
            ));
        }
        $out->writeln('');

        $rulesFilter = array_values(array_filter((array)($result['meta']['rules_filter'] ?? [])));
        $showRuleDetails = $rulesFilter !== [];
        if ($showRuleDetails) {
            $out->writeln(sprintf('<options=bold>Rule details</> (<fg=yellow>%d</>)', count($allFindings)));
        } elseif ($confirmedFindings !== [] || $manualReviewFindings !== []) {
            $out->writeln(sprintf('<options=bold>FINDINGS REQUIRING ATTENTION (%d)</>', count($confirmedFindings) + count($manualReviewFindings)));
        }

        $findingsToRender = $showRuleDetails ? $allFindings : array_merge($confirmedFindings, $manualReviewFindings);
        $currentSeverity = null;
        foreach ($findingsToRender as $f) {
            $sev = strtoupper((string)($f['severity'] ?? 'LOW'));
            $id = trim((string)($f['id'] ?? ''));
            $status = strtoupper((string)($f['status'] ?? ''));
            $text = $showRuleDetails
                ? $this->detailedFindingMessage($f)
                : $this->compactFindingDescription($f);
            $statusTag = $showRuleDetails
                ? match ($status) {
                    'PASS' => '<fg=green;options=bold>[PASS]</> ',
                    'MANUAL_REVIEW' => '<fg=cyan;options=bold>[HUMAN VERIFICATION REQUIRED]</> ',
                    'UNKNOWN' => '<fg=magenta;options=bold>[INCONCLUSIVE]</> ',
                    default => '<fg=red;options=bold>[FAIL]</> ',
                }
                : ($status === 'MANUAL_REVIEW'
                    ? '<fg=cyan;options=bold>[HUMAN VERIFICATION REQUIRED]</> '
                    : '');
            if (!$showRuleDetails && $status !== 'MANUAL_REVIEW' && $sev !== $currentSeverity) {
                $currentSeverity = $sev;
                $out->writeln('');
                $out->writeln(sprintf('  %s (%d)', $sevBadge($sev), $sevCounts[strtolower($sev)] ?? 0));
            }
            $line = $id !== ''
                ? sprintf('%s<href=https://magebean.com/baseline/%2$s>%2$s</>  %3$s', $statusTag, $id, $text)
                : sprintf('%s%s', $statusTag, $text);
            $out->writeln(($showRuleDetails ? '  ' . $sevBadge($sev) . ' ' : '    ') . $line);

            if ($id === 'MB-R072' && $status === 'UNKNOWN') {
                $out->writeln('    Git history was not verified; INCONCLUSIVE does not mean the history is clean.');
                $out->writeln('    Run this rule against the original source checkout containing .git:');
                $out->writeln("      <fg=green>php magebean.phar scan --path='/path/to/magento-source' --rules=MB-R072</>");
            }


            if ($showRuleDetails) {
                $this->renderCheckDetails($out, $f);
            }

            if ($showRuleDetails && in_array($status, ['FAIL', 'UNKNOWN'], true)) {
                $out->writeln('');
                $out->writeln(sprintf('  <options=bold>How to resolve %s</>', $id !== '' ? $id : 'this check'));
                $resolutionSteps = $status === 'UNKNOWN'
                    ? $this->inconclusiveResolutionSteps($f)
                    : $this->failureResolutionSteps($f);
                foreach ($resolutionSteps as $step) {
                    $out->writeln('    - ' . $step);
                }
                if ($id !== '' && !($id === 'MB-R072' && $status === 'UNKNOWN')) {
                    $out->writeln($status === 'UNKNOWN'
                        ? '    - Re-run after resolving the missing evidence:'
                        : '    - Re-run after applying the remediation:');
                    $out->writeln(sprintf('      <fg=green>php magebean.phar scan %s--rules=%s</>', $targetOption, $id));
                }
            }
        }

        if (!$showRuleDetails && $inconclusiveFindings !== []) {
            $out->writeln('');
            $out->writeln(sprintf(
                '<options=bold>INCONCLUSIVE CHECKS (%d)</>',
                count($inconclusiveFindings)
            ));
            foreach ($inconclusiveFindings as $f) {
                $sev = strtoupper((string)($f['severity'] ?? 'LOW'));
                $id = trim((string)($f['id'] ?? ''));
                $text = $this->compactFindingDescription($f);
                $line = $id !== ''
                    ? sprintf('<href=https://magebean.com/baseline/%1$s>%1$s</>  %2$s', $id, $text)
                    : $text;
                $out->writeln('  ' . $line);
                $out->writeln(sprintf('    Potential severity: %s', ucfirst(strtolower($sev))));
                if ($id === 'MB-R072') {
                    $out->writeln('    Git history was not verified; INCONCLUSIVE does not mean the history is clean.');
                    $out->writeln('    Run this rule against the original source checkout containing .git:');
                    $out->writeln("      <fg=green>php magebean.phar scan --path='/path/to/magento-source' --rules=MB-R072</>");
                }
            }
        }
        $out->writeln('');

        if (!$showRuleDetails && ($confirmedFindings !== [] || $inconclusiveFindings !== [])) {
            $exampleRules = array_values(array_filter(array_map(
                static fn(array $finding): string => trim((string)($finding['id'] ?? '')),
                array_slice($confirmedFindings, 0, 1)
            )));
            $out->writeln('<options=bold>NEXT STEPS</>');
            if ($exampleRules !== []) {
                $out->writeln('  Review the highest-priority finding:');
                $out->writeln(sprintf('    <fg=green>php magebean.phar scan %s--rules=%s</>', $targetOption, $exampleRules[0]));

            }
            if ($inconclusiveFindings !== []) {
                $inconclusiveId = trim((string)($inconclusiveFindings[0]['id'] ?? ''));
                if ($inconclusiveId !== '') {
                    $out->writeln('  Resolve an inconclusive check:');
                    $out->writeln(sprintf('    <fg=green>php magebean.phar scan %s--rules=%s</>', $targetOption, $inconclusiveId));
                }
            }
            $out->writeln('');
        }

        // CVE console:
        if (!$isExternal) {
            if (!empty($result['cve_audit']) && is_array($result['cve_audit'])) {
                $cs = $result['cve_audit']['summary'] ?? [];
                $out->writeln(sprintf(
                    "\n<info>✓ CVE Checks</info>: %d packages against %d known CVEs | Affected: <fg=red;options=bold>%d</>",
                    (int)($cs['packages_total'] ?? 0),
                    (int)($cs['dataset_total'] ?? 0),
                    (int)($cs['packages_affected'] ?? 0)
                ));
            }
        }


    }

    private function sevOrder(string $sev): int
    {
        return match (strtolower($sev)) {
            'critical' => 0,
            'high'     => 1,
            'medium'   => 2,
            default    => 3
        };
    }

    private function detectMageMode(string $path): string
    {
        $envFile = rtrim($path, '/') . '/app/etc/env.php';
        if (!is_file($envFile)) return 'UNKNOWN';
        $arr = @include $envFile;
        if (is_array($arr)) {
            if (isset($arr['MAGE_MODE'])) return (string)$arr['MAGE_MODE'];
            // thử key kiểu nested
            $m = $arr['system']['default']['dev']['debug']['environment'] ?? null;
            if (is_string($m) && $m !== '') return $m;
        }
        return 'UNKNOWN';
    }

    public function writePhase(OutputInterface $out, int $current, int $total, string $message): void
    {
        if ($out->isQuiet()) {
            return;
        }

        $out->writeln(sprintf('<fg=cyan>[%d/%d]</> %s', $current, $total, $message));
    }

    public function createRuleProgressBar(OutputInterface $out, int $totalRules): ProgressBar
    {
        $progress = new ProgressBar($out, max(1, $totalRules));
        $progress->setFormat(' %current%/%max% [%bar%] %percent:3s%%  %message%');
        $progress->setMessage('Starting rule scan');
        $progress->start();

        return $progress;
    }

    public function formatRuleProgressMessage(array $event): string
    {
        $ruleId = (string)($event['rule_id'] ?? '');
        $title = trim((string)($event['title'] ?? ''));
        $status = strtoupper((string)($event['status'] ?? ''));

        $label = $ruleId;
        if ($title !== '') {
            $label .= ($label !== '' ? ' - ' : '') . $this->truncateProgressTitle($title, 70);
        }
        if ($status !== '') {
            $label .= ' [' . $status . ']';
        }

        return $label !== '' ? $label : 'Scanning rules';
    }

    private function truncateProgressTitle(string $title, int $maxLength): string
    {
        if (strlen($title) <= $maxLength) {
            return $title;
        }

        return rtrim(substr($title, 0, $maxLength - 3)) . '...';
    }

    private function compactFindingDescription(array $finding): string
    {
        $message = trim((string)($finding['message'] ?? ''));
        $message = preg_replace('/^\[UNKNOWN\]\s*/', '', $message) ?? $message;
        if ($message === '') {
            return trim((string)($finding['title'] ?? ''));
        }

        // Check messages commonly use the first line as their description and
        // subsequent lines for paths, packages, or other supporting evidence.
        $firstLine = trim((string)strtok($message, "\r\n"));
        if ($firstLine !== $message) {
            return rtrim($firstLine, ': ');
        }

        // Some checks append large package/advisory lists on the same line.
        // Hide that payload in the default view while preserving ordinary
        // descriptions such as "HTTP error: certificate problem".
        if (preg_match('/^(.+?):\s+(.+)$/s', $firstLine, $parts) === 1) {
            $detail = $parts[2];
            if (
                str_contains($detail, ' -> ')
                || str_contains($detail, '; ')
                || preg_match('/\S+@\S+/', $detail) === 1
            ) {
                return rtrim(trim($parts[1]), ': ');
            }
        }

        return $firstLine;
    }

    private function detailedFindingMessage(array $finding): string
    {
        $message = trim((string)($finding['message'] ?? ''));
        $message = preg_replace('/^\[UNKNOWN\]\s*/', '', $message) ?? $message;
        return $message !== '' ? $message : trim((string)($finding['title'] ?? ''));
    }

    private function renderCheckDetails(OutputInterface $out, array $finding): void
    {
        $items = is_array($finding['detail'] ?? null) ? $finding['detail'] : [];
        if ($items === []) {
            foreach ((array)($finding['details'] ?? []) as $legacy) {
                if (!is_array($legacy)) continue;
                $items[] = [
                    'check' => (string)($legacy[0] ?? ''),
                    'message' => (string)($legacy[1] ?? ''),
                    'status' => ($legacy[2] ?? null) === true
                        ? 'PASS'
                        : (($legacy[2] ?? null) === false ? 'FAIL' : 'UNKNOWN'),
                ];
            }
        }
        if ($items === []) return;

        $out->writeln('    <options=bold>Detail</>');
        foreach ($items as $item) {
            if (!is_array($item)) continue;
            $check = trim((string)($item['check'] ?? 'check'));
            $status = strtoupper(trim((string)($item['status'] ?? 'UNKNOWN')));
            $message = trim((string)($item['message'] ?? ''));
            $lines = preg_split('/\R/', $message) ?: [];
            $first = array_shift($lines) ?: '';
            $out->writeln(sprintf('      - %s [%s]: %s', $check, $status, $first));
            foreach ($lines as $line) {
                if (trim($line) !== '') {
                    $out->writeln('        ' . rtrim($line));
                }
            }
        }
    }

    private function inconclusiveResolutionSteps(array $finding): array
    {
        $id = strtoupper(trim((string)($finding['id'] ?? '')));
        $message = strtolower((string)($finding['message'] ?? ''));

        return match ($id) {
            'MB-R027' => [
                'Use a trusted TLS certificate, or install and trust the local CA when scanning a development URL.',
                'Confirm the HTTPS response includes a Strict-Transport-Security header with max-age >= 15552000.',
            ],
            'MB-R033' => [
                'Add a readable php.ini or .user.ini to the Magento root with display_errors=Off.',
                'If the rule also checks a URL, confirm application error pages do not expose stack traces.',
            ],
            'MB-R039' => [
                'Run bin/magento indexer:status and resolve indexers that are not ready.',
                'Provide readable normalized indexer evidence at var/.indexer_status using one "indexer: READY" entry per line.',
            ],
            'MB-R047' => [
                'Ensure Magento cron is running and updates var/cron/cron.timestamp, var/log/cron.log, or var/log/magento.cron.log.',
                'Make at least one heartbeat file readable and newer than 900 seconds when the scan runs.',
            ],
            'MB-R048' => [
                'Export a numeric cron backlog metric to var/cron/queue.size, var/cron/backlog.json, or var/cron/backlog.txt.',
                'Make the metric file readable and verify its value can be parsed before re-running the rule.',
            ],
            'MB-R061', 'MB-R063' => [
                'Verify HTTPS connectivity to api.magebean.com/v1/packages/status from the scan environment.',
                'Allow the endpoint through any proxy or firewall, then retry the rule.',
            ],
            'MB-R072' => [
                'Run the scan against the original Git checkout that contains its .git metadata, not a copied release directory.',
                'Ensure the scanner can read .git and the repository history.',
            ],
            'MB-R077' => [
                'Ensure app/code exists and contains the custom PHP files that should be assessed.',
                'Grant the scan process read permission to app/code and its files.',
            ],
            default => $this->genericInconclusiveResolutionSteps($message, $id),
        };
    }

    private function failureResolutionSteps(array $finding): array
    {
        $steps = array_values(array_filter(
            (array)($finding['remediation'] ?? []),
            static fn($step): bool => is_string($step) && trim($step) !== ''
        ));
        if ($steps !== []) {
            return array_map(static fn(string $step): string => trim($step), $steps);
        }

        return [
            'Review the failed check message and evidence above.',
            'Apply the required configuration change, then verify the affected endpoint or file directly.',
        ];
    }

    private function genericInconclusiveResolutionSteps(string $message, string $id): array
    {
        if (str_contains($message, 'api') || str_contains($message, 'http')) {
            return [
                'Verify network, DNS, TLS, proxy, and authentication requirements for the reported endpoint.',
                'Retry the rule after the endpoint is reachable from the scan environment.',
            ];
        }
        if (str_contains($message, 'not found') || str_contains($message, 'unable to read')) {
            return [
                'Restore the missing input named in the message and make it readable by the scan process.',
                'Retry the rule after confirming the file or directory exists under the scan target.',
            ];
        }

        return $id !== ''
            ? ['Review the rule requirements and remediation guidance: https://magebean.com/baseline/' . rawurlencode($id)]
            : ['Review the rule requirements and remediation guidance at https://magebean.com/baseline'];
    }
}
