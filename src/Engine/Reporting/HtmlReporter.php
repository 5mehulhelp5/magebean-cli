<?php

declare(strict_types=1);

namespace Magebean\Engine\Reporting;

final class HtmlReporter
{
    private string $tpl;
    public function __construct(string $tpl)
    {
        $this->tpl = $tpl;
    }

    public function write(array $result, string $outFile): void
    {
        // 1) Đọc template an toàn; nếu không có -> dùng fallback nhỏ
        $html = file_get_contents($this->tpl);
        if ($html === false || $html === '') {
            $html = $this->fallbackTemplate();
        }
        // --- Summary inputs ---
        $sum = $result['summary'] ?? [];
        $completedRaw = $sum['completed'] ?? $result['completed'] ?? $sum['end'] ?? $result['end']
            ?? $sum['completed_at'] ?? $result['completed_at'] ?? null;
        $scanCompleted = $this->formatTsOrNow($completedRaw);

        $pathAudited = $sum['path'] ?? ($result['path'] ?? ($result['meta']['path'] ?? ($result['args']['path'] ?? '')));
        $pathEsc = htmlspecialchars((string)$pathAudited, ENT_QUOTES, 'UTF-8');

        $rulesPassed = (int)($sum['passed'] ?? 0);
        $rulesFailed = (int)($sum['failed'] ?? 0);
        $rulesUnknown = (int)($sum['unknown'] ?? max(0, (($sum['total'] ?? 0) - ($rulesPassed + $rulesFailed))));
        $rulesTotal  = (int)($sum['total']  ?? ($rulesPassed + $rulesFailed + $rulesUnknown));
        $rulesPct    = $rulesTotal > 0 ? round(($rulesPassed / $rulesTotal) * 100, 1) : 0.0;

        // Lấy meta & cờ suppress confidence (được set bởi ScanRunner)
        $meta = (array)($result['meta'] ?? []);
        $suppressConfidence = (bool)($meta['suppress_confidence'] ?? false);

        $sevCounts = ['Critical' => 0, 'High' => 0, 'Medium' => 0, 'Low' => 0];
        $rows = '';

        foreach ($result['findings'] ?? [] as $f) {
            $confVal = isset($f['confidence']) ? (int)$f['confidence'] : null;
            $confWhy = isset($f['confidence_reason']) ? (string)$f['confidence_reason'] : '';
            $id       = htmlspecialchars((string)($f['id'] ?? ''), ENT_QUOTES, 'UTF-8');
            $control  = htmlspecialchars((string)($f['control'] ?? ''), ENT_QUOTES, 'UTF-8');
            $severity = htmlspecialchars((string)($f['severity'] ?? ''), ENT_QUOTES, 'UTF-8');
            $passed   = (bool)($f['passed'] ?? false);
            $status   = $passed ? 'PASS' : 'FAIL';
            $status   = strtoupper((string)($f['status'] ?? ($passed ? 'PASS' : 'FAIL')));
            $statusClass = match ($status) {
                'PASS' => 'status-pass',
                'FAIL' => 'status-fail',
                'UNKNOWN' => 'status-unknown',
                default => 'status-fail'
            };
            $userMsgRaw = (string)($f['message'] ?? '');
            if ($status === 'UNKNOWN' && trim($userMsgRaw) === '') {
                $userMsgRaw = 'CVE file not found (requires --cve-data package)';
            }
            $userMsg  = htmlspecialchars($userMsgRaw, ENT_QUOTES, 'UTF-8');

            if ($status === 'FAIL') {
                $sevKey = ucfirst(strtolower((string)($f['severity'] ?? 'Low')));
                if (!isset($sevCounts[$sevKey])) $sevKey = 'Low';
                $sevCounts[$sevKey]++;
            }

            // Cột nội dung: chỉ in message theo yêu cầu mới
            $rows .= '<tr>'
                . '<td>' . $id . '</td>'
                . '<td>' . $control . '</td>'
                . '<td>' . $severity . '</td>'
                . '<td class="' . $statusClass . '">' . $status . '</td>'
                // . '<td>' . ($userMsg !== '' ? '<div style="color:#333;margin-top:4px">' . $userMsg . '</div>' : '') . '</td>'
                . '<td>'
                . ($userMsg !== '' ? '<div style="color:#333;margin-top:4px">' . $userMsg . '</div>' : '')
                . (
                    (!$suppressConfidence && $confVal !== null)
                    ? '<div style="opacity:.8;margin-top:4px"><small' . ($confWhy !== '' ? ' title="' . htmlspecialchars($confWhy, ENT_QUOTES, 'UTF-8') . '"' : '') . '>confidence: ' . $confVal . '%</small></div>'
                    : ''
                )
                . '</tr>';
        }

        $findingsTotal = array_sum($sevCounts);
        // Footer note nếu có UNKNOWN
        $isExternal = $this->isExternal($result);
        $hasUnknown = false;
        foreach (($result['findings'] ?? []) as $f) {
            if (strtoupper((string)($f['status'] ?? '')) === 'UNKNOWN') {
                $hasUnknown = true;
                break;
            }
        }
        if ($hasUnknown && !$isExternal) {
            $html = str_replace('{{cve_section}}', '<div class="section"><strong>Note:</strong> Some CVE-related rules are <span class="status-unknown">UNKNOWN</span> because CVE data was missing. Provide a CVE bundle via <code>--cve-data=path.zip</code> to enable full checks.</div>' . '{{cve_section}}', $html);
        }

        // Thay placeholder phần findings
        $html = strtr($html, [
            '{{scan_completed}}'       => $scanCompleted,
            '{{path_audited}}'         => $pathEsc,
            '{{rules_total}}'          => (string)$rulesTotal,
            '{{rules_passed}}'         => (string)$rulesPassed,
            '{{rules_failed}}'         => (string)$rulesFailed,
            '{{rules_unknown}}'        => (string)$rulesUnknown,
            '{{rules_passed_percent}}' => (string)$rulesPct,
            '{{findings_critical}}'    => (string)$sevCounts['Critical'],
            '{{findings_high}}'        => (string)$sevCounts['High'],
            '{{findings_medium}}'      => (string)$sevCounts['Medium'],
            '{{findings_low}}'         => (string)$sevCounts['Low'],
            '{{findings_total}}'       => (string)$findingsTotal,
        ]);
        $html = str_replace('{{table}}', $rows, $html);

        // --- CVE section ---
        if (!$isExternal) {
            $cveHtml = $this->renderCveSection($result['cve_audit'] ?? null);
            if (strpos($html, '{{cve_section}}') !== false) {
                $html = str_replace('{{cve_section}}', $cveHtml, $html);
            } else {
                $html = str_replace('</body>', $cveHtml . '</body>', $html);
            }
        }

        // --- Confidence section (URL mode) ---
        // Nếu meta đã có các trường confidence do ScanCommand/ScanRunner tính, hiển thị một block gọn.
        if ($isExternal && !$suppressConfidence) {
            $meta = (array)($result['meta'] ?? []);
            $det  = (array)($meta['detected'] ?? []);
            $detConf = (int)($det['confidence'] ?? 0);
            $overall = (int)($meta['overall_confidence'] ?? 0);
            $tPct    = (int)($meta['transport_success_percent'] ?? 0);
            $cPct    = (int)($meta['coverage_percent'] ?? 0);
            $execd   = (int)($meta['executed_rules'] ?? 0);
            $planned = (int)($meta['planned_rules']  ?? 0);
            $signals = isset($det['signals']) && is_array($det['signals']) ? $det['signals'] : [];

            $confHtml = '<div class="section"><h3>Scan Confidence</h3>'
                . '<div>Detected platform: <strong>Magento 2</strong> (confidence ' . $detConf . '%)</div>'
                . '<div>Overall confidence: <strong>' . $overall . '%</strong> &nbsp;—&nbsp; transport ' . $tPct . '% &middot; coverage ' . $cPct . '%' . ($planned > 0 ? ' (' . $execd . '/' . $planned . ')' : '') . '</div>'
                . (!empty($signals) ? '<div style="opacity:.85;margin-top:6px"><small>Signals: ' . htmlspecialchars(implode(' • ', $signals), ENT_QUOTES, 'UTF-8') . '</small></div>' : '')
                . '</div>';
            $html = str_replace('</body>', $confHtml . '</body>', $html);
        }

        $footer = '<p>This report was generated using Magebean CLI, based on the <a href="https://magebean.com/documentation/index.html">Magebean Security Baseline v1</a>. Findings are provided for informational and audit purposes only.</p>';
        $html = str_replace('</body>', $footer . '</body>', $html);

        // 2) Đảm bảo thư mục output tồn tại
        $dir = dirname($outFile);
        if ($dir !== '' && $dir !== '.' && !is_dir($dir)) {
            @mkdir($dir, 0777, true);
        }

        // 3) Ghi file và kiểm tra lỗi
        $ok = file_put_contents($outFile, $html);
        if ($ok === false) {
            throw new \RuntimeException('Failed to write HTML report to: ' . $outFile);
        }
    }

    private function isExternal(array $result): bool
    {
        $p = (string)($result['summary']['path'] ?? '');
        return str_starts_with($p, 'URL:');
    }

    private function renderCveSection($cve): string
    {
        if (!$cve) {
            return '<div class="section"><h3>CVE checks skipped</h3>
            <div>→ Requires CVE Data (--cve-data=magebean-cve-bundle-' . date('Ym') . '.zip)</div>
            <div>→ Visit <a href="https://magebean.com/download" title="Download">https://magebean.com/download</a></div>
            </div>';
        }
        $sum = $cve['summary'] ?? [];
        $pkgs = $cve['packages'] ?? [];

        $hdr = sprintf(
            "<div><strong>Total</strong>: %d packages against %d known CVEs | Affected: %d</div>",
            (int)($sum['packages_total'] ?? 0),
            (int)($sum['dataset_total'] ?? 0),
            (int)($sum['packages_affected'] ?? 0)
        );

        // Bảng tất cả package
        $rows = '';
        foreach ($pkgs as $p) {
            $name = htmlspecialchars((string)$p['name'], ENT_QUOTES, 'UTF-8');
            $ver  = htmlspecialchars((string)$p['installed'], ENT_QUOTES, 'UTF-8');
            $stat = (string)($p['status'] ?? 'PASS');
            $advc = (int)($p['advisories_count'] ?? 0);
            $sev  = htmlspecialchars((string)$p['highest_severity'] ?? 'None', ENT_QUOTES, 'UTF-8');
            $fx   = htmlspecialchars((string)($p['upgrade_hint'] ?? ''), ENT_QUOTES, 'UTF-8');
            $cls  = $stat === 'FAIL' ? 'status-fail' : 'status-pass';

            $rows .= '<tr>'
                . '<td>' . $name . '</td>'
                . '<td>' . $ver . '</td>'
                . '<td class="' . $cls . '">' . $stat . '</td>'
                . '<td>' . $advc . '</td>'
                . '<td>' . $sev . '</td>'
                . '<td>' . ($fx !== '' ? $fx : '&mdash;') . '</td>'
                . '</tr>';
        }

        // Details packages FAIL
        $details = '';
        foreach ($pkgs as $p) {
            if (($p['status'] ?? 'PASS') !== 'FAIL') continue;
            $name = htmlspecialchars((string)$p['name'], ENT_QUOTES, 'UTF-8');
            $ver  = htmlspecialchars((string)$p['installed'], ENT_QUOTES, 'UTF-8');
            $cnt  = (int)($p['advisories_count'] ?? 0);
            $sev  = htmlspecialchars((string)$p['highest_severity'] ?? 'None', ENT_QUOTES, 'UTF-8');
            $fx   = htmlspecialchars((string)($p['upgrade_hint'] ?? ''), ENT_QUOTES, 'UTF-8');

            $advRows = '';
            foreach (($p['advisories'] ?? []) as $a) {
                $id  = htmlspecialchars((string)($a['id'] ?? 'ADVISORY'), ENT_QUOTES, 'UTF-8');
                $sv  = htmlspecialchars((string)($a['severity'] ?? 'Unknown'), ENT_QUOTES, 'UTF-8');
                $cv  = htmlspecialchars((string)($a['cvss'] ?? ''), ENT_QUOTES, 'UTF-8');

                $aff = $a['affected'] ?? [];
                $ranges = $aff['ranges'] ?? [];
                $vers   = $aff['versions'] ?? [];
                $parts  = [];
                foreach ($ranges as $rg) {
                    $seg = [];
                    if (!empty($rg['introduced'])) $seg[] = '≥ ' . $rg['introduced'];
                    if (!empty($rg['fixed']))      $seg[] = '< ' . $rg['fixed'];
                    $parts[] = implode(', ', $seg);
                }
                if ($vers) $parts[] = 'versions: ' . implode(', ', array_slice($vers, 0, 5));
                $affStr = htmlspecialchars(implode(' | ', $parts), ENT_QUOTES, 'UTF-8');

                $fixed = '';
                if (!empty($a['fixed_versions'])) {
                    $fixed = htmlspecialchars(implode(', ', $a['fixed_versions']), ENT_QUOTES, 'UTF-8');
                }

                $ref = '';
                $refs = $a['references'] ?? [];
                if (!empty($refs) && isset($refs[0]['url'])) {
                    $u = htmlspecialchars((string)$refs[0]['url'], ENT_QUOTES, 'UTF-8');
                    $ref = '<a href="' . $u . '" target="_blank" rel="noopener">reference</a>';
                }

                $sumLine = htmlspecialchars((string)($a['summary'] ?? ''), ENT_QUOTES, 'UTF-8');

                $advRows .= '<tr>'
                    . '<td>' . $id . '</td>'
                    . '<td>' . $sv . ($cv !== '' ? ' / ' . $cv : '') . '</td>'
                    . '<td>' . ($affStr !== '' ? $affStr : '&mdash;') . '</td>'
                    . '<td>' . ($fixed !== '' ? $fixed : '&mdash;') . '</td>'
                    . '<td>' . ($ref !== '' ? $ref : '&mdash;') . '</td>'
                    . '<td>' . ($sumLine !== '' ? $sumLine : '&mdash;') . '</td>'
                    . '</tr>';
            }

            $caption = $name . '@' . $ver . ' — ' . $cnt . ' advisories (Highest: ' . $sev . ')';
            if ($fx !== '') $caption .= ' — min fix: ' . $fx;

            $details .= '<details class="section"><summary><strong>' . $caption . '</strong></summary>'
                . '<table style="width:100%;border-collapse:collapse;margin-top:8px">'
                . '<thead><tr>'
                . '<th>ID</th><th>Severity / CVSS</th><th>Affected</th><th>Fixed in</th><th>Reference</th><th>Summary</th>'
                . '</tr></thead><tbody>' . $advRows . '</tbody></table></details>';
        }

        return '<div class="section">'
            . '<h3>Known CVE Checks</h3>'
            . $hdr
            . '<table style="width:100%;border-collapse:collapse;margin-top:8px">'
            . '<thead><tr><th>Package</th><th>Installed</th><th>Status</th><th>Advisories</th><th>Highest Severity</th><th>Min Fixed</th></tr></thead>'
            . '<tbody>' . $rows . '</tbody></table>'
            . $details
            . '</div>';
    }

    private function formatTsOrNow($tsOrStr): string
    {
        if (is_numeric($tsOrStr)) return date('Y-m-d H:i:s');
        if (is_string($tsOrStr) && $tsOrStr !== '') return $tsOrStr;
        return date('Y-m-d H:i:s');
    }

    private function fallbackTemplate(): string
    {
        // Template mini có đủ placeholder cần thiết
        return <<<HTML
<!doctype html><html><head><meta charset="utf-8"><title>Magebean Report</title>
<style>
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;padding:16px;}
table{width:100%;border-collapse:collapse;margin-top:12px}
td,th{border:1px solid #eee;padding:8px;vertical-align:top}
.status-pass{color:#0a0;font-weight:bold}
.status-unknown{color:#a80;font-weight:bold}
.status-fail{color:#a00;background:#fdeaea;font-weight:600;text-align:center}
summary{cursor:pointer}
.section{margin-top:24px}
</style>
</head><body>
<h2>Magebean Scan</h2>
<div>Completed: {{scan_completed}}</div>
<div>Path: {{path_audited}}</div>
<div>Rules: {{rules_passed}} / {{rules_total}} ({{rules_passed_percent}}%) — Failed: {{rules_failed}} — Unknown: {{rules_unknown}}</div>
<div>Findings Overview — Critical: {{findings_critical}} | High: {{findings_high}} | Medium: {{findings_medium}} | Low: {{findings_low}} | Total: {{findings_total}}</div>
<table>
<thead><tr><th>ID</th><th>Control</th><th>Severity</th><th>Status</th><th>Message</th></tr></thead>
<tbody>
{{table}}
</tbody>
</table>
{{cve_section}}
</body></html>
HTML;
    }
}
