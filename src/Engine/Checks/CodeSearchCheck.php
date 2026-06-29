<?php declare(strict_types=1);

namespace Magebean\Engine\Checks;

use Magebean\Engine\Context;

final class CodeSearchCheck
{
    private Context $ctx;

    public function __construct(Context $ctx) { $this->ctx = $ctx; }

    /**
     * args:
     * - paths[]: thư mục tương đối để quét (vd: ["app","vendor","lib","app/design"])
     * - include_ext[]: đuôi file cần quét (mặc định: php, phtml, js, html, xml)
     * - must_match[]: danh sách regex (ít nhất MỖI regex phải xuất hiện 1 lần)
     * - must_not_match[]: danh sách regex (KHÔNG được xuất hiện ở bất kỳ file nào)
     * - max_results: số phát hiện tối đa báo cáo (default 50)
     */
    public function grep(array $args): array
    {
        $roots = $args['paths'] ?? ['app', 'vendor', 'lib', 'app/design'];
        $inc   = $args['include_ext'] ?? ['php','phtml','js','html','xml'];
        $must  = $args['must_match'] ?? [];
        $mustNot = $args['must_not_match'] ?? [];
        $max   = max(1, (int)($args['max_results'] ?? 50));

        $rootsAbs = array_map(fn($p) => $this->ctx->abs($p), $roots);
        $files = $this->collectFiles($rootsAbs, $inc);

        $matches = [];      // offenders for must_not_match
        $foundMap = [];     // pattern => bool (for must_match)
        foreach ($must as $pat) $foundMap[$pat] = false;

        foreach ($files as $file) {
            $content = @file_get_contents($file);
            if ($content === false) continue;

            // must_not_match: fail ngay nếu có
            foreach ($mustNot as $pat) {
                if (@preg_match('/'.$pat.'/m', '') === false) {
                    return [false, "Invalid regex in must_not_match: /$pat/"];
                }
                if (preg_match('/'.$pat.'/m', $content, $match, PREG_OFFSET_CAPTURE)) {
                    $matches[] = $this->matchEvidence($file, $content, (string)$pat, (int)$match[0][1]);
                    if (count($matches) >= $max) break 2;
                }
            }

            // must_match: đánh dấu nếu thấy
            foreach ($must as $pat) {
                if ($foundMap[$pat] === true) continue;
                if (@preg_match('/'.$pat.'/m', '') === false) {
                    return [false, "Invalid regex in must_match: /$pat/"];
                }
                if (preg_match('/'.$pat.'/m', $content)) {
                    $foundMap[$pat] = true;
                }
            }
        }

        if (!empty($matches)) {
            return [
                false,
                'Forbidden pattern found in: ' . implode(', ', array_map(
                    static fn(array $match): string => $match['file'] . ':' . $match['line'] . ' /' . $match['pattern'] . '/',
                    $matches
                )),
                $matches,
            ];
        }

        // verify all must_match satisfied
        foreach ($foundMap as $pat => $ok) {
            if (!$ok) {
                return [false, "Required pattern not found: /$pat/"];
            }
        }

        return [true, 'code_grep OK (patterns satisfied)'];
    }

    public function rawSql(array $args): array
    {
        $roots = $args['paths'] ?? ['app'];
        $inc = $args['include_ext'] ?? ['php', 'phtml'];
        $max = max(1, (int)($args['max_results'] ?? 50));
        $rootsAbs = array_map(fn($p) => $this->ctx->abs($p), $roots);
        $files = $this->collectFiles($rootsAbs, $inc);

        $offenders = [];
        foreach ($files as $file) {
            $content = @file_get_contents($file);
            if ($content === false) {
                continue;
            }

            foreach ($this->rawSqlFindings($file, $content) as $finding) {
                $offenders[] = $finding;
                if (count($offenders) >= $max) {
                    break 2;
                }
            }
        }

        if ($offenders !== []) {
            return [
                false,
                'Potential unsafe raw SQL found in: ' . implode(', ', array_map(
                    static fn(array $match): string => $match['file'] . ':' . $match['line'] . ' [' . $match['kind'] . ']',
                    $offenders
                )),
                $offenders,
            ];
        }

        return [true, 'No unsafe raw SQL patterns detected'];
    }

    public function piiMinimization(array $args): array
    {
        $roots = $args['paths'] ?? ['app/code'];
        $inc = $args['include_ext'] ?? ['php'];
        $max = max(1, (int)($args['max_results'] ?? 100));
        $rootsAbs = array_map(fn($p) => $this->ctx->abs($p), $roots);

        $findings = [];
        $filesRead = 0;
        foreach ($this->collectFiles($rootsAbs, $inc) as $file) {
            $content = @file_get_contents($file);
            if ($content === false) {
                continue;
            }

            $filesRead++;
            foreach ($this->piiMinimizationFindings($file, $content) as $finding) {
                $findings[] = $finding;
                if (count($findings) >= $max) {
                    break 2;
                }
            }
        }

        $evidence = [
            'paths' => array_values($roots),
            'files_scanned' => $filesRead,
            'findings' => $findings,
            'truncated' => count($findings) >= $max,
        ];

        if ($filesRead === 0) {
            return [null, '[UNKNOWN] PII minimization scan could not read any target files', $evidence];
        }

        if ($findings !== []) {
            $lines = ['Raw sensitive PII appears in third-party outbound flows:'];
            foreach ($findings as $finding) {
                $lines[] = sprintf(
                    '    - %s:%d [%s] %s',
                    $finding['file'],
                    $finding['line'],
                    $finding['kind'],
                    $finding['field']
                );
            }
            if ($evidence['truncated']) {
                $lines[] = sprintf('    - output truncated at %d findings', $max);
            }

            return [false, implode("\n", $lines), $evidence];
        }

        return [true, 'No raw sensitive PII detected in third-party outbound flows', $evidence];
    }
    public function apiKeyStorage(array $args): array
    {
        $roots = $args['paths'] ?? ['app/code', 'app/etc', 'app/design', 'setup'];
        $inc = $args['include_ext'] ?? ['php', 'phtml', 'xml', 'sql'];
        $max = max(1, (int)($args['max_results'] ?? 100));
        $envFile = (string)($args['env_file'] ?? 'app/etc/env.php');
        $rootsAbs = array_map(fn($p) => $this->ctx->abs($p), $roots);

        $findings = [];
        $filesRead = 0;
        foreach ($this->collectFiles($rootsAbs, $inc) as $file) {
            if ($this->relativeFile($file) === $envFile) {
                continue;
            }
            $content = @file_get_contents($file);
            if ($content === false) {
                continue;
            }

            $filesRead++;
            foreach ($this->apiKeyStorageFindings($file, $content) as $finding) {
                $findings[] = $finding;
                if (count($findings) >= $max) {
                    break 2;
                }
            }
        }

        $envEvidence = $this->envCredentialKeyEvidence($envFile);
        $evidence = [
            'paths' => array_values($roots),
            'files_scanned' => $filesRead,
            'env_credentials' => $envEvidence,
            'findings' => $findings,
            'truncated' => count($findings) >= $max,
        ];

        if ($findings !== []) {
            $lines = ['API credentials found outside env.php or written to DB config paths:'];
            foreach ($findings as $finding) {
                $lines[] = sprintf(
                    '    - %s:%d [%s] %s',
                    $finding['file'],
                    $finding['line'],
                    $finding['kind'],
                    $finding['field'] ?? $finding['pattern']
                );
            }
            if ($evidence['truncated']) {
                $lines[] = sprintf('    - output truncated at %d findings', $max);
            }

            return [false, implode("\n", $lines), $evidence];
        }

        if ($filesRead === 0) {
            return [false, 'No application code/config files found to verify API credential storage', $evidence];
        }

        $envCount = (int)($envEvidence['credential_keys'] ?? 0);
        $message = $envCount > 0
            ? 'API credential-like keys are present in env.php and no code/DB storage patterns were detected'
            : 'No API credential code/DB storage patterns detected; env.php credential keys were not found';

        return [true, $message, $evidence];
    }

    public function thirdPartyLoggingSanitized(array $args): array
    {
        $roots = $args['paths'] ?? ['app/code'];
        $inc = $args['include_ext'] ?? ['php'];
        $max = max(1, (int)($args['max_results'] ?? 100));
        $rootsAbs = array_map(fn($p) => $this->ctx->abs($p), $roots);

        $findings = [];
        $filesRead = 0;
        foreach ($this->collectFiles($rootsAbs, $inc) as $file) {
            $content = @file_get_contents($file);
            if ($content === false) {
                continue;
            }

            $filesRead++;
            foreach ($this->thirdPartyLoggingFindings($file, $content) as $finding) {
                $findings[] = $finding;
                if (count($findings) >= $max) {
                    break 2;
                }
            }
        }

        $evidence = [
            'paths' => array_values($roots),
            'files_scanned' => $filesRead,
            'findings' => $findings,
            'truncated' => count($findings) >= $max,
        ];

        if ($findings !== []) {
            $lines = ['Third-party sensitive logging without masking/redaction:'];
            foreach ($findings as $finding) {
                $lines[] = sprintf(
                    '    - %s:%d [%s/%s]',
                    $finding['file'],
                    $finding['line'],
                    $finding['kind'],
                    $finding['risk']
                );
            }
            if ($evidence['truncated']) {
                $lines[] = sprintf('    - output truncated at %d findings', $max);
            }

            return [false, implode("\n", $lines), $evidence];
        }

        if ($filesRead === 0) {
            return [false, 'No application code files found to verify third-party log sanitization', $evidence];
        }

        return [true, 'Third-party sensitive logging is absent or sanitized', $evidence];
    }

    public function saasIntegrationScoped(array $args): array
    {
        $roots = $args['paths'] ?? ['app/code', 'app/etc'];
        $inc = $args['include_ext'] ?? ['php', 'xml'];
        $max = max(1, (int)($args['max_results'] ?? 100));
        $rootsAbs = array_map(fn($p) => $this->ctx->abs($p), $roots);

        $surfaces = [];
        $failures = [];
        $filesRead = 0;
        foreach ($this->collectFiles($rootsAbs, $inc) as $file) {
            $content = @file_get_contents($file);
            if ($content === false) {
                continue;
            }

            $filesRead++;
            foreach ($this->saasIntegrationScopeFindings($file, $content) as $finding) {
                $surfaces[] = $finding;
                if (empty($finding['controls']['ok'])) {
                    $failures[] = $finding;
                    if (count($failures) >= $max) {
                        break 2;
                    }
                }
            }
        }

        $evidence = [
            'paths' => array_values($roots),
            'files_scanned' => $filesRead,
            'surfaces' => $surfaces,
            'failures' => $failures,
            'truncated' => count($failures) >= $max,
        ];

        if ($filesRead === 0) {
            return [false, 'No application code/config files found to verify SaaS integration scoping', $evidence];
        }

        if ($failures !== []) {
            $lines = ['SaaS integration entry points missing least-privilege ACL or IP allowlist:'];
            foreach ($failures as $failure) {
                $lines[] = sprintf(
                    '    - %s:%d [%s] missing %s',
                    $failure['file'],
                    $failure['line'],
                    $failure['kind'],
                    implode('+', $failure['controls']['missing'] ?? ['scoping'])
                );
            }
            if ($evidence['truncated']) {
                $lines[] = sprintf('    - output truncated at %d findings', $max);
            }

            return [false, implode("\n", $lines), $evidence];
        }

        if ($surfaces === []) {
            return [true, 'No SaaS integration entry points detected', $evidence];
        }

        return [true, 'SaaS integration entry points use least-privilege ACL resources or IP allowlists', $evidence];
    }
    public function cardholderDataStorage(array $args): array
    {
        $roots = $args['paths'] ?? ['app/code', 'app/etc', 'setup', 'dev', 'db'];
        $inc = $args['include_ext'] ?? ['php', 'xml', 'sql', 'json'];
        $max = max(1, (int)($args['max_results'] ?? 100));
        $rootsAbs = array_map(fn($p) => $this->ctx->abs($p), $roots);

        $findings = [];
        $filesRead = 0;
        foreach ($this->collectFiles($rootsAbs, $inc) as $file) {
            $content = @file_get_contents($file);
            if ($content === false) {
                continue;
            }

            $filesRead++;
            foreach ($this->cardholderDataStorageFindings($file, $content) as $finding) {
                $findings[] = $finding;
                if (count($findings) >= $max) {
                    break 2;
                }
            }
        }

        $evidence = [
            'paths' => array_values($roots),
            'files_scanned' => $filesRead,
            'findings' => $findings,
            'truncated' => count($findings) >= $max,
        ];

        if ($findings !== []) {
            $lines = ['Raw cardholder data storage patterns detected:'];
            foreach ($findings as $finding) {
                $lines[] = sprintf(
                    '    - %s:%d [%s] %s',
                    $finding['file'],
                    $finding['line'],
                    $finding['kind'],
                    $finding['field'] ?? $finding['pattern']
                );
            }
            if ($evidence['truncated']) {
                $lines[] = sprintf('    - output truncated at %d findings', $max);
            }

            return [false, implode("\n", $lines), $evidence];
        }

        if ($filesRead === 0) {
            return [false, 'No application schema/code files found to verify cardholder data storage', $evidence];
        }

        return [true, 'No raw PAN, CVV, or track-data storage patterns detected', $evidence];
    }
    public function cardholderDataFiles(array $args): array
    {
        $roots = $args['paths'] ?? ['var/export', 'var/import', 'var/backups', 'var/backup', 'var/log', 'var/report', 'pub/media', 'pub/import', 'backups', 'backup'];
        $inc = $args['include_ext'] ?? ['csv', 'sql', 'txt', 'log', 'json', 'xml', 'bak', 'old'];
        $max = max(1, (int)($args['max_results'] ?? 100));
        $rootsAbs = array_map(fn($p) => $this->ctx->abs($p), $roots);

        $findings = [];
        $filesRead = 0;
        foreach ($this->collectFiles($rootsAbs, $inc) as $file) {
            $content = @file_get_contents($file);
            if ($content === false) {
                continue;
            }

            $filesRead++;
            foreach ($this->cardholderDataFileFindings($file, $content) as $finding) {
                $findings[] = $finding;
                if (count($findings) >= $max) {
                    break 2;
                }
            }
        }

        $evidence = [
            'paths' => array_values($roots),
            'files_scanned' => $filesRead,
            'findings' => $findings,
            'truncated' => count($findings) >= $max,
        ];

        if ($findings !== []) {
            $lines = ['Cardholder data found in files, exports, or backups:'];
            foreach ($findings as $finding) {
                $lines[] = sprintf(
                    '    - %s:%d [%s] %s',
                    $finding['file'],
                    $finding['line'],
                    $finding['kind'],
                    $finding['field'] ?? $finding['pattern']
                );
            }
            if ($evidence['truncated']) {
                $lines[] = sprintf('    - output truncated at %d findings', $max);
            }

            return [false, implode("\n", $lines), $evidence];
        }

        if ($filesRead === 0) {
            return [true, 'No high-risk export, backup, media, or log files found to scan', $evidence];
        }

        return [true, 'No cardholder data detected in high-risk files, exports, or backups', $evidence];
    }
    public function cardholderDataLogs(array $args): array
    {
        $roots = $args['paths'] ?? ['var/log', 'var/report', 'pub/media/log', 'pub/media/report'];
        $inc = $args['include_ext'] ?? ['log', 'txt', 'json', 'xml'];
        $max = max(1, (int)($args['max_results'] ?? 100));
        $rootsAbs = array_map(fn($p) => $this->ctx->abs($p), $roots);

        $findings = [];
        $filesRead = 0;
        foreach ($this->collectFiles($rootsAbs, $inc) as $file) {
            $content = @file_get_contents($file);
            if ($content === false) {
                continue;
            }

            $filesRead++;
            foreach ($this->cardholderDataFileFindings($file, $content) as $finding) {
                $findings[] = $finding;
                if (count($findings) >= $max) {
                    break 2;
                }
            }
        }

        $evidence = [
            'paths' => array_values($roots),
            'files_scanned' => $filesRead,
            'findings' => $findings,
            'truncated' => count($findings) >= $max,
        ];

        if ($findings !== []) {
            $lines = ['Cardholder data found in application logs or reports:'];
            foreach ($findings as $finding) {
                $lines[] = sprintf(
                    '    - %s:%d [%s] %s',
                    $finding['file'],
                    $finding['line'],
                    $finding['kind'],
                    $finding['field'] ?? $finding['pattern']
                );
            }
            if ($evidence['truncated']) {
                $lines[] = sprintf('    - output truncated at %d findings', $max);
            }

            return [false, implode("\n", $lines), $evidence];
        }

        if ($filesRead === 0) {
            return [true, 'No application log or report files found to scan', $evidence];
        }

        return [true, 'No cardholder data detected in application logs or reports', $evidence];
    }
    public function paymentMethodScope(array $args): array
    {
        $roots = $args['paths'] ?? ['app/code', 'app/design'];
        $inc = $args['include_ext'] ?? ['php', 'phtml', 'js', 'xml'];
        $max = max(1, (int)($args['max_results'] ?? 100));
        $rootsAbs = array_map(fn($p) => $this->ctx->abs($p), $roots);

        $findings = [];
        $filesRead = 0;
        foreach ($this->collectFiles($rootsAbs, $inc) as $file) {
            $content = @file_get_contents($file);
            if ($content === false) {
                continue;
            }

            $filesRead++;
            foreach ($this->paymentMethodScopeFindings($file, $content) as $finding) {
                $findings[] = $finding;
                if (count($findings) >= $max) {
                    break 2;
                }
            }
        }

        $evidence = [
            'paths' => array_values($roots),
            'files_scanned' => $filesRead,
            'findings' => $findings,
            'truncated' => count($findings) >= $max,
        ];

        if ($findings !== []) {
            $lines = ['Payment method patterns may expand PCI scope:'];
            foreach ($findings as $finding) {
                $lines[] = sprintf(
                    '    - %s:%d [%s] %s',
                    $finding['file'],
                    $finding['line'],
                    $finding['kind'],
                    $finding['field'] ?? $finding['pattern']
                );
            }
            if ($evidence['truncated']) {
                $lines[] = sprintf('    - output truncated at %d findings', $max);
            }

            return [false, implode("\n", $lines), $evidence];
        }

        if ($filesRead === 0) {
            return [true, 'No custom payment method files found to scan', $evidence];
        }

        return [true, 'No direct raw-card payment collection patterns detected', $evidence];
    }
    public function checkoutRawCardCollection(array $args): array
    {
        $roots = $args['paths'] ?? ['app/code', 'app/design'];
        $inc = $args['include_ext'] ?? ['php', 'phtml', 'js', 'html', 'xml'];
        $max = max(1, (int)($args['max_results'] ?? 100));
        $rootsAbs = array_map(fn($p) => $this->ctx->abs($p), $roots);

        $findings = [];
        $filesRead = 0;
        foreach ($this->collectFiles($rootsAbs, $inc) as $file) {
            $content = @file_get_contents($file);
            if ($content === false) {
                continue;
            }

            $filesRead++;
            foreach ($this->checkoutRawCardCollectionFindings($file, $content) as $finding) {
                $findings[] = $finding;
                if (count($findings) >= $max) {
                    break 2;
                }
            }
        }

        $evidence = [
            'paths' => array_values($roots),
            'files_scanned' => $filesRead,
            'findings' => $findings,
            'truncated' => count($findings) >= $max,
        ];

        if ($findings !== []) {
            $lines = ['Raw card collection patterns detected in checkout code:'];
            foreach ($findings as $finding) {
                $lines[] = sprintf(
                    '    - %s:%d [%s] %s',
                    $finding['file'],
                    $finding['line'],
                    $finding['kind'],
                    $finding['field'] ?? $finding['pattern']
                );
            }
            if ($evidence['truncated']) {
                $lines[] = sprintf('    - output truncated at %d findings', $max);
            }

            return [false, implode("\n", $lines), $evidence];
        }

        if ($filesRead === 0) {
            return [true, 'No custom checkout files found to scan', $evidence];
        }

        return [true, 'No raw card collection patterns detected in custom checkout code', $evidence];
    }

    public function paymentScriptInventory(array $args): array
    {
        $inventoryFiles = $args['inventory_files'] ?? ['.magebean/payment-scripts.json', 'docs/payment-script-inventory.md'];
        if (!is_array($inventoryFiles)) {
            $inventoryFiles = ['.magebean/payment-scripts.json', 'docs/payment-script-inventory.md'];
        }
        $roots = $args['paths'] ?? ['app/design', 'app/code'];
        $inc = $args['include_ext'] ?? ['xml', 'phtml', 'html', 'js'];
        $max = max(1, (int)($args['max_results'] ?? 100));
        $rootsAbs = array_map(fn($p) => $this->ctx->abs($p), $roots);

        $inventory = $this->paymentScriptInventoryEvidence(array_values(array_map('strval', $inventoryFiles)));
        $scripts = [];
        $filesRead = 0;
        foreach ($this->collectFiles($rootsAbs, $inc) as $file) {
            $content = @file_get_contents($file);
            if ($content === false) {
                continue;
            }

            $filesRead++;
            foreach ($this->paymentScriptSourceFindings($file, $content) as $finding) {
                $scripts[] = $finding;
                if (count($scripts) >= $max) {
                    break 2;
                }
            }
        }

        $evidence = [
            'inventory' => $inventory,
            'paths' => array_values($roots),
            'files_scanned' => $filesRead,
            'script_sources' => $scripts,
            'truncated' => count($scripts) >= $max,
        ];

        if (!empty($inventory['ok'])) {
            return [true, 'Payment page script inventory is present', $evidence];
        }

        if ($scripts !== []) {
            $lines = ['Payment page script sources detected without an inventory:'];
            foreach ($scripts as $script) {
                $lines[] = sprintf(
                    '    - %s:%d [%s] %s',
                    $script['file'],
                    $script['line'],
                    $script['kind'],
                    $script['source'] ?? $script['snippet'] ?? 'script'
                );
            }
            if ($evidence['truncated']) {
                $lines[] = sprintf('    - output truncated at %d findings', $max);
            }

            return [false, implode("\n", $lines), $evidence];
        }

        if ($filesRead === 0) {
            return [true, 'No custom payment-page files found to scan for script inventory', $evidence];
        }

        return [true, 'No custom payment-page script sources detected', $evidence];
    }


    public function paymentScriptIntegrity(array $args): array
    {
        $evidenceFiles = $args['evidence_files'] ?? ['.magebean/payment-script-integrity.json'];
        if (!is_array($evidenceFiles)) {
            $evidenceFiles = ['.magebean/payment-script-integrity.json'];
        }
        $roots = $args['paths'] ?? ['app/design', 'app/code'];
        $inc = $args['include_ext'] ?? ['xml', 'phtml', 'html', 'js'];
        $max = max(1, (int)($args['max_results'] ?? 100));
        $rootsAbs = array_map(fn($p) => $this->ctx->abs($p), $roots);

        $controlEvidence = $this->paymentScriptIntegrityEvidence(array_values(array_map('strval', $evidenceFiles)));
        $scripts = [];
        $filesRead = 0;
        foreach ($this->collectFiles($rootsAbs, $inc) as $file) {
            $content = @file_get_contents($file);
            if ($content === false) {
                continue;
            }

            $filesRead++;
            $controlEvidence = $this->mergePaymentScriptIntegrityEvidence($controlEvidence, $this->paymentScriptInlineControlEvidence($file, $content));
            foreach ($this->paymentScriptSourceFindings($file, $content) as $finding) {
                $scripts[] = $finding;
                if (count($scripts) >= $max) {
                    break 2;
                }
            }
        }

        $evidence = [
            'controls' => $controlEvidence,
            'paths' => array_values($roots),
            'files_scanned' => $filesRead,
            'script_sources' => $scripts,
            'truncated' => count($scripts) >= $max,
        ];

        if ($scripts === []) {
            return [true, $filesRead === 0 ? 'No custom payment-page files found to scan for script integrity' : 'No custom payment-page script sources detected', $evidence];
        }

        if (!empty($controlEvidence['ok'])) {
            return [true, 'Payment page script allowlist or integrity controls are present', $evidence];
        }

        $lines = ['Payment page scripts detected without allowlist or integrity controls:'];
        foreach ($scripts as $script) {
            $lines[] = sprintf(
                '    - %s:%d [%s] %s',
                $script['file'],
                $script['line'],
                $script['kind'],
                $script['source'] ?? $script['snippet'] ?? 'script'
            );
        }
        if ($evidence['truncated']) {
            $lines[] = sprintf('    - output truncated at %d findings', $max);
        }

        return [false, implode("\n", $lines), $evidence];
    }


    public function checkoutCspEnforced(array $args): array
    {
        $roots = $args['paths'] ?? ['app/code', 'app/etc', 'app/design', 'pub/.htaccess', '.htaccess', 'nginx.conf'];
        $inc = $args['include_ext'] ?? ['xml', 'php', 'phtml', 'html', 'conf', 'htaccess'];
        $required = $args['required_directives'] ?? ['script-src', 'connect-src', 'frame-src', 'form-action'];
        if (!is_array($required)) {
            $required = ['script-src', 'connect-src', 'frame-src', 'form-action'];
        }
        $required = array_values(array_unique(array_map(static fn(mixed $value): string => strtolower((string)$value), $required)));
        $requireReporting = (bool)($args['require_reporting'] ?? true);
        $rootsAbs = array_map(fn($p) => $this->ctx->abs($p), $roots);

        $files = [];
        foreach ($rootsAbs as $root) {
            if (is_file($root)) {
                $files[] = $root;
                continue;
            }
            if (is_dir($root)) {
                foreach ($this->collectFiles([$root], $inc) as $file) {
                    $files[] = $file;
                }
            }
        }
        $files = array_values(array_unique($files));

        $directives = [];
        $locations = [];
        $permissive = [];
        $hasReporting = false;
        $filesRead = 0;
        foreach ($files as $file) {
            $content = @file_get_contents($file);
            if ($content === false) {
                continue;
            }
            $filesRead++;
            $evidence = $this->checkoutCspEvidenceInFile($file, $content);
            foreach ($evidence['directives'] as $directive) {
                $directives[$directive] = true;
            }
            if (!empty($evidence['has_reporting'])) {
                $hasReporting = true;
            }
            foreach ($evidence['locations'] as $location) {
                $locations[] = $location;
            }
            foreach ($evidence['permissive'] as $issue) {
                $permissive[] = $issue;
            }
        }

        $missing = array_values(array_filter($required, static fn(string $directive): bool => empty($directives[$directive])));
        if ($requireReporting && !$hasReporting) {
            $missing[] = 'report-uri/report-to';
        }

        $evidence = [
            'paths' => array_values($roots),
            'files_scanned' => $filesRead,
            'required_directives' => $required,
            'directives' => array_keys($directives),
            'has_reporting' => $hasReporting,
            'locations' => $locations,
            'permissive' => $permissive,
            'missing' => $missing,
        ];

        if ($filesRead === 0) {
            return [false, 'No checkout CSP configuration files found to verify', $evidence];
        }

        if ($missing !== [] || $permissive !== []) {
            $lines = ['Checkout CSP is incomplete or overly permissive:'];
            if ($missing !== []) {
                $lines[] = '    - missing ' . implode(', ', $missing);
            }
            foreach ($permissive as $issue) {
                $lines[] = sprintf('    - %s:%d [%s] %s', $issue['file'], $issue['line'], $issue['kind'], $issue['snippet']);
            }
            return [false, implode("\n", $lines), $evidence];
        }

        return [true, 'Checkout CSP includes required directives and reporting controls', $evidence];
    }

    public function phtmlEscapedOutput(array $args): array
    {
        $roots = $args['paths'] ?? ['app'];
        $max = max(1, (int)($args['max_results'] ?? 50));
        $escapeFunctions = $args['escape_functions'] ?? [
            'escapeHtml',
            'escapeHtmlAttr',
            'escapeUrl',
            'escapeJs',
            'escapeCss',
        ];
        if (!is_array($escapeFunctions)) {
            $escapeFunctions = [];
        }
        $escapeFunctions = array_values(array_filter(array_map(
            static fn(mixed $fn): string => trim((string)$fn),
            $escapeFunctions
        )));

        $rootsAbs = array_map(fn($p) => $this->ctx->abs($p), $roots);
        $files = $this->collectFiles($rootsAbs, ['phtml']);

        $offenders = [];
        foreach ($files as $file) {
            $content = @file_get_contents($file);
            if ($content === false) {
                continue;
            }

            foreach ($this->phtmlOutputFindings($file, $content, $escapeFunctions) as $finding) {
                $offenders[] = $finding;
                if (count($offenders) >= $max) {
                    break 2;
                }
            }
        }

        if ($offenders !== []) {
            return [
                false,
                'Unescaped template output found in: ' . implode(', ', array_map(
                    static fn(array $match): string => $match['file'] . ':' . $match['line'],
                    $offenders
                )),
                $offenders,
            ];
        }

        return [true, 'PHTML output uses approved escaping helpers'];
    }

    public function csrfFormKey(array $args): array
    {
        $roots = $args['paths'] ?? ['app'];
        $max = max(1, (int)($args['max_results'] ?? 50));
        $rootsAbs = array_map(fn($p) => $this->ctx->abs($p), $roots);

        $offenders = [];
        foreach ($this->collectFiles($rootsAbs, ['phtml', 'html']) as $file) {
            $content = @file_get_contents($file);
            if ($content === false) {
                continue;
            }

            foreach ($this->csrfFormFindings($file, $content) as $finding) {
                $offenders[] = $finding;
                if (count($offenders) >= $max) {
                    break 2;
                }
            }
        }

        foreach ($this->collectFiles($rootsAbs, ['php']) as $file) {
            $content = @file_get_contents($file);
            if ($content === false) {
                continue;
            }

            $finding = $this->csrfPostHandlerFinding($file, $content);
            if ($finding !== null) {
                $offenders[] = $finding;
                if (count($offenders) >= $max) {
                    break;
                }
            }
        }

        if ($offenders !== []) {
            return [
                false,
                'Potential CSRF/form_key gaps found in: ' . implode(', ', array_map(
                    static fn(array $match): string => $match['file'] . ':' . $match['line'] . ' [' . $match['kind'] . ']',
                    $offenders
                )),
                $offenders,
            ];
        }

        return [true, 'POST forms and handlers include form_key protection signals'];
    }

    public function ssrfSafeguards(array $args): array
    {
        $roots = $args['paths'] ?? ['app'];
        $inc = $args['include_ext'] ?? ['php'];
        $max = max(1, (int)($args['max_results'] ?? 50));
        $rootsAbs = array_map(fn($p) => $this->ctx->abs($p), $roots);

        $offenders = [];
        foreach ($this->collectFiles($rootsAbs, $inc) as $file) {
            $content = @file_get_contents($file);
            if ($content === false) {
                continue;
            }

            foreach ($this->ssrfFindings($file, $content) as $finding) {
                $offenders[] = $finding;
                if (count($offenders) >= $max) {
                    break 2;
                }
            }
        }

        if ($offenders !== []) {
            return [
                false,
                'Outbound HTTP sinks missing SSRF safeguards in: ' . implode(', ', array_map(
                    static fn(array $match): string => $match['file'] . ':' . $match['line'] . ' [' . $match['kind'] . ']',
                    $offenders
                )),
                $offenders,
            ];
        }

        return [true, 'Outbound HTTP sinks include SSRF safeguard signals'];
    }

    public function outboundEgressControls(array $args): array
    {
        $roots = $args['paths'] ?? ['app/code', 'app/etc'];
        $inc = $args['include_ext'] ?? ['php'];
        $max = max(1, (int)($args['max_results'] ?? 100));
        $rootsAbs = array_map(fn($p) => $this->ctx->abs($p), $roots);

        $sinks = [];
        $failures = [];
        $filesRead = 0;
        foreach ($this->collectFiles($rootsAbs, $inc) as $file) {
            $content = @file_get_contents($file);
            if ($content === false) {
                continue;
            }

            $filesRead++;
            foreach ($this->outboundEgressFindings($file, $content) as $finding) {
                $sinks[] = $finding;
                if (empty($finding['controls']['ok'])) {
                    $failures[] = $finding;
                    if (count($failures) >= $max) {
                        break 2;
                    }
                }
            }
        }

        $evidence = [
            'paths' => array_values($roots),
            'files_scanned' => $filesRead,
            'sinks' => $sinks,
            'failures' => $failures,
            'truncated' => count($failures) >= $max,
        ];

        if ($filesRead === 0) {
            return [null, '[UNKNOWN] Outbound egress scan could not read any target files', $evidence];
        }

        if ($failures !== []) {
            $lines = ['Outbound HTTP sinks missing allowlist/timeout controls:'];
            foreach ($failures as $failure) {
                $lines[] = sprintf(
                    '    - %s:%d [%s] missing %s',
                    $failure['file'],
                    $failure['line'],
                    $failure['kind'],
                    implode('+', $failure['controls']['missing'] ?? ['egress_controls'])
                );
            }
            if ($evidence['truncated']) {
                $lines[] = sprintf('    - output truncated at %d findings', $max);
            }

            return [false, implode("\n", $lines), $evidence];
        }

        if ($sinks === []) {
            return [true, 'No app-level outbound HTTP sinks detected', $evidence];
        }

        return [true, 'Outbound HTTP sinks include allowlist and timeout controls', $evidence];
    }
    public function unserializeSafety(array $args): array
    {
        $roots = $args['paths'] ?? ['app'];
        $inc = $args['include_ext'] ?? ['php'];
        $max = max(1, (int)($args['max_results'] ?? 50));
        $rootsAbs = array_map(fn($p) => $this->ctx->abs($p), $roots);

        $offenders = [];
        foreach ($this->collectFiles($rootsAbs, $inc) as $file) {
            $content = @file_get_contents($file);
            if ($content === false) {
                continue;
            }

            foreach ($this->unserializeFindings($file, $content) as $finding) {
                $offenders[] = $finding;
                if (count($offenders) >= $max) {
                    break 2;
                }
            }
        }

        if ($offenders !== []) {
            return [
                false,
                'Unsafe unserialize usage found in: ' . implode(', ', array_map(
                    static fn(array $match): string => $match['file'] . ':' . $match['line'] . ' [' . $match['risk'] . ']',
                    $offenders
                )),
                $offenders,
            ];
        }

        return [true, 'No unsafe native unserialize() usage detected'];
    }

    public function commandExecutionSafety(array $args): array
    {
        $roots = $args['paths'] ?? ['app'];
        $inc = $args['include_ext'] ?? ['php'];
        $max = max(1, (int)($args['max_results'] ?? 50));
        $rootsAbs = array_map(fn($p) => $this->ctx->abs($p), $roots);

        $offenders = [];
        foreach ($this->collectFiles($rootsAbs, $inc) as $file) {
            $content = @file_get_contents($file);
            if ($content === false) {
                continue;
            }

            foreach ($this->commandExecutionFindings($file, $content) as $finding) {
                $offenders[] = $finding;
                if (count($offenders) >= $max) {
                    break 2;
                }
            }
        }

        if ($offenders !== []) {
            return [
                false,
                'Unsafe command execution found in: ' . implode(', ', array_map(
                    static fn(array $match): string => $match['file'] . ':' . $match['line'] . ' [' . $match['kind'] . '/' . $match['risk'] . ']',
                    $offenders
                )),
                $offenders,
            ];
        }

        return [true, 'Command execution sinks are absent or guarded'];
    }

    public function dynamicExecutionSafety(array $args): array
    {
        $roots = $args['paths'] ?? ['app'];
        $inc = $args['include_ext'] ?? ['php'];
        $max = max(1, (int)($args['max_results'] ?? 50));
        $rootsAbs = array_map(fn($p) => $this->ctx->abs($p), $roots);

        $offenders = [];
        foreach ($this->collectFiles($rootsAbs, $inc) as $file) {
            $content = @file_get_contents($file);
            if ($content === false) {
                continue;
            }

            foreach ($this->dynamicExecutionFindings($file, $content) as $finding) {
                $offenders[] = $finding;
                if (count($offenders) >= $max) {
                    break 2;
                }
            }
        }

        if ($offenders !== []) {
            return [
                false,
                'Unsafe dynamic execution found in: ' . implode(', ', array_map(
                    static fn(array $match): string => $match['file'] . ':' . $match['line'] . ' [' . $match['kind'] . '/' . $match['risk'] . ']',
                    $offenders
                )),
                $offenders,
            ];
        }

        return [true, 'No unsafe dynamic execution patterns detected'];
    }

    public function pathTraversalSafety(array $args): array
    {
        $roots = $args['paths'] ?? ['app'];
        $inc = $args['include_ext'] ?? ['php'];
        $max = max(1, (int)($args['max_results'] ?? 50));
        $rootsAbs = array_map(fn($p) => $this->ctx->abs($p), $roots);

        $offenders = [];
        foreach ($this->collectFiles($rootsAbs, $inc) as $file) {
            $content = @file_get_contents($file);
            if ($content === false) {
                continue;
            }

            foreach ($this->pathTraversalFindings($file, $content) as $finding) {
                $offenders[] = $finding;
                if (count($offenders) >= $max) {
                    break 2;
                }
            }
        }

        if ($offenders !== []) {
            return [
                false,
                'Potential path traversal sinks found in: ' . implode(', ', array_map(
                    static fn(array $match): string => $match['file'] . ':' . $match['line'] . ' [' . $match['kind'] . '/' . $match['risk'] . ']',
                    $offenders
                )),
                $offenders,
            ];
        }

        return [true, 'File path sinks are absent or guarded against traversal'];
    }

    public function uploadSafety(array $args): array
    {
        $roots = $args['paths'] ?? ['app'];
        $inc = $args['include_ext'] ?? ['php'];
        $max = max(1, (int)($args['max_results'] ?? 50));
        $rootsAbs = array_map(fn($p) => $this->ctx->abs($p), $roots);

        $offenders = [];
        foreach ($this->collectFiles($rootsAbs, $inc) as $file) {
            $content = @file_get_contents($file);
            if ($content === false) {
                continue;
            }

            foreach ($this->uploadFindings($file, $content) as $finding) {
                $offenders[] = $finding;
                if (count($offenders) >= $max) {
                    break 2;
                }
            }
        }

        if ($offenders !== []) {
            return [
                false,
                'Potential unsafe upload flows found in: ' . implode(', ', array_map(
                    static fn(array $match): string => $match['file'] . ':' . $match['line'] . ' [' . $match['kind'] . '/' . $match['risk'] . ']',
                    $offenders
                )),
                $offenders,
            ];
        }

        return [true, 'Upload flows are absent or include validation and storage safeguards'];
    }

    public function jsContextEscaping(array $args): array
    {
        $roots = $args['paths'] ?? ['app'];
        $inc = $args['include_ext'] ?? ['phtml', 'html'];
        $max = max(1, (int)($args['max_results'] ?? 50));
        $rootsAbs = array_map(fn($p) => $this->ctx->abs($p), $roots);

        $offenders = [];
        foreach ($this->collectFiles($rootsAbs, $inc) as $file) {
            $content = @file_get_contents($file);
            if ($content === false) {
                continue;
            }

            foreach ($this->jsContextFindings($file, $content) as $finding) {
                $offenders[] = $finding;
                if (count($offenders) >= $max) {
                    break 2;
                }
            }
        }

        if ($offenders !== []) {
            return [
                false,
                'Unescaped JavaScript-context output found in: ' . implode(', ', array_map(
                    static fn(array $match): string => $match['file'] . ':' . $match['line'] . ' [' . $match['kind'] . ']',
                    $offenders
                )),
                $offenders,
            ];
        }

        return [true, 'JavaScript-context PHP output is escaped or encoded'];
    }

    public function csprngSafety(array $args): array
    {
        $roots = $args['paths'] ?? ['app'];
        $inc = $args['include_ext'] ?? ['php'];
        $max = max(1, (int)($args['max_results'] ?? 50));
        $rootsAbs = array_map(fn($p) => $this->ctx->abs($p), $roots);

        $offenders = [];
        foreach ($this->collectFiles($rootsAbs, $inc) as $file) {
            $content = @file_get_contents($file);
            if ($content === false) {
                continue;
            }

            foreach ($this->csprngFindings($file, $content) as $finding) {
                $offenders[] = $finding;
                if (count($offenders) >= $max) {
                    break 2;
                }
            }
        }

        if ($offenders !== []) {
            return [
                false,
                'Weak PRNG used in security-sensitive context: ' . implode(', ', array_map(
                    static fn(array $match): string => $match['file'] . ':' . $match['line'] . ' [' . $match['kind'] . '/' . $match['risk'] . ']',
                    $offenders
                )),
                $offenders,
            ];
        }

        return [true, 'No weak PRNG detected in security-sensitive randomness'];
    }

    public function sensitiveLogging(array $args): array
    {
        $roots = $args['paths'] ?? ['app'];
        $inc = $args['include_ext'] ?? ['php'];
        $max = max(1, (int)($args['max_results'] ?? 50));
        $rootsAbs = array_map(fn($p) => $this->ctx->abs($p), $roots);

        $offenders = [];
        foreach ($this->collectFiles($rootsAbs, $inc) as $file) {
            $content = @file_get_contents($file);
            if ($content === false) {
                continue;
            }

            foreach ($this->sensitiveLoggingFindings($file, $content) as $finding) {
                $offenders[] = $finding;
                if (count($offenders) >= $max) {
                    break 2;
                }
            }
        }

        if ($offenders !== []) {
            return [
                false,
                'Sensitive data may be logged in: ' . implode(', ', array_map(
                    static fn(array $match): string => $match['file'] . ':' . $match['line'] . ' [' . $match['kind'] . '/' . $match['risk'] . ']',
                    $offenders
                )),
                $offenders,
            ];
        }

        return [true, 'No raw sensitive data logging detected'];
    }

    public function magentoApiCryptoSession(array $args): array
    {
        $roots = $args['paths'] ?? ['app'];
        $inc = $args['include_ext'] ?? ['php'];
        $max = max(1, (int)($args['max_results'] ?? 50));
        $rootsAbs = array_map(fn($p) => $this->ctx->abs($p), $roots);

        $offenders = [];
        foreach ($this->collectFiles($rootsAbs, $inc) as $file) {
            $content = @file_get_contents($file);
            if ($content === false) {
                continue;
            }

            foreach ($this->magentoApiCryptoSessionFindings($file, $content) as $finding) {
                $offenders[] = $finding;
                if (count($offenders) >= $max) {
                    break 2;
                }
            }
        }

        if ($offenders !== []) {
            return [
                false,
                'Raw crypto/session API usage found in: ' . implode(', ', array_map(
                    static fn(array $match): string => $match['file'] . ':' . $match['line'] . ' [' . $match['kind'] . '/' . $match['risk'] . ']',
                    $offenders
                )),
                $offenders,
            ];
        }

        return [true, 'Magento crypto and session APIs are used'];
    }

    public function noMixedContent(array $args): array
    {
        $roots = $args['paths'] ?? ['app'];
        $inc = $args['include_ext'] ?? ['phtml', 'html', 'xml', 'js', 'css', 'less'];
        $max = max(1, (int)($args['max_results'] ?? 50));
        $rootsAbs = array_map(fn($p) => $this->ctx->abs($p), $roots);

        $offenders = [];
        foreach ($this->collectFiles($rootsAbs, $inc) as $file) {
            $content = @file_get_contents($file);
            if ($content === false) {
                continue;
            }

            foreach ($this->mixedContentFindings($file, $content) as $finding) {
                $offenders[] = $finding;
                if (count($offenders) >= $max) {
                    break 2;
                }
            }
        }

        if ($offenders !== []) {
            return [
                false,
                'Insecure http:// asset references found in: ' . implode(', ', array_map(
                    static fn(array $match): string => $match['file'] . ':' . $match['line'] . ' [' . $match['kind'] . ']',
                    $offenders
                )),
                $offenders,
            ];
        }

        return [true, 'No insecure http:// asset references found in code'];
    }

    public function httpsEndpoints(array $args): array
    {
        $roots = $args['paths'] ?? ['app/etc', 'app/code', 'app/design'];
        $inc = $args['include_ext'] ?? ['php', 'phtml', 'xml', 'json', 'yaml', 'yml', 'ini', 'js', 'html', 'css'];
        $max = max(1, (int)($args['max_results'] ?? 200));
        $requiredFiles = array_values(array_unique(array_map('strval', $args['required_files'] ?? [])));
        $rootsAbs = array_map(fn($p) => $this->ctx->abs($p), $roots);

        $files = $this->collectFiles($rootsAbs, $inc);
        $seen = [];
        foreach ($files as $file) {
            $seen[$this->relativeFile($file)] = true;
        }

        $missingRequired = [];
        foreach ($requiredFiles as $requiredFile) {
            $abs = $this->ctx->abs($requiredFile);
            if (!is_file($abs)) {
                $missingRequired[] = $requiredFile;
                continue;
            }

            if (!isset($seen[$requiredFile])) {
                $files[] = $abs;
                $seen[$requiredFile] = true;
            }
        }

        $offenders = [];
        $unreadable = [];
        $filesRead = 0;
        foreach (array_values(array_unique($files)) as $file) {
            $content = @file_get_contents($file);
            if ($content === false) {
                $unreadable[] = $this->relativeFile($file);
                continue;
            }

            $filesRead++;
            foreach ($this->configuredPlainHttpFindings($file, $content) as $finding) {
                $offenders[] = $finding;
                if (count($offenders) >= $max) {
                    break 2;
                }
            }
        }

        $targetUrl = trim($this->ctx->url);
        if (preg_match('~^http://~i', $targetUrl) === 1 && count($offenders) < $max) {
            $offenders[] = [
                'file' => 'scan target URL',
                'line' => 0,
                'pattern' => 'target_url',
                'snippet' => $targetUrl,
                'kind' => 'target_url',
                'url' => $targetUrl,
            ];
        }

        if ($hasApplicationSignatureValidation) {
            $failures = array_values(array_filter($failures, static fn(array $failure): bool => !str_starts_with((string)$failure['kind'], 'xml_')));
        }

        $evidence = [
            'paths' => array_values($roots),
            'files_scanned' => $filesRead,
            'target_url' => $targetUrl,
            'missing_required_files' => $missingRequired,
            'unreadable_files' => $unreadable,
            'insecure_endpoints' => $offenders,
            'truncated' => count($offenders) >= $max,
        ];

        if ($offenders !== []) {
            $lines = ['Configured HTTP endpoints detected:'];
            foreach ($offenders as $match) {
                $location = ($match['line'] ?? 0) > 0
                    ? sprintf('%s:%d', $match['file'], $match['line'])
                    : (string)$match['file'];
                $lines[] = sprintf(
                    '    - %s [%s] %s',
                    $location,
                    $match['kind'],
                    $match['url']
                );
            }
            if ($evidence['truncated']) {
                $lines[] = sprintf('    - output truncated at %d findings', $max);
            }

            return [false, implode("\n", $lines), $evidence];
        }

        if ($filesRead === 0) {
            return [null, 'HTTPS endpoint scan could not read any target files', $evidence];
        }

        if ($missingRequired !== [] || $unreadable !== []) {
            $parts = [];
            if ($missingRequired !== []) {
                $parts[] = 'missing required files: ' . implode(', ', $missingRequired);
            }
            if ($unreadable !== []) {
                $parts[] = 'unreadable files: ' . implode(', ', $unreadable);
            }

            return [null, 'HTTPS endpoint scan incomplete (' . implode('; ', $parts) . ')', $evidence];
        }

        return [true, 'All detected configured endpoints use HTTPS', $evidence];
    }

    public function webhookSignatureValidation(array $args): array
    {
        $roots = $args['paths'] ?? ['app/code', 'app/etc', 'routes'];
        $inc = $args['include_ext'] ?? ['php', 'xml'];
        $max = max(1, (int)($args['max_results'] ?? 100));
        $rootsAbs = array_map(fn($p) => $this->ctx->abs($p), $roots);

        $handlers = [];
        $failures = [];
        $hasApplicationSignatureValidation = false;
        $filesRead = 0;
        foreach ($this->collectFiles($rootsAbs, $inc) as $file) {
            $content = @file_get_contents($file);
            if ($content === false) {
                continue;
            }

            $filesRead++;
            if (strtolower(pathinfo($file, PATHINFO_EXTENSION)) === 'php'
                && !empty($this->webhookSignatureEvidence($content, 0)['ok'])) {
                $hasApplicationSignatureValidation = true;
            }

            foreach ($this->webhookHandlerFindings($file, $content) as $handler) {
                $validation = $this->webhookSignatureEvidence($content, (int)$handler['offset']);
                $handler['signature_evidence'] = $validation;
                unset($handler['offset']);
                $handlers[] = $handler;
                if (empty($validation['ok'])) {
                    $failures[] = $handler;
                    if (count($failures) >= $max) {
                        break 2;
                    }
                }
            }
        }

        if ($hasApplicationSignatureValidation) {
            $failures = array_values(array_filter($failures, static fn(array $failure): bool => !str_starts_with((string)$failure['kind'], 'xml_')));
        }

        $evidence = [
            'paths' => array_values($roots),
            'files_scanned' => $filesRead,
            'has_application_signature_validation' => $hasApplicationSignatureValidation,
            'handlers' => $handlers,
            'failures' => $failures,
            'truncated' => count($failures) >= $max,
        ];

        if ($filesRead === 0) {
            return [null, '[UNKNOWN] Webhook signature scan could not read any target files', $evidence];
        }

        if ($failures !== []) {
            $lines = ['Webhook handlers without local signature validation evidence:'];
            foreach ($failures as $failure) {
                $lines[] = sprintf(
                    '    - %s:%d [%s] missing %s',
                    $failure['file'],
                    $failure['line'],
                    $failure['kind'],
                    implode('+', $failure['signature_evidence']['missing'] ?? ['signature_validation'])
                );
            }
            if ($evidence['truncated']) {
                $lines[] = sprintf('    - output truncated at %d findings', $max);
            }

            return [false, implode("\n", $lines), $evidence];
        }

        if ($handlers === []) {
            return [true, 'No webhook handlers detected in application code', $evidence];
        }

        return [true, 'Webhook handlers include local signature validation evidence', $evidence];
    }
    private function collectFiles(array $roots, array $inc): array
    {
        $ret = [];
        $incLower = array_map('strtolower', $inc);
        foreach ($roots as $root) {
            if (!is_dir($root)) continue;
            $rii = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator(
                $root, \FilesystemIterator::SKIP_DOTS
            ));
            foreach ($rii as $f) {
                if (!$f->isFile()) continue;
                $ext = strtolower(pathinfo($f->getFilename(), PATHINFO_EXTENSION));
                if ($ext === '' || !in_array($ext, $incLower, true)) continue;
                // mặc định bỏ qua file > 1MB để tránh tốn bộ nhớ
                if ($f->getSize() > 1024*1024) continue;
                $ret[] = $f->getPathname();
            }
        }
        return $ret;
    }




    private function checkoutCspEvidenceInFile(string $file, string $content): array
    {
        $extension = strtolower(pathinfo($file, PATHINFO_EXTENSION));
        $scanContent = $this->maskSourceComments($content, $extension);
        $directives = [];
        $locations = [];
        $permissive = [];
        $reporting = preg_match('~\b(?:report-uri|report-to|SecurityPolicyViolationEvent|csp[_/-]?report(?:[_/-]?uri)?|report_uri|report_only)\b~i', $scanContent) === 1;
        $directiveRegex = '~\b(?P<directive>script-src|connect-src|frame-src|form-action)\b~i';
        if (preg_match_all($directiveRegex, $scanContent, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER) > 0) {
            foreach ($matches as $match) {
                $directive = strtolower((string)$match['directive'][0]);
                $directives[$directive] = true;
                $locations[] = $this->matchEvidence($file, $content, 'csp_directive', (int)$match['directive'][1]);
            }
        }

        if (preg_match_all('~<policy\b[^>]*\bid\s*=\s*([\'\"])(?P<directive>script-src|connect-src|frame-src|form-action)\1~i', $scanContent, $policyMatches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER) > 0) {
            foreach ($policyMatches as $match) {
                $directive = strtolower((string)$match['directive'][0]);
                $directives[$directive] = true;
                $locations[] = $this->matchEvidence($file, $content, 'csp_policy', (int)$match['directive'][1]);
            }
        }

        $badPatterns = [
            'wildcard_source' => '~(?:\b(?:script-src|connect-src|frame-src|form-action)\b|<policy\b[^>]*\bid\s*=\s*([\'\"])(?:script-src|connect-src|frame-src|form-action)\1)[\s\S]{0,500}(?:\s\*\s|<value\b[^>]*>\s*\*\s*</value>)~i',
            'unsafe_eval' => '~\bunsafe-eval\b~i',
            'unsafe_inline_without_nonce' => '~\bunsafe-inline\b(?![\s\S]{0,300}(?:nonce-|sha256-|sha384-|sha512-))~i',
        ];
        foreach ($badPatterns as $kind => $regex) {
            if (preg_match_all($regex, $scanContent, $badMatches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER) < 1) {
                continue;
            }
            foreach ($badMatches as $match) {
                $evidence = $this->matchEvidence($file, $content, $kind, (int)$match[0][1]);
                $evidence['kind'] = $kind;
                $permissive[] = $evidence;
            }
        }

        return [
            'directives' => array_keys($directives),
            'has_reporting' => $reporting,
            'locations' => $locations,
            'permissive' => $permissive,
        ];
    }

    private function paymentScriptIntegrityEvidence(array $files): array
    {
        $evidence = [
            'ok' => false,
            'manifest' => false,
            'sri_or_hash' => false,
            'nonce' => false,
            'csp_allowlist' => false,
            'monitoring' => false,
            'files' => [],
        ];

        foreach ($files as $relative) {
            $path = $this->ctx->abs($relative);
            $entry = ['file' => $relative, 'present' => is_file($path), 'ok' => false];
            if (!is_file($path)) {
                $evidence['files'][] = $entry;
                continue;
            }

            $content = @file_get_contents($path);
            if ($content === false) {
                $entry['readable'] = false;
                $evidence['files'][] = $entry;
                continue;
            }

            $entry['readable'] = true;
            $decoded = json_decode($content, true);
            if (is_array($decoded)) {
                $entry['entries'] = $this->countPaymentScriptInventoryEntries($decoded);
                $entry['ok'] = $entry['entries'] > 0;
                $evidence['manifest'] = $evidence['manifest'] || $entry['ok'];
                $evidence['sri_or_hash'] = $evidence['sri_or_hash'] || preg_match('~\b(?:sha(?:256|384|512)-|integrity|hash|sri)\b~i', $content) === 1;
                $evidence['nonce'] = $evidence['nonce'] || preg_match('~\bnonce\b~i', $content) === 1;
                $evidence['monitoring'] = $evidence['monitoring'] || preg_match('~\b(?:monitor|tamper|report-uri|report-to|violation)\b~i', $content) === 1;
            }

            $evidence['files'][] = $entry;
        }

        $evidence['ok'] = $evidence['manifest'] || $evidence['sri_or_hash'] || $evidence['nonce'] || $evidence['csp_allowlist'] || $evidence['monitoring'];
        return $evidence;
    }

    private function paymentScriptInlineControlEvidence(string $file, string $content): array
    {
        $relative = $this->relativeFile($file);
        $text = $relative . "\n" . $content;
        $evidence = [
            'ok' => false,
            'manifest' => false,
            'sri_or_hash' => preg_match('~\b(?:integrity\s*=|sha(?:256|384|512)-|sri|script_hash)\b~i', $text) === 1,
            'nonce' => preg_match('~\b(?:nonce\s*=|csp_nonce|script_nonce|nonceProvider|getNonce)\b~i', $text) === 1,
            'csp_allowlist' => preg_match('~\b(?:csp_whitelist|script-src|connect-src|frame-src|form-action)\b~i', $text) === 1,
            'monitoring' => preg_match('~\b(?:report-uri|report-to|SecurityPolicyViolationEvent|tamper|integrity[_-]?monitor|checkout[_-]?monitor)\b~i', $text) === 1,
            'files' => [],
        ];
        $evidence['ok'] = $evidence['sri_or_hash'] || $evidence['nonce'] || $evidence['csp_allowlist'] || $evidence['monitoring'];
        return $evidence;
    }

    private function mergePaymentScriptIntegrityEvidence(array $left, array $right): array
    {
        foreach (['manifest', 'sri_or_hash', 'nonce', 'csp_allowlist', 'monitoring'] as $key) {
            $left[$key] = !empty($left[$key]) || !empty($right[$key]);
        }
        $left['ok'] = !empty($left['manifest']) || !empty($left['sri_or_hash']) || !empty($left['nonce']) || !empty($left['csp_allowlist']) || !empty($left['monitoring']);
        if (!empty($right['files']) && is_array($right['files'])) {
            $left['files'] = array_merge($left['files'] ?? [], $right['files']);
        }
        return $left;
    }

    private function paymentScriptInventoryEvidence(array $files): array
    {
        $checked = [];
        foreach ($files as $relative) {
            $path = $this->ctx->abs($relative);
            $entry = ['file' => $relative, 'present' => is_file($path), 'ok' => false];
            if (!is_file($path)) {
                $checked[] = $entry;
                continue;
            }

            $content = @file_get_contents($path);
            if ($content === false) {
                $entry['readable'] = false;
                $checked[] = $entry;
                continue;
            }

            $entry['readable'] = true;
            $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
            if ($ext === 'json') {
                $decoded = json_decode($content, true);
                $entries = $this->countPaymentScriptInventoryEntries($decoded);
                $entry['entries'] = $entries;
                $entry['ok'] = $entries > 0;
            } else {
                $hasScript = preg_match('~\b(?:script|src|source|checkout|payment|owner|justification|approved)\b~i', $content) === 1;
                $entry['ok'] = $hasScript && preg_match('~\b(?:checkout|payment)\b~i', $content) === 1;
            }

            $checked[] = $entry;
            if (!empty($entry['ok'])) {
                return ['ok' => true, 'files' => $checked];
            }
        }

        return ['ok' => false, 'files' => $checked];
    }

    private function countPaymentScriptInventoryEntries(mixed $decoded): int
    {
        if (!is_array($decoded)) {
            return 0;
        }

        $entries = array_is_list($decoded) ? $decoded : ($decoded['scripts'] ?? $decoded['entries'] ?? []);
        if (!is_array($entries)) {
            return 0;
        }

        $count = 0;
        foreach ($entries as $entry) {
            if (!is_array($entry)) {
                continue;
            }
            $source = (string)($entry['source'] ?? $entry['src'] ?? $entry['url'] ?? $entry['path'] ?? '');
            if ($source !== '') {
                $count++;
            }
        }

        return $count;
    }

    private function paymentScriptSourceFindings(string $file, string $content): array
    {
        $relative = $this->relativeFile($file);
        if (!$this->hasPaymentPageScriptContext($relative, $content)) {
            return [];
        }

        $extension = strtolower(pathinfo($file, PATHINFO_EXTENSION));
        $findings = [];
        $patterns = [];
        if (in_array($extension, ['phtml', 'html'], true)) {
            $patterns['script_tag'] = '~<script\b(?P<attrs>[^>]*)>~is';
        }
        if ($extension === 'xml') {
            $patterns['layout_script'] = '~<(?:script|link)\b[^>]*(?:\bsrc\s*=\s*([\'\"])(?P<src>[^\'\"]+)\1|>(?P<body>[^<]+)</(?:script|link)>)~is';
            $patterns['csp_whitelist_script'] = '~<policy\b[^>]*\bid\s*=\s*([\'\"])(?:script-src|connect-src|frame-src)\1[\s\S]{0,800}<value\b[^>]*>(?P<src>[^<]+)</value>~is';
        }
        if ($extension === 'js' && preg_match('~(?:checkout|payment|placeOrder|setPaymentInformation|script|src|loadScript|require\s*\()~i', $relative . "\n" . $content) === 1) {
            $patterns['custom_payment_js'] = '~\b(?:define\s*\(|require\s*\(|loadScript|script|src|checkout|payment|placeOrder|setPaymentInformation)\b~i';
        }

        foreach ($patterns as $kind => $regex) {
            if (preg_match_all($regex, $content, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER) < 1) {
                continue;
            }

            foreach ($matches as $match) {
                $offset = (int)$match[0][1];
                $source = $this->paymentScriptSourceFromMatch($kind, $match, $content, $offset, $relative);
                if ($source === null) {
                    continue;
                }

                $evidence = $this->matchEvidence($file, $content, $kind, $offset);
                $evidence['kind'] = $kind;
                $evidence['source'] = $source;
                $findings[] = $evidence;
            }
        }

        return $this->dedupeFindings($findings);
    }

    private function hasPaymentPageScriptContext(string $relative, string $content): bool
    {
        return preg_match('~(?:checkout|payment|billing|placeOrder|setPaymentInformation|Magento_Checkout|csp_whitelist|script-src|connect-src|frame-src)~i', $relative . "\n" . $content) === 1;
    }

    private function paymentScriptSourceFromMatch(string $kind, array $match, string $content, int $offset, string $relative): ?string
    {
        if (isset($match['src']) && is_array($match['src']) && trim((string)$match['src'][0]) !== '') {
            return trim((string)$match['src'][0]);
        }
        if (isset($match['body']) && is_array($match['body']) && trim((string)$match['body'][0]) !== '') {
            return trim((string)$match['body'][0]);
        }
        if ($kind === 'script_tag') {
            $attrs = isset($match['attrs']) && is_array($match['attrs']) ? (string)$match['attrs'][0] : '';
            if (preg_match('~\bsrc\s*=\s*([\'\"])(?P<src>[^\'\"]+)\1~i', $attrs, $srcMatch) === 1) {
                return trim((string)$srcMatch['src']);
            }
            return 'inline script in payment/checkout template';
        }
        if ($kind === 'custom_payment_js') {
            return $relative;
        }

        return null;
    }

    private function checkoutRawCardCollectionFindings(string $file, string $content): array
    {
        $relative = $this->relativeFile($file);
        $extension = strtolower(pathinfo($file, PATHINFO_EXTENSION));
        $searchable = $this->maskSourceComments($content, $extension);
        if (!$this->hasCheckoutRawCardContext($relative, $searchable)) {
            return [];
        }

        $findings = [];
        foreach ($this->paymentMethodScopeFindings($file, $content) as $finding) {
            $window = $this->codeWindow($searchable, max(0, (int)($finding['offset'] ?? 0)), 1800);
            if ($this->hasCheckoutRawCardContext($relative, $window)) {
                unset($finding['offset']);
                $findings[] = $finding;
            }
        }

        return $this->dedupeFindings($findings);
    }

    private function hasCheckoutRawCardContext(string $relative, string $text): bool
    {
        return preg_match('~(?:checkout|onepage|payment|billing|Magento_Checkout|checkout_index_index|payment-method|payment_method|placeOrder|setPaymentInformation|savePaymentInformation|card|creditcard|cvv|cvc)~i', $relative . "\n" . $text) === 1;
    }
    private function paymentMethodScopeFindings(string $file, string $content): array
    {
        $extension = strtolower(pathinfo($file, PATHINFO_EXTENSION));
        $relative = $this->relativeFile($file);
        $searchable = $this->maskSourceComments($content, $extension);
        if (!$this->hasPaymentScopeContext($relative, $searchable)) {
            return [];
        }

        $findings = [];
        $patterns = [
            'direct_post' => '~\b(?:direct[_ -]?post|raw[_ -]?card|onsite[_ -]?card|manual[_ -]?card)\b~i',
            'raw_card_form_field' => '~<(?P<tag>input|select|textarea|field)\b[^>]*(?:\b(?:name|id|data-bind|ko-value|data-validate)\s*=\s*([\'\"])(?P<field>[^\'\"]*(?:cc[_-]?(?:num|number)|card[_-]?number|credit[_-]?card[_-]?number|cvv|cvc|cid)[^\'\"]*)\2)[^>]*>~i',
            'php_raw_card_request' => '~(?:->\s*(?:getParam|getPost|getPostValue|getData)\s*\(|\$_(?:POST|REQUEST)\s*\[)\s*[\'\"](?P<field>[^\'\"]*(?:cc[_-]?(?:num|number)|card[_-]?number|credit[_-]?card[_-]?number|cvv|cvc|cid)[^\'\"]*)[\'\"]~i',
            'js_raw_card_capture' => '~(?:querySelector|getElementById|\$\s*\(|document\.forms?|\.val\s*\(|\.value\b)[^;\n]{0,220}(?P<field>\b(?:cc[_-]?(?:num|number)|card[_-]?number|cardNumber|creditCardNumber|cvv|cvc|cid)\b)~i',
            'js_raw_card_config' => '~\b(?:dataScope|name|id|field|component|value)\s*:\s*([\'\"])(?P<field>[^\'\"]*(?:cc[_-]?(?:num|number)|card[_-]?number|cardNumber|creditCardNumber|cvv|cvc|cid)[^\'\"]*)\1~i',
            'xml_raw_card_config' => '~<item\b[^>]*\bname\s*=\s*([\'\"])(?P<field>[^\'\"]*(?:cc[_-]?(?:num|number)|card[_-]?number|cvv|cvc|cid)[^\'\"]*)\1[^>]*>~i',
            'php_additional_data_raw_card' => '~(?:getAdditionalInformation|getData|setAdditionalInformation|setData)\s*\(\s*([\'\"])(?P<field>[^\'\"]*(?:cc[_-]?(?:num|number)|card[_-]?number|credit[_-]?card[_-]?number|cvv|cvc|cid)[^\'\"]*)\1~i',
            'ajax_raw_card_submit' => '~(?P<field>\b(?:cc[_-]?(?:num|number)|card[_-]?number|cardNumber|creditCardNumber|cvv|cvc|cid)\b)[\s\S]{0,360}\b(?:fetch|XMLHttpRequest|\.ajax|mage/storage|storage\.post|post\s*\()\b~i',
        ];

        foreach ($patterns as $kind => $regex) {
            if (preg_match_all($regex, $searchable, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER) < 1) {
                continue;
            }

            foreach ($matches as $match) {
                $offset = (int)$match[0][1];
                $window = $this->codeWindow($searchable, $offset, 1800);
                $field = isset($match['field']) && is_array($match['field']) ? (string)$match['field'][0] : $kind;

                if ($kind !== 'direct_post' && !$this->looksLikeRawPaymentField($field)) {
                    continue;
                }
                if ($this->isSafeHostedPaymentScopeContext($window) && !in_array($kind, ['raw_card_form_field', 'php_raw_card_request', 'php_additional_data_raw_card'], true)) {
                    continue;
                }
                if (!$this->hasPaymentScopeContext($relative, $window)) {
                    continue;
                }

                $evidence = $this->matchEvidence($file, $content, $kind, $offset);
                $evidence['kind'] = $kind;
                $evidence['field'] = $field;
                $evidence['offset'] = $offset;
                $findings[] = $evidence;
            }
        }

        return $this->dedupeFindings($findings);
    }

    private function hasPaymentScopeContext(string $relative, string $text): bool
    {
        return preg_match('~(?:checkout|payment|billing|card|creditcard|gateway|directpost|paypal|braintree|stripe|adyen|authorizenet|authorize|klarna|vault|hosted[_ -]?field|iframe|tokeni[sz]e)~i', $relative . "\n" . $text) === 1;
    }

    private function looksLikeRawPaymentField(string $field): bool
    {
        $normalized = strtolower(str_replace(['-', '.', '/', ':', '[', ']'], '_', trim($field)));
        if (preg_match('~(?:last4|last_four|token|nonce|vault|masked|brand|type|expiry|exp_month|exp_year|cardholder|holder|name)~i', $normalized) === 1) {
            return false;
        }

        return preg_match('~(?:^|_)(?:cc_(?:num|number)|card_number|credit_card_number|cvv|cvc|cid|cardnumber|creditcardnumber)(?:_|$)~i', $normalized) === 1;
    }

    private function isSafeHostedPaymentScopeContext(string $window): bool
    {
        return preg_match('~\b(?:hosted[_ -]?fields?|iframe|redirect|checkout\.com|stripe\.elements|elements\s*\(|createToken|confirmCardPayment|payment_method_nonce|paymentMethodNonce|tokeni[sz]e|braintree\.hostedFields|hostedFields\.create|paypal\.Buttons|AdyenCheckout|encryptedCardNumber|encryptedSecurityCode|klarna|vault[_ -]?token|payment[_ -]?token)\b~i', $window) === 1;
    }
    private function cardholderDataFileFindings(string $file, string $content): array
    {
        $extension = strtolower(pathinfo($file, PATHINFO_EXTENSION));
        $findings = [];

        foreach ($this->cardholderFilePanFindings($file, $content) as $finding) {
            $findings[] = $finding;
        }

        foreach ($this->cardholderFileSensitiveFieldFindings($file, $content, $extension) as $finding) {
            $findings[] = $finding;
        }

        return $this->dedupeFindings($findings);
    }

    private function cardholderFilePanFindings(string $file, string $content): array
    {
        $findings = [];
        $seen = [];
        if (preg_match_all('~(?<!\d)(?:\d[ -]?){13,19}(?!\d)~', $content, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER) < 1) {
            return [];
        }

        foreach ($matches as $match) {
            $raw = (string)$match[0][0];
            $digits = preg_replace('~\D+~', '', $raw) ?? '';
            if (!$this->isLuhnValidPan($digits)) {
                continue;
            }

            $offset = (int)$match[0][1];
            $window = $this->codeWindow($content, $offset, 220);
            if ($this->isMaskedOrTokenizedCardFileContext($window)) {
                continue;
            }

            $fingerprint = substr($digits, 0, 6) . ':' . substr($digits, -4);
            if (isset($seen[$fingerprint])) {
                continue;
            }
            $seen[$fingerprint] = true;

            $evidence = $this->matchEvidence($file, $content, 'pan', $offset);
            $evidence['kind'] = 'pan';
            $evidence['field'] = 'Luhn-valid PAN-like value ending ' . substr($digits, -4);
            $findings[] = $evidence;
        }

        return $findings;
    }

    private function cardholderFileSensitiveFieldFindings(string $file, string $content, string $extension): array
    {
        $findings = [];
        $patterns = [
            'cvv' => '~(?P<field>\b(?:cvv|cvc|cid|card[_ -]?security[_ -]?code)\b)\s*(?:=|:|,|;|\t|=>)\s*[\'\"]?(?P<value>\d{3,4})\b~i',
            'track_data' => '~(?P<field>\b(?:track\s*[12]|track_[12]|magnetic[_ -]?stripe)\b)\s*(?:=|:|,|;|\t|=>)?\s*(?P<value>[^\r\n]{0,160})~i',
        ];

        foreach ($patterns as $kind => $regex) {
            if (preg_match_all($regex, $content, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER) < 1) {
                continue;
            }

            foreach ($matches as $match) {
                $field = (string)$match['field'][0];
                $value = isset($match['value']) && is_array($match['value']) ? trim((string)$match['value'][0]) : '';
                $offset = (int)$match['field'][1];
                $window = $this->codeWindow($content, $offset, 260);

                if ($this->isMaskedOrTokenizedCardFileContext($window)) {
                    continue;
                }
                if ($kind === 'track_data' && !$this->looksLikeTrackDataValue($value, $window)) {
                    continue;
                }
                if ($kind === 'cvv' && $extension === 'xml' && preg_match('~<field\b[^>]*\bid\s*=~i', $window) === 1) {
                    continue;
                }

                $evidence = $this->matchEvidence($file, $content, $kind, $offset);
                $evidence['kind'] = $kind;
                $evidence['field'] = $field;
                $evidence['offset'] = $offset;
                $findings[] = $evidence;
            }
        }

        return $findings;
    }

    private function isLuhnValidPan(string $digits): bool
    {
        $length = strlen($digits);
        if ($length < 13 || $length > 19) {
            return false;
        }
        if (preg_match('~^(\d)\1+$~', $digits) === 1) {
            return false;
        }
        if (preg_match('~^(?:0+|1+|9+)$~', $digits) === 1) {
            return false;
        }

        $sum = 0;
        $alternate = false;
        for ($i = $length - 1; $i >= 0; $i--) {
            $n = (int)$digits[$i];
            if ($alternate) {
                $n *= 2;
                if ($n > 9) {
                    $n -= 9;
                }
            }
            $sum += $n;
            $alternate = !$alternate;
        }

        return $sum % 10 === 0;
    }

    private function isMaskedOrTokenizedCardFileContext(string $window): bool
    {
        return preg_match('~(?:\*{4,}|x{4,}|X{4,}|last\s*4|last4|cc_last4|ending[_ -]?in|token|nonce|vault|payment[_ -]?token|customer[_ -]?profile|payment[_ -]?profile|reference|masked|redacted|fingerprint)~i', $window) === 1;
    }

    private function looksLikeTrackDataValue(string $value, string $window): bool
    {
        return preg_match('~(?:%?B\d{13,19}\^|;\d{13,19}=|\b(?:track\s*[12]|track_[12]|magnetic[_ -]?stripe)\b\s*(?:=|:|,|;|\t|=>)\s*[^\r\n]{6,})~i', $value . "\n" . $window) === 1;
    }
    private function cardholderDataStorageFindings(string $file, string $content): array
    {
        $extension = strtolower(pathinfo($file, PATHINFO_EXTENSION));
        $relative = $this->relativeFile($file);
        $searchable = $this->maskSourceComments($content, $extension);
        $findings = [];

        foreach ($this->cardholderSchemaColumnFindings($file, $content, $searchable, $extension) as $finding) {
            $findings[] = $finding;
        }

        foreach ($this->cardholderSqlStorageFindings($file, $content, $searchable, $extension) as $finding) {
            $findings[] = $finding;
        }

        if (in_array($extension, ['php', 'json', 'xml'], true)) {
            foreach ($this->cardholderCodeStorageFindings($file, $content, $searchable, $relative, $extension) as $finding) {
                $findings[] = $finding;
            }
        }

        return $this->dedupeFindings($findings);
    }

    private function cardholderSchemaColumnFindings(string $file, string $content, string $searchable, string $extension): array
    {
        $findings = [];
        $relative = $this->relativeFile($file);
        if ($extension !== 'xml' || preg_match('~(?:db_schema\.xml|schema\.xml)$~i', $relative) !== 1) {
            return [];
        }

        if (preg_match_all('~<column\b(?P<attrs>[^>]*)>~is', $searchable, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER) < 1) {
            return [];
        }

        foreach ($matches as $match) {
            $attrs = (string)$match['attrs'][0];
            $field = $this->xmlAttributeValue($attrs, 'name') ?? $this->xmlAttributeValue($attrs, 'xsi:type') ?? 'column';
            if (!$this->isRawCardholderField($field)) {
                continue;
            }

            $offset = (int)$match[0][1];
            $evidence = $this->matchEvidence($file, $content, 'schema_column', $offset);
            $evidence['kind'] = 'schema_column';
            $evidence['field'] = $field;
            $findings[] = $evidence;
        }

        return $findings;
    }

    private function cardholderSqlStorageFindings(string $file, string $content, string $searchable, string $extension): array
    {
        $findings = [];
        $sqlContext = $extension === 'sql' || preg_match('~\b(?:CREATE|ALTER)\s+TABLE|\b(?:INSERT\s+INTO|UPDATE)\b~i', $searchable) === 1;
        if (!$sqlContext) {
            return [];
        }

        $patterns = [
            'sql_schema_column' => '~\b(?:CREATE|ALTER)\s+TABLE\b[^;]{0,1800}(?P<field>\b[A-Za-z0-9_]*(?:cc[_-]?(?:num|number)|card[_-]?number|credit[_-]?card[_-]?number|primary[_-]?account[_-]?number|pan|cvv|cvc|cid|track[12]|magnetic[_-]?stripe)[A-Za-z0-9_]*\b)~is',
            'sql_dml_write' => '~\b(?:INSERT\s+INTO|UPDATE)\b[^;]{0,1600}(?P<field>\b[A-Za-z0-9_]*(?:cc[_-]?(?:num|number)|card[_-]?number|credit[_-]?card[_-]?number|primary[_-]?account[_-]?number|pan|cvv|cvc|cid|track[12]|magnetic[_-]?stripe)[A-Za-z0-9_]*\b)~is',
        ];

        foreach ($patterns as $kind => $regex) {
            if (preg_match_all($regex, $searchable, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER) < 1) {
                continue;
            }

            foreach ($matches as $match) {
                $field = (string)$match['field'][0];
                if (!$this->isRawCardholderField($field)) {
                    continue;
                }

                $offset = (int)$match['field'][1];
                $evidence = $this->matchEvidence($file, $content, $kind, $offset);
                $evidence['kind'] = $kind;
                $evidence['field'] = $field;
                $evidence['offset'] = $offset;
                $findings[] = $evidence;
            }
        }

        return $findings;
    }

    private function cardholderCodeStorageFindings(string $file, string $content, string $searchable, string $relative, string $extension): array
    {
        $findings = [];
        $rawFieldRegex = '(?P<field>\b[A-Za-z0-9_./-]*(?:cc[_-]?(?:num|number)|card[_-]?number|credit[_-]?card[_-]?number|primary[_-]?account[_-]?number|pan|cvv|cvc|cid|track[12]|magnetic[_-]?stripe)[A-Za-z0-9_./-]*\b)';
        if (preg_match_all('~' . $rawFieldRegex . '~i', $searchable, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER) < 1) {
            return [];
        }

        foreach ($matches as $match) {
            $field = (string)$match['field'][0];
            if (!$this->isRawCardholderField($field)) {
                continue;
            }

            $offset = (int)$match['field'][1];
            $window = $this->codeWindow($searchable, $offset, 1400);
            $kind = $this->cardholderStorageKind($window, $relative, $extension);
            if ($kind === null) {
                continue;
            }

            $evidence = $this->matchEvidence($file, $content, $kind, $offset);
            $evidence['kind'] = $kind;
            $evidence['field'] = $field;
            $findings[] = $evidence;
        }

        return $findings;
    }

    private function cardholderStorageKind(string $window, string $relative, string $extension): ?string
    {
        $isSetupFile = preg_match('~(?:^|/)(?:Setup|Patch|DataPatch|SchemaPatch)/|(?:Install|Upgrade)(?:Schema|Data)\.php$~i', $relative) === 1;
        $hasDbWrite = preg_match('~(?:->\s*(?:insert|insertMultiple|update|save|saveData|setData|addData|setValue|saveConfig)\s*\(|\b(?:INSERT\s+INTO|UPDATE|CREATE\s+TABLE|ALTER\s+TABLE)\b|\b(?:SchemaSetupInterface|ModuleDataSetupInterface|addColumn|modifyColumn|newTable|createTable)\b)~i', $window) === 1;
        $hasTableContext = preg_match('~\b(?:table|db_schema|schema|resource|collection|connection|core_config_data|sales_order_payment|quote_payment|payment|transaction)\b~i', $window) === 1;

        if ($extension === 'json' && preg_match('~\b(?:schema|table|column|field|migration|fixture|seed)\b~i', $relative . "\n" . $window) === 1) {
            return 'json_storage_field';
        }

        if ($isSetupFile && ($hasDbWrite || $hasTableContext)) {
            return 'setup_storage_write';
        }

        if ($hasDbWrite && $hasTableContext) {
            return 'db_storage_write';
        }

        return null;
    }

    private function isRawCardholderField(string $field): bool
    {
        $normalized = strtolower(str_replace(['-', '.', '/', ':', '[', ']'], '_', trim($field)));
        if ($normalized === '') {
            return false;
        }

        if (preg_match('~(?:last4|last_four|token|nonce|vault|profile|customer_profile|payment_profile|transaction|trans_id|reference|masked|mask|hash|fingerprint|bin|brand|type|expiry|exp_month|exp_year)~i', $normalized) === 1) {
            return false;
        }

        if (preg_match('~(?:span|panel|company|companion|campaign|expand|panels|japan|metadata|shipping|billing|giftcard|cardholder_name|card_name)~i', $normalized) === 1) {
            return false;
        }

        return preg_match('~^(?:cc_(?:num|number)|card_number|credit_card_number|primary_account_number|pan|cvv|cvc|cid|track1|track2|magnetic_stripe)$~i', $normalized) === 1
            || preg_match('~(?:^|_)(?:cc_(?:num|number)|card_number|credit_card_number|primary_account_number|pan|cvv|cvc|cid|track1|track2|magnetic_stripe)(?:_|$)~i', $normalized) === 1;
    }

    private function xmlAttributeValue(string $attrs, string $name): ?string
    {
        if (preg_match('~\b' . preg_quote($name, '~') . '\s*=\s*([\'\"])(?P<value>[^\'\"]*)\1~i', $attrs, $match) === 1) {
            return (string)$match['value'];
        }

        return null;
    }

    private function dedupeFindings(array $findings): array
    {
        $deduped = [];
        $seen = [];
        foreach ($findings as $finding) {
            $key = ($finding['file'] ?? '') . ':' . ($finding['line'] ?? '') . ':' . ($finding['kind'] ?? '') . ':' . strtolower((string)($finding['field'] ?? ''));
            if (isset($seen[$key])) {
                continue;
            }

            $seen[$key] = true;
            $deduped[] = $finding;
        }

        return $deduped;
    }
    private function apiKeyStorageFindings(string $file, string $content): array
    {
        $findings = [];
        $extension = strtolower(pathinfo($file, PATHINFO_EXTENSION));
        $searchable = $this->maskSourceComments($content, $extension);
        $patterns = [
            'core_config_data_secret_write' => '~\b(?:INSERT\s+INTO|UPDATE)\s+[^;]{0,240}\bcore_config_data\b[^;]{0,500}\b(?:api[_-]?key|secret|token|client[_-]?secret|access[_-]?token|private[_-]?key)\b~is',
            'config_writer_secret_write' => '~(?:->\s*(?:setData|setValue|saveConfig)\s*\(|\bConfig\s*\()[^;]{0,400}\b(?:api[_-]?key|secret|token|client[_-]?secret|access[_-]?token|private[_-]?key)\b~is',
            'hardcoded_secret_array' => '~[\'\"](?P<field>[A-Za-z0-9_./-]*(?:api[_-]?key|secret|token|client[_-]?secret|access[_-]?token|private[_-]?key)[A-Za-z0-9_./-]*)[\'\"]\s*=>\s*[\'\"](?P<value>[^\'\"]{8,})[\'\"]~i',
            'hardcoded_secret_assignment' => '~\$(?P<field>[A-Za-z_][A-Za-z0-9_]*(?:ApiKey|apiKey|Secret|secret|Token|token|PrivateKey|privateKey)[A-Za-z0-9_]*)\s*=\s*[\'\"](?P<value>[^\'\"]{8,})[\'\"]~',
            'xml_secret_value' => '~<(?P<field>[A-Za-z0-9_.:-]*(?:api[_-]?key|secret|token|client[_-]?secret|access[_-]?token|private[_-]?key)[A-Za-z0-9_.:-]*)>\s*(?P<value>[^<\s][^<]{7,})\s*</[^>]+>~i',
        ];

        foreach ($patterns as $kind => $regex) {
            $count = preg_match_all($regex, $searchable, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER);
            if ($count === false || $count < 1) {
                continue;
            }

            foreach ($matches as $match) {
                $value = isset($match['value']) && is_array($match['value']) ? (string)$match['value'][0] : '';
                if ($value !== '' && !$this->looksLikeStoredSecretLiteral($value)) {
                    continue;
                }

                $field = isset($match['field']) && is_array($match['field']) ? (string)$match['field'][0] : $kind;
                $offset = (int)$match[0][1];
                $evidence = $this->matchEvidence($file, $content, $kind, $offset);
                $evidence['kind'] = $kind;
                $evidence['field'] = $field;
                $evidence['offset'] = $offset;
                $findings[] = $evidence;
            }
        }

        return $findings;
    }

    private function envCredentialKeyEvidence(string $envFile): array
    {
        $path = $this->ctx->abs($envFile);
        if (!is_file($path)) {
            return ['file' => $envFile, 'present' => false, 'credential_keys' => 0];
        }

        $data = @include $path;
        if (!is_array($data)) {
            return ['file' => $envFile, 'present' => true, 'readable' => false, 'credential_keys' => 0];
        }

        return [
            'file' => $envFile,
            'present' => true,
            'readable' => true,
            'credential_keys' => $this->countCredentialKeys($data),
        ];
    }

    private function countCredentialKeys(array $data): int
    {
        $count = 0;
        foreach ($data as $key => $value) {
            if (preg_match('~(?:api[_-]?key|secret|token|client[_-]?secret|access[_-]?token|private[_-]?key)~i', (string)$key) === 1) {
                $count++;
            }
            if (is_array($value)) {
                $count += $this->countCredentialKeys($value);
            }
        }
        return $count;
    }

    private function looksLikeStoredSecretLiteral(string $value): bool
    {
        $trimmed = trim($value);
        if (preg_match('~^(?:0|1|true|false|null|none|changeme|change_me|your[_-]?key|your[_-]?secret|example|test|dummy|placeholder|xxxx|\*+)$~i', $trimmed) === 1) {
            return false;
        }
        if (preg_match('~^(?:\$|\{\{|%env|env\(|getenv\(|config\(|scopeConfig|getValue)~i', $trimmed) === 1) {
            return false;
        }
        return preg_match('~[A-Za-z0-9+/=_-]{8,}~', $trimmed) === 1;
    }
    private function piiMinimizationFindings(string $file, string $content): array
    {
        $findings = [];
        $searchable = $this->maskSourceComments($content, strtolower(pathinfo($file, PATHINFO_EXTENSION)));
        $fieldRegex = '(?:full[_-]?card|card[_-]?number|cc[_-]?(?:num|number)|credit[_-]?card|cvv|cvc|ssn|social[_-]?security|passport[_-]?number|driver[_-]?license|dob|date[_-]?of[_-]?birth|bank[_-]?account|routing[_-]?number|tax[_-]?id)';
        $regex = '~(?P<field>' . $fieldRegex . ')~i';
        $count = preg_match_all($regex, $searchable, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER);
        if ($count === false || $count < 1) {
            return [];
        }

        $seen = [];
        foreach ($matches as $match) {
            $field = (string)$match['field'][0];
            $offset = (int)$match['field'][1];
            $window = $this->codeWindow($searchable, $offset, 1800);
            if (!$this->hasThirdPartyOutboundFlowSignal($window)) {
                continue;
            }
            if ($this->hasPiiMinimizationSignal($window)) {
                continue;
            }

            $evidence = $this->matchEvidence($file, $content, 'raw_sensitive_pii_third_party_flow', $offset);
            $key = $evidence['file'] . ':' . $evidence['line'] . ':' . strtolower($field);
            if (isset($seen[$key])) {
                continue;
            }

            $seen[$key] = true;
            $evidence['kind'] = 'raw_sensitive_pii_third_party_flow';
            $evidence['field'] = $field;
            $findings[] = $evidence;
        }

        return $findings;
    }

    private function hasThirdPartyOutboundFlowSignal(string $window): bool
    {
        return preg_match('~(?:\\b(?:curl_init|curl_setopt|curl_setopt_array|file_get_contents|fopen|fsockopen|stream_socket_client)\\s*\\(|->\\s*(?:request|get|post|put|patch|delete|send)\\s*\\(|https?://|\\b(?:base_uri|api[_-]?url|endpoint|webhook|callback|payment|gateway|stripe|paypal|braintree|adyen|klarna|authorizenet|authorize)\\b)~i', $window) === 1;
    }

    private function hasPiiMinimizationSignal(string $window): bool
    {
        return preg_match('~\b(?:tokeni[sz]e|token|payment[_-]?token|payment[_-]?method[_-]?nonce|nonce|vault|vaulted|customer[_-]?id|profile[_-]?id|redact|redacted|mask|masked|sanitize|filterSensitive|withoutSensitive|removeSensitive|minimi[sz]e|hash|last4)\b~i', $window) === 1;
    }
    private function rawSqlFindings(string $file, string $content): array
    {
        $findings = [];

        $patterns = [
            'direct_db_api' => '~\b(?:mysqli_query|mysql_query)\s*\(|new\s+\\\\?PDO\s*\(~i',
            'raw_query_method' => '~->\s*rawQuery\s*\(~i',
            'adapter_sql_method' => '~->\s*(?:query|fetchAll|fetchRow|fetchOne|fetchCol|fetchPairs)\s*\((?P<arg>.{0,500})~is',
            'write_method_string_condition' => '~->\s*(?:delete|update)\s*\((?P<arg>.{0,500})~is',
        ];

        foreach ($patterns as $kind => $regex) {
            $count = preg_match_all($regex, $content, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER);
            if ($count === false || $count < 1) {
                continue;
            }
            foreach ($matches as $match) {
                $offset = (int)$match[0][1];
                $arg = isset($match['arg']) && is_array($match['arg']) ? (string)$match['arg'][0] : '';
                if ($kind === 'adapter_sql_method' && !$this->looksLikeUnsafeSqlArgument($arg)) {
                    continue;
                }
                if ($kind === 'write_method_string_condition' && !$this->looksLikeUnsafeConditionArgument($arg)) {
                    continue;
                }

                $evidence = $this->matchEvidence($file, $content, $kind, $offset);
                $evidence['kind'] = $kind;
                $findings[] = $evidence;
            }
        }

        return $findings;
    }

    private function phtmlOutputFindings(string $file, string $content, array $escapeFunctions): array
    {
        $findings = [];
        $patterns = [
            'short_echo' => '~<\?=\s*(?P<expr>.*?)\?>~is',
            'echo_statement' => '~<\?php\s+(?:echo|print)\s+(?P<expr>.*?);?\s*\?>~is',
        ];

        foreach ($patterns as $kind => $regex) {
            $count = preg_match_all($regex, $content, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER);
            if ($count === false || $count < 1) {
                continue;
            }

            foreach ($matches as $match) {
                $expr = isset($match['expr']) && is_array($match['expr']) ? (string)$match['expr'][0] : '';
                if ($this->isEscapedTemplateExpression($expr, $escapeFunctions)) {
                    continue;
                }

                $evidence = $this->matchEvidence($file, $content, $kind, (int)$match[0][1]);
                $evidence['kind'] = $kind;
                $findings[] = $evidence;
            }
        }

        return $findings;
    }

    private function csrfFormFindings(string $file, string $content): array
    {
        $findings = [];
        if (preg_match_all('~<form\b(?P<attrs>[^>]*)>(?P<body>.*?)</form>~is', $content, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER) !== 1) {
            return [];
        }

        foreach ($matches as $match) {
            $attrs = (string)$match['attrs'][0];
            $body = (string)$match['body'][0];
            if (!preg_match('~\bmethod\s*=\s*([\'"]?)post\1~i', $attrs)) {
                continue;
            }
            $formBlock = (string)$match[0][0];
            if ($this->formBlockHasFormKey($formBlock)) {
                continue;
            }

            $evidence = $this->matchEvidence($file, $content, 'post_form_without_form_key', (int)$match[0][1]);
            $evidence['kind'] = 'post_form_without_form_key';
            $evidence['snippet'] = trim(substr(preg_replace('~\s+~', ' ', $formBlock) ?? $formBlock, 0, 240));
            $findings[] = $evidence;
        }

        return $findings;
    }

    private function formBlockHasFormKey(string $formBlock): bool
    {
        $withoutComments = preg_replace('~<!--.*?-->|/\*.*?\*/~s', '', $formBlock) ?? $formBlock;

        return preg_match('~<input\b[^>]*\bname\s*=\s*([\'"])form_key\1[^>]*>~i', $withoutComments) === 1
            || preg_match('~getBlockHtml\s*\(\s*([\'"])formkey\1\s*\)~i', $withoutComments) === 1
            || preg_match('~getFormKey\s*\(~i', $withoutComments) === 1
            || preg_match('~FormKey::FORM_KEY~', $withoutComments) === 1;
    }

    private function csrfPostHandlerFinding(string $file, string $content): ?array
    {
        if (!$this->looksLikePostHandler($content)) {
            return null;
        }
        if ($this->hasCsrfValidationSignal($content)) {
            return null;
        }

        $offset = 0;
        if (preg_match('~\b(?:getPost|getPostValue|isPost|POST)\b~i', $content, $match, PREG_OFFSET_CAPTURE)) {
            $offset = (int)$match[0][1];
        }
        $evidence = $this->matchEvidence($file, $content, 'post_handler_without_form_key_validation', $offset);
        $evidence['kind'] = 'post_handler_without_form_key_validation';

        return $evidence;
    }

    private function outboundEgressFindings(string $file, string $content): array
    {
        $findings = [];
        $seen = [];
        $patterns = [
            'curl_init' => '~\bcurl_init\s*\((?P<arg>.{0,300})~is',
            'curl_url' => '~\bcurl_setopt\s*\([^;]{0,300}\bCURLOPT_URL\b(?P<arg>[^;]{0,300})~is',
            'curl_setopt_array_url' => '~\bcurl_setopt_array\s*\([^;]{0,500}\bCURLOPT_URL\b(?P<arg>[^;]{0,300})~is',
            'php_stream' => '~\b(?:file_get_contents|fopen)\s*\((?P<arg>.{0,300})~is',
            'socket_client' => '~\b(?:fsockopen|stream_socket_client)\s*\((?P<arg>.{0,300})~is',
            'http_client' => '~->\s*(?:request|get|post|put|patch|delete|send)\s*\((?P<arg>.{0,500})~is',
        ];

        foreach ($patterns as $kind => $regex) {
            $matchCount = preg_match_all($regex, $content, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER);
            if ($matchCount === false || $matchCount < 1) {
                continue;
            }

            foreach ($matches as $match) {
                $offset = (int)$match[0][1];
                $arg = isset($match['arg']) && is_array($match['arg']) ? (string)$match['arg'][0] : '';
                $lookupKind = $kind === 'curl_setopt_array_url' ? 'curl_url' : $kind;
                if (!$this->looksLikeOutboundEgressArgument($lookupKind, $arg)) {
                    continue;
                }

                $evidence = $this->matchEvidence($file, $content, $kind, $offset);
                $key = $evidence['file'] . ':' . $evidence['line'] . ':' . $kind;
                if (isset($seen[$key])) {
                    continue;
                }

                $seen[$key] = true;
                $window = $this->codeWindow($content, $offset, 2200);
                $evidence['kind'] = $kind;
                $evidence['controls'] = $this->outboundEgressControlEvidence($window);
                $findings[] = $evidence;
            }
        }

        return $findings;
    }

    private function looksLikeOutboundEgressArgument(string $kind, string $arg): bool
    {
        if ($kind === 'curl_url') {
            return true;
        }

        $trimmed = trim($arg);
        if ($trimmed === '') {
            return false;
        }

        if ($kind === 'php_stream'
            && preg_match('~\b(?:getPathname|getRealPath|__DIR__|dirname|realpath|DirectoryIterator|RecursiveDirectoryIterator|SplFileInfo)\b~i', $trimmed) === 1) {
            return false;
        }

        return preg_match('~^[\'\"]https?://~i', $trimmed) === 1
            || str_contains($trimmed, '$')
            || preg_match('~\b(?:url|uri|endpoint|callback|webhook|host|domain|remote|target|api|base_uri)\b~i', $trimmed) === 1;
    }
    private function outboundEgressControlEvidence(string $window): array
    {
        $hasAllowlist = preg_match('~\b(?:allowedHosts?|allowedDomains?|allowlist|whitelist|trustedHosts?|isAllowedHost|validateHost|validateUrl|allowedBaseUrls?|originAllowlist)\b~i', $window) === 1
            || preg_match('~\b(?:parse_url|getHost|UriInterface)\b[\s\S]{0,260}\b(?:in_array|array_key_exists|isset|contains|allowed|allowlist|whitelist)\b~i', $window) === 1;
        $hasTimeout = preg_match('~\b(?:CURLOPT_TIMEOUT|CURLOPT_CONNECTTIMEOUT|CURLOPT_TIMEOUT_MS|CURLOPT_CONNECTTIMEOUT_MS|timeout|connect_timeout|read_timeout|setTimeout|setConnectTimeout|RequestOptions::(?:TIMEOUT|CONNECT_TIMEOUT))\b~i', $window) === 1;

        $missing = [];
        if (!$hasAllowlist) {
            $missing[] = 'allowlist';
        }
        if (!$hasTimeout) {
            $missing[] = 'timeout';
        }

        return [
            'ok' => $missing === [],
            'has_allowlist' => $hasAllowlist,
            'has_timeout' => $hasTimeout,
            'missing' => $missing,
        ];
    }
    private function ssrfFindings(string $file, string $content): array
    {
        $findings = [];
        $patterns = [
            'curl_init' => '~\bcurl_init\s*\((?P<arg>.{0,300})~is',
            'curl_url' => '~\bcurl_setopt\s*\([^;]{0,300}\bCURLOPT_URL\b(?P<arg>[^;]{0,300})~is',
            'php_stream' => '~\b(?:file_get_contents|fopen)\s*\((?P<arg>.{0,300})~is',
            'socket_client' => '~\b(?:fsockopen|stream_socket_client)\s*\((?P<arg>.{0,300})~is',
            'http_client' => '~->\s*(?:request|get|post|put|send)\s*\((?P<arg>.{0,300})~is',
        ];

        foreach ($patterns as $kind => $regex) {
            $matchCount = preg_match_all($regex, $content, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER);
            if ($matchCount === false || $matchCount < 1) {
                continue;
            }

            foreach ($matches as $match) {
                $offset = (int)$match[0][1];
                $arg = isset($match['arg']) && is_array($match['arg']) ? (string)$match['arg'][0] : '';
                if (!$this->looksLikeOutboundUrlArgument($kind, $arg)) {
                    continue;
                }

                $window = $this->codeWindow($content, $offset, 1800);
                if ($this->hasSsrfSafeguards($window)) {
                    continue;
                }

                $evidence = $this->matchEvidence($file, $content, $kind, $offset);
                $evidence['kind'] = $kind;
                $findings[] = $evidence;
            }
        }

        return $findings;
    }

    private function unserializeFindings(string $file, string $content): array
    {
        $findings = [];
        if (preg_match_all('~(?<!->)(?<!::)(?<!function\s)\b\\\\?unserialize\s*\((?P<args>.{0,500})~is', $content, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER) !== 1) {
            return [];
        }

        foreach ($matches as $match) {
            $offset = (int)$match[0][1];
            $args = isset($match['args']) && is_array($match['args']) ? (string)$match['args'][0] : '';
            if (preg_match('~[\'"]?allowed_classes[\'"]?\s*=>~i', $args) === 1) {
                continue;
            }

            $evidence = $this->matchEvidence($file, $content, 'unsafe_unserialize', $offset);
            $evidence['kind'] = 'unsafe_unserialize';
            $evidence['risk'] = $this->unserializeRisk($content, $offset, $args);
            $findings[] = $evidence;
        }

        return $findings;
    }

    private function commandExecutionFindings(string $file, string $content): array
    {
        $findings = [];
        $searchable = $this->maskPhpStringsAndComments($content);
        $patterns = [
            'command_function' => '~(?<!->)(?<!::)(?<!function\s)\b\\\\?(?:exec|shell_exec|system|passthru|proc_open|popen|pcntl_exec)\s*\((?P<args>.{0,500})~is',
            'backtick_operator' => '~`(?P<args>[^`\r\n]{0,500})`~',
        ];

        foreach ($patterns as $kind => $regex) {
            if (preg_match_all($regex, $searchable, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER) !== 1) {
                continue;
            }

            foreach ($matches as $match) {
                $offset = (int)$match[0][1];
                $args = isset($match['args']) && is_array($match['args']) ? (string)$match['args'][0] : '';
                $risk = $this->commandExecutionRisk($content, $offset, $args);
                if ($risk === null) {
                    continue;
                }

                $evidence = $this->matchEvidence($file, $content, $kind, $offset);
                $evidence['kind'] = $kind;
                $evidence['risk'] = $risk;
                $findings[] = $evidence;
            }
        }

        return $findings;
    }

    private function dynamicExecutionFindings(string $file, string $content): array
    {
        $findings = [];
        $searchable = $this->maskPhpStringsAndComments($content);
        $patterns = [
            'dynamic_code_function' => '~(?<!->)(?<!::)(?<!function\s)\b\\\\?(?:eval|assert|create_function)\s*\((?P<args>.{0,500})~is',
            'dynamic_include' => '~\b(?:include|include_once|require|require_once)\s*(?:\(\s*)?(?P<args>[^;\r\n]{0,500})~i',
            'dynamic_callable' => '~\b(?:call_user_func|call_user_func_array|new\s+\\\\?ReflectionFunction)\s*\((?P<args>.{0,500})~is',
            'variable_function' => '~(?<!function\s)(?P<args>\$[A-Za-z_][A-Za-z0-9_]*)\s*\(~',
        ];

        foreach ($patterns as $kind => $regex) {
            if (preg_match_all($regex, $searchable, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER) !== 1) {
                continue;
            }

            foreach ($matches as $match) {
                $offset = (int)$match[0][1];
                $args = isset($match['args']) && is_array($match['args']) ? (string)$match['args'][0] : '';
                $risk = $this->dynamicExecutionRisk($kind, $content, $offset, $args);
                if ($risk === null) {
                    continue;
                }

                $evidence = $this->matchEvidence($file, $content, $kind, $offset);
                $evidence['kind'] = $kind;
                $evidence['risk'] = $risk;
                $findings[] = $evidence;
            }
        }

        return $findings;
    }

    private function pathTraversalFindings(string $file, string $content): array
    {
        $findings = [];
        $searchable = $this->maskPhpStringsAndComments($content);
        $patterns = [
            'file_read_sink' => '~\b(?:file_get_contents|fopen|readfile|file)\s*\((?P<args>.{0,500})~is',
            'file_write_sink' => '~\b(?:file_put_contents|unlink|copy|rename)\s*\((?P<args>.{0,500})~is',
            'include_sink' => '~\b(?:include|include_once|require|require_once)\s*(?:\(\s*)?(?P<args>[^;\r\n]{0,500})~i',
        ];

        foreach ($patterns as $kind => $regex) {
            if (preg_match_all($regex, $searchable, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER) !== 1) {
                continue;
            }

            foreach ($matches as $match) {
                $offset = (int)$match[0][1];
                $args = isset($match['args']) && is_array($match['args']) ? (string)$match['args'][0] : '';
                $risk = $this->pathTraversalRisk($kind, $content, $offset, $args);
                if ($risk === null) {
                    continue;
                }

                $evidence = $this->matchEvidence($file, $content, $kind, $offset);
                $evidence['kind'] = $kind;
                $evidence['risk'] = $risk;
                $findings[] = $evidence;
            }
        }

        return $findings;
    }

    private function uploadFindings(string $file, string $content): array
    {
        $findings = [];
        $searchable = $this->maskPhpStringsAndComments($content);
        $patterns = [
            'move_uploaded_file' => '~\bmove_uploaded_file\s*\((?P<args>.{0,600})~is',
            'tmp_name_storage' => '~\$_FILES\s*\[[^\]]+\]\s*\[\s*[\'"]tmp_name[\'"]\s*\][\s\S]{0,260}\b(?:copy|rename|file_put_contents|fopen)\s*\((?P<args>.{0,500})~is',
            'magento_uploader_save' => '~(?:UploaderFactory|\\\\Magento\\\\Framework\\\\File\\\\Uploader|\\\\Magento\\\\MediaStorage\\\\Model\\\\File\\\\Uploader|getUploader|createUploader)[\s\S]{0,900}->\s*save\s*\((?P<args>.{0,500})~is',
            'uploaded_file_save' => '~->\s*(?:save|moveTo)\s*\((?P<args>.{0,500})~is',
        ];

        foreach ($patterns as $kind => $regex) {
            if (preg_match_all($regex, $searchable, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER) !== 1) {
                continue;
            }

            foreach ($matches as $match) {
                $offset = (int)$match[0][1];
                $window = $this->codeWindow($content, $offset, 1600);
                if (!$this->looksLikeUploadFlow($kind, $window)) {
                    continue;
                }
                if ($this->hasUploadSafeguards($window)) {
                    continue;
                }

                $evidence = $this->matchEvidence($file, $content, $kind, $offset);
                $evidence['kind'] = $kind;
                $evidence['risk'] = 'high';
                $evidence['missing'] = $this->missingUploadSafeguards($window);
                $findings[] = $evidence;
            }
        }

        return $findings;
    }

    private function jsContextFindings(string $file, string $content): array
    {
        $findings = [];

        if (preg_match_all('~<script\b(?P<attrs>[^>]*)>(?P<body>.*?)</script>~is', $content, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER) === 1) {
            foreach ($matches as $match) {
                $attrs = (string)$match['attrs'][0];
                $body = (string)$match['body'][0];
                if (preg_match('~\btype\s*=\s*([\'"])(?:text/template|text/x-magento-template)\1~i', $attrs) === 1) {
                    continue;
                }

                foreach ($this->phpOutputExpressions($body, (int)$match['body'][1]) as $expr) {
                    if ($this->isSafeJsContextExpression($expr['expr'])) {
                        continue;
                    }
                    $evidence = $this->matchEvidence($file, $content, 'script_php_output', $expr['offset']);
                    $evidence['kind'] = 'script_php_output';
                    $evidence['expression'] = trim($expr['expr']);
                    $findings[] = $evidence;
                }
            }
        }

        if (preg_match_all('~\b(?:on[a-z]+|data-mage-init|x-magento-init)\s*=\s*([\'"])(?P<value>.*?)\1~is', $content, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER) === 1) {
            foreach ($matches as $match) {
                $value = (string)$match['value'][0];
                foreach ($this->phpOutputExpressions($value, (int)$match['value'][1]) as $expr) {
                    if ($this->isSafeJsContextExpression($expr['expr'])) {
                        continue;
                    }
                    $evidence = $this->matchEvidence($file, $content, 'attribute_js_php_output', $expr['offset']);
                    $evidence['kind'] = 'attribute_js_php_output';
                    $evidence['expression'] = trim($expr['expr']);
                    $findings[] = $evidence;
                }
            }
        }

        return $findings;
    }

    private function csprngFindings(string $file, string $content): array
    {
        $findings = [];
        $searchable = $this->maskPhpStringsAndComments($content);
        $regex = '~\b(?P<fn>rand|mt_rand|array_rand|shuffle|str_shuffle|uniqid)\s*\(~i';

        if (preg_match_all($regex, $searchable, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER) !== 1) {
            return [];
        }

        foreach ($matches as $match) {
            $offset = (int)$match[0][1];
            $risk = $this->weakPrngRisk($content, $offset);
            if ($risk === null) {
                continue;
            }

            $evidence = $this->matchEvidence($file, $content, 'weak_prng', $offset);
            $evidence['kind'] = (string)$match['fn'][0];
            $evidence['risk'] = $risk;
            $findings[] = $evidence;
        }

        return $findings;
    }

    private function saasIntegrationScopeFindings(string $file, string $content): array
    {
        $extension = strtolower(pathinfo($file, PATHINFO_EXTENSION));
        if (!$this->hasSaasIntegrationSignal($content, $file)) {
            return [];
        }

        return $extension === 'xml'
            ? $this->saasIntegrationXmlScopeFindings($file, $content)
            : $this->saasIntegrationPhpScopeFindings($file, $content);
    }

    private function saasIntegrationXmlScopeFindings(string $file, string $content): array
    {
        $findings = [];
        $relative = $this->relativeFile($file);

        if (str_ends_with($relative, '/etc/adminhtml/system.xml') || str_ends_with($relative, '/system.xml')) {
            if (preg_match_all('~<section\b(?P<attrs>[^>]*)>(?P<body>.*?)</section>~is', $content, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER) > 0) {
                foreach ($matches as $match) {
                    $offset = (int)$match[0][1];
                    $block = (string)$match[0][0];
                    if (!$this->hasSaasIntegrationSignal($block, $file)) {
                        continue;
                    }

                    $resource = $this->firstXmlTagValue($block, 'resource');
                    $evidence = $this->matchEvidence($file, $content, 'saas_system_section_acl', $offset);
                    $evidence['kind'] = 'system_section';
                    $evidence['resource'] = $resource;
                    $evidence['controls'] = $this->saasAclControlEvidence($resource, $block);
                    $findings[] = $evidence;
                }
            }
        }

        if (str_ends_with($relative, '/etc/webapi.xml') || str_ends_with($relative, '/webapi.xml')) {
            if (preg_match_all('~<route\b(?P<attrs>[^>]*)>(?P<body>.*?)</route>~is', $content, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER) > 0) {
                foreach ($matches as $match) {
                    $offset = (int)$match[0][1];
                    $block = (string)$match[0][0];
                    $attrs = (string)$match['attrs'][0];
                    if (!$this->hasSaasIntegrationSignal($block . "\n" . $attrs, $file)) {
                        continue;
                    }

                    $resources = $this->xmlResourceRefs($block);
                    $evidence = $this->matchEvidence($file, $content, 'saas_webapi_acl', $offset);
                    $evidence['kind'] = 'webapi_route';
                    $evidence['resources'] = $resources;
                    $evidence['controls'] = $this->saasWebapiControlEvidence($resources, $block . "\n" . $content);
                    $findings[] = $evidence;
                }
            }
        }

        return $findings;
    }

    private function saasIntegrationPhpScopeFindings(string $file, string $content): array
    {
        $findings = [];
        $relative = $this->relativeFile($file);
        $isAdminController = preg_match('~/Controller/Adminhtml/~i', $relative) === 1
            || str_contains($content, '\\Adminhtml\\');
        $isPublicCallback = preg_match('~/Controller/~i', $relative) === 1
            && preg_match('~(?:webhook|callback|ipn|notify|notification)~i', $relative . "\n" . $content) === 1;

        if (!$isAdminController && !$isPublicCallback) {
            return [];
        }

        $offset = $this->firstSaasOffset($content);
        $evidence = $this->matchEvidence($file, $content, 'saas_controller_scope', $offset);
        if ($isAdminController) {
            $resource = $this->phpAdminResource($content);
            $evidence['kind'] = 'admin_controller';
            $evidence['resource'] = $resource;
            $evidence['controls'] = $this->saasAclControlEvidence($resource, $content);
        } else {
            $evidence['kind'] = 'public_callback';
            $evidence['controls'] = $this->saasIpAllowlistControlEvidence($content);
        }

        $findings[] = $evidence;
        return $findings;
    }

    private function saasAclControlEvidence(?string $resource, string $haystack): array
    {
        $hasSpecificAcl = $resource !== null && !$this->isBroadSaasAclResource($resource);
        $hasIpAllowlist = $this->hasSaasIpAllowlistSignal($haystack);
        $missing = [];
        if (!$hasSpecificAcl && !$hasIpAllowlist) {
            $missing[] = 'least_privilege_acl_or_ip_allowlist';
        }

        return [
            'ok' => $missing === [],
            'resource' => $resource,
            'has_specific_acl' => $hasSpecificAcl,
            'has_ip_allowlist' => $hasIpAllowlist,
            'missing' => $missing,
        ];
    }

    private function saasWebapiControlEvidence(array $resources, string $haystack): array
    {
        $hasSpecificAcl = false;
        foreach ($resources as $resource) {
            if (!$this->isBroadSaasAclResource($resource)) {
                $hasSpecificAcl = true;
                break;
            }
        }

        $hasIpAllowlist = $this->hasSaasIpAllowlistSignal($haystack);
        $missing = [];
        if (!$hasSpecificAcl && !$hasIpAllowlist) {
            $missing[] = 'least_privilege_acl_or_ip_allowlist';
        }

        return [
            'ok' => $missing === [],
            'resources' => $resources,
            'has_specific_acl' => $hasSpecificAcl,
            'has_ip_allowlist' => $hasIpAllowlist,
            'missing' => $missing,
        ];
    }

    private function saasIpAllowlistControlEvidence(string $haystack): array
    {
        $hasIpAllowlist = $this->hasSaasIpAllowlistSignal($haystack);
        return [
            'ok' => $hasIpAllowlist,
            'has_ip_allowlist' => $hasIpAllowlist,
            'missing' => $hasIpAllowlist ? [] : ['ip_allowlist'],
        ];
    }

    private function hasSaasIntegrationSignal(string $text, string $file): bool
    {
        return preg_match('~\b(?:saas|connector|integration|webhook|callback|ipn|payment[_-]?gateway|gateway|stripe|paypal|braintree|adyen|klarna|authorizenet|authorize(?:\.net)?|shipstation|taxjar|avalara|mailchimp|klaviyo|salesforce|hubspot|erp|crm|analytics)\b~i', $text . "\n" . $this->relativeFile($file)) === 1;
    }

    private function hasSaasIpAllowlistSignal(string $text): bool
    {
        return preg_match('~\b(?:ip[_-]?allow(?:list)?|allow(?:ed)?[_-]?ips?|cidr|trusted[_-]?proxy|remote[_-]?addr|HTTP_X_FORWARDED_FOR|X-Forwarded-For|IpUtils|ipRange|isAllowedIp|validateIp|Require\s+ip|allow\s+from)\b~i', $text) === 1;
    }

    private function isBroadSaasAclResource(string $resource): bool
    {
        $resource = trim($resource);
        if ($resource === '') {
            return true;
        }

        return preg_match('~^(?:anonymous|self|Magento_Backend::admin|Magento_Adminhtml::admin|Magento_Webapi::all|Magento_Customer::customer)$~i', $resource) === 1
            || preg_match('~::all$~i', $resource) === 1;
    }

    private function firstXmlTagValue(string $xml, string $tag): ?string
    {
        if (preg_match('~<' . preg_quote($tag, '~') . '\b[^>]*>(?P<value>.*?)</' . preg_quote($tag, '~') . '>~is', $xml, $match) === 1) {
            return trim(strip_tags((string)$match['value']));
        }

        return null;
    }

    /** @return list<string> */
    private function xmlResourceRefs(string $xml): array
    {
        if (preg_match_all('~<resource\b[^>]*\bref\s*=\s*([\'\"])(?P<ref>[^\'\"]+)\1~i', $xml, $matches) < 1) {
            return [];
        }

        return array_values(array_unique(array_map(static fn(string $ref): string => trim($ref), $matches['ref'])));
    }

    private function phpAdminResource(string $content): ?string
    {
        if (preg_match('~\bconst\s+ADMIN_RESOURCE\s*=\s*([\'\"])(?P<resource>[^\'\"]+)\1~i', $content, $match) === 1) {
            return trim((string)$match['resource']);
        }

        return null;
    }

    private function firstSaasOffset(string $content): int
    {
        if (preg_match('~\b(?:saas|connector|integration|webhook|callback|ipn|gateway|stripe|paypal|braintree|adyen|klarna|authorizenet|authorize(?:\.net)?|shipstation|taxjar|avalara|mailchimp|klaviyo|salesforce|hubspot|erp|crm|analytics)\b~i', $content, $match, PREG_OFFSET_CAPTURE) === 1) {
            return (int)$match[0][1];
        }

        return 0;
    }
    private function thirdPartyLoggingFindings(string $file, string $content): array
    {
        $findings = [];
        $searchable = $this->maskPhpStringsAndComments($content);
        $regex = '~(?P<logger>\$this->\s*[_A-Za-z0-9]*logger|\$[A-Za-z_][A-Za-z0-9_]*logger|\$logger)\s*->\s*(?P<method>debug|info|notice|warning|error|critical|alert|emergency|log)\s*\((?P<args>.{0,900})~is';

        if (preg_match_all($regex, $searchable, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER) !== 1) {
            return [];
        }

        foreach ($matches as $match) {
            $offset = (int)$match[0][1];
            $window = $this->codeWindow($content, $offset, 1400);
            $args = isset($match['args']) && is_array($match['args']) ? (string)$match['args'][0] : '';
            $text = $window . "\n" . $args;

            if (!$this->hasThirdPartyLoggingSignal($text, $file)) {
                continue;
            }
            if (!$this->hasThirdPartyLogSensitiveSignal($text)) {
                continue;
            }
            if ($this->hasRedactionSignal($text)) {
                continue;
            }

            $evidence = $this->matchEvidence($file, $content, 'third_party_sensitive_logging', $offset);
            $evidence['kind'] = (string)$match['method'][0];
            $evidence['risk'] = $this->sensitiveLoggingRisk($text);
            $findings[] = $evidence;
        }

        return $findings;
    }

    private function sensitiveLoggingFindings(string $file, string $content): array
    {
        $findings = [];
        $searchable = $this->maskPhpStringsAndComments($content);
        $regex = '~(?P<logger>\$this->\s*[_A-Za-z0-9]*logger|\$[A-Za-z_][A-Za-z0-9_]*logger|\$logger)\s*->\s*(?P<method>debug|info|notice|warning|error|critical|alert|emergency|log)\s*\((?P<args>.{0,900})~is';

        if (preg_match_all($regex, $searchable, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER) !== 1) {
            return [];
        }

        foreach ($matches as $match) {
            $offset = (int)$match[0][1];
            $window = $this->codeWindow($content, $offset, 1400);
            $args = isset($match['args']) && is_array($match['args']) ? (string)$match['args'][0] : '';
            if (!$this->hasSensitiveLoggingSignal($window . "\n" . $args)) {
                continue;
            }
            if ($this->hasRedactionSignal($window . "\n" . $args)) {
                continue;
            }

            $evidence = $this->matchEvidence($file, $content, 'sensitive_logging', $offset);
            $evidence['kind'] = (string)$match['method'][0];
            $evidence['risk'] = $this->sensitiveLoggingRisk($window . "\n" . $args);
            $findings[] = $evidence;
        }

        return $findings;
    }

    private function magentoApiCryptoSessionFindings(string $file, string $content): array
    {
        $findings = [];
        $searchable = $this->maskPhpStringsAndComments($content);
        $patterns = [
            'raw_session_start' => '~\bsession_start\s*\(~i',
            'raw_session_superglobal' => '~\$_SESSION\s*\[~',
            'raw_session_control' => '~\b(?:session_id|session_name|session_regenerate_id|session_destroy|setcookie|setrawcookie)\s*\(~i',
            'raw_openssl_crypto' => '~\bopenssl_(?:encrypt|decrypt|cipher_iv_length|random_pseudo_bytes)\s*\(~i',
            'legacy_mcrypt' => '~\bmcrypt_[A-Za-z0-9_]*\s*\(~i',
            'weak_hash_secret' => '~\b(?:md5|sha1)\s*\((?P<args>.{0,240})~is',
            'direct_sodium_crypto' => '~\bsodium_crypto_[A-Za-z0-9_]*\s*\(~i',
        ];

        foreach ($patterns as $kind => $regex) {
            if (preg_match_all($regex, $searchable, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER) !== 1) {
                continue;
            }

            foreach ($matches as $match) {
                $offset = (int)$match[0][1];
                $args = isset($match['args']) && is_array($match['args']) ? (string)$match['args'][0] : '';
                $risk = $this->magentoApiCryptoSessionRisk($kind, $content, $offset, $args);
                if ($risk === null) {
                    continue;
                }

                $evidence = $this->matchEvidence($file, $content, $kind, $offset);
                $evidence['kind'] = $kind;
                $evidence['risk'] = $risk;
                $findings[] = $evidence;
            }
        }

        return $findings;
    }

    private function webhookHandlerFindings(string $file, string $content): array
    {
        $findings = [];
        $seen = [];
        $relative = $this->relativeFile($file);
        $extension = strtolower(pathinfo($file, PATHINFO_EXTENSION));
        $webhookWord = '(?:webhook|callback|ipn|notification|notify)';

        $patterns = [];
        if ($extension === 'xml') {
            $patterns['xml_route'] = '~<route\b[^>]*\burl\s*=\s*([\'\"])(?P<target>[^\'\"]*' . $webhookWord . '[^\'\"]*)\1[^>]*>~i';
            $patterns['xml_service_anonymous'] = '~<route\b[^>]*\burl\s*=\s*([\'\"])(?P<target>[^\'\"]*)\1[^>]*>\s*<service\b[^>]*\bresource\s*=\s*([\'\"])anonymous\3~is';
        } else {
            $patterns['route_registration'] = '~\bRoute::\s*(?:post|put|patch|any)\s*\(\s*([\'\"])(?P<target>[^\'\"]*' . $webhookWord . '[^\'\"]*)\1~i';
            $patterns['webhook_class'] = '~\bclass\s+\w*' . $webhookWord . '\w*\b~i';
            $patterns['webhook_method'] = '~\bfunction\s+(?:execute|handleWebhook|webhook|callback|ipn|notify|notification)\s*\(~i';
        }

        foreach ($patterns as $kind => $regex) {
            $count = preg_match_all($regex, $content, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER);
            if ($count === false || $count < 1) {
                continue;
            }

            foreach ($matches as $match) {
                $offset = (int)$match[0][1];
                $target = isset($match['target']) && is_array($match['target']) ? (string)$match['target'][0] : '';
                if ($kind === 'webhook_method' && !$this->hasWebhookContext($relative, $content, $offset)) {
                    continue;
                }
                if ($kind === 'xml_service_anonymous' && preg_match('~' . $webhookWord . '~i', $target) !== 1) {
                    continue;
                }

                $evidence = $this->matchEvidence($file, $content, $kind, $offset);
                $key = $evidence['file'] . ':' . $evidence['line'] . ':' . ($target !== '' ? $target : 'handler');
                if (isset($seen[$key])) {
                    continue;
                }

                $seen[$key] = true;
                $evidence['kind'] = $kind;
                $evidence['target'] = $target;
                $evidence['offset'] = $offset;
                $findings[] = $evidence;
            }
        }

        return $findings;
    }

    private function hasWebhookContext(string $relative, string $content, int $offset): bool
    {
        if (preg_match('~(?:webhook|callback|ipn|notification|notify)~i', $relative) === 1) {
            return true;
        }

        $window = substr($content, max(0, $offset - 800), 1600);
        return preg_match('~(?:webhook|callback|ipn|notification|notify)~i', $window) === 1;
    }

    private function webhookSignatureEvidence(string $content, int $offset): array
    {
        $fileWide = $content;
        $window = substr($content, max(0, $offset - 1600), 3600);
        $haystack = $window . "\n" . $fileWide;

        $hasHeader = preg_match('~(?:HTTP_[A-Z0-9_]*(?:SIGNATURE|HMAC|TRANSMISSION_SIG)|[\'\"](?:X[-_][^\'\"]*(?:Signature|Hmac|Sha256)|Stripe-Signature|Paypal-Transmission-Sig|X-Hub-Signature-256)[\'\"]|->\s*(?:getHeader|getHeaderLine|header)\s*\(\s*[\'\"][^\'\"]*(?:signature|hmac|transmission-sig)[^\'\"]*[\'\"])~i', $haystack) === 1;
        $hasTimingSafeCompare = preg_match('~\bhash_equals\s*\(~i', $haystack) === 1;
        $hasMac = preg_match('~\bhash_hmac\s*\(~i', $haystack) === 1;
        $hasVerifier = preg_match('~\b(?:openssl_verify|sodium_crypto_sign_verify_detached)\s*\(|\b(?:verifySignature|validateSignature|isSignatureValid|checkSignature|assertSignature|constructEvent)\s*\(~i', $haystack) === 1;

        $ok = ($hasHeader && (($hasMac && $hasTimingSafeCompare) || $hasVerifier))
            || preg_match('~\bconstructEvent\s*\(~i', $haystack) === 1;

        $missing = [];
        if (!$hasHeader && preg_match('~\bconstructEvent\s*\(~i', $haystack) !== 1) {
            $missing[] = 'signature_header';
        }
        if (!(($hasMac && $hasTimingSafeCompare) || $hasVerifier)) {
            $missing[] = 'timing_safe_signature_verify';
        }

        return [
            'ok' => $ok,
            'has_signature_header' => $hasHeader,
            'has_hmac' => $hasMac,
            'has_timing_safe_compare' => $hasTimingSafeCompare,
            'has_verifier' => $hasVerifier,
            'missing' => $missing,
        ];
    }
    private function configuredPlainHttpFindings(string $file, string $content): array
    {
        $findings = [];
        $extension = strtolower(pathinfo($file, PATHINFO_EXTENSION));
        $searchable = $this->maskSourceComments($content, $extension);
        $matchCount = preg_match_all('~http://[^\s\'"<>]+~i', $searchable, $matches, PREG_OFFSET_CAPTURE);
        if ($matchCount === false || $matchCount < 1) {
            return [];
        }

        foreach ($matches[0] as $match) {
            $rawUrl = (string)$match[0];
            $offset = (int)$match[1];
            $url = rtrim($rawUrl, '),.;]');
            if ($url === '' || $this->isAllowedPlainHttpReference($url)) {
                continue;
            }

            $before = substr($searchable, max(0, $offset - 220), min(220, $offset));
            $after = substr($searchable, $offset + strlen($rawUrl), 220);
            $kind = $this->configuredHttpContext($file, $before, $after);
            if ($kind === null) {
                continue;
            }

            $evidence = $this->matchEvidence($file, $content, $kind, $offset);
            $evidence['kind'] = $kind;
            $evidence['url'] = $url;
            $findings[] = $evidence;
        }

        return $findings;
    }

    private function configuredHttpContext(string $file, string $before, string $after): ?string
    {
        if ($this->relativeFile($file) === 'app/etc/env.php') {
            return 'env_config';
        }

        $keyPattern = '(?:url|uri|endpoint|host|hostname|base_url|webhook|callback|api_url|wsdl|dsn|service_url)';
        if (preg_match('~[\'" ]?' . $keyPattern . '[\'" ]?\s*(?:=>|=|:)\s*[\'" ]?\s*$~i', $before) === 1) {
            return 'named_config';
        }

        if (preg_match('~(?:set|get|with)?' . $keyPattern . '\s*\([^)]*$~i', $before) === 1) {
            return 'endpoint_method';
        }

        if (preg_match('~(?:curl_init|fetch|request|get|post|put|patch|delete|send)\s*\([^)]*$~i', $before) === 1) {
            return 'http_client_literal';
        }

        if (preg_match('~<[^>]*' . $keyPattern . '[^>]*>\s*$~i', $before) === 1
            && preg_match('~^\s*</[^>]+>~', $after) === 1) {
            return 'xml_config';
        }

        return null;
    }

    private function maskSourceComments(string $content, string $extension): string
    {
        $replaceWithSpaces = static fn(array $match): string => str_repeat(' ', strlen($match[0]));
        $masked = preg_replace_callback('~<!--.*?-->~s', $replaceWithSpaces, $content);
        if ($masked === null) {
            $masked = $content;
        }

        if (in_array($extension, ['php', 'phtml', 'js', 'css', 'less'], true)) {
            $blockMasked = preg_replace_callback('~/\*.*?\*/~s', $replaceWithSpaces, $masked);
            if ($blockMasked !== null) {
                $masked = $blockMasked;
            }

            $lineMasked = preg_replace_callback('~(?<!:)//[^\r\n]*~', $replaceWithSpaces, $masked);
            if ($lineMasked !== null) {
                $masked = $lineMasked;
            }
        }

        if (in_array($extension, ['php', 'phtml', 'yaml', 'yml', 'ini'], true)) {
            $hashMasked = preg_replace_callback('~(?m)^[\t ]*#[^\r\n]*~', $replaceWithSpaces, $masked);
            if ($hashMasked !== null) {
                $masked = $hashMasked;
            }
        }

        return $masked;
    }
    private function mixedContentFindings(string $file, string $content): array
    {
        $findings = [];
        $patterns = [
            'html_attr' => '~(?<!\.)\b(?:src|href|action|formaction|poster|data-src|data-href|data-url|data-mage-init|x-magento-init)\s*=\s*([\'"])(?P<url>http://[^\'"\s<>]+)\1~i',
            'srcset_attr' => '~\b(?:srcset|data-srcset)\s*=\s*([\'"])(?P<url>[^\'"]*http://[^\'"]+)\1~i',
            'css_url' => '~url\(\s*([\'"]?)(?P<url>http://[^\'")\s]+)\1\s*\)~i',
            'js_assignment' => '~(?:\.\s*(?:src|href|action)\s*=|\burl\s*:)\s*([\'"])(?P<url>http://[^\'"\s<>]+)\1~i',
            'xml_asset' => '~>\s*(?P<url>http://[^<\s]+)\s*<~i',
        ];

        foreach ($patterns as $kind => $regex) {
            $mixedContentMatchCount = preg_match_all($regex, $content, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER);
            if ($mixedContentMatchCount === false || $mixedContentMatchCount < 1) {
                continue;
            }
            foreach ($matches as $match) {
                $url = isset($match['url']) && is_array($match['url']) ? (string)$match['url'][0] : '';
                if ($this->isAllowedPlainHttpReference($url)) {
                    continue;
                }

                $evidence = $this->matchEvidence($file, $content, $kind, (int)$match[0][1]);
                $evidence['kind'] = $kind;
                $evidence['url'] = $url;
                $findings[] = $evidence;
            }
        }

        return $findings;
    }

    /**
     * @return array<int, array{expr:string, offset:int}>
     */
    private function phpOutputExpressions(string $content, int $baseOffset): array
    {
        $expressions = [];
        $patterns = [
            '~<\?=\s*(?P<expr>.*?)\?>~is',
            '~<\?php\s+(?:echo|print)\s+(?P<expr>.*?);?\s*\?>~is',
        ];

        foreach ($patterns as $regex) {
            if (preg_match_all($regex, $content, $matches, PREG_OFFSET_CAPTURE | PREG_SET_ORDER) !== 1) {
                continue;
            }
            foreach ($matches as $match) {
                $expr = isset($match['expr']) && is_array($match['expr']) ? (string)$match['expr'][0] : '';
                $expressions[] = [
                    'expr' => $expr,
                    'offset' => $baseOffset + (int)$match[0][1],
                ];
            }
        }

        return $expressions;
    }

    private function maskPhpStringsAndComments(string $content): string
    {
        $out = $content;
        $len = strlen($content);
        $i = 0;

        while ($i < $len) {
            $ch = $content[$i];
            $next = $i + 1 < $len ? $content[$i + 1] : '';

            if ($ch === "'" || $ch === '"') {
                $quote = $ch;
                $start = $i;
                $i++;
                while ($i < $len) {
                    if ($content[$i] === '\\') {
                        $i += 2;
                        continue;
                    }
                    if ($content[$i] === $quote) {
                        $i++;
                        break;
                    }
                    $i++;
                }
                $out = substr_replace($out, str_repeat(' ', $i - $start), $start, $i - $start);
                continue;
            }

            if ($ch === '/' && $next === '/') {
                $start = $i;
                $end = strpos($content, "\n", $i);
                $i = $end === false ? $len : $end;
                $out = substr_replace($out, str_repeat(' ', $i - $start), $start, $i - $start);
                continue;
            }

            if ($ch === '#') {
                $start = $i;
                $end = strpos($content, "\n", $i);
                $i = $end === false ? $len : $end;
                $out = substr_replace($out, str_repeat(' ', $i - $start), $start, $i - $start);
                continue;
            }

            if ($ch === '/' && $next === '*') {
                $start = $i;
                $end = strpos($content, '*/', $i + 2);
                $i = $end === false ? $len : $end + 2;
                $out = substr_replace($out, str_repeat(' ', $i - $start), $start, $i - $start);
                continue;
            }

            $i++;
        }

        return $out;
    }

    private function unserializeRisk(string $content, int $offset, string $args): string
    {
        $window = $this->codeWindow($content, $offset, 1200) . "\n" . $args;
        if (preg_match('~\b(?:getParam|getPost|getPostValue|getCookie|COOKIE|REQUEST|POST|GET|FILES|SERVER|php://input)\b~i', $window) === 1) {
            return 'high';
        }

        return 'medium';
    }

    private function commandExecutionRisk(string $content, int $offset, string $args): ?string
    {
        $window = $this->codeWindow($content, $offset, 1200) . "\n" . $args;
        $command = trim($args);

        if ($this->hasCommandInjectionGuard($window)) {
            return null;
        }

        if (preg_match('~\b(?:getParam|getPost|getPostValue|getQuery|getCookie|getHeader|REQUEST|POST|GET|COOKIE|FILES|SERVER|php://input)\b~i', $window) === 1) {
            return 'high';
        }

        if (preg_match('~\$(?:_?[A-Za-z][A-Za-z0-9_]*|{)~', $command) === 1
            || preg_match('~(?:["\']\s*\.|\.\s*\$|\$\w+\s*\.)~', $command) === 1
            || str_contains($command, '{$')) {
            return 'medium';
        }

        return null;
    }

    private function dynamicExecutionRisk(string $kind, string $content, int $offset, string $args): ?string
    {
        $window = $this->codeWindow($content, $offset, 1200) . "\n" . $args;
        $hasUserInput = preg_match('~\b(?:getParam|getPost|getPostValue|getQuery|getCookie|getHeader|REQUEST|POST|GET|COOKIE|FILES|SERVER|php://input)\b~i', $window) === 1;
        $hasDynamicArg = preg_match('~\$(?:_?[A-Za-z][A-Za-z0-9_]*|{)~', $args) === 1
            || preg_match('~(?:["\']\s*\.|\.\s*\$|\$\w+\s*\.)~', $args) === 1
            || str_contains($args, '{$');

        if ($kind === 'dynamic_code_function') {
            return $hasUserInput ? 'high' : 'medium';
        }

        if ($kind === 'dynamic_include') {
            if (!$hasDynamicArg) {
                return null;
            }
            if ($this->isTrustedLocalConfigArrayIncludeContext($window)) {
                return null;
            }
            if ($hasUserInput) {
                return 'high';
            }
            if (preg_match('~\b(?:upload|tmp|temp|cache|media|var|remote|url|uri)\b|(?:\.\./|php://|data://|phar://|https?://)~i', $window) === 1) {
                return 'medium';
            }
            return null;
        }

        if ($kind === 'dynamic_callable' || $kind === 'variable_function') {
            if ($hasUserInput) {
                return 'high';
            }
            if ($kind === 'variable_function' && preg_match('~\b(?:callback|callable|handler|action|method)\b~i', $window) === 1) {
                return 'medium';
            }
            return null;
        }

        return null;
    }

    private function pathTraversalRisk(string $kind, string $content, int $offset, string $args): ?string
    {
        $window = $this->codeWindow($content, $offset, 1400) . "\n" . $args;
        $hasUserInput = preg_match('~\b(?:getParam|getPost|getPostValue|getQuery|getCookie|getHeader|REQUEST|POST|GET|COOKIE|FILES|SERVER|php://input|getClientOriginalName|getUploadedFileName)\b~i', $window) === 1;
        $hasDynamicPath = preg_match('~\$(?:_?[A-Za-z][A-Za-z0-9_]*|{)~', $args) === 1
            || preg_match('~(?:["\']\s*\.|\.\s*\$|\$\w+\s*\.)~', $args) === 1
            || str_contains($args, '{$');
        $hasDangerousPath = preg_match('~(?:\.\./|php://|data://|phar://|zip://|https?://|\\\\0)~i', $window) === 1;

        if (!$hasDynamicPath && !$hasUserInput && !$hasDangerousPath) {
            return null;
        }

        if ($this->isLocalEnumeratedPathContext($window)) {
            return null;
        }

        if ($kind === 'include_sink' && $this->isTrustedLocalConfigArrayIncludeContext($window)) {
            return null;
        }

        if ($this->hasPathTraversalGuard($window)) {
            return null;
        }

        if ($hasUserInput || preg_match('~\$_(?:GET|POST|REQUEST|FILES|COOKIE|SERVER)\b~', $args) === 1) {
            return 'high';
        }

        if ($hasDangerousPath) {
            return 'medium';
        }

        if (preg_match('~\b(?:upload|tmp|temp|cache|media|var|filename|filepath|path|relative|template)\b~i', $window) === 1) {
            return 'medium';
        }

        return null;
    }

    private function looksLikeUploadFlow(string $kind, string $window): bool
    {
        if ($kind === 'uploaded_file_save') {
            return preg_match('~\b(?:UploadedFileInterface|getUploadedFile|getUploadedFiles|UploaderFactory|\$_FILES|tmp_name|getClientFilename|getClientMediaType)\b~i', $window) === 1;
        }

        return true;
    }

    private function isSafeJsContextExpression(string $expr): bool
    {
        if (stripos($expr, '@noEscape') !== false || stripos($expr, 'noEscape') !== false) {
            return true;
        }

        $trimmed = trim($expr);
        if ($trimmed === '') {
            return true;
        }

        if (preg_match('~^(?:true|false|null|\d+(?:\.\d+)?|[\'"][^\'"]*[\'"])$~i', $trimmed) === 1) {
            return true;
        }

        return preg_match('~\b(?:escapeJs|escapeJsQuote|json_encode|serialize|unserialize|JsonHelper|SerializerInterface|Json::encode|->jsonEncode)\s*\(~i', $expr) === 1
            || preg_match('~(?:->|::)\s*(?:escapeJs|escapeJsQuote|jsonEncode|serialize)\s*\(~i', $expr) === 1;
    }

    private function weakPrngRisk(string $content, int $offset): ?string
    {
        $window = $this->codeWindow($content, $offset, 900);
        $identifierContext = $this->identifierContext($content, $offset);

        if ($this->hasSecurityRandomnessSignal($window . "\n" . $identifierContext)) {
            return 'high';
        }

        if (preg_match('~\b(?:generate|create|build|make|issue|reset|verify|activate|auth)\w*\s*\(~i', $identifierContext) === 1
            && preg_match('~\b(?:token|code|key|secret|nonce|otp|salt|password|passcode)\b~i', $window . "\n" . $identifierContext) === 1) {
            return 'high';
        }

        return null;
    }

    private function identifierContext(string $content, int $offset): string
    {
        $before = substr($content, max(0, $offset - 700), min(700, $offset));
        $context = '';

        if (preg_match('~function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*$~s', $before, $match)) {
            $context .= ' function ' . $match[1];
        }
        if (preg_match('~\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*$~s', $before, $match)) {
            $context .= ' variable ' . $match[1];
        }
        if (preg_match('~[\'"]([A-Za-z0-9_.-]*(?:token|otp|password|passcode|reset|nonce|secret|api[_-]?key|salt|verify|activation|auth|code)[A-Za-z0-9_.-]*)[\'"]\s*=>\s*$~is', $before, $match)) {
            $context .= ' array_key ' . $match[1];
        }

        return $context;
    }

    private function hasSecurityRandomnessSignal(string $text): bool
    {
        return preg_match('~[A-Za-z0-9_.-]*(?:token|otp|one.?time.?password|password|passcode|reset|nonce|secret|api[_-]?key|key|salt|verify|activation|verification[_-]?code|auth[_-]?code|csrf|form[_-]?key|session|cookie|invite|recovery)[A-Za-z0-9_.-]*~i', $text) === 1;
    }

    private function hasThirdPartyLoggingSignal(string $text, string $file): bool
    {
        return preg_match('~(?:third[_-]?party|integration|gateway|payment|provider|api|webhook|callback|client|connector|stripe|paypal|braintree|adyen|klarna|authorizenet|authorize|shipping|carrier|tax|fraud|analytics|crm|erp|saas)~i', $text . "\n" . $this->relativeFile($file)) === 1;
    }

    private function hasThirdPartyLogSensitiveSignal(string $text): bool
    {
        return $this->hasSensitiveLoggingSignal($text)
            || preg_match('~\b(?:email|customer[_-]?id|customer[_-]?email|telephone|phone|billing|shipping|address|order[_-]?id|quote[_-]?id|transaction[_-]?id|external[_-]?id|identifier)\b~i', $text) === 1;
    }

    private function hasSensitiveLoggingSignal(string $text): bool
    {
        return preg_match('~[A-Za-z0-9_.-]*(?:password|passwd|pwd|token|access[_-]?token|refresh[_-]?token|authorization|auth(?:orization)?[_-]?header|bearer|cookie|set[_-]?cookie|session(?:[_-]?id)?|secret|api[_-]?key|private[_-]?key|cvv|cvc|card[_-]?number|card|pan|payment|expiry|exp[_-]?month|exp[_-]?year)[A-Za-z0-9_.-]*~i', $text) === 1
            || preg_match('~\b(?:Authorization|Cookie|Set-Cookie|X-Api-Key)\b~i', $text) === 1;
    }

    private function hasRedactionSignal(string $text): bool
    {
        return preg_match('~\b(?:redact|redacted|mask|masked|sanitize|sanitized|filterSensitive|removeSensitive|withoutSensitive|scrub|obfuscate)\b~i', $text) === 1
            || preg_match('~(?:\[REDACTED\]|\*{3,}|x{3,}|X{3,})~', $text) === 1;
    }

    private function sensitiveLoggingRisk(string $text): string
    {
        if (preg_match('~\b(?:cvv|cvc|card[_-]?number|pan|Authorization|access[_-]?token|refresh[_-]?token|password|private[_-]?key)\b~i', $text) === 1) {
            return 'high';
        }

        return 'medium';
    }

    private function magentoApiCryptoSessionRisk(string $kind, string $content, int $offset, string $args): ?string
    {
        $window = $this->codeWindow($content, $offset, 1000) . "\n" . $args;

        if ($this->hasMagentoFrameworkCryptoSessionSignal($window)) {
            return null;
        }

        if ($kind === 'weak_hash_secret' && !$this->hasSecurityRandomnessSignal($window)) {
            return null;
        }

        return match ($kind) {
            'legacy_mcrypt', 'raw_openssl_crypto', 'weak_hash_secret' => 'high',
            'direct_sodium_crypto' => 'medium',
            default => 'medium',
        };
    }

    private function hasMagentoFrameworkCryptoSessionSignal(string $window): bool
    {
        return preg_match('~\b(?:Magento\\\\Framework\\\\Encryption\\\\EncryptorInterface|EncryptorInterface|\\\\Magento\\\\Framework\\\\Session|SessionManagerInterface|SessionManager|CustomerSession|CheckoutSession|BackendSession|FormKey|CookieManagerInterface|CookieMetadataFactory|SessionConfig)\b~i', $window) === 1;
    }

    private function isAllowedPlainHttpReference(string $url): bool
    {
        return preg_match('~^http://(?:www\.)?w3\.org/~i', $url) === 1
            || preg_match('~^http://(?:www\.)?schema\.org/~i', $url) === 1
            || preg_match('~^http://localhost(?::\d+)?(?:/|$)~i', $url) === 1
            || preg_match('~^http://127\.0\.0\.1(?::\d+)?(?:/|$)~', $url) === 1;
    }

    private function hasUploadSafeguards(string $window): bool
    {
        $missing = $this->missingUploadSafeguards($window);
        return $missing === [];
    }

    private function missingUploadSafeguards(string $window): array
    {
        $missing = [];
        $hasMimeValidation = preg_match('~\b(?:finfo_(?:open|file)|mime_content_type|get(?:MimeType|ClientMimeType|ClientMediaType)|validateMime|checkMimeType|isValid|validateFile|addValidateCallback)\b~i', $window) === 1;
        $hasExtensionAllowlist = preg_match('~\b(?:setAllowedExtensions|allowedExtensions?|PATHINFO_EXTENSION|checkAllowedExtension|getClientOriginalExtension|extensionAllowlist|validateExtension)\b~i', $window) === 1;
        $hasSizeLimit = preg_match('~\b(?:getSize|size|MAX_FILE_SIZE|maxFileSize|setAllowCreateFolders|validateSize|filesize)\b~i', $window) === 1
            && preg_match('~(?:<=|<|max|limit|allowed)~i', $window) === 1;
        $hasStoragePolicy = preg_match('~\b(?:setAllowRenameFiles|setFilesDispersion|random_bytes|uniqid|hash|sha1|md5|DirectoryList|VAR_DIR|TMP|MEDIA|outsideWebroot|pub/media|media/tmp|uploadDir|destination)\b~i', $window) === 1;

        if (!$hasMimeValidation) {
            $missing[] = 'mime_validation';
        }
        if (!$hasExtensionAllowlist) {
            $missing[] = 'extension_allowlist';
        }
        if (!$hasSizeLimit) {
            $missing[] = 'size_limit';
        }
        if (!$hasStoragePolicy) {
            $missing[] = 'storage_policy';
        }

        return $missing;
    }

    private function isLocalEnumeratedPathContext(string $window): bool
    {
        return preg_match('~\b(?:collectFiles|RecursiveDirectoryIterator|DirectoryIterator|FilesystemIterator|SplFileInfo|getPathname|getRealPath|scandir|glob)\b~i', $window) === 1
            || preg_match('~foreach\s*\(\s*\$[A-Za-z_][A-Za-z0-9_]*\s+as\s+\$file\s*\)~i', $window) === 1;
    }

    private function isTrustedLocalConfigArrayIncludeContext(string $window): bool
    {
        return preg_match('~\b\$file\s*=\s*\$this->ctx->abs\s*\(\s*\$relativeFile\s*\)~', $window) === 1
            && preg_match('~\bis_file\s*\(\s*\$file\s*\)~', $window) === 1
            && preg_match('~\binclude\s+\$file\b~', $window) === 1
            && preg_match('~\bis_array\s*\(\s*\$[A-Za-z_][A-Za-z0-9_]*\s*\)~', $window) === 1;
    }

    private function hasPathTraversalGuard(string $window): bool
    {
        $hasNormalize = preg_match('~\b(?:realpath|basename|pathinfo|normalizePath|resolvePath|getPath|DirectoryList)\b~i', $window) === 1;
        $hasBaseCheck = preg_match('~\b(?:str_starts_with|strpos|strncmp|preg_match|in_array|allowedPaths?|allowedDirs?|baseDir|basePath|DirectoryList|ROOT|MEDIA|VAR_DIR)\b~i', $window) === 1;
        $hasTraversalReject = preg_match('~(?:\.\./|\.\.\\\\|basename\s*\(|PATHINFO_BASENAME|FILTER_SANITIZE|validatePath|isValidPath)~i', $window) === 1;

        return ($hasNormalize && $hasBaseCheck) || ($hasNormalize && $hasTraversalReject);
    }

    private function hasCommandInjectionGuard(string $window): bool
    {
        return preg_match('~\b(?:escapeshellarg|escapeshellcmd)\s*\(~i', $window) === 1
            || preg_match('~\b(?:preg_match|in_array|array_key_exists|match)\b[\s\S]{0,240}\b(?:allowlist|whitelist|allowed|^[A-Za-z0-9_.:/ -]+$|^[a-z0-9_-]+$)\b~i', $window) === 1
            || preg_match('~\b(?:allowlist|whitelist|allowedCommands?|allowedBins?|validateCommand|isAllowedCommand)\b~i', $window) === 1;
    }

    private function looksLikeOutboundUrlArgument(string $kind, string $arg): bool
    {
        if ($kind === 'curl_url') {
            return true;
        }

        $trimmed = trim($arg);
        if ($trimmed === '') {
            return false;
        }

        if (preg_match('~^[\'"]https?://[^\'"$]+[\'"]~i', $trimmed) === 1) {
            return false;
        }

        if ($kind === 'php_stream') {
            if (preg_match('~\b(?:getPathname|getRealPath|__DIR__|dirname|realpath|DirectoryIterator|RecursiveDirectoryIterator|SplFileInfo)\b~i', $trimmed) === 1) {
                return false;
            }

            return preg_match('~\b(?:getParam|getPost|getQuery|getBody|REQUEST|POST|GET|COOKIE|SERVER)\b~i', $trimmed) === 1
                || preg_match('~^[\'"]https?://~i', $trimmed) === 1
                || (
                    str_contains($trimmed, '$')
                    && preg_match('~\b(?:url|uri|endpoint|callback|webhook|host|domain|remote|target|api)\b~i', $trimmed) === 1
                );
        }

        return str_contains($trimmed, '$')
            || preg_match('~\b(?:getParam|getPost|getQuery|getBody|REQUEST|POST|GET|COOKIE|SERVER)\b~i', $trimmed) === 1
            || preg_match('~^[\'"]https?://~i', $trimmed) === 1;
    }

    private function hasSsrfSafeguards(string $window): bool
    {
        $hasHostValidation = preg_match('~\b(?:parse_url|UriInterface|getHost|filter_var|FILTER_VALIDATE_URL|allowedHosts?|allowlist|whitelist|isAllowedHost|validateHost|validateUrl)\b~i', $window) === 1;
        $hasPrivateIpGuard = preg_match('~\b(?:FILTER_FLAG_NO_PRIV_RANGE|FILTER_FLAG_NO_RES_RANGE|private|localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254|10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168|::1|fc00|fe80|metadata)\b~i', $window) === 1;
        $hasProtocolGuard = preg_match('~\b(?:https?|scheme|getScheme)\b[\s\S]{0,160}(?:===|==|in_array|allowed|https)~i', $window) === 1;
        $hasTimeout = preg_match('~\b(?:CURLOPT_TIMEOUT|CURLOPT_CONNECTTIMEOUT|timeout|setTimeout|connect_timeout|read_timeout)\b~i', $window) === 1;

        return $hasTimeout && ($hasHostValidation || $hasPrivateIpGuard || $hasProtocolGuard);
    }

    private function codeWindow(string $content, int $offset, int $radius): string
    {
        $start = max(0, $offset - $radius);
        return substr($content, $start, $radius * 2);
    }

    private function looksLikePostHandler(string $content): bool
    {
        return preg_match('~\b(?:getPost|getPostValue|isPost)\s*\(|\$_POST\b|RequestInterface~i', $content) === 1
            && preg_match('~\bexecute\s*\(~', $content) === 1;
    }

    private function hasCsrfValidationSignal(string $content): bool
    {
        return preg_match('~\b(?:FormKey\\Validator|formKeyValidator|validateForCsrf|CsrfAwareActionInterface|FORM_KEY|getFormKey|form_key)\b~i', $content) === 1;
    }

    private function isEscapedTemplateExpression(string $expr, array $escapeFunctions): bool
    {
        if (stripos($expr, '@noEscape') !== false || stripos($expr, 'noEscape') !== false) {
            return true;
        }

        $trimmed = trim($expr);
        if ($trimmed === '') {
            return true;
        }

        if (preg_match('~^(?:true|false|null|\d+(?:\.\d+)?|[\'"][^\'"]*[\'"])$~i', $trimmed) === 1) {
            return true;
        }

        foreach ($escapeFunctions as $fn) {
            if ($fn !== '' && preg_match('~(?:->|::)?' . preg_quote($fn, '~') . '\s*\(~i', $expr) === 1) {
                return true;
            }
        }

        return false;
    }

    private function looksLikeUnsafeSqlArgument(string $arg): bool
    {
        if (!preg_match('~\b(?:select|insert|update|delete|replace|drop|alter|truncate)\b~i', $arg)) {
            return false;
        }

        return str_contains($arg, '.')
            || str_contains($arg, '$')
            || str_contains($arg, '{$')
            || preg_match('~["\'][^"\']*\b(?:select|insert|update|delete|replace|drop|alter|truncate)\b[^"\']*["\']~i', $arg) === 1;
    }

    private function looksLikeUnsafeConditionArgument(string $arg): bool
    {
        if (!preg_match('~["\'][^"\']*(?:=|<|>|like|in\s*\()[^"\']*["\']~i', $arg)) {
            return false;
        }

        return str_contains($arg, '.') || str_contains($arg, '$') || str_contains($arg, '{$');
    }

    private function relativeFile(string $file): string
    {
        $root = rtrim($this->ctx->path, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
        if (str_starts_with($file, $root)) {
            return str_replace(DIRECTORY_SEPARATOR, '/', substr($file, strlen($root)));
        }

        return str_replace(DIRECTORY_SEPARATOR, '/', $file);
    }
    private function matchEvidence(string $file, string $content, string $pattern, int $offset): array
    {
        $line = substr_count(substr($content, 0, $offset), "\n") + 1;
        $lineStart = strrpos(substr($content, 0, $offset), "\n");
        $lineStart = $lineStart === false ? 0 : $lineStart + 1;
        $lineEnd = strpos($content, "\n", $offset);
        $lineEnd = $lineEnd === false ? strlen($content) : $lineEnd;

        return [
            'file' => $file,
            'line' => $line,
            'pattern' => $pattern,
            'snippet' => trim(substr($content, $lineStart, $lineEnd - $lineStart)),
        ];
    }
}
