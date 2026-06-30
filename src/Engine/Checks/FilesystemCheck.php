<?php

declare(strict_types=1);

namespace Magebean\Engine\Checks;

use Magebean\Engine\Context;

final class FilesystemCheck
{
    private Context $ctx;
    public function __construct(Context $ctx)
    {
        $this->ctx = $ctx;
    }

    public function noWorldWritable(array $args): array
    {
        $root = $this->ctx->abs($args['path'] ?? '.');
        $max = max(1, (int)($args['max_results'] ?? 50));
        if (!file_exists($root)) {
            return [false, "Path not found: {$root}"];
        }

        $offenders = [];
        $truncated = false;
        $flags = \FilesystemIterator::SKIP_DOTS;

        $this->collectWorldWritableOffender($root, $offenders, $max, $truncated);

        $rii = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($root, $flags),
            \RecursiveIteratorIterator::SELF_FIRST
        );
        foreach ($rii as $file) {
            if ($file->isLink()) {
                continue;
            }

            $this->collectWorldWritableOffender($file->getPathname(), $offenders, $max, $truncated);
            if ($truncated) {
                break;
            }
        }

        if ($offenders) {
            $shown = count($offenders);
            $msg = "World-writable entries found ({$shown}" . ($truncated ? '+' : '') . " shown): "
                . implode(', ', array_map(
                    static fn(array $o): string => $o['path'] . ' [' . $o['type'] . ':' . $o['mode'] . ']',
                    $offenders
                ));
            if ($truncated) {
                $msg .= ". More offenders exist; increase max_results to inspect additional entries.";
            }
            return [false, $msg, $offenders];
        }
        return [true, "No world-writable files or directories detected under {$root}"];
    }

    public function fileModeMax(array $args): array
    {
        $rel = $args['file'] ?? 'app/etc/env.php';
        $file = $this->ctx->abs($rel);
        $allowedModeRaw = (string)($args['max_octal'] ?? '0640');
        $allowedMode = octdec($allowedModeRaw);
        if (!is_file($file)) return [false, "{$rel} is missing"];
        $perm = fileperms($file) & 0777;

        $extraBits = $perm & (~$allowedMode & 0777);
        $evidence = [
            'path' => $file,
            'observed_mode' => sprintf('%o', $perm),
            'allowed_mode' => sprintf('%o', $allowedMode),
        ];
        if ($extraBits !== 0) {
            $evidence['excess_bits'] = sprintf('%o', $extraBits);
            return [
                false,
                "{$rel} mode " . sprintf('%o', $perm) . " is more permissive than allowed policy " . sprintf('%o', $allowedMode),
                $evidence,
            ];
        }

        return [
            true,
            "{$rel} mode " . sprintf('%o', $perm) . " complies with allowed policy " . sprintf('%o', $allowedMode),
            $evidence,
        ];
    }

    public function fileOwnerGroupMatches(array $args): array
    {
        $rel = (string)($args['file'] ?? '');
        if ($rel === '') {
            return [false, 'file_owner_group_matches requires file'];
        }

        $file = $this->ctx->abs($rel);
        if (!is_file($file)) {
            return [false, "{$rel} is missing"];
        }

        $ownerRefRel = (string)($args['owner_reference'] ?? '.');
        $groupRefRel = (string)($args['group_reference'] ?? $ownerRefRel);
        $ownerRef = $this->ctx->abs($ownerRefRel);
        $groupRef = $this->ctx->abs($groupRefRel);

        if (!file_exists($ownerRef)) {
            return [false, "Owner reference not found: {$ownerRefRel}"];
        }
        if (!file_exists($groupRef)) {
            return [false, "Group reference not found: {$groupRefRel}"];
        }

        $owner = @fileowner($file);
        $group = @filegroup($file);
        $expectedOwner = @fileowner($ownerRef);
        $expectedGroup = @filegroup($groupRef);
        if ($owner === false || $group === false || $expectedOwner === false || $expectedGroup === false) {
            return [false, "Could not stat ownership for {$rel}"];
        }

        $evidence = [
            'path' => $file,
            'owner' => $this->formatIdentity((int)$owner, true),
            'group' => $this->formatIdentity((int)$group, false),
            'owner_reference' => $ownerRef,
            'expected_owner' => $this->formatIdentity((int)$expectedOwner, true),
            'group_reference' => $groupRef,
            'expected_group' => $this->formatIdentity((int)$expectedGroup, false),
        ];

        if ($owner !== $expectedOwner || $group !== $expectedGroup) {
            return [
                false,
                "{$rel} ownership does not match expected application owner/group",
                $evidence,
            ];
        }

        return [
            true,
            "{$rel} ownership matches expected application owner/group",
            $evidence,
        ];
    }

    public function webrootHygiene(array $args): array
    {
        $webroot = $this->ctx->abs($args['webroot'] ?? 'pub');
        $bad = $args['forbidden'] ?? ['.git', '.env', '.env.local', '*.bak', '*.old', '*~'];
        if (!is_dir($webroot)) return [true, "Webroot {$webroot} not found (skipped)"];
        $matches = [];
        $max = max(1, (int)($args['max_results'] ?? 50));
        $truncated = false;

        $this->collectForbiddenWebrootArtifact($webroot, $bad, $matches, $max, $truncated);

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($webroot, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::SELF_FIRST,
            \RecursiveIteratorIterator::CATCH_GET_CHILD
        );
        foreach ($iterator as $file) {
            $path = $file->getPathname();
            $this->collectForbiddenWebrootArtifact($path, $bad, $matches, $max, $truncated);
            if ($file->isLink()) {
                continue;
            }
            if ($truncated) {
                break;
            }
        }
        if ($matches) {
            $shown = count($matches);
            $msg = "Forbidden artifacts found in webroot ({$shown}" . ($truncated ? '+' : '') . " shown): "
                . implode(', ', array_map(
                    static fn(array $match): string => $match['path'] . ' [' . $match['type'] . ', pattern:' . $match['pattern'] . ']',
                    $matches
                ));
            if ($truncated) {
                $msg .= ". More matches exist; increase max_results to inspect additional entries.";
            }
            return [false, $msg, $matches];
        }
        return [true, "Webroot clean: {$webroot}"];
    }

    public function logsReportsNotInWebroot(array $args): array
    {
        $webrootRel = (string)($args['webroot'] ?? 'pub');
        $webroot = $this->ctx->abs($webrootRel);
        if (!is_dir($webroot)) {
            return [null, '[UNKNOWN] Webroot not found for log/report exposure check', ['webroot' => $webrootRel]];
        }

        $forbidden = $args['forbidden_paths'] ?? ['var/log', 'var/report'];
        if (!is_array($forbidden)) {
            $forbidden = ['var/log', 'var/report'];
        }
        $forbidden = array_values(array_filter(array_map(
            static fn(mixed $value): string => trim(str_replace('\\', '/', (string)$value), '/'),
            $forbidden
        )));

        $projectTargets = [];
        foreach ($forbidden as $relative) {
            $target = realpath($this->ctx->abs($relative));
            if ($target !== false) {
                $projectTargets[$relative] = $target;
            }
        }

        $matches = [];
        $max = max(1, (int)($args['max_results'] ?? 50));
        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($webroot, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::SELF_FIRST,
            \RecursiveIteratorIterator::CATCH_GET_CHILD
        );

        foreach ($iterator as $file) {
            $path = $file->getPathname();
            $relative = str_replace('\\', '/', ltrim(substr($path, strlen(rtrim($webroot, DIRECTORY_SEPARATOR))), DIRECTORY_SEPARATOR));
            foreach ($forbidden as $pattern) {
                if ($relative === $pattern || str_starts_with($relative, $pattern . '/')) {
                    $matches[] = [
                        'path' => $path,
                        'relative_path' => $relative,
                        'pattern' => $pattern,
                        'type' => is_link($path) ? 'link' : (is_dir($path) ? 'dir' : 'file'),
                    ];
                    break;
                }
            }

            if (is_link($path)) {
                $target = realpath($path);
                if ($target !== false) {
                    foreach ($projectTargets as $pattern => $projectTarget) {
                        if ($target === $projectTarget || str_starts_with($target, rtrim($projectTarget, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR)) {
                            $matches[] = [
                                'path' => $path,
                                'relative_path' => $relative,
                                'pattern' => $pattern,
                                'type' => 'link',
                                'target' => $target,
                            ];
                            break;
                        }
                    }
                }
            }

            if (count($matches) >= $max) {
                break;
            }
        }

        if ($matches !== []) {
            return [false, 'Log/report paths are exposed under webroot', ['webroot' => $webrootRel, 'matches' => $matches]];
        }

        return [true, 'Log and report paths are not exposed under webroot', ['webroot' => $webrootRel, 'checked' => $forbidden]];
    }

    public function logRotationConfigured(array $args): array
    {
        $fileRel = (string)($args['file'] ?? 'devops/logrotate.conf');
        $file = $this->ctx->abs($fileRel);
        if (!is_file($file)) {
            return [false, 'Log rotation configuration file not found', ['file' => $fileRel]];
        }

        $content = @file_get_contents($file);
        if ($content === false) {
            return [null, '[UNKNOWN] Unable to read log rotation configuration', ['file' => $fileRel]];
        }

        $activeLines = [];
        foreach (preg_split("~\r?\n~", $content) as $line) {
            $line = trim(preg_replace('~\s+#.*$~', '', (string)$line) ?? '');
            if ($line === '' || str_starts_with($line, '#')) {
                continue;
            }
            $activeLines[] = $line;
        }
        $active = implode("\n", $activeLines);

        $hasRotate = preg_match('~^\s*rotate\s+\d+\b~mi', $active) === 1;
        $hasCompress = preg_match('~^\s*(?:delaycompress|compress)\b~mi', $active) === 1;
        $hasLogTarget = preg_match('~(?:^|\s)(?:/[^{}\s]*var/log/[^{}\s]*|var/log/[^{}\s]*|[^{}\s]*\.log)(?:\s|\{|$)~mi', $active) === 1;

        $evidence = [
            'file' => $fileRel,
            'has_rotate' => $hasRotate,
            'has_compress' => $hasCompress,
            'has_log_target' => $hasLogTarget,
        ];

        $missing = [];
        if (!$hasLogTarget) {
            $missing[] = 'log target';
        }
        if (!$hasRotate) {
            $missing[] = 'rotate directive';
        }
        if (!$hasCompress) {
            $missing[] = 'compress directive';
        }
        if ($missing !== []) {
            return [false, 'Log rotation configuration is incomplete: missing ' . implode(', ', $missing), $evidence];
        }

        return [true, 'Log rotation is configured with rotate and compression', $evidence];
    }

    public function codeDirsReadonly(array $args): array
    {
        $dirs = $args['dirs'] ?? ['app', 'vendor', 'lib'];
        $max = max(1, (int)($args['max_results'] ?? 50));
        $off = [];
        $truncated = false;
        foreach ($dirs as $rel) {
            $path = $this->ctx->abs($rel);
            if (!is_dir($path)) continue;

            $this->collectWritableCodePath($path, $off, $max, $truncated);
            if ($truncated) {
                break;
            }

            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($path, \FilesystemIterator::SKIP_DOTS),
                \RecursiveIteratorIterator::SELF_FIRST,
                \RecursiveIteratorIterator::CATCH_GET_CHILD
            );
            foreach ($iterator as $file) {
                $this->collectWritableCodePath($file->getPathname(), $off, $max, $truncated);
                if ($truncated) {
                    break 2;
                }
            }
        }

        if ($off) {
            $shown = count($off);
            $msg = "Writable code paths found ({$shown}" . ($truncated ? '+' : '') . " shown): "
                . implode(', ', array_map(
                    static fn(array $entry): string => $entry['path'] . ' [' . $entry['type'] . ':' . $entry['mode'] . ']'
                        . (isset($entry['target']) ? ' -> ' . $entry['target'] : ''),
                    $off
                ));
            if ($truncated) {
                $msg .= ". More offenders exist; increase max_results to inspect additional entries.";
            }
            return [false, $msg, $off];
        }

        return [true, "Code directories are read-only"];
    }

    public function noDirectoryListing(array $args): array
    {
        $pub = $this->ctx->abs($args['webroot'] ?? 'pub');
        $ht = $pub . '/.htaccess';
        if (is_file($ht)) {
            $c = (string)file_get_contents($ht);
            if (stripos($c, 'Options -Indexes') !== false) return [true, "Apache: Options -Indexes present"];
        }
        $ng = $this->ctx->abs('nginx.conf');
        if (is_file($ng)) {
            $c = (string)file_get_contents($ng);
            if (stripos($c, 'autoindex off') !== false) return [true, "Nginx: autoindex off"];
        }
        return [false, "Could not verify directory listing disabled"];
    }

    public function fsExists(array $args): array
    {
        $rel = (string)($args['path'] ?? '');
        if ($rel === '') return [false, 'fs_exists requires path'];
        $abs = $this->ctx->abs($rel);
        $ok  = file_exists($abs);
        return [$ok, ($ok ? 'Exists: ' : 'Not found: ') . $rel];
    }

    public function securityMitigationsDocumented(array $args): array
    {
        $rel = trim((string)($args['path'] ?? 'SECURITY.md'));
        if ($rel === '') {
            return [false, 'security_mitigations_documented requires path'];
        }

        $abs = $this->ctx->abs($rel);
        $evidence = [
            'path' => $rel,
            'exists' => is_file($abs),
            'mitigation_documented' => false,
            'lifecycle_documented' => false,
        ];
        if (!is_file($abs)) {
            return [false, 'Mitigation document not found: ' . $rel, $evidence];
        }

        $content = @file_get_contents($abs);
        if (!is_string($content)) {
            return [null, '[UNKNOWN] Unable to read mitigation document: ' . $rel, $evidence];
        }

        $content = trim($content);
        if ($content === '') {
            return [false, 'Mitigation document is empty: ' . $rel, $evidence];
        }

        $hasMitigation = (bool)preg_match(
            '/\b(mitigation|workaround|temporary\s+(?:control|measure)|compensating\s+control|hotfix)\b/i',
            $content
        );
        $hasLifecycle = (bool)preg_match(
            '/\b(rollback|revert|expiry|expiration|review\s+date|valid\s+until|permanent\s+fix|upgrade\s+to|remove\s+after)\b/i',
            $content
        );
        $evidence['mitigation_documented'] = $hasMitigation;
        $evidence['lifecycle_documented'] = $hasLifecycle;

        $missing = [];
        if (!$hasMitigation) {
            $missing[] = 'mitigation/workaround action';
        }
        if (!$hasLifecycle) {
            $missing[] = 'rollback, review/expiry, or permanent-fix plan';
        }
        if ($missing !== []) {
            return [
                false,
                'Incomplete mitigation documentation in ' . $rel . ': missing ' . implode(' and ', $missing),
                $evidence,
            ];
        }

        return [
            true,
            'Temporary mitigations and their rollback/remediation lifecycle are documented in ' . $rel,
            $evidence,
        ];
    }

    public function pciManualEvidenceDocumented(array $args): array
    {
        $paths = $args['paths'] ?? ['.magebean/pci-evidence.md', 'docs/pci-evidence.md', 'SECURITY.md'];
        if (!is_array($paths)) {
            $paths = ['.magebean/pci-evidence.md', 'docs/pci-evidence.md', 'SECURITY.md'];
        }
        $requiredTopics = $args['required_topics'] ?? ['payment_scope', 'saq_notes', 'access_review', 'incident_response', 'vendor_responsibilities'];
        if (!is_array($requiredTopics)) {
            $requiredTopics = ['payment_scope', 'saq_notes', 'access_review', 'incident_response', 'vendor_responsibilities'];
        }

        $topicPatterns = [
            'payment_scope' => '~\b(?:payment\s+scope|cardholder\s+data\s+environment|\bCDE\b|checkout|payment\s+flow|card\s+data|scope\s+(?:summary|boundary))\b~i',
            'saq_notes' => '~\\b(?:SAQ|self[- ]assessment|merchant\\s+level|attestation|AOC|ROC)\\b~i',
            'access_review' => '~\b(?:access\s+review|user\s+access|privilege\s+review|admin\s+access|MFA|2FA|least\s+privilege|quarterly\s+review)\b~i',
            'incident_response' => '~\b(?:incident\s+response|breach|forensic|containment|escalation|security\s+incident|IR\s+plan|response\s+plan)\b~i',
            'vendor_responsibilities' => '~\b(?:vendor\s+responsibilit(?:y|ies)|service\s+provider|third[- ]party|shared\s+responsibilit(?:y|ies)|processor|gateway|contract|SLA)\b~i',
        ];

        $required = array_values(array_filter(array_map(static fn(mixed $topic): string => (string)$topic, $requiredTopics)));
        $found = array_fill_keys($required, false);
        $documents = [];
        $readable = 0;

        foreach ($paths as $rel) {
            $rel = (string)$rel;
            $abs = $this->ctx->abs($rel);
            $entry = [
                'path' => $rel,
                'exists' => is_file($abs),
                'readable' => false,
                'topics' => [],
            ];
            if (!is_file($abs)) {
                $documents[] = $entry;
                continue;
            }

            $content = @file_get_contents($abs);
            if (!is_string($content)) {
                $documents[] = $entry;
                continue;
            }

            $entry['readable'] = true;
            $readable++;
            $text = trim($content);
            foreach ($required as $topic) {
                $pattern = $topicPatterns[$topic] ?? null;
                $ok = $pattern !== null && $text !== '' && preg_match($pattern, $text) === 1;
                $entry['topics'][$topic] = $ok;
                if ($ok) {
                    $found[$topic] = true;
                }
            }
            $documents[] = $entry;
        }

        $missing = array_values(array_filter($required, static fn(string $topic): bool => empty($found[$topic])));
        $evidence = [
            'paths' => array_values(array_map('strval', $paths)),
            'documents' => $documents,
            'required_topics' => $required,
            'found_topics' => array_keys(array_filter($found)),
            'missing_topics' => $missing,
        ];

        if ($readable === 0) {
            return [false, 'No readable PCI evidence checklist found', $evidence];
        }

        if ($missing !== []) {
            $labels = [
                'payment_scope' => 'payment scope',
                'saq_notes' => 'SAQ/PCI notes',
                'access_review' => 'access review',
                'incident_response' => 'incident response',
                'vendor_responsibilities' => 'vendor responsibilities',
            ];
            $missingLabels = array_map(static fn(string $topic): string => $labels[$topic] ?? $topic, $missing);
            return [
                false,
                'PCI evidence checklist is incomplete: missing ' . implode(', ', $missingLabels),
                $evidence,
            ];
        }

        return [true, 'PCI evidence checklist covers required manual evidence topics', $evidence];
    }
    public function diCompiled(array $args): array
    {
        $metadataRel = (string)($args['metadata_path'] ?? 'generated/metadata');
        $codeRel = (string)($args['code_path'] ?? 'generated/code');
        $minMetadataFiles = max(1, (int)($args['min_metadata_php_files'] ?? 1));
        $minCodeFiles = max(1, (int)($args['min_code_php_files'] ?? 1));

        $metadataAbs = $this->ctx->abs($metadataRel);
        $codeAbs = $this->ctx->abs($codeRel);
        $evidence = [
            'metadata_path' => $metadataRel,
            'code_path' => $codeRel,
            'metadata_present' => is_dir($metadataAbs),
            'code_present' => is_dir($codeAbs),
            'metadata_php_files' => 0,
            'code_php_files' => 0,
        ];

        $missing = [];
        if (!is_dir($metadataAbs)) {
            $missing[] = $metadataRel;
        }
        if (!is_dir($codeAbs)) {
            $missing[] = $codeRel;
        }
        if ($missing !== []) {
            return [false, 'Compiled DI directories missing: ' . implode(', ', $missing), $evidence];
        }

        $metadataCount = $this->countPhpFiles($metadataAbs);
        $codeCount = $this->countPhpFiles($codeAbs);
        if ($metadataCount === null || $codeCount === null) {
            return [null, '[UNKNOWN] Unable to inspect generated DI directories', $evidence];
        }

        $evidence['metadata_php_files'] = $metadataCount;
        $evidence['code_php_files'] = $codeCount;
        $evidence['min_metadata_php_files'] = $minMetadataFiles;
        $evidence['min_code_php_files'] = $minCodeFiles;

        $failures = [];
        if ($metadataCount < $minMetadataFiles) {
            $failures[] = "{$metadataRel} has {$metadataCount} PHP files";
        }
        if ($codeCount < $minCodeFiles) {
            $failures[] = "{$codeRel} has {$codeCount} PHP files";
        }
        if ($failures !== []) {
            return [false, 'Compiled DI output is incomplete: ' . implode('; ', $failures), $evidence];
        }

        return [true, 'Generated DI metadata and code contain compiled PHP output', $evidence];
    }

    public function staticContentDeployed(array $args): array
    {
        $staticRel = (string)($args['static_path'] ?? 'pub/static');
        $preprocessedRel = (string)($args['preprocessed_path'] ?? 'var/view_preprocessed');
        $minStaticFiles = max(1, (int)($args['min_static_files'] ?? 1));
        $minPreprocessedFiles = max(1, (int)($args['min_preprocessed_files'] ?? 1));

        $staticAbs = $this->ctx->abs($staticRel);
        $preprocessedAbs = $this->ctx->abs($preprocessedRel);
        $evidence = [
            'static_path' => $staticRel,
            'preprocessed_path' => $preprocessedRel,
            'static_present' => is_dir($staticAbs),
            'preprocessed_present' => is_dir($preprocessedAbs),
            'static_files' => 0,
            'preprocessed_files' => 0,
        ];

        $missing = [];
        if (!is_dir($staticAbs)) {
            $missing[] = $staticRel;
        }
        if (!is_dir($preprocessedAbs)) {
            $missing[] = $preprocessedRel;
        }
        if ($missing !== []) {
            return [false, 'Static content directories missing: ' . implode(', ', $missing), $evidence];
        }

        $staticCount = $this->countFiles($staticAbs, ['.htaccess']);
        $preprocessedCount = $this->countFiles($preprocessedAbs, []);
        if ($staticCount === null || $preprocessedCount === null) {
            return [null, '[UNKNOWN] Unable to inspect static content directories', $evidence];
        }

        $evidence['static_files'] = $staticCount;
        $evidence['preprocessed_files'] = $preprocessedCount;
        $evidence['min_static_files'] = $minStaticFiles;
        $evidence['min_preprocessed_files'] = $minPreprocessedFiles;

        $failures = [];
        if ($staticCount < $minStaticFiles) {
            $failures[] = "{$staticRel} has {$staticCount} deployed files";
        }
        if ($preprocessedCount < $minPreprocessedFiles) {
            $failures[] = "{$preprocessedRel} has {$preprocessedCount} preprocessed files";
        }
        if ($failures !== []) {
            return [false, 'Static content output is incomplete: ' . implode('; ', $failures), $evidence];
        }

        return [true, 'Static content directories contain deployed output', $evidence];
    }

    public function indexersReady(array $args): array
    {
        $rel = (string)($args['file'] ?? 'var/.indexer_status');
        $abs = $this->ctx->abs($rel);
        if (!is_file($abs)) {
            return [null, '[UNKNOWN] Indexer status file not found', ['file' => $rel]];
        }

        $content = @file_get_contents($abs);
        if ($content === false) {
            return [null, '[UNKNOWN] Unable to read indexer status file', ['file' => $rel]];
        }

        $statuses = [];
        foreach (preg_split("~\r?\n~", trim($content)) as $line) {
            $line = trim((string)$line);
            if ($line === '') {
                continue;
            }

            if (str_contains($line, ':')) {
                [$name, $status] = array_map('trim', explode(':', $line, 2));
            } else {
                $parts = preg_split('~\s+~', $line);
                $status = (string)array_pop($parts);
                $name = trim(implode(' ', $parts));
            }

            $normalizedStatus = strtoupper(str_replace([' ', '-'], '_', $status));
            $statuses[] = [
                'indexer' => $name !== '' ? $name : null,
                'status' => $status,
                'normalized_status' => $normalizedStatus,
                'ready' => $normalizedStatus === 'READY',
                'line' => $line,
            ];
        }

        if ($statuses === []) {
            return [null, '[UNKNOWN] Indexer status file is empty', ['file' => $rel]];
        }

        $failures = array_values(array_filter($statuses, static fn(array $entry): bool => empty($entry['ready'])));
        $evidence = ['file' => $rel, 'statuses' => $statuses];
        if ($failures !== []) {
            return [false, 'Some indexers are not READY', $evidence + ['failures' => $failures]];
        }

        return [true, 'All observed indexers are READY', $evidence];
    }

    public function mtimeMaxAge(array $args): array
    {
        $rel = (string)($args['file'] ?? '');
        $max = (int)($args['seconds'] ?? 0);
        if ($rel === '' || $max <= 0) return [false, 'fs_mtime_max_age requires file & seconds'];

        $abs = $this->ctx->abs($rel);
        if (!is_file($abs)) return [false, "$rel not found"];

        $mtime = @filemtime($abs);
        if ($mtime === false) return [false, "Cannot stat $rel"];
        $age = time() - $mtime;

        $ok = ($age <= $max);
        return [$ok, "mtime age {$age}s (max {$max}s) for $rel"];
    }

    private function countPhpFiles(string $root): ?int
    {
        try {
            $count = 0;
            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS),
                \RecursiveIteratorIterator::LEAVES_ONLY,
                \RecursiveIteratorIterator::CATCH_GET_CHILD
            );
            foreach ($iterator as $file) {
                if (!$file->isFile()) {
                    continue;
                }
                if (strtolower(pathinfo($file->getFilename(), PATHINFO_EXTENSION)) === 'php') {
                    $count++;
                }
            }
            return $count;
        } catch (\UnexpectedValueException) {
            return null;
        }
    }

    private function countFiles(string $root, array $ignoredBasenames): ?int
    {
        try {
            $ignored = array_flip($ignoredBasenames);
            $count = 0;
            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS),
                \RecursiveIteratorIterator::LEAVES_ONLY,
                \RecursiveIteratorIterator::CATCH_GET_CHILD
            );
            foreach ($iterator as $file) {
                if (!$file->isFile()) {
                    continue;
                }
                if (isset($ignored[$file->getFilename()])) {
                    continue;
                }
                $count++;
            }
            return $count;
        } catch (\UnexpectedValueException) {
            return null;
        }
    }

    private function collectWorldWritableOffender(string $path, array &$offenders, int $max, bool &$truncated): void
    {
        if ($truncated || is_link($path)) {
            return;
        }

        $perm = @fileperms($path);
        if ($perm === false) {
            return;
        }

        $perm = $perm & 0777;
        if (($perm & 0002) !== 0002) {
            return;
        }

        if (count($offenders) >= $max) {
            $truncated = true;
            return;
        }

        $offenders[] = [
            'path' => $path,
            'mode' => sprintf('%o', $perm),
            'type' => is_dir($path) ? 'dir' : 'file',
        ];
    }

    private function formatIdentity(int $id, bool $user): string
    {
        $lookup = $user ? 'posix_getpwuid' : 'posix_getgrgid';
        if (function_exists($lookup)) {
            $info = $lookup($id);
            if (is_array($info) && isset($info['name']) && is_string($info['name']) && $info['name'] !== '') {
                return $info['name'] . " ({$id})";
            }
        }

        return (string)$id;
    }

    private function collectForbiddenWebrootArtifact(string $path, array $patterns, array &$matches, int $max, bool &$truncated): void
    {
        if ($truncated) {
            return;
        }

        $name = basename($path);
        $matchedPattern = null;
        foreach ($patterns as $pattern) {
            if ($this->matchesForbiddenArtifact($name, (string)$pattern)) {
                $matchedPattern = (string)$pattern;
                break;
            }
        }
        if ($matchedPattern === null) {
            return;
        }

        if (count($matches) >= $max) {
            $truncated = true;
            return;
        }

        $matches[] = [
            'path' => $path,
            'pattern' => $matchedPattern,
            'type' => is_link($path) ? 'link' : (is_dir($path) ? 'dir' : 'file'),
        ];
    }

    private function matchesForbiddenArtifact(string $name, string $pattern): bool
    {
        return fnmatch($pattern, $name, \FNM_PERIOD);
    }

    private function collectWritableCodePath(string $path, array &$offenders, int $max, bool &$truncated): void
    {
        if ($truncated) {
            return;
        }

        $statPath = $path;
        $target = null;
        if (is_link($path)) {
            $target = realpath($path);
            if ($target === false) {
                return;
            }
            $statPath = $target;
        }

        $perm = @fileperms($statPath);
        if ($perm === false) {
            return;
        }

        $perm = $perm & 0777;
        if (($perm & 0222) === 0) {
            return;
        }

        if (count($offenders) >= $max) {
            $truncated = true;
            return;
        }

        $entry = [
            'path' => $path,
            'mode' => sprintf('%o', $perm),
            'type' => is_link($path) ? 'link' : (is_dir($statPath) ? 'dir' : 'file'),
        ];
        if ($target !== null) {
            $entry['target'] = $target;
        }

        $offenders[] = $entry;
    }
}
