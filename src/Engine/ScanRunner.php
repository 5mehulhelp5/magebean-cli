<?php

declare(strict_types=1);

namespace Magebean\Engine;

use Magebean\Engine\Checks\{FilesystemCheck, PhpConfigCheck, ComposerCheck, MagentoCheck, HttpCheck, CodeSearchCheck, WebServerConfigCheck, GitHistoryCheck};

final class ScanRunner
{
    private Context $ctx;
    private array $pack;
    public function __construct(Context $ctx, array $pack)
    {
        $this->ctx = $ctx;
        $this->pack = $pack;
    }

    private function evalCheckWithEvidence(
        string $name,
        array $args,
        FilesystemCheck $fs,
        PhpConfigCheck $phpc,
        ComposerCheck $comp,
        MagentoCheck $mage,
        HttpCheck $http,
        CodeSearchCheck $code,
        WebServerConfigCheck $web,
        GitHistoryCheck $git
    ): array {
        $res = $this->evalCheck($name, $args, $fs, $phpc, $comp, $mage, $http, $code, $web, $git);
        if (!is_array($res)) {
            $res = [false, 'Unknown check: ' . $name];
        }
        $ok  = $res[0] ?? null;
        $msg = (string)($res[1] ?? '');
        $ev  = $res[2] ?? [];
        if (!is_array($ev)) {
            $ev = $ev !== null ? [$ev] : [];
        }
        return [$ok, $msg, $ev];
    }


    public function run(): array
    {
        $findings = [];
        $passed = 0;
        $failed = 0;
        $plannedRules = is_array($this->pack['rules'] ?? null) ? count($this->pack['rules']) : 0;
        $executedRules = 0;

        $fs  = new FilesystemCheck($this->ctx);
        $phpc = new PhpConfigCheck($this->ctx);
        $comp = new ComposerCheck($this->ctx);
        $mage = new MagentoCheck($this->ctx);
        $http = new HttpCheck($this->ctx);
        $code = new CodeSearchCheck($this->ctx);
        $web  = new WebServerConfigCheck($this->ctx);
        $git  = new GitHistoryCheck($this->ctx);

        foreach ($this->pack['rules'] as $rule) {
            $executedRules++;
            $op = $rule['op'] ?? 'all';
            // Với 'any' khởi tạo FAIL cho tới khi có check PASS
            $ok = ($op === 'any') ? false : true;

            $details  = [];
            $evidence = [];
            $hasTrue = false;
            $hasFalse = false;
            $hasUnknown = false;

            foreach ($rule['checks'] as $chk) {
                $name = $chk['name'];
                $args = $chk['args'] ?? [];

                [$cok, $msg, $ev] = $this->evalCheckWithEvidence(
                    $name,
                    $args,
                    $fs,
                    $phpc,
                    $comp,
                    $mage,
                    $http,
                    $code,
                    $web,
                    $git
                );

                $details[] = [$name, $msg, $cok];
                if (!empty($ev)) {
                    $evidence = array_merge($evidence, is_array($ev) ? $ev : [$ev]);
                }
                if ($op === 'all' && $cok === false) {
                    $ok = false;
                }
                if ($op === 'any' && $cok === true) {
                    $ok = true;
                    break;
                }
                if ($cok === true) $hasTrue = true;
                elseif ($cok === false) $hasFalse = true;
                else $hasUnknown = true;
            }

            $status = null;
            if ($hasFalse) {
                $ok = false;
                $status = 'FAIL';
            } elseif ($hasTrue) {
                $ok = true;
                $status = 'PASS';
            } elseif ($hasUnknown) {
                $ok = false; // giữ boolean để tương thích cũ, nhưng status sẽ là UNKNOWN
                $status = 'UNKNOWN';
            } else {
                // không có check nào -> PASS
                $ok = true;
                $status = 'PASS';
            }
            $msgPass = $rule['messages']['pass'] ?? null;
            $msgFail = $rule['messages']['fail'] ?? null;
            if ($status === 'UNKNOWN') {
                $unkMsgs = array_values(array_map(
                    fn($d) => $d[1],
                    array_filter($details, fn($d) => ($d[2] === null) || (is_string($d[1]) && str_starts_with((string)$d[1], '[UNKNOWN]')))
                ));
                $finalMsg = $unkMsgs[0] ?? 'CVE file not found (requires --cve-data package)';
            } elseif ($ok) {
                if ($msgPass) {
                    $finalMsg = $msgPass;
                } else {
                    $okMsgs = array_values(array_map(
                        fn($d) => $d[1],
                        array_filter($details, fn($d) => $d[2] === true)
                    ));
                    $finalMsg = $okMsgs[0] ?? 'Rule passed';
                }
            } else {
                if ($msgFail) {
                    $finalMsg = $msgFail;
                } else {
                    $bad = array_values(array_map(
                        fn($d) => $d[1],
                        array_filter($details, fn($d) => $d[2] === false)
                    ));
                    $finalMsg = $bad ? implode(' | ', array_slice($bad, 0, 2)) : 'Rule failed';
                }
            }

            if ($status === 'UNKNOWN' && (!isset($finalMsg) || trim((string)$finalMsg) === '')) {
                $finalMsg = 'CVE file not found (requires --cve-data package)';
            }
            // Ước lượng confidence cho finding (dựa trên loại check & evidence gom được)
            [$conf, $confWhy] = $this->estimateConfidenceForRule((array)($rule['checks'] ?? []), $evidence, (string)$status);
            $findings[] = [
                'id'       => $rule['id'],
                'title'    => $rule['title'],
                'control'  => $rule['control'],
                'severity' => $rule['severity'],
                'passed'   => $ok,
                'status'   => $status,
                'message'  => $finalMsg,
                'details'  => $details,
                'details'  => $details,
                'evidence' => $evidence,
                'confidence' => $conf,
                'confidence_reason' => $confWhy
            ];

            // Đếm theo status để UNKNOWN không bị tính là failed
            if ($status === 'PASS') {
                $passed++;
            } elseif ($status === 'FAIL') {
                $failed++;
            } // UNKNOWN: không cộng vào passed/failed
        }

        $unknown = 0;
        foreach ($findings as $f) {
            if (($f['status'] ?? '') === 'UNKNOWN') $unknown++;
        }
        // Lấy transport counters từ HttpCheck nếu có (để tính transport_success_percent ở ScanCommand)
        $transportOk = 0;
        $transportTotal = 0;
        if (method_exists($http, 'getTransportCounts')) {
            $tc = $http->getTransportCounts();
            $transportOk    = (int)($tc['ok'] ?? 0);
            $transportTotal = (int)($tc['total'] ?? 0);
        }

        return [
            'summary'  => ['passed' => $passed, 'failed' => $failed, 'unknown' => $unknown, 'total' => count($findings)],
            'findings' => $findings,
            'meta'     => [
                'planned_rules'  => $plannedRules,
                'executed_rules' => $executedRules,
                'transport_ok'   => $transportOk,
                'transport_total' => $transportTotal
            ]
        ];
    }


    private function evalCheck(
        string $name,
        array $args,
        FilesystemCheck $fs,
        PhpConfigCheck $phpc,
        ComposerCheck $comp,
        MagentoCheck $mage,
        HttpCheck $http,
        CodeSearchCheck $code,
        WebServerConfigCheck $web,
        GitHistoryCheck $git
    ): array {
        $path = $this->ctx->path;
        return match ($name) {
            // Filesystem
            'fs_no_world_writable' => $fs->noWorldWritable($args),
            'file_mode_max'        => $fs->fileModeMax($args),
            'webroot_hygiene'      => $fs->webrootHygiene($args),
            'code_dirs_readonly'   => $fs->codeDirsReadonly($args),
            'no_directory_listing' => $fs->noDirectoryListing($args),
            'fs_exists'            => $fs->fsExists($args),
            'fs_mtime_max_age' => $fs->mtimeMaxAge($args),

            // PhpConfig
            'php_array_exists',
            'php_array_eq',
            'php_array_neq',
            'php_array_numeric_compare',
            'php_array_absent' => $phpc->dispatch($name, $args),

            'composer_audit' => $comp->stub($args),
            'magento_config' => $mage->stub($args),
            'http_header'    => $http->stub($args),

            'code_grep' => $code->grep($args),

            'nginx_directive'            => $web->nginxDirective($args),
            'apache_htaccess_directive'  => $web->apacheDirective($args),

            'composer_audit_offline'         => $comp->auditOffline($args),
            'composer_core_advisories_offline' => $comp->coreAdvisoriesOffline($args),
            'composer_fix_version'           => $comp->fixVersion($args),
            'composer_risk_surface_tag'      => $comp->riskSurfaceTag($args),
            'composer_match_list'            => $comp->matchList($args),
            'composer_constraints_conflict'  => $comp->constraintsConflict($args),
            'composer_yanked_offline'        => $comp->yankedOffline($args),
            'composer_outdated_offline'      => $comp->outdatedOffline($args),
            'composer_advisory_latency'      => $comp->advisoryLatency($args),
            'composer_vendor_support_offline' => $comp->vendorSupportOffline($args),
            'composer_abandoned_offline'        => $comp->abandonedOffline($args),
            'composer_release_recency_offline'  => $comp->releaseRecencyOffline($args),
            'composer_repo_archived_offline'    => $comp->repoArchivedOffline($args),
            'composer_risky_fork_offline'       => $comp->riskyForkOffline($args),
            'composer_json_constraints' => $comp->jsonConstraints($path),
            'composer_json_kv'          => $comp->jsonKv($args),
            'composer_lock_integrity'   => $comp->lockIntegrity($args),

            'php_array_key_search' => $phpc->keySearch($args),
            'git_history_scan'     => $git->secretScan($args),

            // HTTP (external-url) checks
            'http_force_https_redirect'   => $http->dispatch($name, $args),
            'http_has_hsts'               => $http->dispatch($name, $args),
            'http_no_mixed_content'       => $http->dispatch($name, $args),
            'http_cookie_flags'           => $http->dispatch($name, $args),
            'http_no_directory_listing'   => $http->dispatch($name, $args),
            'http_no_public_artifacts'    => $http->dispatch($name, $args),
            'http_no_stacktrace'          => $http->dispatch($name, $args),
            'http_no_xdebug_headers'      => $http->dispatch($name, $args),
            'http_admin_path_heuristics'  => $http->dispatch($name, $args),
            'http_magento_fingerprint'    => $http->dispatch($name, $args),

            default => [false, 'Unknown check: ' . $name],
        };
    }

    private function estimateConfidenceForRule(array $checks, array $evidence, string $status): array
    {
        $first = is_array($checks[0] ?? null) ? $checks[0] : [];
        $name  = strtolower((string)($first['name'] ?? ''));
        $base  = match ($name) {
            // header/value exact
            'http_has_hsts', 'http_cookie_flags',
            'http_header_equals', 'http_header_in' => 95,
            // redirects / status gating
            'http_force_https_redirect', 'http_block_path' => 90,
            // tls/cert
            'http_tls_min_version', 'http_tls_cert_days_left' => 85,
            // html/dom content
            'http_no_mixed_content', 'http_no_stacktrace' => 80,
            // absence / probing
            'http_no_directory_listing', 'http_no_public_artifacts' => 70,
            // heuristic
            'http_admin_path_heuristics', 'http_server_banner_not_verbose' => 60,
            default => 75,
        };

        // Nếu UNKNOWN → giảm 20
        if (strtoupper($status) === 'UNKNOWN') {
            $base = max(0, $base - 20);
        }

        // Tìm headers trong evidence để dò CDN/WAF → giảm 10
        $hdrs = [];
        if (isset($evidence['headers']) && is_array($evidence['headers'])) {
            $hdrs = array_change_key_case($evidence['headers'], CASE_LOWER);
        } else {
            foreach ($evidence as $ev) {
                if (is_array($ev) && isset($ev['headers']) && is_array($ev['headers'])) {
                    $hdrs = array_change_key_case($ev['headers'], CASE_LOWER);
                    break;
                }
            }
        }
        $server = (string)($hdrs['server'] ?? '');
        foreach (['cloudflare', 'akamai', 'fastly', 'sucuri', 'incapsula', 'varnish'] as $kw) {
            if ($server !== '' && stripos($server, $kw) !== false) {
                $base = max(0, $base - 10);
                break;
            }
        }

        $base = max(0, min(100, (int)$base));
        return [$base, 'Estimated by check type ' . ($name ?: 'n/a') . ($server ? " (server: {$server})" : '')];
    }
}
