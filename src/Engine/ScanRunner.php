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
        $ok  = (bool)($res[0] ?? false);
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

        $fs  = new FilesystemCheck($this->ctx);
        $phpc = new PhpConfigCheck($this->ctx);
        $comp = new ComposerCheck($this->ctx);
        $mage = new MagentoCheck($this->ctx);
        $http = new HttpCheck($this->ctx);
        $code = new CodeSearchCheck($this->ctx);
        $web  = new WebServerConfigCheck($this->ctx);
        $git  = new GitHistoryCheck($this->ctx);

        foreach ($this->pack['rules'] as $rule) {
            $op = $rule['op'] ?? 'all';
            // Với 'any' khởi tạo FAIL cho tới khi có check PASS
            $ok = ($op === 'any') ? false : true;

            $details  = [];
            $evidence = [];

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

                $details[] = [$name, $msg, (bool)$cok];
                if (!empty($ev)) {
                    $evidence = array_merge($evidence, is_array($ev) ? $ev : [$ev]);
                }
                if ($op === 'all' && !$cok) {
                    $ok = false;
                }
                if ($op === 'any' && $cok) {
                    $ok = true;
                    break;
                }
            }

            $msgPass = $rule['messages']['pass'] ?? null;
            $msgFail = $rule['messages']['fail'] ?? null;
            if ($ok) {
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

            $findings[] = [
                'id'       => $rule['id'],
                'title'    => $rule['title'],
                'control'  => $rule['control'],
                'severity' => $rule['severity'],
                'passed'   => $ok,
                'message'  => $finalMsg,
                'details'  => $details,
                'evidence' => $evidence
            ];

            if ($ok) $passed++;
            else $failed++;
        }

        return [
            'summary'  => ['passed' => $passed, 'failed' => $failed, 'total' => $passed + $failed],
            'findings' => $findings
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

            default => [false, 'Unknown check: ' . $name],
        };
    }
}
