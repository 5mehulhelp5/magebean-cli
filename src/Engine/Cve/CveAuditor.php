<?php

declare(strict_types=1);

namespace Magebean\Engine\Cve;

use Magebean\Engine\Context;

final class CveAuditor
{
    private Context $ctx;

    public function __construct(Context $ctx)
    {
        $this->ctx = $ctx;
    }

    /** @return array cve_audit */
    public function run(string $cveDataPath): array
    {
        // 1) composer.lock
        $lockFile = $this->ctx->abs('composer.lock');
        $lockJson = is_file($lockFile) ? json_decode((string)file_get_contents($lockFile), true) : null;
        if (!is_array($lockJson)) {
            return ['summary' => [
                'packages_total' => 0,
                'packages_affected' => 0,
                'advisories_total' => 0,
                'highest_severity' => 'Unknown',
                'dataset_total' => 0
            ], 'packages' => []];
        }
        $pkgs = array_merge($lockJson['packages'] ?? [], $lockJson['packages-dev'] ?? []);
        $installed = [];
        foreach ($pkgs as $p) {
            if (!isset($p['name'], $p['version'])) continue;
            $installed[$p['name']] = ltrim((string)$p['version'], 'v');
        }
        $installedNames = array_fill_keys(array_keys($installed), true);

        // 2) CVE data (from VULNS only)
        $vulns = $this->readCveFile($cveDataPath);
        $datasetTotal = is_array($vulns) ? count($vulns) : 0;

        // 3) map package
        $pkgMap = [];
        foreach ($installed as $name => $ver) {
            $pkgMap[$name] = [
                'name' => $name,
                'installed' => $ver,
                'status' => 'PASS',
                'advisories_count' => 0,
                'highest_severity' => 'None',
                'upgrade_hint' => null,
                'advisories' => [],
            ];
        }

        // 4) match
        $advisoriesTotal = 0;
        foreach ($vulns as $vuln) {
            if (!is_array($vuln)) continue;
            $affList = $vuln['affected'] ?? null;
            if (!is_array($affList)) continue;

            [$sevLabel, $cvssScore] = $this->extractSeverity($vuln);
            $idPrimary = $this->primaryId($vuln);
            $aliases   = array_values(array_filter(($vuln['aliases'] ?? []), 'is_string'));
            $summary   = (string)($vuln['summary'] ?? '');
            $refs      = $this->extractReferences($vuln);
            $pub       = (string)($vuln['published'] ?? '');
            $mod       = (string)($vuln['modified']  ?? '');

            foreach ($affList as $aff) {
                $pkg = $aff['package']['name'] ?? null;
                $eco = strtolower((string)($aff['package']['ecosystem'] ?? ''));
                if (!$pkg || !isset($installedNames[$pkg])) continue;
                if ($eco !== 'packagist' && $eco !== 'composer') continue;

                $curVer = $installed[$pkg];
                $hit = false;

                // explicit versions list
                if (!empty($aff['versions']) && is_array($aff['versions'])) {
                    foreach ($aff['versions'] as $v) {
                        $v = ltrim((string)$v, 'v');
                        if ($v !== '' && version_compare($curVer, $v, '==')) {
                            $hit = true;
                            break;
                        }
                    }
                }

                $minFixed = null;
                if (!$hit && !empty($aff['ranges']) && is_array($aff['ranges'])) {
                    foreach ($aff['ranges'] as $rng) {
                        $events = $rng['events'] ?? [];
                        $intervals = $this->eventsToIntervals($events, $minFixedCandidate);
                        foreach ($intervals as [$a, $b]) {
                            if ($this->inRange($curVer, $a, $b)) {
                                $hit = true;
                            }
                            if ($b !== null) {
                                $minFixed = $this->minVersion($minFixed, $b);
                            }
                        }
                        if (isset($minFixedCandidate)) $minFixed = $this->minVersion($minFixed, $minFixedCandidate);
                    }
                }

                if ($hit) {
                    $adv = [
                        'id' => $idPrimary,
                        'aliases' => $aliases,
                        'severity' => $sevLabel,
                        'cvss' => $cvssScore,
                        'affected' => $this->compactAffected($aff),
                        'fixed_versions' => $minFixed ? [$minFixed] : [],
                        'published' => $pub,
                        'modified'  => $mod,
                        'references' => $refs,
                        'summary'   => $summary,
                    ];
                    $pkgMap[$pkg]['advisories'][] = $adv;
                    $pkgMap[$pkg]['status'] = 'FAIL';
                    $pkgMap[$pkg]['advisories_count']++;
                    $pkgMap[$pkg]['highest_severity'] = $this->maxSeverity(
                        $pkgMap[$pkg]['highest_severity'],
                        $sevLabel
                    );
                    if ($minFixed) {
                        $pkgMap[$pkg]['upgrade_hint'] = $this->minVersion(
                            $pkgMap[$pkg]['upgrade_hint'],
                            $minFixed
                        );
                    }
                    $advisoriesTotal++;
                }
            }
        }

        $packagesTotal = count($pkgMap);
        $packagesAffected = count(array_filter($pkgMap, fn($p) => $p['status'] === 'FAIL'));
        $highestOverall = 'None';
        foreach ($pkgMap as $p) $highestOverall = $this->maxSeverity($highestOverall, $p['highest_severity']);

        usort($pkgMap, function ($a, $b) {
            if ($a['status'] !== $b['status']) return $a['status'] === 'FAIL' ? -1 : 1;
            $sa = $this->sevOrder($a['highest_severity']);
            $sb = $this->sevOrder($b['highest_severity']);
            if ($sa !== $sb) return $sa <=> $sb;
            return strcmp($a['name'], $b['name']);
        });

        return [
            'summary' => [
                'packages_total'    => $packagesTotal,
                'packages_affected' => $packagesAffected,
                'advisories_total'  => $advisoriesTotal,
                'highest_severity'  => $highestOverall,
                'dataset_total'     => $datasetTotal, // Known CVEs trong bundle
            ],
            'packages' => array_values($pkgMap),
        ];
    }

    /** --------- helpers --------- */

    /**
     * Đọc dataset CVE từ đường dẫn chỉ bằng VULNS:
     * - Nếu là .zip: gom VULNS/*.json trong zip
     * - Nếu là thư mục bundle hoặc file nằm trong bundle: tìm root rồi gom VULNS/*.json
     * - Nếu là 1 file JSON đơn lẻ: thử coi như 1 vuln object/list (ít dùng)
     */
    private function readCveFile(string $path): array
    {
        if (is_dir($path)) {
            return $this->readCveFromBundleDir($path);
        }
        if (is_file($path) && str_ends_with(strtolower($path), '.zip')) {
            return $this->readCveZip($path);
        }
        if (is_file($path)) {
            $root = $this->discoverBundleRoot($path);
            if ($root !== null) {
                return $this->readCveFromBundleDir($root);
            }
            $raw = @file_get_contents($path);
            if ($raw === false || $raw === '') return [];
            $arr = json_decode($raw, true);
            if (is_array($arr)) {
                if (isset($arr['affected']) || isset($arr['id'])) {
                    $this->normalizeVulnId($arr);
                    return [$arr];
                }
                if ($this->isList($arr)) {
                    $out = [];
                    foreach ($arr as $it) {
                        if (is_array($it)) { $this->normalizeVulnId($it); $out[] = $it; }
                    }
                    return $out;
                }
            }
            return [];
        }
        return [];
    }

    /** Tìm root bundle khi đưa vào 1 file/dir nằm sâu bên trong; root có VULNS/ hoặc DATA/ hoặc MANIFEST/ */
    private function discoverBundleRoot(string $path): ?string
    {
        $p = is_dir($path) ? rtrim($path, DIRECTORY_SEPARATOR) : dirname($path);
        for ($i = 0; $i < 5; $i++) {
            if (is_dir($p . '/VULNS') || is_dir($p . '/DATA') || is_dir($p . '/MANIFEST')) {
                return $p;
            }
            $parent = dirname($p);
            if ($parent === $p) break;
            $p = $parent;
        }
        return null;
    }

    /** Đọc dataset trong một thư mục bundle đã giải nén: gom VULNS/*.json */
    private function readCveFromBundleDir(string $root): array
    {
        $vulnsDir = rtrim($root, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . 'VULNS';
        if (!is_dir($vulnsDir)) return [];
        $out = [];
        $dh = @opendir($vulnsDir);
        if ($dh) {
            while (($fn = readdir($dh)) !== false) {
                if ($fn === '.' || $fn === '..') continue;
                if (!str_ends_with(strtolower($fn), '.json')) continue;
                $full = $vulnsDir . DIRECTORY_SEPARATOR . $fn;
                $raw = @file_get_contents($full);
                if ($raw === false) continue;
                $v = json_decode($raw, true);
                if (!is_array($v)) continue;
                $this->normalizeVulnId($v);
                $out[] = $v;
            }
            closedir($dh);
        }
        return $out;
    }

    /** Đọc bundle .zip: gom VULNS/*.json trong zip */
    private function readCveZip(string $zipPath): array
    {
        $z = new \ZipArchive();
        if ($z->open($zipPath) !== true) return [];
        $out = [];
        for ($i = 0; $i < $z->numFiles; $i++) {
            $name = $z->getNameIndex($i);
            if (!$name) continue;
            $lname = strtolower($name);
            if (str_starts_with($lname, 'vulns/') && str_ends_with($lname, '.json')) {
                $raw = $z->getFromIndex($i);
                if ($raw === false) continue;
                $v = json_decode((string)$raw, true);
                if (!is_array($v)) continue;
                $this->normalizeVulnId($v);
                $out[] = $v;
            }
        }
        $z->close();
        return $out;
    }

    /** array_is_list tương thích (PHP < 8.1) */
    private function isList(array $a): bool
    {
        if (function_exists('array_is_list')) return array_is_list($a);
        $i = 0;
        foreach ($a as $k => $_) {
            if ($k !== $i) return false;
            $i++;
        }
        return true;
    }

    /** Bổ sung id chuẩn nếu thiếu: preferred_id -> vuln_id -> aliases[0] -> 'UNKNOWN' */
    private function normalizeVulnId(array &$v): void
    {
        if (!isset($v['id']) || $v['id'] === '' || $v['id'] === null) {
            if (isset($v['preferred_id']) && is_string($v['preferred_id']) && $v['preferred_id'] !== '') {
                $v['id'] = $v['preferred_id']; return;
            }
            if (isset($v['vuln_id']) && is_string($v['vuln_id']) && $v['vuln_id'] !== '') {
                $v['id'] = $v['vuln_id']; return;
            }
            if (isset($v['aliases']) && is_array($v['aliases']) && isset($v['aliases'][0]) && is_string($v['aliases'][0])) {
                $v['id'] = $v['aliases'][0]; return;
            }
            $v['id'] = 'UNKNOWN';
        }
    }

    private function eventsToIntervals(array $events, ?string &$minFixedCandidate = null): array
    {
        $res = [];
        $curStart = null;
        $minFixedCandidate = null;
        foreach ($events as $ev) {
            if (isset($ev['introduced'])) {
                $curStart = ltrim((string)$ev['introduced'], 'v');
            } elseif (isset($ev['fixed'])) {
                $fx = ltrim((string)$ev['fixed'], 'v');
                $minFixedCandidate = $this->minVersion($minFixedCandidate, $fx);
                if ($curStart !== null) {
                    $res[] = [$curStart, $fx];
                    $curStart = null;
                } else {
                    $res[] = [null, $fx];
                }
            }
        }
        if ($curStart !== null) $res[] = [$curStart, null];
        return $res;
    }

    private function inRange(string $cur, ?string $a, ?string $b): bool
    {
        $cur = ltrim($cur, 'v');
        if ($a !== null && version_compare($cur, $a, '<')) return false;
        if ($b !== null && version_compare($cur, $b, '>=')) return false;
        return true;
    }

    private function minVersion(?string $cur, string $cand): string
    {
        if ($cur === null) return ltrim($cand, 'v');
        return version_compare(ltrim($cand, 'v'), $cur, '<') ? ltrim($cand, 'v') : $cur;
    }

    private function primaryId(array $vuln): string
    {
        $id = (string)($vuln['id'] ?? '');
        foreach (($vuln['aliases'] ?? []) as $al) {
            if (is_string($al) && str_starts_with($al, 'CVE-')) return $al;
        }
        return $id !== '' ? $id : 'ADVISORY';
    }

    private function extractReferences(array $vuln): array
    {
        $refs = $vuln['references'] ?? [];
        if (!is_array($refs)) return [];
        $out = [];
        foreach ($refs as $r) {
            $u = (string)($r['url'] ?? '');
            if ($u !== '') {
                $out[] = ['type' => (string)($r['type'] ?? ''), 'url' => $u];
            }
        }
        return $out;
    }

    /** returns [label, score] */
    private function extractSeverity(array $vuln): array
    {
        $sevArr = $vuln['severity'] ?? null;
        if (is_array($sevArr) && isset($sevArr[0]['score'])) {
            $score = (string)$sevArr[0]['score'];
            $num = floatval($score);
            $label = $this->labelByCvss($num);
            return [$label, $score];
        }
        $ds = $vuln['database_specific']['severity'] ?? '';
        if (is_string($ds) && $ds !== '') {
            $label = ucfirst(strtolower($ds));
            return [$label, ''];
        }
        return ['Unknown', ''];
    }

    private function labelByCvss(float $v): string
    {
        if ($v >= 9.0) return 'Critical';
        if ($v >= 7.0) return 'High';
        if ($v >= 4.0) return 'Medium';
        if ($v > 0.0)  return 'Low';
        return 'Unknown';
    }

    private function maxSeverity(string $a, string $b): string
    {
        return $this->sevOrder($a) <= $this->sevOrder($b) ? $a : $b;
    }

    private function sevOrder(string $s): int
    {
        return match (strtolower($s)) {
            'critical' => 0,
            'high'     => 1,
            'medium'   => 2,
            'low'      => 3,
            'none'     => 4,
            default    => 5,
        };
    }

    private function compactAffected(array $aff): array
    {
        $out = ['ranges' => [], 'versions' => []];
        if (!empty($aff['ranges']) && is_array($aff['ranges'])) {
            foreach ($aff['ranges'] as $rng) {
                $evs = $rng['events'] ?? [];
                $intervals = $this->eventsToIntervals($evs, $minFx);
                foreach ($intervals as [$a, $b]) {
                    $out['ranges'][] = array_filter(['introduced' => $a, 'fixed' => $b], fn($x) => $x !== null);
                }
            }
        }
        if (!empty($aff['versions']) && is_array($aff['versions'])) {
            foreach ($aff['versions'] as $v) $out['versions'][] = ltrim((string)$v, 'v');
        }
        return $out;
    }
}
