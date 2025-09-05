<?php declare(strict_types=1);

namespace Magebean\Bundle;

final class BundleManager
{
    /**
     * Extract an OSV/Packagist JSON/NDJSON from a CVE ZIP bundle.
     * - Extract toàn bộ ZIP vào thư mục tạm (giữ cấu trúc)
     * - Hỗ trợ .tar/.tar.gz/.tgz (PharData), .gz, .bz2
     * - Chọn file JSON/NDJSON lớn nhất sau khi giải nén
     * @return string|null absolute path đến file JSON/NDJSON (plain)
     */
    public function extractOsvFileFromZip(string $zipPath): ?string
    {
        $zipPath = realpath($zipPath) ?: $zipPath;
        if (!is_file($zipPath) || !class_exists(\ZipArchive::class)) return null;

        $tmpRoot = sys_get_temp_dir().'/magebean-cve-'.bin2hex(random_bytes(4));
        @mkdir($tmpRoot, 0777, true);

        $zip = new \ZipArchive();
        if ($zip->open($zipPath) !== true) return null;
        // extract all entries (kể cả nested dirs)
        $zip->extractTo($tmpRoot);
        $zip->close();

        // duyệt toàn bộ cây sau khi extract; materialize file plain json-like
        $candidates = [];
        $it = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($tmpRoot, \FilesystemIterator::SKIP_DOTS)
        );
        foreach ($it as $p) {
            if (!$p->isFile()) continue;
            $plain = $this->materializePlainJsonLike($p->getPathname());
            if ($plain !== null && is_file($plain) && $this->looksLikeJsonOrNdjson($plain)) {
                $candidates[$plain] = filesize($plain) ?: 0;
            }
        }
        if (!$candidates) return null;

        arsort($candidates, SORT_NUMERIC); // largest first
        return array_key_first($candidates);
    }

    /** Convert path thành file .json/.ndjson/.jsonl plain nếu có (untar/ungzip/bunzip nếu cần) */
    private function materializePlainJsonLike(string $path): ?string
    {
        $lower = strtolower($path);

        // 1) TAR containers (.tar, .tar.gz, .tgz)
        if (preg_match('/\.(tar\.gz|tgz|tar)$/i', $lower)) {
            if (!class_exists(\PharData::class)) return null;
            $outDir = $path . '.extracted';
            @mkdir($outDir, 0777, true);
            try {
                if (preg_match('/\.(tar\.gz|tgz)$/i', $lower)) {
                    $tarPath = preg_replace('/\.(tar\.gz|tgz)$/i', '.tar', $path) ?: ($path.'.tar');
                    if (!$this->gunzipTo($path, $tarPath)) return null;
                    $ph = new \PharData($tarPath);
                } else {
                    $ph = new \PharData($path);
                }
                $ph->extractTo($outDir, null, true);
            } catch (\Throwable $e) {
                return null;
            }

            $best = null; $bestSize = -1;
            $it = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($outDir, \FilesystemIterator::SKIP_DOTS)
            );
            foreach ($it as $p) {
                if (!$p->isFile()) continue;
                $plain = $this->materializePlainJsonLike($p->getPathname());
                if ($plain && is_file($plain) && $this->looksLikeJsonOrNdjson($plain)) {
                    $sz = filesize($plain) ?: 0;
                    if ($sz > $bestSize) { $best = $plain; $bestSize = $sz; }
                }
            }
            return $best;
        }

        // 2) Compressed single file (.gz/.bz2) đè trên .json/.ndjson/.jsonl
        if (preg_match('/\.(json|ndjson|jsonl)\.(gz|bz2)$/i', $lower, $m)) {
            $plain = preg_replace('/\.(gz|bz2)$/i', '', $path) ?: $path.'.out';
            $ok = strtolower($m[2]) === 'gz'
                ? $this->gunzipTo($path, $plain)
                : $this->bunzip2To($path, $plain);
            return $ok ? $plain : null;
        }

        // 3) Already plain json-like
        if (preg_match('/\.(json|ndjson|jsonl)$/i', $lower)) {
            return $path;
        }

        // 4) Unsupported (e.g. .zst, .xz)
        return null;
    }

    private function gunzipTo(string $src, string $dst): bool
    {
        $data = @file_get_contents($src);
        if ($data !== false) {
            $decoded = @gzdecode($data);
            if ($decoded !== false && file_put_contents($dst, $decoded)!==false) return true;
        }
        $gz = @gzopen($src, 'rb');
        if (!$gz) return false;
        $out = @fopen($dst, 'wb'); if (!$out) { gzclose($gz); return false; }
        while (!gzeof($gz)) {
            $chunk = gzread($gz, 1<<20);
            if ($chunk === false) break;
            fwrite($out, $chunk);
        }
        fclose($out); gzclose($gz);
        return is_file($dst);
    }

    private function bunzip2To(string $src, string $dst): bool
    {
        if (!function_exists('bzdecompress')) return false;
        $data = @file_get_contents($src);
        if ($data === false) return false;
        $decoded = @bzdecompress($data);
        if (!is_string($decoded)) return false;
        return file_put_contents($dst, $decoded)!==false;
    }

    private function looksLikeJsonOrNdjson(string $path): bool
    {
        $fh = @fopen($path, 'rb'); if (!$fh) return false;
        $buf = fread($fh, 4096); fclose($fh);
        if ($buf === false || $buf === '') return false;

        if (preg_match('/^\s*[\{\[]/s', $buf)) return true; // JSON object/array

        // NDJSON / JSONL heuristic
        $lines = preg_split('/\r?\n/', $buf);
        $seen = 0; $jsonish = 0;
        foreach ($lines as $ln) {
            $ln = ltrim($ln);
            if ($ln === '') continue;
            $seen++;
            if ($ln[0] === '{' || $ln[0] === '[') $jsonish++;
            if ($seen >= 8) break;
        }
        return $jsonish >= 3;
    }
}
