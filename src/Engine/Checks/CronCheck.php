<?php

declare(strict_types=1);

namespace Magebean\Engine\Checks;

final class CronCheck
{
    /**
     * args:
     *  - users: string[]  (ví dụ ["www-data","nginx","apache","www","magento","deploy"])
     *  - patterns: string[] (regex PCRE, KHÔNG có delimiter /…/)
     *  - timeout_ms?: int (mặc định 2000)
     */
    public function crontabGrep(array $args): array
    {
        $users    = array_values(array_filter(array_map('trim', (array)($args['users'] ?? []))));
        $patterns = array_values(array_filter((array)($args['patterns'] ?? [])));
        $timeout  = (int)($args['timeout_ms'] ?? 2000);

        if (!$patterns) {
            return [null, 'No patterns provided'];
        }
        if (!$users) {
            // fallback phổ biến
            $users = ['www-data','nginx','apache','http','www','magento','deploy'];
        }

        $found = [];
        foreach ($users as $u) {
            $txt = $this->readUserCrontab($u, $timeout);
            if ($txt === null) continue; // user không có crontab / không đọc được
            $lines = preg_split("~\r?\n~", $txt);
            foreach ($lines as $ln) {
                $line = trim((string)$ln);
                if ($line === '' || str_starts_with($line, '#')) continue;
                foreach ($patterns as $rx) {
                    // bọc delimiter, thêm 'i' cho dễ khớp
                    $ok = @preg_match('/' . $rx . '/i', $line);
                    if ($ok === 1) {
                        $found[] = $u . ': ' . $line;
                        break;
                    }
                }
            }
        }

        if ($found) {
            return [true, 'Found cron: ' . implode(' | ', array_slice($found, 0, 5))];
        }

        // thử thêm các nguồn hệ thống (optional)
        foreach (['/etc/crontab', '/etc/cron.d'] as $path) {
            $txt = $this->readCronFileOrDir($path);
            if ($txt === null) continue;
            foreach (preg_split("~\r?\n~", $txt) as $ln) {
                $line = trim((string)$ln);
                if ($line === '' || str_starts_with($line, '#')) continue;
                foreach ($patterns as $rx) {
                    if (@preg_match('/' . $rx . '/i', $line) === 1) {
                        return [true, 'Found cron in ' . $path . ': ' . $line];
                    }
                }
            }
        }

        return [false, 'No matching crontab entries'];
    }

    private function readUserCrontab(string $user, int $timeoutMs): ?string
    {
        // ưu tiên lệnh crontab -u (nếu được phép)
        if (function_exists('proc_open')) {
            $cmd = ['bash','-lc', 'crontab -u ' . escapeshellarg($user) . ' -l 2>/dev/null || true'];
            $desc = [1 => ['pipe','w'], 2 => ['pipe','w'], 0 => ['pipe','r']];
            $p = @proc_open($cmd, $desc, $pipes, null, null, ['bypass_shell'=>true]);
            if (is_resource($p)) {
                fclose($pipes[0]);
                stream_set_timeout($pipes[1], max(1, (int)ceil($timeoutMs/1000)));
                $out = stream_get_contents($pipes[1]);
                fclose($pipes[1]);
                if (is_resource($pipes[2])) fclose($pipes[2]);
                @proc_close($p);
                $out = is_string($out) ? trim($out) : '';
                if ($out !== '') return $out;
            }
        }

        // fallback đọc file hệ thống (Debian/Ubuntu): /var/spool/cron/crontabs/<user>
        $spool = '/var/spool/cron/crontabs/' . $user;
        if (is_readable($spool)) {
            $s = @file_get_contents($spool);
            if (is_string($s) && $s !== '') return $s;
        }
        return null;
    }

    private function readCronFileOrDir(string $path): ?string
    {
        if (is_file($path) && is_readable($path)) {
            $s = @file_get_contents($path);
            return is_string($s) ? $s : null;
        }
        if (is_dir($path) && is_readable($path)) {
            $buf = '';
            foreach (scandir($path) ?: [] as $f) {
                if ($f === '.' || $f === '..') continue;
                $p = $path . '/' . $f;
                if (is_file($p) && is_readable($p)) {
                    $buf .= "\n" . @file_get_contents($p);
                }
            }
            return trim($buf) !== '' ? $buf : null;
        }
        return null;
    }
}
