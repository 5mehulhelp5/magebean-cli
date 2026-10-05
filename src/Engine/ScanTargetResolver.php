<?php
declare(strict_types=1);
namespace Magebean\Engine;
final class ScanTargetResolver
{
    private const MODE_REMOTE = 'REMOTE';
    private const MODE_LOCAL = 'LOCAL';
    private const MODE_HYBRID = 'HYBRID';
    /** Caller owns rendering; the callback receives only the detected path. */
    public function resolve(bool $hasPath, bool $hasUrl, string $pathOpt, string $urlOpt, ?callable $detectedRoot = null): ResolvedScanTarget
    {
        $detectedRoot ??= static function (string $path): void {};
        $targetMode = $this->mode($hasPath, $hasUrl);
        if ($hasPath && $pathOpt === '') {
            throw new \RuntimeException('--path requires a non-empty value.');
        }
        if ($hasUrl && $urlOpt === '') {
            throw new \RuntimeException('--url requires a non-empty HTTP or HTTPS URL.');
        }

        $requestedUrl = $hasUrl ? $this->normalizeRemoteUrl($urlOpt) : '';

        if ($targetMode === self::MODE_REMOTE) {
            $projectUrl = $requestedUrl;
            $projectPath = 'URL:' . $projectUrl;
        } else {
            $requestedPath = ProjectPath::normalize($hasPath ? $pathOpt : (string)getcwd());

            if (!self::isMagentoRoot($requestedPath)) {
                $detected = self::detectMagentoRoot($requestedPath, 4);
                if ($detected === null) {
                    throw new \RuntimeException(
                        "Cannot locate Magento root from: {$requestedPath}\n" .
                        'Hint: run from your Magento root or pass --path=/absolute/path/to/magento'
                    );
                }
                $detectedRoot($detected);
                $requestedPath = $detected;
            }

            $magentoRoot = $this->findMagentoRoot($requestedPath, 2);
            if ($magentoRoot === null) {
                throw new \RuntimeException(
                    "Not a valid Magento 2 installation.\n" .
                    "- Expected files: bin/magento, composer.json, app/etc/config.php\n" .
                    "- Checked: {$requestedPath} (and up to 2 parents)"
                );
            }

            $this->assertMagento2Root($magentoRoot);
            $projectPath = (string)$magentoRoot;
            $projectUrl = $hasUrl
                ? $requestedUrl
                : (string)$this->autoDetectBaseUrl($projectPath);
        }

        return new ResolvedScanTarget($projectPath, $projectUrl, $targetMode);
    }
    private function findMagentoRoot(string $path, int $maxParents = 0): ?string
    {
        $probe = function (string $p): bool {
            return is_dir($p)
                && is_file($p . '/composer.json')
                && is_file($p . '/bin/magento')
                && (is_file($p . '/app/etc/config.php') || is_file($p . '/app/etc/env.php'));
        };

        $current = $path;
        for ($i = 0; $i <= $maxParents; $i++) {
            if ($probe($current)) {
                return realpath($current) ?: $current;
            }
            $parent = dirname($current);
            if ($parent === $current) {
                break;
            }
            $current = $parent;
        }
        return null;
    }

    private function assertMagento2Root(string $root): void
    {
        // 1) Thư mục tồn tại & đọc được
        if (!is_dir($root) || !is_readable($root)) {
            throw new \RuntimeException("Path '{$root}' is not readable.");
        }

        // 2) Các file/binary quan trọng
        $required = [
            'composer.json',
            'bin/magento',
        ];
        foreach ($required as $rel) {
            $abs = $root . DIRECTORY_SEPARATOR . $rel;
            if (!file_exists($abs)) {
                throw new \RuntimeException("Missing required file: {$rel} at {$root}");
            }
        }

        // 3) Ít nhất phải có một trong hai: app/etc/config.php hoặc app/etc/env.php
        $hasConfig = is_file($root . '/app/etc/config.php') || is_file($root . '/app/etc/env.php');
        if (!$hasConfig) {
            throw new \RuntimeException("Missing app/etc/config.php or app/etc/env.php at {$root}");
        }

        // 4) bin/magento nên executable (không bắt buộc trên mọi OS, nhưng kiểm tra giúp debug)
        $binMagento = $root . '/bin/magento';
        if (!is_readable($binMagento)) {
            throw new \RuntimeException("bin/magento is not readable at {$root}");
        }
        // if (strncasecmp(PHP_OS, 'WIN', 3) !== 0 && !is_executable($binMagento)) {
        //     throw new \RuntimeException("bin/magento is not executable at {$root}");
        // }

        // 5) composer.json phải có "require": { "magento/framework": ... } hoặc name magento/*
        $composer = @file_get_contents($root . '/composer.json');
        if ($composer === false) {
            throw new \RuntimeException("Unable to read composer.json at {$root}");
        }

        $json = json_decode($composer, true);
        if (!is_array($json)) {
            throw new \RuntimeException("Invalid composer.json at {$root}");
        }

        $hasFramework =
            isset($json['require']['magento/framework']) ||
            (isset($json['name']) && is_string($json['name']) && str_starts_with($json['name'], 'magento/'));

        if (!$hasFramework) {
            throw new \RuntimeException(
                "composer.json does not look like a Magento 2 project (missing require: magento/framework)."
            );
        }
    }

    public function mode(bool $hasPath, bool $hasUrl): string
    {
        if ($hasUrl && !$hasPath) {
            return self::MODE_REMOTE;
        }
        if ($hasPath && $hasUrl) {
            return self::MODE_HYBRID;
        }

        return self::MODE_LOCAL;
    }

    private function normalizeRemoteUrl(string $url): string
    {
        $url = trim($url);
        if ($url === '' || filter_var($url, FILTER_VALIDATE_URL) === false) {
            throw new \RuntimeException('Invalid --url. Expected an absolute HTTP or HTTPS URL.');
        }

        $parts = parse_url($url);
        $scheme = strtolower((string)($parts['scheme'] ?? ''));
        $host = (string)($parts['host'] ?? '');
        if (!in_array($scheme, ['http', 'https'], true) || $host === '') {
            throw new \RuntimeException('Invalid --url. Only absolute HTTP and HTTPS URLs are supported.');
        }
        if (isset($parts['user']) || isset($parts['pass'])) {
            throw new \RuntimeException('Invalid --url. Credentials in the target URL are not supported.');
        }
        if (isset($parts['query']) || isset($parts['fragment'])) {
            throw new \RuntimeException('Invalid --url. Use a store base URL without a query string or fragment.');
        }

        return rtrim($url, '/');
    }

    private static function isMagentoRoot(string $dir): bool
    {
        // Tiêu chí an toàn: có cả env.php và bin/magento
        return is_file($dir . '/app/etc/env.php') && is_file($dir . '/bin/magento');
    }

    private static function detectMagentoRoot(string $startDir, int $maxUp = 4): ?string
    {
        $dir = ProjectPath::normalize($startDir);
        for ($i = 0; $i <= $maxUp; $i++) {
            if (self::isMagentoRoot($dir)) {
                return $dir;
            }
            $parent = dirname($dir);
            if ($parent === $dir) break; // đến root FS
            $dir = $parent;
        }
        return null;
    }

    private function autoDetectBaseUrl(string $projectPath): string
    {
        $root    = rtrim($projectPath, DIRECTORY_SEPARATOR);
        $envFile = $root . '/app/etc/env.php';
        if (!is_file($envFile)) {
            return '';
        }

        $env = @include $envFile;
        if (!is_array($env) || empty($env['db']['connection']['default'])) {
            return '';
        }

        $db     = $env['db']['connection']['default'];
        $prefix = $env['db']['table_prefix'] ?? '';
        $table  = ($prefix ? $prefix : '') . 'core_config_data';

        $host     = $db['host'] ?? 'localhost';
        $dbname   = $db['dbname'] ?? '';
        $username = $db['username'] ?? '';
        $password = $db['password'] ?? '';
        $port     = null;

        if (strpos($host, ':') !== false) {
            [$host, $port] = explode(':', $host, 2);
        }
        if ($dbname === '' || $username === '') {
            return '';
        }

        $dsn = "mysql:host={$host};dbname={$dbname};charset=utf8mb4";
        if (!empty($port)) {
            $dsn .= ";port={$port}";
        }

        try {
            $pdo = new \PDO($dsn, $username, $password, [
                \PDO::ATTR_ERRMODE            => \PDO::ERRMODE_EXCEPTION,
                \PDO::ATTR_DEFAULT_FETCH_MODE => \PDO::FETCH_ASSOC,
            ]);
        } catch (\PDOException $e) {
            return '';
        }

        $paths = ['web/secure/base_url', 'web/unsecure/base_url'];
        $in    = implode(',', array_fill(0, count($paths), '?'));
        $sql   = "SELECT scope, scope_id, path, value FROM {$table} WHERE path IN ($in)";

        try {
            $stmt = $pdo->prepare($sql);
            $stmt->execute($paths);
            $rows = $stmt->fetchAll();
        } catch (\PDOException $e) {
            return '';
        }
        if (!$rows) {
            return '';
        }

        $bucket = [
            'web/secure/base_url'   => ['stores' => [], 'websites' => [], 'default' => []],
            'web/unsecure/base_url' => ['stores' => [], 'websites' => [], 'default' => []],
        ];
        foreach ($rows as $r) {
            $path    = (string)($r['path'] ?? '');
            $scope   = strtolower((string)($r['scope'] ?? 'default'));
            if (!isset($bucket[$path][$scope])) $scope = 'default';
            $scopeId = (int)($r['scope_id'] ?? 0);
            $val     = trim((string)($r['value'] ?? ''));
            if ($val !== '' && isset($bucket[$path])) {
                $bucket[$path][$scope][$scopeId] = $val;
            }
        }

        $pick = function (array $b): ?string {
            if (!empty($b['stores'])) {
                $https = array_filter($b['stores'], fn($v) => stripos($v, 'https://') === 0);
                $cand  = reset($https);
                if ($cand) return $cand;
                return reset($b['stores']);
            }
            if (!empty($b['websites'])) {
                $https = array_filter($b['websites'], fn($v) => stripos($v, 'https://') === 0);
                $cand  = reset($https);
                if ($cand) return $cand;
                return reset($b['websites']);
            }
            if (!empty($b['default'])) {
                $https = array_filter($b['default'], fn($v) => stripos($v, 'https://') === 0);
                $cand  = reset($https);
                if ($cand) return $cand;
                return reset($b['default']);
            }
            return null;
        };

        $secure = $pick($bucket['web/secure/base_url']);
        $unsec  = $pick($bucket['web/unsecure/base_url']);

        $base = $secure ?: $unsec;
        if (!$base) return '';

        // Normalize: strip trailing index.php and ensure trailing slash
        $base = preg_replace('~/index\.php/?$~i', '/', $base);
        if (substr($base, -1) !== '/') {
            $base .= '/';
        }

        return $base;
    }
}
