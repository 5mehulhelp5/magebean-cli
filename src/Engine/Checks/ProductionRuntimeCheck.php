<?php
declare(strict_types=1);

namespace Magebean\Engine\Checks;

use Magebean\Engine\Context;

/** Precisely scoped observations. No assertion files are accepted as runtime proof. */
final class ProductionRuntimeCheck
{
    public function __construct(private Context $ctx, private mixed $httpProbe = null, private mixed $processProbe = null) {}

    /** Kernel access checks are valid only in the exact declared worker security context. */
    public function boundWorkerCodeReadonly(array $args): array
    {
        $pids = $args['worker_pids'] ?? null;
        if (PHP_OS_FAMILY !== 'Linux' || !function_exists('posix_geteuid') || !is_array($pids) || $pids === [] || count($pids) > 64) return $this->unknown('Supply Linux PHP-FPM worker_pids and run the scanner under their exact effective identity and mount namespace');
        $scanner = $this->processIdentity(getmypid(), false);
        if ($scanner === null) return $this->unknown('Scanner effective identity, capabilities or mount namespace cannot be collected');
        $starts = [];
        foreach ($pids as $pid) {
            if ((!is_int($pid) && (!is_string($pid) || !ctype_digit($pid))) || (int)$pid < 1) return $this->unknown('Worker PID policy is malformed');
            $worker = is_callable($this->processProbe) ? ($this->processProbe)((int)$pid) : $this->processIdentity((int)$pid, true);
            if (!is_array($worker) || $worker !== $scanner) return $this->unknown('Worker and scanner effective UID, GID, groups, capabilities, project tree or mount namespace differ or are unobservable');
            $starts[(int)$pid] = $this->processStart((int)$pid);
            if ($starts[(int)$pid] === null) return $this->unknown('Worker process lifetime cannot be bound');
        }
        $dirs = $args['dirs'] ?? ['app', 'vendor', 'lib'];
        if (!is_array($dirs) || $dirs === [] || count($dirs) > 16) return $this->unknown('Supply a bounded list of code roots');
        $budget = max(1, min(100000, (int)($args['max_entries'] ?? 50000)));
        $deadline = microtime(true) + max(100, min(15000, (int)($args['max_duration_ms'] ?? 5000))) / 1000;
        $seen = 0; $gaps = []; $writable = [];
        foreach ($dirs as $relative) {
            if (!is_string($relative) || $relative === '' || str_starts_with($relative, '/') || in_array('..', explode('/', $relative), true)) { $gaps[] = 'unsupported_code_root'; continue; }
            $path = $this->ctx->abs($relative);
            if (!is_dir($path) || is_link($path) || !is_readable($path)) { $gaps[] = $relative; continue; }
            $parent = dirname($path);
            if (is_writable($parent) && is_executable($parent)) {
                // Sticky-directory deletion rules require owner analysis; don't guess a violation.
                $mode = @fileperms($parent);
                if ($mode === false || ($mode & 01000) !== 0) $gaps[] = $relative . ':sticky_parent';
                else $writable[] = ['path' => $relative, 'reason' => 'writable_replaceable_parent'];
            }
            try {
                if (is_writable($path)) $writable[] = ['path' => $relative, 'reason' => 'kernel_write_access'];
                $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($path, \FilesystemIterator::SKIP_DOTS), \RecursiveIteratorIterator::SELF_FIRST);
                foreach ($it as $file) {
                    if (microtime(true) > $deadline) { $gaps[] = 'time_budget'; break 2; }
                    if (++$seen > $budget) { $gaps[] = 'entry_budget'; break 2; }
                    $name = $relative . '/' . substr($file->getPathname(), strlen($path) + 1);
                    if ($file->isLink()) { $gaps[] = $name; continue; }
                    if (!$file->isReadable()) { $gaps[] = $name; continue; }
                    if (is_writable($file->getPathname())) $writable[] = ['path' => $name, 'reason' => 'kernel_write_access'];
                    if (count($writable) >= 50) break 2;
                }
            } catch (\Throwable $e) { $gaps[] = $relative . ':inventory_unavailable'; }
        }
        // Recollect identities to detect PID replacement or credential/namespace changes during inventory.
        foreach ($pids as $pid) {
            $worker = is_callable($this->processProbe) ? ($this->processProbe)((int)$pid) : $this->processIdentity((int)$pid, true);
            if (!is_array($worker) || $worker !== $scanner || $this->processStart((int)$pid) !== $starts[(int)$pid]) return $this->unknown('Worker identity, lifetime or namespace changed during collection');
        }
        $ev = ['scope' => 'supplied PHP-FPM workers bound to scanner effective identity and namespace; kernel write-access observation', 'entries' => $seen, 'writable_paths' => array_slice($writable, 0, 50), 'collection_gaps' => array_slice($gaps, 0, 50)];
        if ($writable !== []) return [false, 'Bound application worker identity can write or replace inspected code paths', $ev];
        if ($gaps !== []) return $this->unknown('Code access inventory is incomplete', $ev);
        return [true, 'No kernel write access found for bound worker identities in the complete inspected code inventory', $ev];
    }

    private function processIdentity(int $pid, bool $worker): ?array
    {
        $status = @file_get_contents('/proc/' . $pid . '/status');
        $namespace = @readlink('/proc/' . $pid . '/ns/mnt');
        $root = realpath($this->ctx->path);
        if (!is_string($status) || !is_string($namespace) || $root === false) return null;
        if ($worker) {
            $command = @file_get_contents('/proc/' . $pid . '/cmdline');
            if (!is_string($command) || !preg_match('~php-fpm[^\x00]*:\s*pool\s+~', $command)) return null;
        }
        if (!preg_match('/^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$/m', $status, $uid) || !preg_match('/^Gid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$/m', $status, $gid) || !preg_match('/^Groups:\s*([\d ]*)$/m', $status, $groups) || !preg_match('/^CapEff:\s*([0-9a-f]+)$/mi', $status, $caps)) return null;
        if ((int)$uid[2] === 0 || array_unique(array_slice($uid, 1)) !== [$uid[1]] || array_unique(array_slice($gid, 1)) !== [$gid[1]] || trim($caps[1], '0') !== '') return null;
        foreach (['CapPrm', 'CapAmb'] as $field) if (!preg_match('/^' . $field . ':\s*([0-9a-f]+)$/mi', $status, $cap) || trim($cap[1], '0') !== '') return null;
        if (!preg_match('/^Seccomp:\s*(\d+)$/m', $status, $seccomp) || !preg_match('/^NoNewPrivs:\s*(\d+)$/m', $status, $privs)) return null;
        // A seccomp filter cannot be equated by mode alone; custom filtered workers are unsupported.
        if ((int)$seccomp[1] !== 0) return null;
        $security = @file_get_contents('/proc/' . $pid . '/attr/current');
        if (!is_string($security)) return null;
        $groupIds = array_map('intval', preg_split('/\s+/', trim($groups[1]), -1, PREG_SPLIT_NO_EMPTY));
        $groupIds[] = (int)$gid[2]; $groupIds = array_values(array_unique($groupIds)); sort($groupIds);
        $ownStat = @stat($root); $workerStat = @stat('/proc/' . $pid . '/root' . $root);
        if (!$ownStat || !$workerStat || $ownStat['dev'] !== $workerStat['dev'] || $ownStat['ino'] !== $workerStat['ino']) return null;
        return ['uid' => (int)$uid[2], 'gid' => (int)$gid[2], 'groups' => $groupIds, 'mount_namespace' => $namespace, 'project_dev' => $ownStat['dev'], 'project_inode' => $ownStat['ino'], 'security_context' => trim($security), 'no_new_privs' => (int)$privs[1]];
    }

    private function processStart(int $pid): ?string
    {
        $stat = @file_get_contents('/proc/' . $pid . '/stat');
        if (!is_string($stat) || ($offset = strrpos($stat, ') ')) === false) return null;
        $fields = preg_split('/\s+/', substr($stat, $offset + 2));
        return isset($fields[19]) && ctype_digit($fields[19]) ? $fields[19] : null;
    }

    /** Known signatures, not absence of every form of executable code. */
    public function uploadSignaturesAbsent(array $args): array
    {
        $roots = $args['paths'] ?? ['pub/media'];
        if (!is_array($roots) || $roots === [] || count($roots) > 16) return $this->unknown('Supply between one and sixteen upload inventory paths');
        $maxEntries = max(1, min(50000, (int)($args['max_entries'] ?? 10000)));
        $maxBytes = max(1, min(4194304, (int)($args['max_file_bytes'] ?? 1048576)));
        $maxTotal = max(1, min(67108864, (int)($args['max_total_bytes'] ?? 16777216)));
        $deadline = microtime(true) + max(100, min(15000, (int)($args['max_duration_ms'] ?? 5000))) / 1000;
        $seen = 0; $read = 0; $totalBytes = 0; $gaps = []; $found = [];
        foreach ($roots as $relative) {
            if (!is_string($relative) || $relative === '' || is_link($this->ctx->abs($relative))) { $gaps[] = 'unsupported_root'; continue; }
            $root = realpath($this->ctx->abs($relative));
            if ($root === false || !is_dir($root) || !is_readable($root)) { $gaps[] = $relative; continue; }
            try {
                $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS), \RecursiveIteratorIterator::SELF_FIRST);
                foreach ($it as $file) {
                    if (microtime(true) > $deadline) { $gaps[] = 'time_budget'; break 2; }
                    if (++$seen > $maxEntries) { $gaps[] = 'entry_budget'; break 2; }
                    $name = $relative . '/' . substr($file->getPathname(), strlen($root) + 1);
                    if ($file->isLink()) { $gaps[] = $name; continue; }
                    if (!$file->isFile()) continue;
                    if (preg_match('~\.(?:php\d*|phtml|pht|phar)(?:\.|$)~i', $name)) $found[] = ['path' => $name, 'signal' => 'php_like_extension'];
                    $size = $file->getSize();
                    if ($size > $maxBytes || !$file->isReadable()) { $gaps[] = $name; continue; }
                    if ($totalBytes + $size > $maxTotal) { $gaps[] = 'total_byte_budget'; break 2; }
                    $content = @file_get_contents($file->getPathname(), false, null, 0, $maxBytes + 1);
                    if (!is_string($content) || strlen($content) > $maxBytes || strlen($content) !== $size) { $gaps[] = $name; continue; }
                    ++$read;
                    $totalBytes += strlen($content);
                    // Only explicit long PHP tags: XML declarations and bare <? are not PHP proof.
                    if (preg_match('~<\?(?:php\s|=)~i', $content, $match, PREG_OFFSET_CAPTURE)) {
                        $found[] = ['path' => $name, 'line' => 1 + substr_count(substr($content, 0, $match[0][1]), "\n"), 'signal' => 'php_open_tag'];
                    }
                    if (strtolower(basename($name)) === '.htaccess' && preg_match('~^\s*(?:AddHandler|SetHandler|AddType)\b[^\r\n]*(?:php|cgi|fcgid)~im', $content)) $found[] = ['path' => $name, 'signal' => 'script_handler_directive'];
                    if (count($found) >= 50) break 2;
                }
            } catch (\Throwable $e) { $gaps[] = $relative . ':inventory_unavailable'; }
        }
        $ev = ['scope' => 'configured upload paths; PHP-like filenames, explicit PHP tags and htaccess script-handler signatures', 'entries' => $seen, 'files_read' => $read, 'bytes_read' => $totalBytes, 'findings' => array_slice($found, 0, 50), 'collection_gaps' => array_slice($gaps, 0, 50)];
        if ($found !== []) return [false, 'Configured executable-content signatures found in upload inventory', $ev];
        if ($gaps !== []) return $this->unknown('Upload inventory is incomplete; no clean conclusion is available', $ev);
        return [true, 'No configured executable-content signatures in the complete bounded upload inventory', $ev];
    }

    /** This is deliberately a default-scope configuration predicate. */
    public function nativeDebugDefaultsDisabled(array $args): array
    {
        $paths = $args['paths'] ?? ['dev/debug/template_hints', 'dev/debug/template_hints_storefront', 'dev/translate_inline/active'];
        return $this->resolvedFlagsDisabled($paths, 'Resolved native default-scope debug settings');
    }

    /** Caller supplies explicit integration setting paths, not a heuristic key regex. */
    public function integrationDebugDefaultsDisabled(array $args): array
    {
        if (!isset($args['paths'])) return $this->unknown('Explicit supported integration debug configuration paths are required');
        return $this->resolvedFlagsDisabled($args['paths'], 'Explicit named default-scope integration debug settings');
    }

    /** Direct database grants only; business approval is explicit check configuration. */
    public function directGlobalRolesApproved(array $args): array
    {
        if (!array_key_exists('approved_role_ids', $args) || !is_array($args['approved_role_ids'])) return $this->unknown('Supply an explicit approved_role_ids policy; omitted policy is not deny-all');
        $approved = [];
        foreach ($args['approved_role_ids'] as $id) {
            if ((!is_int($id) && (!is_string($id) || !ctype_digit($id))) || (int)$id < 1) return $this->unknown('Approved role IDs must be positive integers');
            $approved[] = (int)$id;
        }
        try {
            [$pdo, $prefix] = $this->database();
            if (!$pdo instanceof \PDO) return $this->unknown('Deployed Magento database is unavailable; direct global grants cannot be assessed');
            $roles = $pdo->query('SELECT role_id, role_type FROM `' . $prefix . 'authorization_role` LIMIT 10001')->fetchAll(\PDO::FETCH_ASSOC);
            $rules = $pdo->query('SELECT role_id, resource_id, permission FROM `' . $prefix . 'authorization_rule` LIMIT 10001')->fetchAll(\PDO::FETCH_ASSOC);
        } catch (\Throwable $e) { return $this->unknown('Unable to read deployed authorization_role and authorization_rule; verify SELECT permission'); }
        if ($roles === [] || count($roles) > 10000 || count($rules) > 10000) return $this->unknown('ACL inventory is empty or exceeds the bounded row budget');
        $groups = [];
        foreach ($roles as $role) {
            $id = $role['role_id'] ?? null; $type = $role['role_type'] ?? null;
            if ((!is_int($id) && (!is_string($id) || !ctype_digit($id))) || (int)$id < 1 || !in_array($type, ['G', 'U'], true) || isset($groups[(int)$id])) return $this->unknown('ACL role rows are malformed or duplicated');
            $groups[(int)$id] = $type;
        }
        $global = [];
        foreach ($rules as $rule) {
            if (!isset($rule['role_id'], $rule['resource_id'], $rule['permission']) || !is_scalar($rule['role_id']) || !ctype_digit((string)$rule['role_id']) || !isset($groups[(int)$rule['role_id']]) || !is_string($rule['resource_id']) || !in_array($rule['permission'], ['allow', 'deny'], true)) return $this->unknown('ACL rules are malformed or reference uncollected roles');
            if ($rule['permission'] === 'allow' && in_array($rule['resource_id'], ['Magento_Backend::all', 'Magento_Adminhtml::all'], true)) {
                if ($groups[(int)$rule['role_id']] !== 'G') return $this->unknown('Direct user global ACL rules require separate effective authorization evaluation');
                $global[] = (int)$rule['role_id'];
            }
        }
        $global = array_values(array_unique($global)); $unapproved = array_values(array_diff($global, $approved));
        $ev = ['scope' => 'direct database allow grants to Magento global resources for group roles only; no inherited or plugin authorization claim', 'source' => 'deployed_database_select', 'role_rows' => count($roles), 'rule_rows' => count($rules), 'global_role_ids' => $global, 'unapproved_role_ids' => $unapproved];
        return [$unapproved === [], $unapproved === [] ? 'Direct global ACL group grants match the explicit approved-role policy' : 'Unapproved direct global ACL group grants found', $ev];
    }

    private function database(): array
    {
        $pdo = $this->ctx->get('pdo');
        $prefix = $this->ctx->get('db_table_prefix', '');
        if ($pdo instanceof \PDO) return is_string($prefix) && preg_match('/^[a-zA-Z0-9_]*$/D', $prefix) ? [$pdo, $prefix] : [null, ''];
        $file = $this->ctx->abs('app/etc/env.php');
        if (!is_file($file) || !is_readable($file)) return [null, ''];
        $env = include $file;
        $db = is_array($env) ? ($env['db']['connection']['default'] ?? null) : null;
        $prefix = is_array($env) ? ($env['db']['table_prefix'] ?? '') : '';
        if (!is_array($db) || !is_string($prefix) || !preg_match('/^[a-zA-Z0-9_]*$/D', $prefix)) return [null, ''];
        $host = $db['host'] ?? null; $name = $db['dbname'] ?? null; $port = $db['port'] ?? 3306;
        if (!is_string($host) || !is_string($name) || $host === '' || $name === '' || str_contains($host, ';') || str_contains($name, ';') || !is_scalar($port) || !ctype_digit((string)$port) || (int)$port < 1 || (int)$port > 65535) return [null, ''];
        return [new \PDO('mysql:host=' . $host . ';dbname=' . $name . ';port=' . (int)$port . ';charset=utf8mb4', (string)($db['username'] ?? ''), (string)($db['password'] ?? ''), [\PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION, \PDO::ATTR_TIMEOUT => 2]), $prefix];
    }

    private function resolvedFlagsDisabled(mixed $paths, string $label): array
    {
        if (!is_array($paths) || $paths === [] || count($paths) > 32) return $this->unknown('Supply one to thirty-two explicit configuration paths');
        foreach ($paths as $path) if (!is_string($path) || !preg_match('~^[a-zA-Z0-9_]+(?:/[a-zA-Z0-9_]+){2,}$~D', $path)) return $this->unknown('Configuration path is malformed');
        $values = (new MagentoCheck($this->ctx))->effectiveConfigurationValues(array_values(array_unique($paths)));
        $observed = []; $gaps = []; $fail = [];
        foreach ($values as $path => $value) {
            if (!$value['available']) { $gaps[] = $path; continue; }
            $flag = $this->flag($value['value']);
            if ($flag === null) { $gaps[] = $path; continue; }
            $observed[] = ['path' => $path, 'enabled' => $flag, 'source' => $value['source']];
            if ($flag) $fail[] = $path;
        }
        $ev = ['scope' => 'resolved default scope only; store overrides and web process environment are outside this predicate', 'observed' => $observed, 'unresolved_paths' => $gaps, 'enabled_paths' => $fail];
        if ($fail !== []) return [false, $label . ' include enabled settings', $ev];
        if ($gaps !== []) return $this->unknown($label . ' could not all be resolved', $ev);
        return [true, $label . ' are disabled', $ev];
    }

    /** Only a runtime nosniff response assertion; HSTS/frame controls are separate IDs. */
    public function runtimeNosniff(array $args): array
    {
        [$ok, $ev, $headers] = $this->response($args);
        if (!$ok) return $this->unknown('A successful same-origin HTTPS application response is required', $ev);
        $values = $headers['x-content-type-options'] ?? [];
        if (count($values) > 1) return $this->unknown('Duplicate nosniff headers are ambiguous', $ev);
        $pass = count($values) === 1 && strtolower(trim($values[0])) === 'nosniff';
        return [$pass, $pass ? 'Observed HTTPS response emits X-Content-Type-Options nosniff' : 'Observed HTTPS response lacks an exact nosniff header', $ev + ['header_present' => $values !== []]];
    }

    /** An exact emitted-policy baseline, not checkout-wide CSP or XSS assurance. */
    public function checkoutCspResponse(array $args): array
    {
        if (!isset($args['path']) || !is_string($args['path']) || !str_starts_with($args['path'], '/')) return $this->unknown('Supply an explicit checkout page path; the homepage is not checkout proof');
        [$ok, $ev, $headers] = $this->response($args);
        if (!$ok) return $this->unknown('A successful same-origin checkout response is required; redirects cannot establish checkout policy', $ev);
        $values = $headers['content-security-policy'] ?? [];
        if ($values === []) return [false, 'Checkout response has no enforced Content-Security-Policy header', $ev + ['report_only_present' => isset($headers['content-security-policy-report-only'])]];
        if (count($values) !== 1 || str_contains($values[0], ',')) return $this->unknown('Multiple or combined CSP policies require policy-intersection evaluation', $ev);
        $directives = [];
        foreach (explode(';', $values[0]) as $part) {
            $tokens = preg_split('/\s+/', trim($part));
            if (!$tokens || $tokens[0] === '') continue;
            $name = strtolower(array_shift($tokens));
            if (!preg_match('/^[a-z][a-z0-9-]*$/D', $name) || isset($directives[$name])) return $this->unknown('CSP has duplicate or malformed directives', $ev);
            $directives[$name] = $tokens;
        }
        $required = ['script-src', 'connect-src', 'frame-src', 'form-action', 'object-src', 'base-uri'];
        $problems = [];
        foreach ($required as $name) {
            if (!isset($directives[$name]) || $directives[$name] === []) { $problems[] = $name . ':missing_explicit_sources'; continue; }
            $tokens = $directives[$name];
            foreach ($tokens as $token) {
                if (str_contains($token, '*') || in_array(strtolower($token), ["'unsafe-inline'", "'unsafe-eval'", 'data:', 'http:', 'https:'], true)) { $problems[] = $name . ':broad_or_unsafe_source'; continue; }
                if (in_array($token, ["'self'", "'none'"], true) || preg_match("~^'(?:nonce-[a-zA-Z0-9+/_=-]+|sha(?:256|384|512)-[a-zA-Z0-9+/_=-]+)'$~D", $token)) continue;
                $source = parse_url($token);
                if (!is_array($source) || ($source['scheme'] ?? '') !== 'https' || empty($source['host']) || isset($source['user']) || isset($source['query']) || isset($source['fragment'])) return $this->unknown('CSP contains unsupported source syntax; no clean policy conclusion is available', $ev);
            }
            if (in_array("'none'", $tokens, true) && count($tokens) !== 1) return $this->unknown('CSP none source is combined with other sources', $ev);
            if ($name === 'object-src' && $tokens !== ["'none'"]) $problems[] = 'object-src:must_be_none';
            if ($name === 'base-uri' && $tokens !== ["'none'"] && $tokens !== ["'self'"]) $problems[] = 'base-uri:must_be_none_or_self';
        }
        if (($args['require_reporting'] ?? true) && empty($directives['report-uri']) && empty($directives['report-to'])) $problems[] = 'reporting:missing';
        $ev += ['assessed_directives' => $required, 'policy_issues' => array_values(array_unique($problems)), 'report_only_present' => isset($headers['content-security-policy-report-only'])];
        return [$problems === [], $problems === [] ? 'Named checkout response emits the explicit enforced CSP baseline' : 'Named checkout response violates the explicit CSP baseline', $ev];
    }

    private function response(array $args): array
    {
        $base = (new HttpCheck($this->ctx))->runtimeBaseUrl();
        $path = $args['path'] ?? '/';
        if (!is_string($path) || !str_starts_with($path, '/') || str_starts_with($path, '//') || str_contains($path, '?') || str_contains($path, '#') || str_contains($path, "\r") || str_contains($path, "\n")) return [false, ['reason' => 'invalid_probe_path'], []];
        $parts = parse_url($base);
        if (!is_array($parts) || ($parts['scheme'] ?? '') !== 'https' || empty($parts['host']) || isset($parts['user']) || isset($parts['query']) || isset($parts['fragment'])) return [false, ['reason' => 'explicit_https_url_required'], []];
        $url = $base . $path;
        $timeout = max(100, min(15000, (int)($args['timeout_ms'] ?? 5000)));
        $result = is_callable($this->httpProbe) ? ($this->httpProbe)($url, $timeout) : $this->boundedGet($url, $timeout);
        $ev = ['path' => $path, 'status' => $result['status'] ?? null, 'scope' => 'one successful no-redirect HTTPS GET at scan time'];
        if (empty($result['complete_headers']) || ($result['status'] ?? 0) !== 200 || ($result['final_url'] ?? $url) !== $url) return [false, $ev + ['reason' => 'response_unavailable_or_not_application_200'], []];
        $headers = [];
        foreach (($result['headers'] ?? []) as $name => $values) {
            if (!is_string($name)) return [false, $ev + ['reason' => 'malformed_headers'], []];
            foreach ((array)$values as $value) {
                if (!is_string($value) || str_contains($value, "\r") || str_contains($value, "\n")) return [false, $ev + ['reason' => 'malformed_headers'], []];
                $headers[strtolower($name)][] = $value;
            }
        }
        return [true, $ev, $headers];
    }

    /** No redirects, cookies, credentials, retained body or unbounded response buffering. */
    private function boundedGet(string $url, int $timeout): array
    {
        if (!function_exists('curl_init')) return ['complete_headers' => false];
        $headers = []; $bytes = 0; $body = 0; $headerGap = false; $bodyLimit = false;
        $ch = curl_init($url);
        curl_setopt_array($ch, [CURLOPT_TIMEOUT_MS => $timeout, CURLOPT_CONNECTTIMEOUT_MS => $timeout, CURLOPT_FOLLOWLOCATION => false, CURLOPT_SSL_VERIFYPEER => true, CURLOPT_SSL_VERIFYHOST => 2, CURLOPT_USERAGENT => 'Magebean-CLI/1.0', CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_HEADERFUNCTION => static function ($ch, string $line) use (&$headers, &$bytes, &$headerGap): int {
                $bytes += strlen($line);
                if ($bytes > 65536) { $headerGap = true; return 0; }
                if (str_starts_with($line, 'HTTP/')) $headers = [];
                elseif (str_contains($line, ':')) { [$name, $value] = explode(':', $line, 2); $headers[strtolower(trim($name))][] = trim($value); }
                return strlen($line);
            },
            CURLOPT_WRITEFUNCTION => static function ($ch, string $chunk) use (&$body, &$bodyLimit): int {
                $body += strlen($chunk);
                if ($body > 65536) { $bodyLimit = true; return 0; }
                return strlen($chunk);
            },
        ]);
        $success = curl_exec($ch);
        $error = curl_errno($ch); $status = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE); $final = (string)curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
        curl_close($ch);
        $valid = !$headerGap && ($success !== false || ($bodyLimit && $error === CURLE_WRITE_ERROR));
        return ['complete_headers' => $valid, 'headers' => $headers, 'status' => $status, 'final_url' => $final];
    }

    private function flag(mixed $value): ?bool
    {
        if (in_array($value, [false, 0, '0', 'false', 'off', 'no'], true)) return false;
        if (in_array($value, [true, 1, '1', 'true', 'on', 'yes'], true)) return true;
        return null;
    }

    private function unknown(string $reason, array $evidence = []): array { return [null, '[UNKNOWN] ' . $reason, $evidence]; }
}
