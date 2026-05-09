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
