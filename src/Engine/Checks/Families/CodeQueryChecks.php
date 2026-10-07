<?php
declare(strict_types=1);
namespace Magebean\Engine\Checks\Families;
use Magebean\Engine\Context;
use Magebean\Engine\Collectors\CollectorSet;

final class CodeQueryChecks extends CodeSearchSupport
{
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
            $content = $this->collectors->files->read($file);
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

    public function noMixedContent(array $args): array
    {
        if (!empty($args['strict_scope'])) return $this->strictLiteralMixedContent($args);
        $roots = $args['paths'] ?? ['app'];
        $inc = $args['include_ext'] ?? ['phtml', 'html', 'xml', 'js', 'css', 'less'];
        $max = max(1, (int)($args['max_results'] ?? 50));
        $rootsAbs = array_map(fn($p) => $this->ctx->abs($p), $roots);

        $offenders = [];
        foreach ($this->collectFiles($rootsAbs, $inc) as $file) {
            $content = $this->collectors->files->read($file);
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


    private function strictLiteralMixedContent(array $args): array
    {
        $roots = array_values($args['paths'] ?? ['app']);
        $extensions = array_map('strtolower', $args['include_ext'] ?? ['phtml', 'html', 'xml', 'css', 'less']);
        $abs = array_map(fn($p) => $this->ctx->abs($p), $roots);
        foreach ($abs as $root) if (!is_dir($root) || !is_readable($root)) return [null, '[UNKNOWN] Source scope missing or unreadable', ['paths' => $roots]];
        $offenders = []; $unreadable = []; $count = 0;
        try {
            foreach ($this->collectors->code->anyExtension($abs) as $file) {
                if (!in_array(strtolower(pathinfo($file, PATHINFO_EXTENSION)), $extensions, true)) continue;
                $content = $this->collectors->files->read($file);
                if ($content === false) { $unreadable[] = $this->relativeFile($file); continue; }
                $count++;
                $clean = preg_replace(['~<!--[\s\S]*?-->~', '~/\*[\s\S]*?\*/~'], '', $content) ?? $content;
                // Anchor hrefs, XML namespace identifiers and ordinary URL strings are not subresource loads.
                $patterns = [
                    'resource_attribute' => '~<(?:script|img|iframe|frame|link|audio|video|source|track|embed|object|input|form)\b[^>]*?\b(?:src|href|action|data|poster|srcset)\s*=\s*([\'"])(?P<url>[^\'"]*http://[^\'"]*)\1~i',
                    'css_resource' => '~(?:url\(\s*[\'"]?|@import\s*[\'"])(?P<url>http://[^\'"\s)<>]+)~i',
                ];
                foreach ($patterns as $kind => $pattern) {
                    preg_match_all($pattern, $clean, $matches, PREG_SET_ORDER | PREG_OFFSET_CAPTURE);
                    foreach ($matches as $match) $offenders[] = ['file' => $this->relativeFile($file), 'kind' => $kind, 'url' => $match['url'][0], 'snippet' => substr($match[0][0], 0, 240)];
                }
            }
        } catch (\UnexpectedValueException $e) { return [null, '[UNKNOWN] Cannot enumerate complete source scope', ['paths' => $roots]]; }
        $evidence = ['paths' => $roots, 'files_scanned' => $count, 'unreadable' => $unreadable, 'offenders' => array_slice($offenders, 0, max(1, (int)($args['max_results'] ?? 50)))];
        if ($offenders !== []) return [false, 'Literal insecure HTTP subresource/form references found', $evidence];
        if ($unreadable !== [] || $count === 0) return [null, '[UNKNOWN] No complete readable markup/CSS source scope', $evidence];
        return [true, 'No literal insecure HTTP subresource/form references in inspected markup/CSS', $evidence];
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
            $content = $this->collectors->files->read($file);
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

    private function isAllowedPlainHttpReference(string $url): bool
    {
        return preg_match('~^http://(?:www\.)?w3\.org/~i', $url) === 1
            || preg_match('~^http://(?:www\.)?schema\.org/~i', $url) === 1
            || preg_match('~^http://localhost(?::\d+)?(?:/|$)~i', $url) === 1
            || preg_match('~^http://127\.0\.0\.1(?::\d+)?(?:/|$)~', $url) === 1;
    }
}
