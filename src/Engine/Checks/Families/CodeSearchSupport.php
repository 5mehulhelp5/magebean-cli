<?php
declare(strict_types=1);
namespace Magebean\Engine\Checks\Families;
use Magebean\Engine\Context;
use Magebean\Engine\Collectors\CollectorSet;

/** Internal shared primitives for compatible check families. */
abstract class CodeSearchSupport
{
    protected Context $ctx;
    protected CollectorSet $collectors;
    public function __construct(Context $ctx, ?CollectorSet $collectors = null)
    {
        $this->ctx = $ctx;
        $this->collectors = $collectors ?? new CollectorSet();
    }
    protected function collectFiles(array $roots, array $inc): array
    {
        return $this->collectors->code->files($roots, $inc);
    }

    protected function isExcludedRelativePath(string $relative, array $excludeDirs): bool
    {
        $relative = trim(str_replace('\\', '/', $relative), '/');
        foreach ($excludeDirs as $excludeDir) {
            $excludeDir = trim(str_replace('\\', '/', (string)$excludeDir), '/');
            if ($excludeDir !== '' && ($relative === $excludeDir || str_starts_with($relative, $excludeDir . '/'))) {
                return true;
            }
        }
        return false;
    }

    protected function dedupeFindings(array $findings): array
    {
        $deduped = [];
        $seen = [];
        foreach ($findings as $finding) {
            $key = ($finding['file'] ?? '') . ':' . ($finding['line'] ?? '') . ':' . ($finding['kind'] ?? '') . ':' . strtolower((string)($finding['field'] ?? ''));
            if (isset($seen[$key])) {
                continue;
            }

            $seen[$key] = true;
            $deduped[] = $finding;
        }

        return $deduped;
    }

    protected function xmlResourceRefs(string $xml): array
    {
        if (preg_match_all('~<resource\b[^>]*\bref\s*=\s*([\'\"])(?P<ref>[^\'\"]+)\1~i', $xml, $matches) < 1) {
            return [];
        }

        return array_values(array_unique(array_map(static fn(string $ref): string => trim($ref), $matches['ref'])));
    }

    protected function maskSourceComments(string $content, string $extension): string
    {
        $replaceWithSpaces = static fn(array $match): string => str_repeat(' ', strlen($match[0]));
        $masked = preg_replace_callback('~<!--.*?-->~s', $replaceWithSpaces, $content);
        if ($masked === null) {
            $masked = $content;
        }

        if (in_array($extension, ['php', 'phtml', 'js', 'css', 'less'], true)) {
            $blockMasked = preg_replace_callback('~/\*.*?\*/~s', $replaceWithSpaces, $masked);
            if ($blockMasked !== null) {
                $masked = $blockMasked;
            }

            $lineMasked = preg_replace_callback('~(?<!:)//[^\r\n]*~', $replaceWithSpaces, $masked);
            if ($lineMasked !== null) {
                $masked = $lineMasked;
            }
        }

        if (in_array($extension, ['php', 'phtml', 'yaml', 'yml', 'ini'], true)) {
            $hashMasked = preg_replace_callback('~(?m)^[\t ]*#[^\r\n]*~', $replaceWithSpaces, $masked);
            if ($hashMasked !== null) {
                $masked = $hashMasked;
            }
        }

        return $masked;
    }

    protected function maskPhpStringsAndComments(string $content): string
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

    protected function hasSecurityRandomnessSignal(string $text): bool
    {
        return preg_match('~[A-Za-z0-9_.-]*(?:token|otp|one.?time.?password|password|passcode|reset|nonce|secret|api[_-]?key|key|salt|verify|activation|verification[_-]?code|auth[_-]?code|csrf|form[_-]?key|session|cookie|invite|recovery)[A-Za-z0-9_.-]*~i', $text) === 1;
    }

    protected function codeWindow(string $content, int $offset, int $radius): string
    {
        $start = max(0, $offset - $radius);
        return substr($content, $start, $radius * 2);
    }

    protected function relativeFile(string $file): string
    {
        $root = rtrim($this->ctx->path, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
        if (str_starts_with($file, $root)) {
            return str_replace(DIRECTORY_SEPARATOR, '/', substr($file, strlen($root)));
        }

        return str_replace(DIRECTORY_SEPARATOR, '/', $file);
    }

    protected function matchEvidence(string $file, string $content, string $pattern, int $offset): array
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
