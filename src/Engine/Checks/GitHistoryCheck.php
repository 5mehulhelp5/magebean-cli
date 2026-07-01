<?php

declare(strict_types=1);

namespace Magebean\Engine\Checks;

use Magebean\Engine\Context;

final class GitHistoryCheck
{
    private Context $ctx;

    public function __construct(Context $ctx)
    {
        $this->ctx = $ctx;
    }

    public function secretScan(array $args): array
    {
        $configuredPatterns = array_values(array_filter(array_map(
            static fn(mixed $pattern): string => trim((string)$pattern),
            (array)($args['patterns'] ?? [])
        ), static fn(string $pattern): bool => $pattern !== ''));
        $patterns = $this->validPatterns($configuredPatterns);
        if ($patterns === []) {
            return [null, '[UNKNOWN] git_history_scan requires at least one valid pattern'];
        }
        if (count($patterns) !== count($configuredPatterns)) {
            return [null, '[UNKNOWN] git_history_scan contains an invalid regular expression'];
        }

        $paths = array_values(array_filter(array_map(
            static fn(mixed $path): string => trim(str_replace('\\', '/', (string)$path), '/'),
            (array)($args['paths'] ?? ['.'])
        ), static fn(string $path): bool => $path !== ''));
        if ($paths === []) {
            $paths = ['.'];
        }
        $excludeDirs = array_values(array_filter(array_map(
            static fn(mixed $path): string => trim(str_replace('\\', '/', (string)$path), '/'),
            (array)($args['exclude_dirs'] ?? [
                '.git', 'vendor', 'var', 'generated', 'node_modules',
                'pub/media', 'pub/static', 'pub/cache',
                'setup', 'dev/tests', 'dev/tools',
            ])
        )));
        $maxResults = max(1, (int)($args['max_results'] ?? 200));
        $maxFileBytes = max(1024, (int)($args['max_file_bytes'] ?? 1048576));
        $repoRoot = $this->ctx->abs('.');

        $workingTree = $this->scanWorkingTree(
            $repoRoot,
            $paths,
            $excludeDirs,
            $patterns,
            $maxResults,
            $maxFileBytes
        );
        $history = $this->scanGitHistory(
            $repoRoot,
            $paths,
            $excludeDirs,
            $patterns,
            $maxResults
        );

        $findings = array_merge($workingTree['findings'], $history['findings']);
        $evidence = [
            'paths' => $paths,
            'exclude_dirs' => $excludeDirs,
            'working_tree_files_scanned' => $workingTree['files_scanned'],
            'working_tree_findings' => $workingTree['findings'],
            'git_history_assessed' => $history['assessed'],
            'git_commits_scanned' => $history['commits_scanned'],
            'git_history_findings' => $history['findings'],
            'truncated' => $workingTree['truncated'] || $history['truncated'],
        ];

        if ($findings !== []) {
            $details = array_map(static function (array $finding): string {
                $location = $finding['path'] . ':' . $finding['line'];
                if (isset($finding['commit'])) {
                    $location = substr((string)$finding['commit'], 0, 12) . ':' . $location;
                }
                return $location . ' [' . $finding['scope'] . ', secret redacted]';
            }, $findings);
            $message = "Potential secrets detected:\n    - " . implode("\n    - ", $details);
            if ($evidence['truncated']) {
                $message .= "\n    Additional matches were omitted after reaching max_results.";
            }
            if (!$history['assessed']) {
                $message .= "\n    Git history was not assessable: " . $history['error'];
            }
            return [false, $message, $evidence];
        }

        if (!$history['assessed']) {
            return [
                null,
                '[UNKNOWN] Working tree is clean, but Git history could not be assessed: '
                    . $history['error'],
                $evidence,
            ];
        }

        return [
            true,
            'No secrets detected in the working tree or ' . $history['commits_scanned'] . ' Git commit(s)',
            $evidence,
        ];
    }

    private function validPatterns(array $patterns): array
    {
        $valid = [];
        foreach ($patterns as $pattern) {
            $pattern = trim((string)$pattern);
            if ($pattern !== '' && @preg_match($this->pcre($pattern), '') !== false) {
                $valid[] = $pattern;
            }
        }
        return $valid;
    }

    private function scanWorkingTree(
        string $repoRoot,
        array $paths,
        array $excludeDirs,
        array $patterns,
        int $maxResults,
        int $maxFileBytes
    ): array {
        $findings = [];
        $filesScanned = 0;
        $truncated = false;

        foreach ($paths as $relative) {
            $target = $relative === '.' ? $repoRoot : $repoRoot . DIRECTORY_SEPARATOR . $relative;
            foreach ($this->filesUnder($target, $repoRoot, $excludeDirs) as $file) {
                if (!$file->isFile() || $file->isLink() || $file->getSize() > $maxFileBytes) {
                    continue;
                }
                $content = @file_get_contents($file->getPathname());
                if (!is_string($content) || str_contains($content, "\0")) {
                    continue;
                }
                $filesScanned++;
                $relativePath = $this->relativePath($repoRoot, $file->getPathname());
                foreach ($patterns as $patternIndex => $pattern) {
                    if (!preg_match_all($this->pcre($pattern), $content, $matches, PREG_OFFSET_CAPTURE)) {
                        continue;
                    }
                    foreach ($matches[0] as $match) {
                        $findings[] = [
                            'scope' => 'working_tree',
                            'path' => $relativePath,
                            'line' => substr_count(substr($content, 0, (int)$match[1]), "\n") + 1,
                            'pattern' => $patternIndex + 1,
                        ];
                        if (count($findings) >= $maxResults) {
                            $truncated = true;
                            break 3;
                        }
                    }
                }
            }
        }

        return [
            'findings' => $findings,
            'files_scanned' => $filesScanned,
            'truncated' => $truncated,
        ];
    }

    private function scanGitHistory(
        string $repoRoot,
        array $paths,
        array $excludeDirs,
        array $patterns,
        int $maxResults
    ): array {
        $gitMetadata = $repoRoot . DIRECTORY_SEPARATOR . '.git';
        if (!is_dir($gitMetadata) && !is_file($gitMetadata)) {
            return $this->historyUnavailable('Git metadata (.git) is unavailable');
        }

        [$revisionExit, $revisionOutput, $revisionError] = $this->run([
            'git', '-C', $repoRoot, 'rev-list', '--all',
        ]);
        if ($revisionExit !== 0) {
            return $this->historyUnavailable(
                'git rev-list failed' . ($revisionError !== '' ? ': ' . trim($revisionError) : '')
            );
        }

        $commits = preg_split('/\r?\n/', trim($revisionOutput), -1, PREG_SPLIT_NO_EMPTY) ?: [];
        if ($commits === []) {
            return [
                'assessed' => true,
                'commits_scanned' => 0,
                'findings' => [],
                'truncated' => false,
                'error' => null,
            ];
        }

        $ere = implode('|', array_map(static fn(string $pattern): string => '(' . $pattern . ')', $patterns));
        $pathspecs = $paths;
        foreach ($excludeDirs as $excludeDir) {
            $pathspecs[] = ':(exclude)' . $excludeDir . '/**';
        }

        $findings = [];
        $seen = [];
        $truncated = false;
        foreach (array_chunk($commits, 50) as $batch) {
            $command = array_merge(
                ['git', '-C', $repoRoot, 'grep', '-I', '-i', '-n', '-E', $ere],
                $batch,
                ['--'],
                $pathspecs
            );
            [$exit, $output, $error] = $this->run($command);
            if (!in_array($exit, [0, 1], true)) {
                return $this->historyUnavailable(
                    'git grep failed' . ($error !== '' ? ': ' . trim($error) : '')
                );
            }
            if ($exit === 1 || trim($output) === '') {
                continue;
            }

            foreach (preg_split('/\r?\n/', trim($output), -1, PREG_SPLIT_NO_EMPTY) ?: [] as $line) {
                if (!preg_match('/^([0-9a-f]{7,64}):(.+?):([0-9]+):/i', $line, $match)) {
                    continue;
                }
                $key = strtolower($match[1]) . ':' . $match[2] . ':' . $match[3];
                if (isset($seen[$key])) {
                    continue;
                }
                $seen[$key] = true;
                $findings[] = [
                    'scope' => 'git_history',
                    'commit' => strtolower($match[1]),
                    'path' => $match[2],
                    'line' => (int)$match[3],
                ];
                if (count($findings) >= $maxResults) {
                    $truncated = true;
                    break 2;
                }
            }
        }

        return [
            'assessed' => true,
            'commits_scanned' => count($commits),
            'findings' => $findings,
            'truncated' => $truncated,
            'error' => null,
        ];
    }

    private function filesUnder(string $target, string $repoRoot, array $excludeDirs): iterable
    {
        if (is_file($target)) {
            yield new \SplFileInfo($target);
            return;
        }
        if (!is_dir($target)) {
            return;
        }

        $directory = new \RecursiveDirectoryIterator($target, \FilesystemIterator::SKIP_DOTS);
        $filter = new \RecursiveCallbackFilterIterator(
            $directory,
            function (\SplFileInfo $file) use ($repoRoot, $excludeDirs): bool {
                $relative = $this->relativePath($repoRoot, $file->getPathname());
                foreach ($excludeDirs as $excludeDir) {
                    if ($relative === $excludeDir || str_starts_with($relative, $excludeDir . '/')) {
                        return false;
                    }
                }
                return !$file->isLink();
            }
        );
        yield from new \RecursiveIteratorIterator($filter);
    }

    private function run(array $command): array
    {
        $pipes = [];
        try {
            $process = @proc_open($command, [
                1 => ['pipe', 'w'],
                2 => ['pipe', 'w'],
            ], $pipes, null, null, ['bypass_shell' => true]);
        } catch (\Throwable $error) {
            return [127, '', $error->getMessage()];
        }
        if (!is_resource($process)) {
            return [127, '', 'Unable to start git process'];
        }
        $stdout = stream_get_contents($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        return [proc_close($process), (string)$stdout, (string)$stderr];
    }

    private function historyUnavailable(string $error): array
    {
        return [
            'assessed' => false,
            'commits_scanned' => 0,
            'findings' => [],
            'truncated' => false,
            'error' => $error,
        ];
    }

    private function pcre(string $pattern): string
    {
        return '~' . str_replace('~', '\\~', $pattern) . '~im';
    }

    private function relativePath(string $root, string $path): string
    {
        return str_replace(
            '\\',
            '/',
            ltrim(substr($path, strlen(rtrim($root, DIRECTORY_SEPARATOR))), DIRECTORY_SEPARATOR)
        );
    }
}