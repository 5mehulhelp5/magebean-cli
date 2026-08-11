<?php
declare(strict_types=1);

namespace Magebean\Agent;

final class AgentPaths
{
    public function __construct(public readonly string $root) {}

    public static function resolve(?string $option = null): self
    {
        $root = trim((string)$option);
        if ($root === '') $root = trim((string)getenv('MAGEBEAN_HOME'));
        if ($root === '') {
            $home = trim((string)(getenv('HOME') ?: getenv('USERPROFILE')));
            if ($home === '') throw new \RuntimeException('Cannot resolve home directory; use --config-dir or MAGEBEAN_HOME.');
            $root = $home . DIRECTORY_SEPARATOR . '.magebean';
        }
        return new self(rtrim($root, '/\\'));
    }

    public function prepare(): void
    {
        foreach ([$this->root, $this->cache(), $this->pending(), $this->logs()] as $dir) {
            if (!is_dir($dir) && !mkdir($dir, 0700, true) && !is_dir($dir)) {
                throw new \RuntimeException("Cannot create agent directory: {$dir}");
            }
            @chmod($dir, 0700);
        }
    }

    public function config(): string { return $this->root . '/config.json'; }
    public function credentials(): string { return $this->root . '/credentials.json'; }
    public function state(): string { return $this->root . '/state.json'; }
    public function lock(): string { return $this->root . '/agent.lock'; }
    public function cache(): string { return $this->root . '/cache/manifests'; }
    public function pending(): string { return $this->root . '/queue/pending-uploads'; }
    public function logs(): string { return $this->root . '/logs'; }
}
