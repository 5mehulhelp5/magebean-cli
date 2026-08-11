<?php
declare(strict_types=1);

namespace Magebean\Agent;

final class AgentLock
{
    private mixed $handle = null;
    public function acquire(string $path): bool
    {
        $this->handle = fopen($path, 'c+');
        if ($this->handle === false) throw new \RuntimeException("Cannot open lock: {$path}");
        @chmod($path, 0600);
        if (!flock($this->handle, LOCK_EX | LOCK_NB)) { fclose($this->handle); $this->handle = null; return false; }
        ftruncate($this->handle, 0);
        fwrite($this->handle, (string)getmypid());
        return true;
    }
    public function release(): void
    {
        if (is_resource($this->handle)) { flock($this->handle, LOCK_UN); fclose($this->handle); }
        $this->handle = null;
    }
    public function __destruct() { $this->release(); }
}
