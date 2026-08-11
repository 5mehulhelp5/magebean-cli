<?php
declare(strict_types=1);
namespace Magebean\Agent;
final class AgentRepository
{
    public const SCHEMA_VERSION = 1;
    public function __construct(public readonly AgentPaths $paths, private readonly AtomicJsonStore $store = new AtomicJsonStore()) { $paths->prepare(); }
    public function config(): array { return $this->load($this->paths->config()); }
    public function credentials(): array { return $this->load($this->paths->credentials()); }
    public function state(): array { return $this->store->read($this->paths->state(), ['schema_version' => self::SCHEMA_VERSION]); }
    public function saveConfig(array $value): void { $this->store->write($this->paths->config(), ['schema_version' => self::SCHEMA_VERSION] + $value); }
    public function saveCredentials(array $value): void { $this->store->write($this->paths->credentials(), ['schema_version' => self::SCHEMA_VERSION] + $value); }
    public function saveState(array $value): void { $this->store->write($this->paths->state(), ['schema_version' => self::SCHEMA_VERSION] + $value); }
    public function isConnected(): bool { return ($this->credentials()['token'] ?? '') !== '' && ($this->config()['console_url'] ?? '') !== ''; }
    public function disconnect(): void { if (is_file($this->paths->credentials())) unlink($this->paths->credentials()); $this->saveState(['connected' => false, 'disconnected_at' => gmdate(DATE_ATOM)]); }
    public function credentialsArePrivate(): bool { return $this->store->permissionsArePrivate($this->paths->credentials()); }
    private function load(string $path): array { $data = $this->store->read($path); $schema = (int)($data['schema_version'] ?? 1); if ($schema > self::SCHEMA_VERSION) throw new \RuntimeException("Unsupported agent schema version {$schema}; update Magebean CLI."); return $data; }
}
