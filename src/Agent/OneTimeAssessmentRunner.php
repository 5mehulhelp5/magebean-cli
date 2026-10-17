<?php
declare(strict_types=1);
namespace Magebean\Agent;

use Magebean\Agent\Http\ConsoleTransport;
use Magebean\Agent\Http\ConsoleRequestException;

final class OneTimeAssessmentRunner
{
    public function run(ConsoleTransport $client, string $assessment, string $path, callable $scan): array
    {
        (new MagentoRepositoryValidator())->assertValid($path);
        $endpoint = 'one-time/assessments/' . rawurlencode($assessment);
        $manifest = $client->get('/v1/' . $endpoint . '/manifest');
        if (($manifest['assessment_id'] ?? null) !== $assessment || empty($manifest['rules']) || empty($manifest['manifest_hash'])) {
            throw new \RuntimeException('Invalid one-time assessment manifest.');
        }
        $started = gmdate(DATE_ATOM);
        $result = $this->minimalEvidence($scan($path, $manifest));
        foreach ($result['results'] as &$item) {
            foreach (['message' => 10000, 'title' => 255] as $field => $limit) {
                if (isset($item[$field]) && is_string($item[$field])
                    && preg_match('/^(.{0,' . ($limit - 3) . '}).{4}/us', $item[$field], $match) === 1) {
                    $item[$field] = $match[1] . '...';
                }
            }
        }
        unset($item);
        $bytes = random_bytes(16);
        $bytes[6] = chr((ord($bytes[6]) & 15) | 64);
        $bytes[8] = chr((ord($bytes[8]) & 63) | 128);
        $hex = bin2hex($bytes);
        $uuid = substr($hex, 0, 8).'-'.substr($hex, 8, 4).'-'.substr($hex, 12, 4).'-'.substr($hex, 16, 4).'-'.substr($hex, 20);
        $payload = $result + ['scan_uuid' => $uuid, 'cli_version' => \Magebean\Application::VERSION, 'started_at' => $started, 'completed_at' => gmdate(DATE_ATOM)];
        for ($attempt = 0; ; $attempt++) {
            try { return $client->postApi($endpoint . '/scans', $payload); }
            catch (ConsoleRequestException $error) {
                if ($attempt >= 2 || !$error->retryable) throw $error;
            }
        }
    }

    private function minimalEvidence(array $value): array
    {
        $safe = [];
        foreach ($value as $key => $entry) {
            if (is_string($key) && preg_match('/password|secret|token|private_key|file_content|customer_data/i', $key)) continue;
            $safe[$key] = is_array($entry) ? $this->minimalEvidence($entry) : $entry;
        }
        return $safe;
    }
}
