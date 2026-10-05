<?php
declare(strict_types=1);
namespace Magebean\Agent;
use Magebean\Agent\Http\ConsoleTransport;

/** Delivery is durable until both upload and job completion have been acknowledged. */
final class PendingOutbox
{
    public function __construct(private readonly AgentPaths $paths, private readonly AtomicJsonStore $store = new AtomicJsonStore()) {}

    public function enqueue(array $entry): string
    {
        $this->validate($entry);
        $uuid = (string)$entry['payload']['scan_uuid'];
        if (!preg_match('/^[a-zA-Z0-9-]+$/D', $uuid)) throw new \RuntimeException('Invalid pending scan UUID.');
        $file = $this->paths->pending() . '/' . $uuid . '.json';
        if (is_file($file)) throw new \RuntimeException('Pending scan already exists: ' . $uuid);
        $this->store->write($file, $entry);
        return $file;
    }

    /** At most one attempt per delivery step, per tick. Retry happens on the next tick. */
    public function retry(ConsoleTransport $client, ?callable $completed = null): void
    {
        foreach (glob($this->paths->pending() . '/*.json') ?: [] as $file) $this->deliver($file, $client, $completed);
    }

    public function deliver(string $file, ConsoleTransport $client, ?callable $completed = null): void
    {
        $entry = $this->store->read($file);
        $this->validate($entry);
        $stage = $entry['_delivery']['stage'] ?? 'queued';
        if (!in_array($stage, ['queued', 'uploaded', 'completed'], true)) throw new \RuntimeException('Invalid pending delivery stage.');
        $uuid = (string)$entry['payload']['scan_uuid'];
        $headers = ['X-Magebean-Lease' => (string)$entry['lease_token']];
        if ($stage === 'queued') {
            $client->postApi('assessments/' . $entry['assessment_id'] . '/scans', $entry['payload'], ['Idempotency-Key' => $uuid] + $headers);
            // A crash before this write replays the same payload/idempotency key.
            $entry['_delivery'] = ['stage' => 'uploaded'];
            $this->store->write($file, $entry);
            $stage = 'uploaded';
        }
        if ($stage === 'uploaded') {
            $client->post('jobs/' . $entry['job_id'] . '/complete', ['schema_version' => '1.0', 'scan_uuid' => $uuid], $headers);
            $entry['_delivery'] = ['stage' => 'completed'];
            $this->store->write($file, $entry);
        }
        if ($completed !== null) $completed($entry);
        // Completed entries left by an interrupted cleanup do not send requests again.
        if (!unlink($file)) throw new \RuntimeException('Cannot remove completed pending scan.');
    }

    private function validate(array $entry): void
    {
        foreach (['assessment_id', 'job_id', 'lease_token'] as $key) {
            if (!isset($entry[$key]) || !is_scalar($entry[$key]) || ($key !== 'lease_token' && (string)$entry[$key] === ''))
                throw new \RuntimeException('Invalid pending scan field: ' . $key);
        }
        if (!is_array($entry['payload'] ?? null) || !is_string($entry['payload']['scan_uuid'] ?? null) || $entry['payload']['scan_uuid'] === '')
            throw new \RuntimeException('Invalid pending scan payload.');
        if (isset($entry['_delivery']) && !is_array($entry['_delivery'])) throw new \RuntimeException('Invalid pending delivery metadata.');
    }
}
