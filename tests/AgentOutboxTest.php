<?php
declare(strict_types=1);
require_once __DIR__ . '/../vendor/autoload.php';
use Magebean\Agent\{AgentPaths, AgentRepository, PendingOutbox, AtomicJsonStore, TickRunner, AgentScanner, AgentLock};
use Magebean\Agent\Http\{ConsoleTransport, ConsoleRequestException};

function outboxAssert(bool $ok, string $message): void { if (!$ok) throw new RuntimeException($message); }
final class OutboxTestTransport implements ConsoleTransport
{
    public array $calls = [];
    public int $failUploads = 0;
    public int $failCompletions = 0;
    public array $jobs = [];
    public array $manifest = ['schema_version' => '1.0', 'manifest_hash' => 'fixture', 'rules' => [['rule_key' => 'MB-R091', 'assessment_item_id' => 'item']]];
    public function get(string $path, array $headers = []): array { $this->calls[] = ['GET', $path, [], $headers]; return $this->manifest; }
    public function post(string $path, array $body = [], array $headers = []): array {
        $this->calls[] = ['POST', $path, $body, $headers];
        if (str_ends_with($path, '/complete') && $this->failCompletions-- > 0) throw new ConsoleRequestException('completion failed', 503);
        return $path === 'jobs/claim' ? ['job' => array_shift($this->jobs)] : [];
    }
    public function postApi(string $path, array $body = [], array $headers = []): array {
        $this->calls[] = ['API', $path, $body, $headers];
        if ($this->failUploads-- > 0) throw new ConsoleRequestException('upload response lost', 503);
        return [];
    }
}
$root = sys_get_temp_dir() . '/magebean-outbox-' . bin2hex(random_bytes(6));
$paths = AgentPaths::resolve($root . '/agent');
$paths->prepare();
$store = new AtomicJsonStore();
$entry = ['assessment_id' => 'assessment', 'job_id' => 'job', 'lease_token' => 'lease', 'payload' => ['scan_uuid' => 'fixture-uuid', 'summary' => ['total' => 1], 'results' => [['status' => 'pass']]]];
try {
    $outbox = new PendingOutbox($paths);
    $client = new OutboxTestTransport();
    $client->failUploads = 1;
    $file = $outbox->enqueue($entry);
    $thrown = false;
    try { $outbox->deliver($file, $client); } catch (ConsoleRequestException) { $thrown = true; }
    outboxAssert($thrown && $store->read($file) === $entry, 'Unacknowledged upload preserves the exact queued payload.');
    outboxAssert($store->permissionsArePrivate($file), 'Pending payload permissions stay private.');
    $original = file_get_contents($file);
    $thrown = false;
    try { $store->write($file, ['invalid' => "\xFF"]); } catch (JsonException) { $thrown = true; }
    outboxAssert($thrown && file_get_contents($file) === $original && glob($paths->pending() . '/.magebean-*') === [], 'Serialization failure leaves the previous durable record intact without temp files.');
    $client->failCompletions = 1;
    try { (new PendingOutbox($paths))->retry($client); } catch (ConsoleRequestException) {}
    $uploaded = $store->read($file);
    outboxAssert($uploaded['_delivery']['stage'] === 'uploaded' && $uploaded['payload'] === $entry['payload'], 'Completion failure retains acknowledged upload stage and original payload.');
    outboxAssert($client->calls[0][2] === $client->calls[1][2] && $client->calls[0][3]['Idempotency-Key'] === $client->calls[1][3]['Idempotency-Key'], 'Lost response retries same scan UUID, payload and idempotency key.');
    $apiCount = count(array_filter($client->calls, static fn(array $call): bool => $call[0] === 'API'));
    (new PendingOutbox($paths))->retry($client);
    outboxAssert(!is_file($file) && count(array_filter($client->calls, static fn(array $call): bool => $call[0] === 'API')) === $apiCount, 'Restart at uploaded stage retries completion without reuploading.');
    $completed = $entry; $completed['_delivery'] = ['stage' => 'completed'];
    $store->write($file, $completed);
    $callCount = count($client->calls);
    $outbox->retry($client);
    outboxAssert(!is_file($file) && count($client->calls) === $callCount, 'Crash after completed acknowledgement only requires local cleanup.');
    $badFile = $paths->pending() . '/corrupt.json';
    file_put_contents($badFile, '{bad');
    $thrown = false;
    try { $outbox->retry($client); } catch (RuntimeException) { $thrown = true; }
    outboxAssert($thrown && is_file($badFile) && count($client->calls) === $callCount, 'Corruption is surfaced without deleting pending data or sending malformed requests.');
    unlink($badFile);
    $bad = $entry; $bad['_delivery'] = ['stage' => 'invented']; $store->write($file, $bad);
    $thrown = false;
    try { $outbox->retry($client); } catch (RuntimeException) { $thrown = true; }
    outboxAssert($thrown && is_file($file), 'Unknown stages are retained for inspection.');
    unlink($file);
    // Local acknowledgement bookkeeping failure retains the completed stage.
    $store->write($file, $entry);
    $thrown = false;
    try { $outbox->deliver($file, $client, static function (array $entry): void { throw new RuntimeException('state write failed'); }); } catch (RuntimeException) { $thrown = true; }
    outboxAssert($thrown && $store->read($file)['_delivery']['stage'] === 'completed', 'Local state failure retains the acknowledged record.');
    $callCount = count($client->calls); $bookkept = false;
    $outbox->retry($client, static function (array $entry) use (&$bookkept): void { $bookkept = $entry['job_id'] === 'job'; });
    outboxAssert($bookkept && !is_file($file) && count($client->calls) === $callCount, 'Restart retries local bookkeeping without repeating server requests.');
    // Existing entries without delivery metadata remain readable.
    $store->write($file, $entry); $outbox->retry($client);
    outboxAssert(!is_file($file), 'Legacy pending schema migrates through delivery.');
    $traversal = $entry; $traversal['payload']['scan_uuid'] = '../escape';
    $thrown = false;
    try { $outbox->enqueue($traversal); } catch (RuntimeException) { $thrown = true; }
    outboxAssert($thrown, 'Enqueue rejects UUID path traversal.');
    mkdir($root . '/magento/pub/media', 0700, true);
    $repo = new AgentRepository($paths);
    $repo->saveConfig(['console_url' => 'https://fixture.invalid/api', 'magento_path' => $root . '/magento']);
    $repo->saveCredentials(['token' => 'fixture']);
    $tickClient = new OutboxTestTransport();
    $tickClient->jobs = [['id' => 'job1', 'assessment_id' => 'assessment', 'lease_token' => 'lease']];
    $tickClient->failCompletions = 1;
    $tick = new TickRunner($repo, new AgentScanner(), static fn(array $config, array $credentials): ConsoleTransport => $tickClient);
    $thrown = false;
    try { $tick->run(); } catch (ConsoleRequestException) { $thrown = true; }
    $pending = glob($paths->pending() . '/*.json');
    outboxAssert($thrown && count($pending) === 1 && $store->read($pending[0])['_delivery']['stage'] === 'uploaded', 'Real tick persists completed scan until job completion acknowledgement.');
    outboxAssert(!array_filter($tickClient->calls, static fn(array $call): bool => str_ends_with($call[1], '/fail')), 'Durably queued scans are not incorrectly marked failed after delivery error.');
    $lock = new AgentLock();
    outboxAssert($lock->acquire($paths->lock()), 'Tick releases its lock after delivery error.'); $lock->release();
    $before = count($tickClient->calls);
    outboxAssert($tick->run() === 'idle' && glob($paths->pending() . '/*.json') === [], 'Next tick completes pending delivery before claiming more work.');
    outboxAssert($repo->state()['last_job_id'] === 'job1' && $repo->state()['last_scan_uuid'] !== '', 'Recovered delivery updates local last-job and scan state.');
    outboxAssert($tickClient->calls[$before][1] === 'jobs/job1/complete', 'Pending completion runs before heartbeat/claim.');
    outboxAssert(count(array_filter($tickClient->calls, static fn(array $call): bool => $call[0] === 'API')) === 1, 'Retry does not rescan or reupload acknowledged results.');
    $tickClient->jobs = [['id' => 'job2', 'assessment_id' => 'assessment', 'lease_token' => 'lease']];
    outboxAssert($tick->run() === 'completed job job2' && $repo->state()['last_job_id'] === 'job2', 'Normal successful tick preserves return and state contract.');
    $tickClient->manifest = ['schema_version' => 'broken'];
    $tickClient->jobs = [['id' => 'job3', 'assessment_id' => 'assessment', 'lease_token' => 'lease']];
    $thrown = false;
    try { $tick->run(); } catch (RuntimeException) { $thrown = true; }
    outboxAssert($thrown && count(array_filter($tickClient->calls, static fn(array $call): bool => $call[1] === 'jobs/job3/fail')) === 1, 'Errors before durable enqueue still fail the job.');
} finally {
    if (is_dir($root)) {
        $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
        foreach ($files as $file) $file->isDir() ? rmdir($file->getPathname()) : unlink($file->getPathname());
        rmdir($root);
    }
}
echo "AgentOutboxTest passed\n";
