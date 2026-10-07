<?php
declare(strict_types=1);
require_once __DIR__ . '/../vendor/autoload.php';
use Magebean\Engine\Collectors\HttpCollector;
use Magebean\Engine\Checks\HttpCheck;
use Magebean\Engine\Context;
use Magebean\Engine\ScanDeadline;
use Magebean\Engine\Collectors\{CollectorSet, CollectionSession};
use Magebean\Agent\Http\{ConsoleClient, ConsoleRequestException};

function httpCollectorAssert(bool $ok, string $message): void {
    if (!$ok) throw new RuntimeException($message);
}
function exerciseHttpCollector(string $url): array {
    $collector = new HttpCollector();
    $observations = [];
    $observe = static function (bool $ok) use (&$observations): void { $observations[] = $ok; };
    $first = $collector->fetch($url, 'GET', ['X-Probe' => 'one'], 1000, true, null, $observe);
    $second = $collector->fetch($url, 'GET', ['X-Probe' => 'two'], 2000, false, null, $observe);
    $post = $collector->fetch($url, 'POST', ['Content-Type' => 'text/plain'], 1000, true, 'fixture-body', $observe);
    $one = json_decode($first[2]['body'], true);
    $two = json_decode($second[2]['body'], true);
    $three = json_decode($post[2]['body'], true);
    httpCollectorAssert($first[0] === true && $first[2]['status'] === 200 && $one['count'] < $two['count'], 'Repeated HTTP GET probes stay fresh.');
    httpCollectorAssert($one['probe'] === 'one' && $two['probe'] === 'two', 'Request headers are preserved.');
    httpCollectorAssert($three['method'] === 'POST' && $three['body'] === 'fixture-body', 'Request method and body are preserved.');
    httpCollectorAssert(count($first[2]['headers']['set-cookie']) === 2 && $observations === [true, true, true], 'Duplicate cookies and transport observations retain semantics.');
    $redirect = $collector->fetch($url . '/?redirect=1');
    httpCollectorAssert($redirect[2]['status'] === 200 && !isset($redirect[2]['headers']['strict-transport-security']) && $redirect[2]['headers']['x-final'] === 'yes', 'Redirect final response must not inherit HSTS from an earlier hop.');
    httpCollectorAssert($redirect[2]['final_url'] !== $url . '/?redirect=1', 'Both HTTP backends report the effective redirect destination.');
    $resolve = new ReflectionMethod(HttpCollector::class, 'redirectUrl');
    foreach (['../login?x=1'=>'https://store.test/login?x=1', '/account/'=>'https://store.test/account/', '?x=2'=>'https://store.test/path/page?x=2', '//other.test/path'=>'https://other.test/path'] as $location=>$expected) {
        httpCollectorAssert($resolve->invoke($collector, 'https://store.test/path/page', $location) === $expected, 'Redirect resolution preserves destination: '.$location);
    }
    $check = new HttpCheck(new Context('.', $url, '', ['url' => $url]));
    $result = $check->dispatch('http_cache_signals', ['timeout_ms' => 1000]);
    httpCollectorAssert($result[0] === true && $check->getTransportCounts() === ['ok' => 2, 'total' => 2], 'Cache-signal check makes two real requests and counts both.');
    return ['ok' => true, 'curl' => function_exists('curl_init')];
}
if (($argv[1] ?? '') === '--stream-client') {
    echo json_encode(exerciseHttpCollector($argv[2]), JSON_THROW_ON_ERROR);
    exit(0);
}
$root = sys_get_temp_dir() . '/magebean-http-collector-' . bin2hex(random_bytes(6));
mkdir($root);
$server = null;
try {
    $socket = stream_socket_server('tcp://127.0.0.1:0', $errno, $error);
    httpCollectorAssert(is_resource($socket), 'Cannot reserve fixture port.');
    $address = stream_socket_get_name($socket, false);
    fclose($socket);
    $server = proc_open([PHP_BINARY, '-S', $address, __DIR__ . '/support/CollectorHttpRouter.php'], [0 => ['file', '/dev/null', 'r'], 1 => ['file', $root . '/server.log', 'a'], 2 => ['file', $root . '/server.log', 'a']], $pipes, $root);
    httpCollectorAssert(is_resource($server), 'Cannot start fixture server.');
    $ready = false;
    for ($i = 0; $i < 100; $i++) {
        $connection = @stream_socket_client('tcp://' . $address, $errno, $error, 0.05);
        if (is_resource($connection)) { fclose($connection); $ready = true; break; }
        if (!proc_get_status($server)['running']) break;
        usleep(20000);
    }
    httpCollectorAssert($ready, 'Fixture did not start.');
    exerciseHttpCollector('http://' . $address);
    $child = proc_open([PHP_BINARY, '-n', '-d', 'date.timezone=UTC', __FILE__, '--stream-client', 'http://' . $address], [0 => ['file', '/dev/null', 'r'], 1 => ['file', $root . '/stream.out', 'w'], 2 => ['file', $root . '/stream.err', 'w']], $pipes);
    httpCollectorAssert(is_resource($child), 'Cannot start stream fallback test.');
    $exit = proc_close($child);
    $stream = json_decode(file_get_contents($root . '/stream.out'), true);
    httpCollectorAssert($exit === 0 && $stream === ['ok' => true, 'curl' => false], 'Stream fallback failed: ' . file_get_contents($root . '/stream.err'));
    foreach ([400 => false, 408 => true, 429 => true, 503 => true] as $status => $retryable) {
        $thrown = false;
        try { (new ConsoleClient('http://' . $address . '?status=' . $status . '&path=', timeout: 2))->post('probe'); }
        catch (ConsoleRequestException $error) { $thrown = $error->httpStatus === $status && $error->retryable === $retryable; }
        httpCollectorAssert($thrown, 'Agent transport classifies HTTP status ' . $status);
    }
    $thrown = false;
    try { (new ConsoleClient('http://' . $address . '?status=200&invalid=1&path=', timeout: 2))->post('probe'); }
    catch (ConsoleRequestException $error) { $thrown = $error->httpStatus === 200 && $error->retryable; }
    httpCollectorAssert($thrown, 'Malformed successful acknowledgement remains retryable.');
    if (function_exists('curl_init')) {
        $set = new CollectorSet(new CollectionSession());
        $set->session->begin(new ScanDeadline(0.1));
        $attempts = [];
        $start = microtime(true);
        $result = $set->http->fetch('http://' . $address . '/?delay=1', timeoutMs: 5000, observe: static function (bool $ok) use (&$attempts): void { $attempts[] = $ok; });
        $elapsed = microtime(true) - $start;
        $set->session->end();
        httpCollectorAssert($result[0] === null && $attempts === [false] && $elapsed < 0.6, 'HTTP timeout is capped to the remaining scan budget.');
    }
    proc_terminate($server); proc_close($server); $server = null;
    $observed = [];
    $result = (new HttpCollector())->fetch('http://' . $address, 'GET', [], 100, true, null, static function (bool $ok) use (&$observed): void { $observed[] = $ok; });
    httpCollectorAssert($result[0] === null && str_starts_with($result[1], '[UNKNOWN] HTTP error') && $observed === [false], 'Transport failure remains UNKNOWN and records a failed observation.');
} finally {
    if (is_resource($server)) { proc_terminate($server); proc_close($server); }
    foreach (glob($root . '/*') as $path) unlink($path);
    rmdir($root);
}
echo "HttpCollectorTest passed\n";
