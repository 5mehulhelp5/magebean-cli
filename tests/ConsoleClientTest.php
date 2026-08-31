<?php
declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

use Magebean\Agent\Http\ConsoleClient;

function consoleClientAssert(bool $condition, string $message): void
{
    if (!$condition) {
        fwrite(STDERR, "ConsoleClientTest: {$message}\n");
        exit(1);
    }
}

$client = new ConsoleClient(ConsoleClient::DEFAULT_BASE_URL);
$method = new ReflectionMethod($client, 'errorMessage');

consoleClientAssert(
    $method->invoke($client, ['error' => ['code' => 'method_not_allowed', 'message' => 'Method not allowed']], 405)
        === 'Method not allowed (method_not_allowed) (HTTP 405)',
    'nested API error was not formatted correctly'
);
consoleClientAssert(
    $method->invoke($client, ['message' => 'Invalid pairing code'], 422) === 'Invalid pairing code (HTTP 422)',
    'flat API error was not formatted correctly'
);
consoleClientAssert(
    $method->invoke($client, [], 500) === 'Security Dashboard request rejected (HTTP 500)',
    'fallback API error was not formatted correctly'
);

echo "ConsoleClientTest: PASS\n";
