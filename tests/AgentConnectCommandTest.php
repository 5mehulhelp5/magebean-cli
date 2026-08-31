<?php
declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

use Magebean\Agent\Http\ConsoleClient;
use Magebean\Console\AgentConnectCommand;

function connectAssert(bool $condition, string $message): void
{
    if (!$condition) {
        fwrite(STDERR, "AgentConnectCommandTest: {$message}\n");
        exit(1);
    }
}

$command = new AgentConnectCommand();
$options = $command->getDefinition()->getOptions();

connectAssert(array_keys($options) === ['code', 'magento-path', 'dev'], 'agent:connect must expose --code, --magento-path and --dev');
connectAssert($options['code']->isValueRequired(), '--code must require a value');
connectAssert($options['magento-path']->isValueRequired(), '--magento-path must require a value');
connectAssert(! $options['dev']->acceptValue(), '--dev must be a boolean flag');
connectAssert(ConsoleClient::DEFAULT_BASE_URL === 'https://console.magebean.com/api', 'unexpected default dashboard API URL');
connectAssert(ConsoleClient::DEV_BASE_URL === 'https://console.magebean.local/api', 'unexpected local dashboard API URL');

echo "AgentConnectCommandTest: PASS\n";
