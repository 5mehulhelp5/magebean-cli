<?php
declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

use Magebean\Agent\AgentPaths;
use Magebean\Agent\AgentRepository;
use Magebean\Agent\TickRunner;

function healthAssert(bool $condition, string $message): void
{
    if (! $condition) {
        fwrite(STDERR, "AgentHealthPayloadTest: {$message}\n");
        exit(1);
    }
}

$root = sys_get_temp_dir().'/magebean-health-'.bin2hex(random_bytes(5));
$magento = $root.'/magento';
mkdir($magento.'/app', 0777, true);
mkdir($magento.'/bin', 0777, true);
touch($magento.'/app/bootstrap.php');
touch($magento.'/bin/magento');

try {
    $runner = new TickRunner(new AgentRepository(AgentPaths::resolve($root.'/agent')));
    $method = new ReflectionMethod($runner, 'health');
    $healthy = $method->invoke($runner, $magento);
    healthAssert($healthy['status'] === 'healthy', 'valid Magento paths must report healthy');

    unlink($magento.'/bin/magento');
    $warning = $method->invoke($runner, $magento);
    healthAssert($warning['status'] === 'warning', 'missing Magento CLI must report warning');
} finally {
    if (is_dir($root)) {
        $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
        foreach ($files as $file) {
            $file->isDir() ? rmdir($file->getPathname()) : unlink($file->getPathname());
        }
        rmdir($root);
    }
}

echo "AgentHealthPayloadTest: PASS\n";