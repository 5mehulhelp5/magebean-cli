<?php
declare(strict_types=1);
require_once __DIR__ . '/../vendor/autoload.php';
use Magebean\Agent\AgentLock;
use Magebean\Agent\AgentPaths;
use Magebean\Agent\AtomicJsonStore;
function agentAssert(bool $ok, string $message): void { if (!$ok) { fwrite(STDERR, "AgentFoundationTest: {$message}\n"); exit(1); } }
$dir = sys_get_temp_dir() . '/magebean-agent-' . bin2hex(random_bytes(5));
try {
    $paths = AgentPaths::resolve($dir);
    $paths->prepare();
    agentAssert(is_dir($paths->pending()), 'pending upload directory missing');
    $store = new AtomicJsonStore();
    $store->write($paths->credentials(), ['token' => 'secret']);
    agentAssert($store->read($paths->credentials())['token'] === 'secret', 'atomic JSON roundtrip failed');
    agentAssert($store->permissionsArePrivate($paths->credentials()), 'credentials permissions are broader than 0600');
    $one = new AgentLock(); $two = new AgentLock();
    agentAssert($one->acquire($paths->lock()), 'first lock failed');
    agentAssert(!$two->acquire($paths->lock()), 'concurrent lock was allowed');
    $one->release();
    agentAssert($two->acquire($paths->lock()), 'released lock was not reusable');
} finally {
    if (is_dir($dir)) {
        $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
        foreach ($files as $file) { $file->isDir() ? rmdir($file->getPathname()) : unlink($file->getPathname()); }
        rmdir($dir);
    }
}
echo "AgentFoundationTest: PASS\n";
