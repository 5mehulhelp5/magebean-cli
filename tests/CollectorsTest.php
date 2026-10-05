<?php
declare(strict_types=1);
require_once __DIR__ . '/../vendor/autoload.php';
use Magebean\Engine\{Context, ScanRunner};
use Magebean\Engine\Checks\{CheckRegistry, CodeSearchCheck, PhpConfigCheck};
use Magebean\Engine\Collectors\{CollectorSet, CollectionSession};

function collectorAssert(bool $ok, string $message): void {
    if (!$ok) throw new RuntimeException($message);
}
$root = sys_get_temp_dir() . '/magebean-collectors-' . bin2hex(random_bytes(6));
mkdir($root . '/source', 0777, true);
try {
    $file = $root . '/source/a.php';
    file_put_contents($file, '<?php echo "fixture";');
    file_put_contents($root . '/source/b.txt', 'fixture');
    file_put_contents($root . '/source/large.php', str_repeat('x', 1048577));
    $set = new CollectorSet();
    $set->session->begin();
    $first = $set->files->read($file);
    file_put_contents($file, '<?php echo "changed";');
    collectorAssert($set->files->read($file) === $first, 'One scan retains the first successful local file observation.');
    collectorAssert($set->session->stats()['hits'] === 1, 'Repeated local read is reused.');
    collectorAssert($set->files->read($root . '/missing') === false, 'Missing file remains a failed read.');
    file_put_contents($root . '/missing', 'new');
    collectorAssert($set->files->read($root . '/missing') === 'new', 'Failed reads are retried rather than cached.');
    $inventory = $set->code->files([$root . '/source', $root . '/source'], ['PHP']);
    collectorAssert($inventory === [$file, $file], 'Inventory keeps root order, duplicates, case insensitive extensions and size limit.');
    $hits = $set->session->stats()['hits'];
    collectorAssert($set->code->files([$root . '/source', $root . '/source'], ['PHP']) === $inventory && $set->session->stats()['hits'] === $hits + 1, 'Identical traversal is shared.');
    collectorAssert($set->code->anyExtension([$file]) === [$file] && $set->code->files([$file], ['php']) === [], 'Any-extension and filtered inventory retain different file-root policies.');
    $set->session->end();
    collectorAssert($set->session->stats()['bytes'] === 0 && $set->session->stats()['entries'] === 0, 'Sensitive observations are released at scan end.');
    $set->session->begin();
    collectorAssert($set->files->read($file) !== $first, 'The next scan reads current file contents.');
    $set->session->end();
    file_put_contents($file, 'standalone');
    collectorAssert($set->files->read($file) === 'standalone', 'Standalone reads are fresh.');
    file_put_contents($file, 'updated');
    collectorAssert($set->files->read($file) === 'updated', 'Standalone reads do not retain snapshots.');
    $small = new CollectionSession(3, 1);
    $small->begin(); $loads = 0;
    $load = static function () use (&$loads): string { $loads++; return 'too large'; };
    $small->remember('large', $load); $small->remember('large', $load);
    collectorAssert($loads === 2 && $small->stats()['bytes'] === 0, 'Oversize observations are not retained.');
    $small->remember('one', static fn(): string => 'a');
    $small->remember('two', static fn(): string => 'b');
    collectorAssert($small->stats()['entries'] === 1, 'Entry limit is enforced.');
    $small->end();
    file_put_contents($root . '/dynamic.php', '<?php $GLOBALS["collector_evaluations"]++; return ["value" => $GLOBALS["collector_evaluations"], "scope" => get_class($this), "relative" => $relativeFile];');
    $GLOBALS['collector_evaluations'] = 0;
    $php = new PhpConfigCheck(new Context($root, ''), $set);
    $set->session->begin();
    $args = ['file' => 'dynamic.php', 'path' => 'value', 'equals' => 1];
    $one = $php->dispatch('php_array_eq', $args);
    $args['equals'] = 2;
    $two = $php->dispatch('php_array_eq', $args);
    collectorAssert($one[0] === true && $two[0] === true && $GLOBALS['collector_evaluations'] === 2, 'Executable PHP configuration is evaluated freshly.');
    $args['path'] = 'scope'; $args['equals'] = PhpConfigCheck::class;
    collectorAssert($php->dispatch('php_array_eq', $args)[0] === true, 'PHP include retains legacy check scope.');
    $set->session->end();
    $lock = $root . '/composer.lock';
    file_put_contents($lock, json_encode(['packages' => [['name' => 'same/package', 'version' => '1', 'source' => ['url' => 'first']]], 'packages-dev' => [['name' => 'same/package', 'version' => '2']]]));
    $set->session->begin();
    $packages = $set->composer->packages($lock);
    $set->composer->packages($lock);
    collectorAssert($packages['same/package']['version'] === '2' && $packages['same/package']['source'] === null && $set->session->stats()['hits'] === 1, 'Composer projection retains packages-dev overwrite and shared reads.');
    $set->session->end();
    $context = new Context($root, '');
    $registry = CheckRegistry::fromContext($context, $set);
    $check = ['name' => 'code_grep', 'args' => ['paths' => ['source'], 'include_ext' => ['php'], 'must_match' => ['updated']]];
    $pack = ['rules' => [
        ['id' => 'A', 'title' => 'Fixture', 'control' => 'T', 'severity' => 'low', 'checks' => [$check]],
        ['id' => 'B', 'title' => 'Fixture', 'control' => 'T', 'severity' => 'low', 'checks' => [$check]],
    ]];
    $report = (new ScanRunner($context, $pack, null, $registry))->run();
    $uncachedSet = new CollectorSet(new CollectionSession(0, 0));
    $uncachedRegistry = CheckRegistry::fromContext($context, $uncachedSet);
    $uncached = (new ScanRunner($context, $pack, null, $uncachedRegistry))->run();
    collectorAssert($report === $uncached && $uncachedSet->session->stats()['hits'] === 0, 'Cached and uncached execution produce identical complete reports on stable input.');
    collectorAssert($report['summary']['passed'] === 2 && $set->session->stats()['hits'] >= 2 && !$set->session->stats()['active'], 'Runner shares reads/traversals and closes session.');
    $direct = new CodeSearchCheck($context);
    collectorAssert($report['findings'][0]['message'] === $direct->grep($check['args'])[1], 'Collector integration preserves the check message.');
    file_put_contents($file, 'removed');
    collectorAssert((new ScanRunner($context, $pack, null, $registry))->run()['summary']['failed'] === 2, 'Reusing a registry starts a fresh cache for the next scan.');
    $registry->register('throwing', static function (array $args): array { throw new RuntimeException('fixture'); });
    $pack['rules'][0]['checks'] = [['name' => 'throwing', 'args' => []]];
    $thrown = false;
    try { (new ScanRunner($context, $pack, null, $registry))->run(); } catch (RuntimeException $e) { $thrown = $e->getMessage() === 'fixture'; }
    collectorAssert($thrown && !$set->session->stats()['active'] && $set->session->stats()['entries'] === 0, 'Exceptions propagate and cleanup runs in finally.');
} finally {
    foreach (glob($root . '/source/*') as $path) unlink($path);
    rmdir($root . '/source');
    foreach (glob($root . '/*') as $path) unlink($path);
    rmdir($root);
    unset($GLOBALS['collector_evaluations']);
}
echo "CollectorsTest passed\n";
