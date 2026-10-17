<?php
declare(strict_types=1);
require_once __DIR__.'/../vendor/autoload.php';

use Magebean\Agent\Http\ConsoleTransport;
use Magebean\Agent\Http\ConsoleRequestException;
use Magebean\Agent\OneTimeAssessmentRunner;
use Magebean\Console\OneTimeAssessmentCommand;
use Symfony\Component\Console\Tester\CommandTester;

function oneTimeAssert(bool $ok, string $message): void {
    if (!$ok) throw new RuntimeException($message);
}
$client = new class implements ConsoleTransport {
    public array $uploads = [];
    public function get(string $path, array $headers = []): array {
        oneTimeAssert($path === '/v1/one-time/assessments/test/manifest', 'manifest endpoint');
        return ['assessment_id' => 'test', 'manifest_hash' => 'sha256:test', 'rules' => [['rule_key' => 'MB-TEST']]];
    }
    public function post(string $path, array $body = [], array $headers = []): array {
        throw new RuntimeException('Must not pair, heartbeat or create agent jobs.');
    }
    public function postApi(string $path, array $body = [], array $headers = []): array {
        oneTimeAssert($path === 'one-time/assessments/test/scans', 'upload endpoint');
        $this->uploads[] = $body;
        if (count($this->uploads) === 1) throw new ConsoleRequestException('Response lost');
        return ['scan_id' => 'scan-1'];
    }
};
$root = sys_get_temp_dir().'/magebean-one-time-'.bin2hex(random_bytes(6));
mkdir($root.'/bin', 0700, true);
mkdir($root.'/app', 0700, true);
file_put_contents($root.'/composer.json', json_encode(['require' => ['magento/product-community-edition' => '2.4.8']]));
file_put_contents($root.'/bin/magento', '<?php');
file_put_contents($root.'/app/bootstrap.php', '<?php');
$validator = new Magebean\Agent\MagentoRepositoryValidator();
$validator->assertValid($root);
foreach (['{}', '{invalid', '{"require":{"laravel/framework":"*"}}'] as $invalidComposer) {
    file_put_contents($root.'/composer.json', $invalidComposer);
    try { $validator->assertValid($root); throw new LogicException('Accepted non-Magento repository'); }
    catch (RuntimeException $error) { oneTimeAssert(str_contains($error->getMessage(), 'Not a valid Magento 2'), 'reject invalid Magento composer'); }
}
file_put_contents($root.'/composer.json', json_encode(['require' => ['magento/product-community-edition' => '2.4.8']]));
$noNetwork = new class implements ConsoleTransport {
    public function get(string $path, array $headers = []): array { throw new LogicException('Must validate before HTTP'); }
    public function post(string $path, array $body = [], array $headers = []): array { throw new LogicException('Must not upload'); }
    public function postApi(string $path, array $body = [], array $headers = []): array { throw new LogicException('Must not upload'); }
};
try {
    (new OneTimeAssessmentRunner())->run($noNetwork, 'test', $root.'/bin', function () { throw new LogicException('Must not scan'); });
    throw new LogicException('Accepted non-Magento directory');
} catch (RuntimeException $error) {
    oneTimeAssert(str_contains($error->getMessage(), 'Not a valid Magento 2'), 'reject directory before scanning or network');
}
$scans = 0;
$result = (new OneTimeAssessmentRunner())->run($client, 'test', $root, function ($path, $manifest) use (&$scans) {
    $scans++;
    return ['schema_version' => '1.0', 'manifest_hash' => $manifest['manifest_hash'], 'results' => [['status' => 'pass', 'message' => str_repeat('ế', 10001), 'title' => str_repeat('ế', 256), 'evidence' => ['nested' => ['token' => '[REDACTED]', 'safe' => true]]]]];
});
oneTimeAssert($result['scan_id'] === 'scan-1' && $scans === 1, 'one scan and successful retry');
oneTimeAssert(preg_match('/^.{10000}$/us', $client->uploads[0]['results'][0]['message']) === 1, 'limit message to 10000 Unicode characters');
oneTimeAssert(preg_match('/^.{255}$/us', $client->uploads[0]['results'][0]['title']) === 1, 'limit title to 255 Unicode characters');
oneTimeAssert($client->uploads[0] === $client->uploads[1], 'retry must preserve full payload and UUID');
oneTimeAssert($client->uploads[0]['results'][0]['evidence']['nested'] === ['safe' => true], 'remove sensitive evidence keys recursively');
oneTimeAssert((bool)preg_match('/^[a-f0-9-]{36}$/', $client->uploads[0]['scan_uuid']), 'UUID format');
$command = new OneTimeAssessmentCommand();
oneTimeAssert($command->getDefinition()->hasOption('dev'), 'support dev flag');
oneTimeAssert(! $command->getDefinition()->getOption('dev')->acceptValue(), 'dev is a boolean flag');
$tester = new CommandTester($command);
oneTimeAssert($tester->execute(['--console-url' => 'http://example.com/api']) === 2, 'reject HTTP or missing credentials');
oneTimeAssert(!(str_contains($tester->getDisplay(), 'mbot_')), 'do not print credentials');
oneTimeAssert((new Magebean\Application())->has('assessment:run'), 'register command');
unlink($root.'/composer.json');
unlink($root.'/bin/magento');
unlink($root.'/app/bootstrap.php');
rmdir($root.'/bin');
rmdir($root.'/app');
rmdir($root);

echo "OneTimeAssessmentTest: PASS\n";
