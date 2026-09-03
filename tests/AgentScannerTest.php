<?php
declare(strict_types=1);
require_once __DIR__ . '/../vendor/autoload.php';
use Magebean\Agent\AgentScanner;
function scannerAssert(bool $ok,string $message):void{if(!$ok){fwrite(STDERR,"AgentScannerTest: {$message}\n");exit(1);}}
$scanner=new AgentScanner();
$manifest=['schema_version'=>'1.0','manifest_hash'=>'sha256:test','rules'=>[['assessment_item_id'=>'item-1','rule_key'=>'SERVER-COMMAND-NOT-ALLOWED']]];
$result=$scanner->run(__DIR__,$manifest);
scannerAssert(count($result['results'])===1,'unsupported rule must be reported');
scannerAssert($result['results'][0]['status']==='unsupported','unknown rule must not execute');
scannerAssert($result['results'][0]['assessment_item_id']==='item-1','assessment item mapping missing');
scannerAssert($result['manifest_hash']==='sha256:test','manifest hash missing');
$rejected=false;
try{$scanner->run(__DIR__,['schema_version'=>'2.0','rules'=>[['assessment_item_id'=>'item-1','rule_key'=>'MB-R001']]]);}catch(RuntimeException){$rejected=true;}
scannerAssert($rejected,'future manifest schema must be rejected');
$root = sys_get_temp_dir() . '/magebean-agent-title-' . bin2hex(random_bytes(8));
mkdir($root . '/pub/media', 0700, true);
try {
    // Harmless fixture: inspected as text, never executed.
    file_put_contents($root . '/pub/media/unexpected.php', '<?php echo 1;');
    $mediaManifest = ['schema_version' => '1.0', 'manifest_hash' => 'sha256:media', 'rules' => [
        ['assessment_item_id' => 'media-item', 'rule_key' => 'MB-R091'],
    ]];
    $failed = $scanner->run($root, $mediaManifest)['results'][0];
    scannerAssert($failed['status'] === 'fail', 'executable media fixture must fail');
    scannerAssert($failed['title'] === 'Executable code or script-enabling handlers detected in media/upload paths', 'upload must use issue summary, not rule title: ' . $failed['title']);
    scannerAssert($failed['assessment_item_id'] === 'media-item', 'title must preserve item mapping');
    scannerAssert(str_contains($failed['message'], "\n"), 'full message must retain evidence lines');
    scannerAssert($failed['detail'][0]['status'] === 'FAIL', 'failed-check detail must remain intact');
    scannerAssert(!str_contains(json_encode($failed), $root), 'payload must not expose installation root');
    chmod($root . '/pub/media/unexpected.php', 0777);
    $permissions = $scanner->run($root, [
        'schema_version' => '1.0', 'manifest_hash' => 'sha256:permissions',
        'rules' => [['assessment_item_id' => 'permissions-item', 'rule_key' => 'MB-R001']],
    ])['results'][0];
    scannerAssert($permissions['status'] === 'fail', 'world-writable fixture must fail');
    scannerAssert($permissions['title'] === 'World-writable files or directories detected.', 'title must exclude remediation on the same line');
    scannerAssert($permissions['message'] === 'World-writable files or directories detected. Tighten permissions and remove public write access.', 'full result message must retain remediation');
    scannerAssert($permissions['detail'] !== [] && $permissions['evidence'] !== [], 'detailed evidence must remain available');
    unlink($root . '/pub/media/unexpected.php');
    $passed = $scanner->run($root, $mediaManifest)['results'][0];
    scannerAssert($passed['status'] === 'pass', 'empty media directory must pass');
    scannerAssert($passed['title'] === 'No executable code or script-enabling handlers detected in media or upload paths.', 'passing result must retain its actual outcome');
} finally {
    if (is_file($root . '/pub/media/unexpected.php')) unlink($root . '/pub/media/unexpected.php');
    rmdir($root . '/pub/media');
    rmdir($root . '/pub');
    rmdir($root);
}

$titleMethod = new ReflectionMethod(AgentScanner::class, 'resultTitle');
$titleMethod->setAccessible(true);
$titleFor = fn(array $result): string => $titleMethod->invoke($scanner, $result);
foreach ([
    'app/etc/env.php is too permissive. Restrict it to 0640 or tighter.' => 'app/etc/env.php is too permissive.',
    'TLS 1.0 and 1.1 are enabled. Restrict to TLS 1.2+.' => 'TLS 1.0 and 1.1 are enabled.',
    'Sensitive artifacts found under pub/. Remove them.' => 'Sensitive artifacts found under pub/.',
    'Unsafe settings detected! Disable them.' => 'Unsafe settings detected!',
    'Certificate for example.com is invalid. Replace it.' => 'Certificate for example.com is invalid.',
    'app/etc/env.php is writable' => 'app/etc/env.php is writable',
] as $message => $expected) {
    scannerAssert($titleFor(['status' => 'fail', 'message' => $message]) === $expected, 'title must keep only the issue sentence: ' . $message);
}
scannerAssert($titleFor(['status' => 'fail', 'message' => '', 'detail' => [
    ['status' => 'PASS', 'message' => 'Safe'], ['status' => 'FAIL', 'message' => "Actual failure:\r\nEvidence"],
]]) === 'Actual failure', 'empty summary must use failed check, not passing check');
scannerAssert($titleFor(['status' => 'fail', 'message' => ' ', 'title' => 'No executable code']) === 'Security check failed', 'missing outcome must not fall back to rule title');
scannerAssert($titleFor(['status' => 'error', 'message' => '']) === 'Security check could not be completed', 'unknown result must not claim a failure');
scannerAssert($titleFor(['status' => 'fail', 'message' => str_repeat('a', 255)]) === str_repeat('a', 255), '255-character title should remain intact');
scannerAssert($titleFor(['status' => 'fail', 'message' => str_repeat('é', 256)]) === str_repeat('é', 252) . '...', 'long title must truncate safely without corrupting UTF-8');
echo "AgentScannerTest: PASS\n";
