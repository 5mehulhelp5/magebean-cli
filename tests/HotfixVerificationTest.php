<?php
declare(strict_types=1);
require __DIR__ . '/../vendor/autoload.php';
use Magebean\Engine\Cve\HotfixVerifier;
use Magebean\Engine\Checks\ComposerCheck;
use Magebean\Engine\Context;
function hotfixAssert(bool $ok, string $message): void {
    if (!$ok) throw new RuntimeException($message);
}
$root = sys_get_temp_dir() . '/magebean-hotfix-' . bin2hex(random_bytes(6));
mkdir($root); mkdir($root . '/vendor');
file_put_contents($root . '/vendor/a.php', 'patched-a');
file_put_contents($root . '/vendor/b.php', 'patched-b');
$rule = ['id' => 'TEST-HOTFIX', 'advisories' => ['CVE-TEST'], 'package' => 'test/package',
    'versions' => ['1.0.0'], 'variants' => [['id' => 'v1', 'files' => [
        ['path' => 'vendor/a.php', 'sha256' => hash('sha256', 'patched-a')],
        ['path' => 'vendor/b.php', 'sha256' => hash('sha256', 'patched-b')]]]]];
$verifier = new HotfixVerifier();
$verify = fn($rules) => $verifier->verify($root, 'test/package', '1.0.0', $rules);
try {
    hotfixAssert($verify([$rule])['status'] === 'verified_fixed', 'complete proof');
    file_put_contents($root . '/vendor/b.php', 'original');
    hotfixAssert($verify([$rule])['status'] === 'unverified', 'partial/reverted patch');
    file_put_contents($root . '/vendor/b.php', 'patched-b');
    $bad = $rule; $bad['versions'] = ['1.0.1'];
    hotfixAssert($verify([$bad])['status'] === 'unverified', 'version scope');
    $bad = $rule; $bad['variants'][0]['files'] = [];
    hotfixAssert($verify([$bad])['status'] === 'unverified', 'empty proof');
    $bad = $rule; $bad['variants'][0]['files'][0]['path'] = '../outside';
    hotfixAssert($verify([$bad])['status'] === 'unverified', 'traversal');
    $bad = $rule; $bad['variants'][0]['files'][0]['path'] = 'vendor/missing';
    hotfixAssert($verify([$bad])['status'] === 'unverified', 'missing file');
    $outside = $root . '-outside';
    file_put_contents($outside, 'patched-a');
    symlink($outside, $root . '/vendor/link');
    $bad = $rule; $bad['variants'][0]['files'][0]['path'] = 'vendor/link';
    hotfixAssert($verify([$bad])['status'] === 'unverified', 'symlink escape');

    $check = new ComposerCheck(new Context($root, ''));
    $evaluate = new ReflectionMethod($check, 'evaluateOsvAdvisories');
    $advisory = ['id' => 'GHSA-TEST', 'aliases' => ['CVE-TEST'],
        'affected' => [['package' => ['name' => 'test/package', 'ecosystem' => 'Packagist'],
        'versions' => ['1.0.0'], 'database_specific' => ['magebean_hotfixes' => [$rule]]]]];
    $run = fn($advisories) => $evaluate->invoke($check, $advisories, ['test/package' => '1.0.0'], []);
    $result = $run([$advisory]);
    hotfixAssert($result[0] === true && count($result[2]['remediated_findings']) === 1,
        'verified fix reconciles CVE and retains evidence');
    $other = $advisory; $other['id'] = 'CVE-OTHER'; $other['aliases'] = [];
    $result = $run([$advisory, $other]);
    hotfixAssert($result[0] === false && count($result[2]['findings']) === 1,
        'fix must not hide unrelated CVE');
    file_put_contents($root . '/vendor/b.php', 'original');
    $result = $run([$advisory]);
    hotfixAssert($result[0] === false && $result[2]['findings'][0]['hotfix_verification']['status'] === 'unverified',
        'unrecognized code keeps finding');
    unset($advisory['affected'][0]['database_specific']);
    hotfixAssert($run([$advisory])[0] === false, 'old API remains compatible');
    echo "HotfixVerificationTest passed\n";
} finally {
    foreach (['a.php', 'b.php', 'link'] as $file) {
        if (is_file($root . '/vendor/' . $file) || is_link($root . '/vendor/' . $file)) unlink($root . '/vendor/' . $file);
    }
    if (isset($outside) && is_file($outside)) unlink($outside);
    rmdir($root . '/vendor'); rmdir($root);
}
