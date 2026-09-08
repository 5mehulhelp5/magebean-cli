<?php

declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

use Magebean\Engine\Checks\ComposerCheck;
use Magebean\Engine\Context;

function assertUnsupportedBranchMessage(bool $condition, string $message): void
{
    if (!$condition) {
        fwrite(STDERR, "AdobeUnsupportedBranchMessageTest: {$message}\n");
        exit(1);
    }
}

$check = new ComposerCheck(new Context(__DIR__, ''));
$method = new ReflectionMethod($check, 'unsupportedBranchMessage');
$method->setAccessible(true);

$sameBranch = $method->invoke($check, [
    'branch' => '2.4.9',
    'reason' => 'lifecycle_not_covered',
    'recommended_latest_branch' => '2.4.9',
    'supported_branches' => ['2.4.8', '2.4.9'],
], '2.4.9');
assertUnsupportedBranchMessage(
    !str_contains($sameBranch, 'upgrade to a supported release line such as 2.4.9'),
    'the unsupported current branch must not be recommended as its own upgrade target'
);
assertUnsupportedBranchMessage(
    str_contains($sameBranch, 'No supported upgrade recommendation is currently available.'),
    'a suppressed recommendation must explain that no valid recommendation is available'
);

$validUpgrade = $method->invoke($check, [
    'branch' => '2.4.7',
    'reason' => 'security_support_ended',
    'recommended_latest_branch' => '2.4.8',
    'supported_branches' => [['branch' => '2.4.8']],
], '2.4.7-p3');
assertUnsupportedBranchMessage(
    str_contains($validUpgrade, 'upgrade to a supported release line such as 2.4.8'),
    'a different recommendation present in supported_branches should be shown'
);

$unsupportedRecommendation = $method->invoke($check, [
    'branch' => '2.4.7',
    'recommended_latest_branch' => '2.4.9',
    'supported_branches' => ['2.4.8'],
], '2.4.7');
assertUnsupportedBranchMessage(
    !str_contains($unsupportedRecommendation, 'such as 2.4.9'),
    'a recommendation absent from supported_branches must not be shown'
);

echo "AdobeUnsupportedBranchMessageTest: PASS\n";
