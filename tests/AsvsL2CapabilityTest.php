<?php

declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

use Magebean\Engine\ProfileLoader;
use Magebean\Engine\RulePackLoader;

function assertCapability(bool $condition, string $message): void
{
    if (!$condition) {
        fwrite(STDERR, $message . "\n");
        exit(1);
    }
}

$contextControl = json_decode((string)file_get_contents(__DIR__ . '/../src/Rules/controls/MB-C16.json'), true, 512, JSON_THROW_ON_ERROR);
assertCapability(count($contextControl['rules'] ?? []) === 55, 'Expected 55 contextual ASVS L2 rules');
assertCapability(array_column($contextControl['rules'] ?? [], 'id') === array_map(static fn(int $id): string => sprintf('MB-R%03d', $id), range(218, 272)), 'Contextual rule IDs must be sequential');
foreach ($contextControl['rules'] ?? [] as $rule) {
    assertCapability(isset($rule['applicability']['capability']), 'Every contextual rule must declare a capability');
}

$profile = ProfileLoader::load('asvs-l2');
$catalog = RulePackLoader::loadAll();

$ids = static fn(array $pack): array => array_column($pack['rules'] ?? [], 'id');
$default = $ids(ProfileLoader::apply($catalog, $profile));
assertCapability(count($default) === 183, 'Default L2 selection must exclude capability-dependent rules');
assertCapability(!in_array('MB-R275', $default, true), 'GraphQL automated rule must be inactive by default');

$graphql = $ids(ProfileLoader::apply($catalog, $profile, false, ['graphql' => true]));
assertCapability(count($graphql) === 184, 'GraphQL capability must add exactly its automated rule');
assertCapability(in_array('MB-R275', $graphql, true), 'GraphQL automated rule was not activated');

$oauth = $ids(ProfileLoader::apply($catalog, $profile, false, ['oauth_oidc' => true]));
assertCapability(count($oauth) === 207, 'OAuth/OIDC capability must activate 24 conditional review rules');

$webrtc = $ids(ProfileLoader::apply($catalog, $profile, false, ['webrtc']));
assertCapability(count($webrtc) === 190, 'List-form capability configuration must activate seven WebRTC rules');

$disabled = $ids(ProfileLoader::apply($catalog, $profile, false, ['webrtc' => false]));
assertCapability($disabled === $default, 'Explicitly disabled capability must not activate contextual rules');

echo "AsvsL2CapabilityTest: PASS\n";
