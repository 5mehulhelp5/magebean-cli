<?php
declare(strict_types=1);
require __DIR__ . '/../vendor/autoload.php';
use Magebean\Engine\{RequirementCatalog, RequirementProfileCatalog, ProfileLoader, ScanContext, ScanRequest, ScanPlanner, LegacyScanPlanner};
use Magebean\Engine\Checks\CheckRegistry;
use Symfony\Component\Console\Tester\CommandTester;
function removedProfileAssert(bool $ok, string $message): void { if (!$ok) throw new RuntimeException($message); }
$root = sys_get_temp_dir() . '/mb-removed-profile-' . bin2hex(random_bytes(5));
mkdir($root);
try {
    $context = new ScanContext($root, '');
    $registry = CheckRegistry::fromContext($context->toLegacy());
    foreach (['baseline', 'all', 'magebean', 'external'] as $name) {
        foreach ([
            'primary catalog' => static fn() => RequirementCatalog::forProfile($name),
            'primary profile loader' => static fn() => RequirementProfileCatalog::load($name),
            'legacy profile loader' => static fn() => ProfileLoader::load($name, $root),
            'primary planner' => static fn() => (new ScanPlanner())->planCli(new ScanRequest($context, ['profile' => $name]), $registry),
            'legacy planner' => static fn() => (new LegacyScanPlanner())->planCli(new ScanRequest($context, ['profile' => $name]), $registry),
            'primary planner with legacy selector' => static fn() => (new ScanPlanner())->planCli(new ScanRequest($context, ['profile' => $name, 'rules' => 'MB-R001']), $registry),
            'legacy planner with legacy selector' => static fn() => (new LegacyScanPlanner())->planCli(new ScanRequest($context, ['profile' => $name, 'rules' => 'MB-R001']), $registry),
            'primary listing' => static fn() => (new CommandTester((new \Magebean\Application())->find('rules:list')))->execute(['--profile' => $name, '--no-ansi' => true]),
        ] as $path => $attempt) {
            $rejected = false;
            try { $attempt(); } catch (RuntimeException $e) { $rejected = str_contains(strtolower($e->getMessage()), 'profile'); }
            removedProfileAssert($rejected, "$path must reject removed profile $name");
        }
    }
    $catalog = RequirementCatalog::loadAll()['rules'];
    $id = $catalog[0]['id'];
    $plan = (new ScanPlanner())->planCli(new ScanRequest($context, ['rules' => $id]), $registry);
    removedProfileAssert($plan !== null && array_column($plan->pack['rules'], 'id') === [$id], 'Explicit selection retains full catalog access without inventory profile');
    removedProfileAssert($plan->metadata['profile_selector'] === 'basic', 'Explicit selection rerun context uses supported default profile');
    echo "RemovedInventoryProfileTest passed\n";
} finally { rmdir($root); }
