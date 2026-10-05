<?php
declare(strict_types=1);
require_once __DIR__ . '/../vendor/autoload.php';
use Magebean\Engine\{ScanContext, ScanRequest, ScanPlan, ScanReport, ScanReportAssembler, ScanDiagnostic, CheckResult, CheckOutcome};
use Magebean\Engine\Checks\{CodeSearchCheck, ComposerCheck};
use Magebean\Console\ScanConsoleRenderer;
use Symfony\Component\Console\Output\BufferedOutput;

function architectureAssert(bool $ok, string $message): void { if (!$ok) throw new RuntimeException($message); }
$fixture = json_decode(file_get_contents(__DIR__ . '/fixtures/architecture/check-api.json'), true, 512, JSON_THROW_ON_ERROR);
$actual = [];
foreach ([CodeSearchCheck::class, ComposerCheck::class] as $class) {
    $reflection = new ReflectionClass($class);
    foreach ($reflection->getMethods(ReflectionMethod::IS_PUBLIC) as $method) {
        if ($method->isConstructor()) continue;
        $parameters = [];
        foreach ($method->getParameters() as $parameter) {
            $parameters[] = (string)$parameter->getType() . ' $' . $parameter->getName();
            architectureAssert(!$parameter->isOptional() && !$parameter->isPassedByReference() && !$parameter->isVariadic(), 'Legacy check parameter contract changed.');
        }
        $key = $reflection->getShortName() . '.' . $method->getName();
        $actual[$key] = 'public function ' . $method->getName() . '(' . implode(', ', $parameters) . '): ' . $method->getReturnType();
    }
}
ksort($fixture); ksort($actual);
architectureAssert($actual === $fixture, 'Legacy public check API changed during family extraction.');
$domainFiles = ['ScanPlanner', 'ScanTargetResolver', 'ResolvedScanTarget', 'ProjectPath', 'ScanReportAssembler', 'ScanService', 'ScanExitPolicy', 'ScanDiagnostic'];
foreach ($domainFiles as $name) {
    $source = file_get_contents(__DIR__ . '/../src/Engine/' . $name . '.php');
    architectureAssert(!str_contains($source, 'Symfony\\') && !str_contains($source, 'Magebean\\Console\\'), 'Application/domain service depends on console: ' . $name);
}
$planner = file_get_contents(__DIR__ . '/../src/Engine/ScanPlanner.php');
architectureAssert(!preg_match('/<(?:info|comment|error)>/', $planner), 'Planner must emit plain diagnostics.');
$output = new BufferedOutput(32, false);
$diagnostic = new ScanDiagnostic('comment', 'Unknown rule id:', ' fixture');
(new ScanConsoleRenderer())->diagnostic($output, $diagnostic);
architectureAssert($diagnostic->message() === 'Unknown rule id: fixture' && trim($output->fetch()) === $diagnostic->message(), 'Diagnostic rendering preserves plain content.');
$observation = CheckResult::of(CheckOutcome::Pass, 'fixture', [], 'FIXTURE', 'fixture');
$report = ScanReport::fromLegacy(['summary' => ['passed' => 1, 'failed' => 0, 'total' => 1], 'findings' => [['id' => 'FIXTURE', 'status' => 'PASS']], 'meta' => ['original' => 'retained'], 'extension' => ['retained' => true]], [[$observation]]);
$request = new ScanRequest(new ScanContext('/fixture', '', '', ['meta' => ['target_mode' => 'LOCAL']]));
$metadata = ['configBasePath' => '/fixture', 'configFile' => null, 'activeProfile' => ['id' => 'fixture'], 'standard' => 'fixture', 'isPciProfile' => false, 'profileRulesTotal' => 1, 'profileManualRulesTotal' => 0, 'manualRulesExcluded' => 0, 'includeManualReview' => false, 'hasExplicitRuleSelection' => false, 'requestedIds' => [], 'controlsFilter' => []];
$assembled = (new ScanReportAssembler())->assemble($report, new ScanPlan($request, ['rules' => []], $metadata));
architectureAssert($assembled->checkResults[0][0] === $observation && $assembled->toLegacy()['extension'] === ['retained' => true] && $assembled->meta['original'] === 'retained', 'Report assembly must retain internal observations and external extensions.');
architectureAssert($assembled->summary['path'] === '/fixture' && $assembled->meta['profile']['id'] === 'fixture' && !str_contains(json_encode($assembled), 'FIXTURE\",\"checkName'), 'Assembler preserves canonical target/profile without exporting internal observations.');
echo "ArchitectureBoundaryTest passed\n";
