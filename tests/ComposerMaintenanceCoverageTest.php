<?php
declare(strict_types=1);
require __DIR__ . '/../vendor/autoload.php';
use Magebean\Engine\Checks\Families\ComposerRepositoryChecks;
use Magebean\Engine\Context;
$check = new ComposerRepositoryChecks(new Context('/unused', ''));
$release = new ReflectionMethod($check, 'assessReleaseRecencyStatuses');
$repo = new ReflectionMethod($check, 'assessRepositoryStatuses');
$packages = [['name' => 'acme/a', 'version' => '1.0.0', 'repository_url' => 'https://github.com/acme/a'], ['name' => 'acme/b', 'version' => '2.0.0', 'repository_url' => 'https://github.com/acme/b']];
$args = ['strict_scope' => true]; $count = 0;
$assert = static function (bool $condition, string $message) use (&$count): void { $count++; if (!$condition) throw new RuntimeException($message); };
set_error_handler(static function (int $severity, string $message): never { throw new RuntimeException($message); });
try {
    $fresh = ['release_history_known' => true, 'latest_date' => date(DATE_ATOM, time() - 86400)];
    $assert($release->invoke($check, $packages, ['acme/a' => $fresh, 'acme/b' => $fresh], $args)[0] === true, 'Complete fresh release histories pass');
    $assert($release->invoke($check, $packages, ['acme/a' => $fresh], $args)[0] === null, 'Missing release status is incomplete without PHP warnings');
    $assert($release->invoke($check, $packages, [], $args)[0] === null, 'Empty response cannot pass release policy');
    $assert($release->invoke($check, $packages, ['acme/a' => ['release_history_known' => false], 'acme/b' => $fresh], $args)[0] === null, 'Unavailable history cannot pass release policy');
    $stale = ['release_history_known' => true, 'latest_date' => '2000-01-01T00:00:00Z'];
    $assert($release->invoke($check, $packages, ['acme/a' => $stale], $args)[0] === false, 'Known stale finding survives partial coverage');
    $future = ['release_history_known' => true, 'latest_date' => '2099-01-01T00:00:00Z'];
    $assert($release->invoke($check, $packages, ['acme/a' => $future, 'acme/b' => $fresh], $args)[0] === null, 'Future release date is invalid');
    $active = ['repository_status_known' => true, 'repository_archived' => false, 'repository_disabled' => false];
    $assert($repo->invoke($check, $packages, ['acme/a' => $active, 'acme/b' => $active], $args)[0] === true, 'Complete explicit active statuses pass');
    $assert($repo->invoke($check, $packages, ['acme/a' => $active], $args)[0] === null, 'One active repository does not hide missing status');
    $assert($repo->invoke($check, $packages, ['acme/a' => ['repository_status_known' => true], 'acme/b' => $active], $args)[0] === null, 'Missing flags cannot pass repository policy');
    $unsupported = ['repository_status_known' => false, 'repository_status_reason' => 'repository_provider_unsupported'];
    $assert($repo->invoke($check, $packages, ['acme/a' => $unsupported, 'acme/b' => $active], $args)[0] === null, 'Unsupported provider is a coverage limitation');
    $archived = $active; $archived['repository_archived'] = true;
    $assert($repo->invoke($check, $packages, ['acme/a' => $archived], $args)[0] === false, 'Known archived repository survives partial coverage');
    echo "Composer maintenance coverage: $count assertions passed\n";
} finally { restore_error_handler(); }
