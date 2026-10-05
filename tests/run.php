<?php
declare(strict_types=1);

// Standalone tests define their own helpers: execute each in a separate process.
if (!function_exists('proc_open')) {
    fwrite(STDERR, "Test runner requires proc_open.\n");
    exit(1);
}
$failures = [];
$tests = glob(__DIR__ . '/*Test.php') ?: [];
sort($tests);
if ($tests === []) {
    fwrite(STDERR, "No tests found.\n");
    exit(1);
}
foreach ($tests as $test) {
    $pipes = [];
    $process = proc_open([PHP_BINARY, $test], [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, dirname(__DIR__));
    if (!is_resource($process)) { $failures[] = basename($test); echo 'FAIL ', basename($test), " (cannot start)\n"; continue; }
    fclose($pipes[0]);
    stream_set_blocking($pipes[1], false);
    stream_set_blocking($pipes[2], false);
    $deadline = microtime(true) + 45.0;
    $output = '';
    $exit = null;
    $failureReason = '';
    do {
        $output .= (string)stream_get_contents($pipes[1]);
        $output .= (string)stream_get_contents($pipes[2]);
        $status = proc_get_status($process);
        if (!$status['running']) { $exit = $status['exitcode']; break; }
        if (strlen($output) > 1048576 || microtime(true) >= $deadline) {
            $failureReason = strlen($output) > 1048576 ? 'output limit exceeded' : '45-second timeout';
            proc_terminate($process);
            // Give cooperative cleanup a short grace period, then stop the test.
            usleep(100000);
            if (proc_get_status($process)['running']) proc_terminate($process, 9);
            $exit = 124;
            break;
        }
        usleep(10000);
    } while (true);
    $output .= (string)stream_get_contents($pipes[1]);
    $output .= (string)stream_get_contents($pipes[2]);
    fclose($pipes[1]); fclose($pipes[2]);
    $closed = proc_close($process);
    if ($exit === null || $exit < 0) $exit = $closed;
    echo ($exit === 0 ? 'PASS ' : 'FAIL '), basename($test), "\n";
    if ($exit !== 0) {
        $failures[] = basename($test);
        if ($failureReason !== '') echo $failureReason, "\n";
        echo substr($output, 0, 16000), "\n";
    }
}
printf("\n%d tests, %d passed, %d failed.\n", count($tests), count($tests) - count($failures), count($failures));
exit($failures === [] ? 0 : 1);
