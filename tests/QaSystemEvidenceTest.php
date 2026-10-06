<?php
declare(strict_types=1);
require_once __DIR__ . '/../vendor/autoload.php';
use Magebean\Engine\Checks\SystemCheck;
$root = sys_get_temp_dir() . '/magebean-qa-system-' . bin2hex(random_bytes(6));
mkdir($root); $oldPath = getenv('PATH'); $count = 0;
try {
    file_put_contents($root . '/ufw', '#!/bin/sh' . "\n" . '[ "$*" = "status verbose" ] || exit 1' . "\n" . '/bin/cat "' . $root . '/ufw.out"' . "\n");
    file_put_contents($root . '/iptables', '#!/bin/sh' . "\n" . '/bin/cat "' . $root . '/iptables.out"' . "\n");
    chmod($root . '/ufw', 0700); chmod($root . '/iptables', 0700); putenv('PATH=' . $root);
    file_put_contents($root . '/iptables.out', '');
    foreach ([
        "Status: active\nDefault: deny (incoming), deny (outgoing), disabled (routed)\n" => true,
        "Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n" => false,
        "Status: active\n" => null,
    ] as $output => $expected) {
        file_put_contents($root . '/ufw.out', $output); $actual = (new SystemCheck(new \Magebean\Engine\Context($root, '')))->egressRestricted()[0]; $count++;
        if ($actual !== $expected) throw new RuntimeException('UFW default-policy evidence mismatch');
    }
    file_put_contents($root . '/ufw.out', "Status: inactive\n");
    foreach (["-P OUTPUT ACCEPT\n" => false, "-P OUTPUT DROP\n" => true, "-P OUTPUT ACCEPT\n-A OUTPUT -j REJECT\n" => null, "-P OUTPUT DROP\n-A OUTPUT -j ACCEPT\n" => false] as $output => $expected) {
        file_put_contents($root . '/iptables.out', $output); $count++;
        if ((new SystemCheck(new \Magebean\Engine\Context($root, '')))->egressRestricted()[0] !== $expected) throw new RuntimeException('iptables policy/rule mismatch');
    }
} finally {
    putenv('PATH=' . $oldPath);
    foreach (glob($root . '/*') as $file) unlink($file); rmdir($root);
}
echo "QaSystemEvidenceTest: {$count} cases passed\n";
