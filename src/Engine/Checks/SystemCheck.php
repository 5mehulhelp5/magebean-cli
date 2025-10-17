<?php
declare(strict_types=1);

namespace Magebean\Engine\Checks;

use Magebean\Engine\Context;

final class SystemCheck
{
    private Context $context;

    public function __construct(Context $ctx)
    {
        $this->context = $ctx;
    }

    /**
     * PASS nếu hệ thống đang chặn outbound (egress) ở mức firewall:
     * - UFW: Status active + Default: deny (outgoing) hoặc Outgoing: DENY
     * - IPTABLES: Chain OUTPUT policy DROP/REJECT (hoặc không phải ACCEPT)
     * UNKNOWN nếu thiếu quyền/chưa cài ufw/iptables; FAIL nếu thấy rõ ràng policy ACCEPT (mở hết).
     */
    public function egressRestricted(array $args = []): array
    {
        // 1) UFW trước, nếu có
        if ($this->isCmdAvailable('ufw')) {
            $out = $this->safeShell('ufw status');
            if ($out['ok']) {
                $t = strtolower($out['stdout']);
                $active = (strpos($t, 'status: active') !== false);
                $deny1  = (strpos($t, 'default: deny (outgoing)') !== false);
                // một số distro in khác: "Outgoing: DENY"
                $deny2  = (strpos($t, 'outgoing: deny') !== false);
                if ($active && ($deny1 || $deny2)) {
                    return [true, 'UFW is active and denies outgoing traffic by default', [
                        'tool' => 'ufw',
                        'output' => $out['stdout'],
                    ]];
                }
                if ($active) {
                    // active nhưng cho phép outbound
                    return [false, 'UFW is active but does not deny outgoing traffic', [
                        'tool' => 'ufw',
                        'output' => $out['stdout'],
                    ]];
                }
                // not active → tiếp tục thử iptables
            } else {
                // không chạy được ufw → tiếp tục iptables
            }
        }

        // 2) IPTABLES
        if ($this->isCmdAvailable('iptables')) {
            // Thử dạng -S trước (rule dạng câu lệnh)
            $out = $this->safeShell('iptables -S OUTPUT');
            if ($out['ok'] && trim($out['stdout']) !== '') {
                $policy = $this->parseIptablesPolicy($out['stdout']);
                if ($policy === 'DROP' || $policy === 'REJECT') {
                    return [true, 'iptables OUTPUT policy denies by default', [
                        'tool' => 'iptables -S',
                        'policy' => $policy,
                        'output' => $out['stdout'],
                    ]];
                }
                if ($policy === 'ACCEPT') {
                    return [false, 'iptables OUTPUT policy is ACCEPT (unrestricted)', [
                        'tool' => 'iptables -S',
                        'policy' => $policy,
                        'output' => $out['stdout'],
                    ]];
                }
                // unknown policy string → thử -L
            }

            // Fallback: -L (human readable)
            $out2 = $this->safeShell('iptables -L OUTPUT -n');
            if ($out2['ok'] && trim($out2['stdout']) !== '') {
                $line1 = strtolower(strtok($out2['stdout'], "\n")); // "Chain OUTPUT (policy ACCEPT)"
                if (strpos($line1, '(policy drop)') !== false || strpos($line1, '(policy reject)') !== false) {
                    return [true, 'iptables OUTPUT policy denies by default', [
                        'tool' => 'iptables -L',
                        'output' => $out2['stdout'],
                    ]];
                }
                if (strpos($line1, '(policy accept)') !== false) {
                    return [false, 'iptables OUTPUT policy is ACCEPT (unrestricted)', [
                        'tool' => 'iptables -L',
                        'output' => $out2['stdout'],
                    ]];
                }
            }
        }

        // 3) Không có ufw/iptables hoặc không đủ quyền → UNKNOWN
        return [null, 'Cannot determine egress firewall policy (missing tools or permissions)', [
            'tools' => [
                'ufw_available' => $this->isCmdAvailable('ufw'),
                'iptables_available' => $this->isCmdAvailable('iptables'),
            ]
        ]];
    }

    private function isCmdAvailable(string $cmd): bool
    {
        $check = $this->safeShell('command -v ' . escapeshellarg($cmd));
        return $check['ok'] && trim($check['stdout']) !== '';
    }

    private function safeShell(string $cmd): array
    {
        try {
            $out = [];
            $ret = 0;
            $stdout = @shell_exec($cmd . ' 2>/dev/null');
            if ($stdout === null) {
                // shell_exec bị disable hoặc lỗi
                return ['ok' => false, 'stdout' => '', 'code' => null];
            }
            return ['ok' => true, 'stdout' => (string)$stdout, 'code' => $ret];
        } catch (\Throwable $e) {
            return ['ok' => false, 'stdout' => '', 'code' => null];
        }
    }

    private function parseIptablesPolicy(string $s): string
    {
        // ví dụ: "-P OUTPUT ACCEPT"
        foreach (explode("\n", $s) as $line) {
            $line = trim($line);
            if (preg_match('~^-P\s+OUTPUT\s+(ACCEPT|DROP|REJECT)~i', $line, $m)) {
                return strtoupper($m[1]);
            }
        }
        return '';
    }
}
