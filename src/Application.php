<?php

declare(strict_types=1);

namespace Magebean;

use Symfony\Component\Console\Application as ConsoleApp;
use Magebean\Console\{
    ScanCommand,
    RulesListCommand,
    AgentConnectCommand,
    AgentStatusCommand,
    AgentDoctorCommand,
    AgentDisconnectCommand,
    AgentTickCommand,
    AgentCronCommand
};

final class Application extends ConsoleApp
{
    public const VERSION = '1.0.0';
    public const BASELINE_VERSION = '1.0';

    public function __construct()
    {
        $name = 'Magebean CLI — Magento 2 Security Audit';
        parent::__construct($name, self::VERSION);
        $this->add(new ScanCommand());
        $this->add(new RulesListCommand());
        $this->add(new AgentConnectCommand());
        $this->add(new AgentStatusCommand());
        $this->add(new AgentCronCommand());
        $this->add(new AgentDoctorCommand());
        $this->add(new AgentDisconnectCommand());
        $this->add(new AgentTickCommand());
    }

    public function getLongVersion(): string
    {
        return parent::getLongVersion()
            . PHP_EOL
            . 'A practical Magento 2 security audit tool powered by Magebean Baseline v'
            . self::BASELINE_VERSION
            . '.'
            . PHP_EOL;
    }
}
