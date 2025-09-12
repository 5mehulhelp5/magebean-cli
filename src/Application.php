<?php

declare(strict_types=1);

namespace Magebean;

use Symfony\Component\Console\Application as ConsoleApp;
use Magebean\Console\{
    ScanCommand,
    RulesListCommand,
    RulesValidateCommand,
    BundleUpdateCommand,
    LicenseActivateCommand,
    SelfUpdateCommand,
    ReportOpenCommand
};

final class Application extends ConsoleApp
{
    public function __construct()
    {
        $name = 'Magebean CLI — Magento 2 Security Audit';
        parent::__construct($name, '0.1.0');
        $this->add(new ScanCommand());
        $this->add(new RulesListCommand());
    }

    public function getLongVersion(): string
    {
        return parent::getLongVersion()
            . PHP_EOL
            . 'A practical Magento 2 security audit tool powered by Magebean Baseline V1.'
            . PHP_EOL;
    }
}
