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
    parent::__construct('Magebean CLI', '0.1.0');
    $this->add(new ScanCommand());
    $this->add(new RulesListCommand());
    $this->add(new RulesValidateCommand());
    $this->add(new BundleUpdateCommand());
    $this->add(new LicenseActivateCommand());
    $this->add(new SelfUpdateCommand());
    $this->add(new ReportOpenCommand());
  }
}
