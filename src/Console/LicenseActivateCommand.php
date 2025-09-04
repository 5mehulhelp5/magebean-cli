<?php

declare(strict_types=1);

namespace Magebean\Console;

use Symfony\Component\Console\{Command\Command, Input\InputInterface, Output\OutputInterface};

final class LicenseActivateCommand extends Command
{
    protected function configure(): void
    {
        $this->setName('license:activate')->setDescription('[stub] Activate license');
    }
    protected function execute(InputInterface $in, OutputInterface $out): int
    {
        $out->writeln('<comment>Licensing is not required in v0.1</comment>');
        return Command::SUCCESS;
    }
}
