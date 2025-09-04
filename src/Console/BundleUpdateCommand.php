<?php

declare(strict_types=1);

namespace Magebean\Console;

use Symfony\Component\Console\{Command\Command, Input\InputInterface, Output\OutputInterface};

final class BundleUpdateCommand extends Command
{
    protected function configure(): void
    {
        $this->setName('bundle:update')->setDescription('[stub] Update rule bundle (future)');
    }
    protected function execute(InputInterface $in, OutputInterface $out): int
    {
        $out->writeln('<comment>bundle:update is disabled in v0.1 (built-in rules only)</comment>');
        return Command::SUCCESS;
    }
}
