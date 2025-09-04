<?php

declare(strict_types=1);

namespace Magebean\Console;

use Symfony\Component\Console\{Command\Command, Input\InputInterface, Output\OutputInterface};

final class SelfUpdateCommand extends Command
{
    protected function configure(): void
    {
        $this->setName('self-update')->setDescription('[stub] Self update');
    }
    protected function execute(InputInterface $in, OutputInterface $out): int
    {
        $out->writeln('<comment>self-update will be enabled when publishing PHAR</comment>');
        return Command::SUCCESS;
    }
}
