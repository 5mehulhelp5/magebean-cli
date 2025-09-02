<?php

declare(strict_types=1);

namespace Magebean\Console;

use Symfony\Component\Console\{Command\Command, Input\InputInterface, Output\OutputInterface};

final class ReportOpenCommand extends Command
{
    protected function configure(): void
    {
        $this->setName('report:open')->setDescription('[stub] Open HTML report in browser');
    }
    protected function execute(InputInterface $in, OutputInterface $out): int
    {
        $out->writeln('<comment>Open the HTML file manually for now</comment>');
        return Command::SUCCESS;
    }
}
