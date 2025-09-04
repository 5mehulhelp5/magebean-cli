<?php

declare(strict_types=1);

namespace Magebean\Console;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Magebean\Engine\RulePackLoader;

final class RulesValidateCommand extends Command
{
    protected function configure(): void
    {
        $this->setName('rules:validate')->setDescription('Validate control JSON files');
    }
    protected function execute(InputInterface $in, OutputInterface $out): int
    {
        [$pack, $errors] = RulePackLoader::validate();
        if ($errors) {
            foreach ($errors as $e) $out->writeln("<error>{$e}</error>");
            return Command::FAILURE;
        }
        $out->writeln("<info>OK</info> Loaded controls: " . implode(',', $pack['controls']) . " | Rules: " . count($pack['rules']));
        return Command::SUCCESS;
    }
}
