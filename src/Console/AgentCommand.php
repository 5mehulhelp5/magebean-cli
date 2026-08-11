<?php
declare(strict_types=1);
namespace Magebean\Console;
use Magebean\Agent\{AgentPaths, AgentRepository};
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
abstract class AgentCommand extends Command
{
    protected function configureAgentOptions(): void { $this->addOption('config-dir', null, InputOption::VALUE_REQUIRED, 'Agent data directory (overrides MAGEBEAN_HOME)'); }
    protected function repository(InputInterface $input): AgentRepository { return new AgentRepository(AgentPaths::resolve(is_string($input->getOption('config-dir')) ? $input->getOption('config-dir') : null)); }
}
