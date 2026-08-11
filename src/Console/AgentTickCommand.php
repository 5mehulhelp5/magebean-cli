<?php
declare(strict_types=1);
namespace Magebean\Console;
use Magebean\Agent\TickRunner;use Symfony\Component\Console\Input\InputInterface;use Symfony\Component\Console\Output\OutputInterface;
final class AgentTickCommand extends AgentCommand
{
 protected function configure():void{$this->setName('agent:tick')->setDescription('Run one bounded agent polling cycle');$this->configureAgentOptions();}
 protected function execute(InputInterface $input,OutputInterface $output):int{try{$message=(new TickRunner($this->repository($input)))->run();if(!$output->isQuiet())$output->writeln($message);return self::SUCCESS;}catch(\Throwable $e){$output->writeln('<error>'.$e->getMessage().'</error>');return self::FAILURE;}}
}
