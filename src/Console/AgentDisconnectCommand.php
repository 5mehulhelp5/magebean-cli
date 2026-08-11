<?php
declare(strict_types=1);
namespace Magebean\Console;
use Magebean\Agent\Http\ConsoleClient;
use Symfony\Component\Console\Input\InputInterface; use Symfony\Component\Console\Output\OutputInterface;
final class AgentDisconnectCommand extends AgentCommand
{
    protected function configure(): void { $this->setName('agent:disconnect')->setDescription('Disconnect this host and remove its local token'); $this->configureAgentOptions(); }
    protected function execute(InputInterface $input, OutputInterface $output): int { try{$r=$this->repository($input); if($r->isConnected()){ $c=$r->config(); try{(new ConsoleClient((string)$c['console_url'],(string)$r->credentials()['token']))->post('disconnect');}catch(\Throwable $e){$output->writeln('<comment>Console could not be notified: '.$e->getMessage().'</comment>');} } $r->disconnect(); $output->writeln('<info>Agent disconnected; local token removed.</info>'); return self::SUCCESS;}catch(\Throwable $e){$output->writeln('<error>'.$e->getMessage().'</error>');return self::FAILURE;} }
}
