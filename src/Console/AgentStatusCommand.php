<?php
declare(strict_types=1);
namespace Magebean\Console;
use Magebean\Agent\Http\ConsoleClient;
use Symfony\Component\Console\Input\InputInterface; use Symfony\Component\Console\Output\OutputInterface;
final class AgentStatusCommand extends AgentCommand
{
    protected function configure(): void { $this->setName('agent:status')->setDescription('Show local and Security Dashboard agent status'); $this->configureAgentOptions(); }
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        try { $repo=$this->repository($input); if(!$repo->isConnected()){ $output->writeln('Agent: disconnected'); return self::SUCCESS; } $c=$repo->config(); $s=$repo->state(); $remote=(new ConsoleClient((string)$c['console_url'], (string)$repo->credentials()['token'], verifyTls: empty($c['dev_mode'])))->get('me'); $output->writeln(['Agent: connected','Security Dashboard: '.$c['console_url'],'Magento: '.$c['magento_path'],'Remote status: '.($remote['status'] ?? $remote['agent']['status'] ?? 'unknown'),'Last tick: '.($s['last_tick_at'] ?? 'never')]); if(!$repo->credentialsArePrivate()) $output->writeln('<comment>Warning: credentials.json permissions are broader than 0600.</comment>'); return self::SUCCESS; } catch(\Throwable $e){ $output->writeln('<error>'.$e->getMessage().'</error>'); return self::FAILURE; }
    }
}
