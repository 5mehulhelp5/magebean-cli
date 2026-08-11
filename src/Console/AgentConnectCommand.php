<?php
declare(strict_types=1);
namespace Magebean\Console;
use Magebean\Agent\InstallationMetadata;
use Magebean\Agent\Http\ConsoleClient;
use Symfony\Component\Console\Input\{InputInterface, InputOption};
use Symfony\Component\Console\Output\OutputInterface;
final class AgentConnectCommand extends AgentCommand
{
    protected function configure(): void
    {
        $this->setName('agent:connect')->setDescription('Pair this host with Magebean Security Dashboard'); $this->configureAgentOptions();
        $this->addOption('code', null, InputOption::VALUE_REQUIRED, 'One-time pairing code')->addOption('magento-path', null, InputOption::VALUE_REQUIRED, 'Absolute Magento root')->addOption('console-url', null, InputOption::VALUE_REQUIRED, 'Security Dashboard URL')->addOption('agent-name', null, InputOption::VALUE_REQUIRED, 'Agent display name', gethostname() ?: 'magebean-agent')->addOption('force', null, InputOption::VALUE_NONE, 'Replace existing connection');
    }
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $repo = $this->repository($input); if ($repo->isConnected() && !$input->getOption('force')) { $output->writeln('<error>Agent is already connected. Use --force to replace it.</error>'); return self::FAILURE; }
        $code = trim((string)$input->getOption('code')); $path = realpath((string)$input->getOption('magento-path')); $url = rtrim(trim((string)$input->getOption('console-url')), '/');
        if ($code === '' || $path === false || !is_readable($path) || $url === '') { $output->writeln('<error>--code, readable --magento-path and --console-url are required.</error>'); return self::INVALID; }
        try {
            $metadata = (new InstallationMetadata())->detect($path);
            $result = (new ConsoleClient($url))->post('pair', ['schema_version' => '1.0', 'pairing_code' => $code, 'agent_name' => (string)$input->getOption('agent-name'), 'installation_fingerprint' => hash('sha256', $path . '|' . (gethostname() ?: 'unknown')), 'magento_path' => $path, 'cli_version' => \Magebean\Application::VERSION, 'php_version' => PHP_VERSION, ...$metadata]);
            $token = (string)($result['token'] ?? ''); if ($token === '') throw new \RuntimeException('Pair response did not contain a token.');
            $repo->saveConfig(['console_url' => $url, 'magento_path' => $path, 'agent_name' => (string)$input->getOption('agent-name'), 'agent_id' => $result['agent']['id'] ?? $result['agent_id'] ?? null]);
            $repo->saveCredentials(['token' => $token]); $repo->saveState(['connected' => true, 'connected_at' => gmdate(DATE_ATOM)]);
            $output->writeln('<info>Agent connected. Token stored locally and not displayed.</info>'); return self::SUCCESS;
        } catch (\Throwable $e) { $output->writeln('<error>' . $e->getMessage() . '</error>'); return self::FAILURE; }
    }
}
