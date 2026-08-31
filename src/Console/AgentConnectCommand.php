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
        $this->setName('agent:connect')->setDescription('Pair this host with Magebean Security Dashboard');
        $this->addOption('code', null, InputOption::VALUE_REQUIRED, 'One-time pairing code')->addOption('magento-path', null, InputOption::VALUE_REQUIRED, 'Absolute Magento root')->addOption('dev', null, InputOption::VALUE_NONE, 'Use the local Security Dashboard API');
    }
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $repo = $this->repository($input); if ($repo->isConnected()) { $output->writeln('<error>Agent is already connected. Run agent:disconnect before connecting again.</error>'); return self::FAILURE; }
        $code = trim((string)$input->getOption('code')); $path = realpath((string)$input->getOption('magento-path'));
        if ($code === '' || $path === false || !is_readable($path)) { $output->writeln('<error>--code and readable --magento-path are required.</error>'); return self::INVALID; }
        try {
            $devMode = (bool) $input->getOption('dev');
            $url = $devMode ? ConsoleClient::DEV_BASE_URL : ConsoleClient::DEFAULT_BASE_URL;
            $agentName = gethostname() ?: 'magebean-agent';
            $metadata = (new InstallationMetadata())->detect($path);
            $result = (new ConsoleClient($url, verifyTls: ! $devMode))->post('pair', ['schema_version' => '1.0', 'pairing_code' => $code, 'agent_name' => $agentName, 'installation_fingerprint' => hash('sha256', $path . '|' . (gethostname() ?: 'unknown')), 'magento_path' => $path, 'cli_version' => \Magebean\Application::VERSION, 'php_version' => PHP_VERSION, ...$metadata]);
            $token = (string)($result['token'] ?? ''); if ($token === '') throw new \RuntimeException('Pair response did not contain a token.');
            $repo->saveConfig(['console_url' => $url, 'dev_mode' => $devMode, 'magento_path' => $path, 'agent_name' => $agentName, 'agent_id' => $result['agent']['id'] ?? $result['agent_id'] ?? null]);
            $repo->saveCredentials(['token' => $token]); $repo->saveState(['connected' => true, 'connected_at' => gmdate(DATE_ATOM)]);
            $output->writeln([
                '<info>Agent connected. Token stored locally and not displayed.</info>',
                'Config saved to: ' . $repo->paths->config(),
                'Credentials saved to: ' . $repo->paths->credentials(),
            ]); return self::SUCCESS;
        } catch (\Throwable $e) { $output->writeln('<error>' . $e->getMessage() . '</error>'); return self::FAILURE; }
    }
}
