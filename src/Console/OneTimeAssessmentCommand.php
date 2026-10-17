<?php
declare(strict_types=1);
namespace Magebean\Console;

use Magebean\Agent\AgentScanner;
use Magebean\Agent\OneTimeAssessmentRunner;
use Magebean\Agent\Http\ConsoleClient;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\{InputInterface, InputOption};
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Formatter\OutputFormatter;

final class OneTimeAssessmentCommand extends Command
{
    protected function configure(): void
    {
        $this->setName('assessment:run')->setDescription('Scan once and submit to a dashboard assessment without pairing or cron');
        $this->addOption('magento-path', null, InputOption::VALUE_REQUIRED, 'Magento repository root', '.')
            ->addOption('console-url', null, InputOption::VALUE_REQUIRED, 'Dashboard API URL')
            ->addOption('dev', null, InputOption::VALUE_NONE, 'Use the local Security Dashboard API')
            ->addOption('assessment', null, InputOption::VALUE_REQUIRED, 'Assessment ID')
            ->addOption('token', null, InputOption::VALUE_REQUIRED, '15-minute one-time assessment token');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $path = realpath((string)$input->getOption('magento-path'));
        $devMode = (bool) $input->getOption('dev');
        $url = rtrim((string) ($input->getOption('console-url') ?: ($devMode ? ConsoleClient::DEV_BASE_URL : ConsoleClient::DEFAULT_BASE_URL)), '/');
        $assessment = (string)$input->getOption('assessment');
        $token = (string)$input->getOption('token');
        if (!$path || !is_dir($path) || !is_readable($path) || !preg_match('/^[0-9A-HJKMNP-TV-Z]{26}$/i', $assessment)
            || !preg_match('/^mbot_[a-f0-9]{64}$/', $token) || !filter_var($url, FILTER_VALIDATE_URL) || parse_url($url, PHP_URL_SCHEME) !== 'https'
            || parse_url($url, PHP_URL_USER) || parse_url($url, PHP_URL_QUERY) || parse_url($url, PHP_URL_FRAGMENT)) {
            $output->writeln('<error>A readable --magento-path, HTTPS --console-url, --assessment and valid --token are required.</error>');
            return self::INVALID;
        }
        try {
            $output->writeln('Running one-time assessment…');
            (new OneTimeAssessmentRunner())->run(new ConsoleClient($url, $token, verifyTls: ! $devMode), $assessment, $path, fn($root, $manifest) => (new AgentScanner())->run($root, $manifest));
            $output->writeln('<info>Results submitted. Open your assessment in the dashboard.</info>');
            return self::SUCCESS;
        } catch (\Throwable $error) {
            $output->writeln('<error>'.OutputFormatter::escape(str_replace($token, '[redacted]', $error->getMessage())).'</error>');
            return self::FAILURE;
        }
    }
}
