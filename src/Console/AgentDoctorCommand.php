<?php
declare(strict_types=1);
namespace Magebean\Console;
use Symfony\Component\Console\Input\InputInterface; use Symfony\Component\Console\Output\OutputInterface;
final class AgentDoctorCommand extends AgentCommand
{
    protected function configure(): void { $this->setName('agent:doctor')->setDescription('Validate local agent and Magento prerequisites'); $this->configureAgentOptions(); }
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        try{$r=$this->repository($input);$c=$r->config();$path=(string)($c['magento_path']??'');$checks=['PHP >= 8.1'=>PHP_VERSION_ID>=80100,'curl extension'=>extension_loaded('curl'),'Agent connected'=>$r->isConnected(),'Private credentials'=>$r->credentialsArePrivate(),'Magento path readable'=>$path!==''&&is_readable($path),'Magento bootstrap'=>is_file($path.'/app/bootstrap.php'),'Magento CLI'=>is_file($path.'/bin/magento'),'Writable agent queue'=>is_writable($r->paths->pending()),'Disk space > 100 MB'=>(@disk_free_space($path?:$r->paths->root)?:0)>104857600];$failed=false;foreach($checks as $name=>$ok){$output->writeln(($ok?'<info>PASS</info>':'<error>FAIL</error>').' '.$name);$failed=$failed||!$ok;}return $failed?self::FAILURE:self::SUCCESS;}catch(\Throwable $e){$output->writeln('<error>'.$e->getMessage().'</error>');return self::FAILURE;}
    }
}
