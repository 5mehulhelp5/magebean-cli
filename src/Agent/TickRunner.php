<?php
declare(strict_types=1);
namespace Magebean\Agent;
use Magebean\Agent\Http\ConsoleClient;
use Magebean\Agent\Http\ConsoleTransport;
use Magebean\Engine\ScanDeadline;
use Magebean\Update\SelfUpdater;
final class TickRunner
{
    private $clientFactory;
    public function __construct(private readonly AgentRepository $repo, private readonly AgentScanner $scanner=new AgentScanner(), ?callable $clientFactory = null)
    {
        $this->clientFactory = $clientFactory;
    }
    public function run(): string
    {
        if(!$this->repo->isConnected()) throw new \RuntimeException('Agent is not connected.');
        $lock=new AgentLock();if(!$lock->acquire($this->repo->paths->lock()))return 'skipped: another tick is running';
        try{$c=$this->repo->config();$client = $this->clientFactory !== null ? ($this->clientFactory)($c, $this->repo->credentials()) : new ConsoleClient((string)$c['console_url'], (string)$this->repo->credentials()['token'], verifyTls: empty($c['dev_mode']));
            if (!$client instanceof ConsoleTransport) throw new \RuntimeException('Invalid agent console transport.');
            $outbox = new PendingOutbox($this->repo->paths);
            $state = $this->repo->state();
            $onDelivered = function (array $entry) use (&$state): void {
                $state['last_job_id'] = (string)$entry['job_id'];
                $state['last_scan_uuid'] = (string)$entry['payload']['scan_uuid'];
                $state['last_tick_at'] = gmdate(DATE_ATOM);
                $this->repo->saveState($state);
            };
            $outbox->retry($client, $onDelivered);
            $heartbeat=['schema_version'=>'1.0','cli_version'=>\Magebean\Application::VERSION,'current_version'=>\Magebean\Application::VERSION,'php_version'=>PHP_VERSION,'installation_fingerprint'=>hash('sha256',(string)$c['magento_path'].'|'.(gethostname()?:'unknown'))];
            if(time()-strtotime((string)($state['last_health_at']??'1970-01-01'))>=300){$heartbeat['runtime_health']=$this->health((string)$c['magento_path']);$state['last_health_at']=gmdate(DATE_ATOM);}
            $heartbeatResponse=$client->post('heartbeat',$heartbeat);
            if(is_array($heartbeatResponse['update']??null))return $this->update($client,$heartbeatResponse['update']);
            $claim=$client->post('jobs/claim',['schema_version'=>'1.0']);$job=$claim['job']??null;
            if(!is_array($job)||!isset($job['id'])){$state['last_tick_at']=gmdate(DATE_ATOM);$this->repo->saveState($state);return 'idle';}
            $id=(string)$job['id'];$lease=(string)($job['lease_token']??$claim['lease_token']??'');$headers=['X-Magebean-Lease'=>$lease];
            $queued = false;
            try{$client->post("jobs/{$id}/start",['schema_version'=>'1.0'],$headers);$manifest=$client->get("jobs/{$id}/manifest",$headers);$lastLease=time();$startedAt=gmdate(DATE_ATOM);
                $deadline = isset($c['scan_timeout_seconds']) ? new ScanDeadline((float)$c['scan_timeout_seconds']) : null;
                $renewLease = function()use($client,$id,$headers,&$lastLease):void{if(time()-$lastLease>=30){$client->post("jobs/{$id}/lease",['schema_version'=>'1.0'],$headers);$lastLease=time();}};
                $result=$this->scanner->run((string)$c['magento_path'],$manifest,$renewLease, $deadline, $renewLease);
                $scanUuid=$this->uuid();$assessment=(string)($job['assessment_id']??$manifest['assessment_id']??'');if($assessment==='')throw new \RuntimeException('Job has no assessment_id.');
                $payload=$result+['scan_uuid'=>$scanUuid,'job_id'=>$id,'cli_version'=>\Magebean\Application::VERSION,'started_at'=>$startedAt,'completed_at'=>gmdate(DATE_ATOM),'status'=>'completed'];
                $pending = $outbox->enqueue(['assessment_id'=>$assessment,'payload'=>$payload,'lease_token'=>$lease,'job_id'=>$id]);
                $queued = true;
                $outbox->deliver($pending, $client, $onDelivered);
                return 'completed job '.$id;
            }catch(\Throwable $e){if (!$queued) {try{$client->post("jobs/{$id}/fail",['schema_version'=>1,'message'=>substr($e->getMessage(),0,500)],$headers);}catch(\Throwable){}}throw $e;}
        }finally{$lock->release();}
    }
    /** @param array<string,mixed> $release */
    private function update(ConsoleTransport $client,array $release):string
    {
        $current=\Phar::running(false)?:realpath((string)($_SERVER['argv'][0]??''));
        try{if(!$current||!str_ends_with($current,'.phar'))throw new \RuntimeException('Self-update is only available when running magebean.phar.');(new SelfUpdater())->update($release,$current);$client->post('update-status',['schema_version'=>'1.0','current_version'=>(string)$release['version'],'status'=>'updated','error'=>null]);return 'updated to '.(string)$release['version'].'; restart required';}
        catch(\Throwable $exception){try{$client->post('update-status',['schema_version'=>'1.0','current_version'=>\Magebean\Application::VERSION,'status'=>'failed','error'=>substr($exception->getMessage(),0,2000)]);}catch(\Throwable){}throw $exception;}
    }
    private function health(string $path): array
    {
        $health = [
            'magento_path_readable' => is_readable($path),
            'bootstrap_present' => is_file($path.'/app/bootstrap.php'),
            'cli_present' => is_file($path.'/bin/magento'),
            'disk_free_bytes' => (int) (@disk_free_space($path) ?: 0),
            'php_version' => PHP_VERSION,
        ];
        $health['status'] = $health['magento_path_readable']
            && $health['bootstrap_present']
            && $health['cli_present']
            ? 'healthy'
            : 'warning';

        return $health;
    }
    private function uuid():string{$b=random_bytes(16);$b[6]=chr((ord($b[6])&15)|64);$b[8]=chr((ord($b[8])&63)|128);return vsprintf('%s%s-%s-%s-%s-%s%s%s',str_split(bin2hex($b),4));}
}
