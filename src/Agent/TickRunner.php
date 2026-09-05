<?php
declare(strict_types=1);
namespace Magebean\Agent;
use Magebean\Agent\Http\ConsoleClient;
use Magebean\Update\SelfUpdater;
final class TickRunner
{
    public function __construct(private readonly AgentRepository $repo, private readonly AgentScanner $scanner=new AgentScanner()){}
    public function run(): string
    {
        if(!$this->repo->isConnected()) throw new \RuntimeException('Agent is not connected.');
        $lock=new AgentLock();if(!$lock->acquire($this->repo->paths->lock()))return 'skipped: another tick is running';
        try{$c=$this->repo->config();$client=new ConsoleClient((string)$c['console_url'], (string)$this->repo->credentials()['token'], verifyTls: empty($c['dev_mode']));$this->retryPending($client);
            $state=$this->repo->state();$heartbeat=['schema_version'=>'1.0','cli_version'=>\Magebean\Application::VERSION,'current_version'=>\Magebean\Application::VERSION,'php_version'=>PHP_VERSION,'installation_fingerprint'=>hash('sha256',(string)$c['magento_path'].'|'.(gethostname()?:'unknown'))];
            if(time()-strtotime((string)($state['last_health_at']??'1970-01-01'))>=300){$heartbeat['runtime_health']=$this->health((string)$c['magento_path']);$state['last_health_at']=gmdate(DATE_ATOM);}
            $heartbeatResponse=$client->post('heartbeat',$heartbeat);
            if(is_array($heartbeatResponse['update']??null))return $this->update($client,$heartbeatResponse['update']);
            $claim=$client->post('jobs/claim',['schema_version'=>'1.0']);$job=$claim['job']??null;
            if(!is_array($job)||!isset($job['id'])){$state['last_tick_at']=gmdate(DATE_ATOM);$this->repo->saveState($state);return 'idle';}
            $id=(string)$job['id'];$lease=(string)($job['lease_token']??$claim['lease_token']??'');$headers=['X-Magebean-Lease'=>$lease];
            try{$client->post("jobs/{$id}/start",['schema_version'=>'1.0'],$headers);$manifest=$client->get("jobs/{$id}/manifest",$headers);$lastLease=time();$startedAt=gmdate(DATE_ATOM);
                $result=$this->scanner->run((string)$c['magento_path'],$manifest,function()use($client,$id,$headers,&$lastLease):void{if(time()-$lastLease>=30){$client->post("jobs/{$id}/lease",['schema_version'=>'1.0'],$headers);$lastLease=time();}});
                $scanUuid=$this->uuid();$assessment=(string)($job['assessment_id']??$manifest['assessment_id']??'');if($assessment==='')throw new \RuntimeException('Job has no assessment_id.');
                $payload=$result+['scan_uuid'=>$scanUuid,'job_id'=>$id,'cli_version'=>\Magebean\Application::VERSION,'started_at'=>$startedAt,'completed_at'=>gmdate(DATE_ATOM),'status'=>'completed'];
                $pending=$this->repo->paths->pending().'/'.$scanUuid.'.json';(new AtomicJsonStore())->write($pending,['assessment_id'=>$assessment,'payload'=>$payload,'lease_token'=>$lease,'job_id'=>$id]);
                $client->postApi("assessments/{$assessment}/scans",$payload,['Idempotency-Key'=>$scanUuid,'X-Magebean-Lease'=>$lease]);unlink($pending);$client->post("jobs/{$id}/complete",['schema_version'=>'1.0','scan_uuid'=>$scanUuid],$headers);
                $state['last_job_id']=$id;$state['last_scan_uuid']=$scanUuid;$state['last_tick_at']=gmdate(DATE_ATOM);$this->repo->saveState($state);return 'completed job '.$id;
            }catch(\Throwable $e){try{$client->post("jobs/{$id}/fail",['schema_version'=>1,'message'=>substr($e->getMessage(),0,500)],$headers);}catch(\Throwable){}throw $e;}
        }finally{$lock->release();}
    }
    /** @param array<string,mixed> $release */
    private function update(ConsoleClient $client,array $release):string
    {
        $current=\Phar::running(false)?:realpath((string)($_SERVER['argv'][0]??''));
        try{if(!$current||!str_ends_with($current,'.phar'))throw new \RuntimeException('Self-update is only available when running magebean.phar.');(new SelfUpdater())->update($release,$current);$client->post('update-status',['schema_version'=>'1.0','current_version'=>(string)$release['version'],'status'=>'updated','error'=>null]);return 'updated to '.(string)$release['version'].'; restart required';}
        catch(\Throwable $exception){try{$client->post('update-status',['schema_version'=>'1.0','current_version'=>\Magebean\Application::VERSION,'status'=>'failed','error'=>substr($exception->getMessage(),0,2000)]);}catch(\Throwable){}throw $exception;}
    }
    private function retryPending(ConsoleClient $client):void{foreach(glob($this->repo->paths->pending().'/*.json')?:[] as $file){$p=(new AtomicJsonStore())->read($file);$client->postApi('assessments/'.$p['assessment_id'].'/scans',$p['payload'],['Idempotency-Key'=>(string)$p['payload']['scan_uuid'],'X-Magebean-Lease'=>(string)$p['lease_token']]);$client->post('jobs/'.$p['job_id'].'/complete',['schema_version'=>'1.0','scan_uuid'=>$p['payload']['scan_uuid']],['X-Magebean-Lease'=>(string)$p['lease_token']]);unlink($file);}}
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
