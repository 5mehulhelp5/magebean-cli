<?php
declare(strict_types=1);
namespace Magebean\Engine\Checks;

use Magebean\Engine\Context;

/** Bounded deployment observations; never reads or returns secret file contents. */
final class BasicPracticeCheck
{
    private ?\Closure $run;
    public function __construct(private Context $ctx, ?callable $run = null)
    {
        $this->run=$run===null?null:\Closure::fromCallable($run);
    }

    public function envNotTracked(array $args): array
    {
        $command=['git','-C',$this->ctx->path,'ls-files','--error-unmatch','--','app/etc/env.php'];
        $result=$this->run!==null?($this->run)($command):$this->execute($command);
        // ls-files returns 1 only when the exact path is absent from a readable index.
        if(!($result['complete']??false)||!in_array($result['exit']??null,[0,1],true))return[null,'[UNKNOWN] Cannot inspect the deployment Git index for app/etc/env.php.',['scope'=>'current Git index only; historical commits and remote repositories are not inspected']];
        $tracked=$result['exit']===0;
        return[!$tracked,$tracked?'Sensitive app/etc/env.php is tracked in the current Git index.':'Sensitive app/etc/env.php is absent from the current Git index.',['scope'=>'current Git index only; historical commits and remote repositories are not inspected']];
    }

    /** Checks published or explicit deployed scopes; does not infer active stores. */
    public function staticScopesReady(array $args): array
    {
        $scopes=$args['scopes']??$this->ctx->get('static_scopes');
        $scopeLabel='explicit_frontend_scopes';
        if($scopes===null){
            $scopeLabel='observed_published_scopes';$scopes=[];
            $base=$this->ctx->abs('pub/static/frontend');$root=realpath($this->ctx->path);$nodes=0;
            $walk=function(string $path,int $depth,array $parts)use(&$walk,&$scopes,&$nodes,$root):bool{
                if(++$nodes>500||is_link($path)||!is_readable($path)||!is_dir($path))return false;
                $real=realpath($path);
                if($root===false||$real===false||!str_starts_with($real,$root.DIRECTORY_SEPARATOR))return false;
                $entries=@scandir($path);if($entries===false)return false;
                foreach($entries as $entry){
                    if($entry==='.'||$entry==='..'||str_starts_with($entry,'.'))continue;
                    $child=$path.'/'.$entry;
                    if(is_link($child))return false;
                    if(!is_dir($child))continue;
                    if($depth===2){
                        if(!preg_match('/^[a-z]{2,3}_[A-Z]{2}$/D',$entry))continue;
                        if(!is_readable($child)||++$nodes>500)return false;
                        $scopes[]=['theme'=>implode('/',$parts),'locale'=>$entry];
                        if(count($scopes)>100)return false;
                    }else{
                        if(!preg_match('/^[A-Za-z0-9_-]+$/D',$entry)||!$walk($child,$depth+1,[...$parts,$entry]))return false;
                    }
                }
                return true;
            };
            if(!$walk($base,0,[]))return[null,'[UNKNOWN] Published static scope discovery is incomplete, unreadable, or exceeds its bounds.',['scope'=>$scopeLabel]];
        }
        if(!is_array($scopes)||$scopes===[]||count($scopes)>100)return[null,'[UNKNOWN] No complete frontend theme and locale scope is available to verify static deployment.',['scope'=>$scopeLabel]];
        $missing=[];$assetBudget=5000;$assetDeadline=microtime(true)+2;
        foreach($scopes as $scope){
            if(!is_array($scope))return[null,'[UNKNOWN] Static deployment scope is malformed.',[]];
            $theme=$scope['theme']??'';$locale=$scope['locale']??'';
            if(!is_string($theme)||!preg_match('~^[A-Za-z0-9_-]+/[A-Za-z0-9_-]+$~D',$theme)||!is_string($locale)||!preg_match('/^[a-z]{2,3}_[A-Z]{2}$/D',$locale))return[null,'[UNKNOWN] Static deployment scope is malformed.',[]];
            $relative='pub/static/frontend/'.$theme.'/'.$locale;
            $path=$this->ctx->abs($relative);$real=realpath($path);$root=realpath($this->ctx->path);
            if($real===false){$missing[]=$relative;continue;}
            if($root===false||!str_starts_with($real,$root.DIRECTORY_SEPARATOR)||!is_readable($real))return[null,'[UNKNOWN] Static deployment scope is unreadable or resolves outside the project.',['path'=>$relative]];
            // Generic assets accommodate non-Luma themes. No RequireJS assumption.
            $types=[];
            $assets=function(string $directory)use(&$assets,&$types,&$assetBudget,$assetDeadline,$root):bool{
                if(--$assetBudget<0||microtime(true)>$assetDeadline||is_link($directory)||!is_readable($directory))return false;
                $entries=@scandir($directory);if($entries===false)return false;
                foreach($entries as $entry){
                    if($entry==='.'||$entry==='..')continue;
                    if(--$assetBudget<0||microtime(true)>$assetDeadline)return false;
                    $file=$directory.'/'.$entry;
                    if(is_link($file))return false;
                    if(is_dir($file)){if(!$assets($file))return false;continue;}
                    $extension=strtolower(pathinfo($entry,PATHINFO_EXTENSION));
                    if(!in_array($extension,['css','js'],true))continue;
                    $resolved=realpath($file);
                    if($resolved===false||!str_starts_with($resolved,$root.DIRECTORY_SEPARATOR)||!is_readable($file))return false;
                    if(is_file($file)&&filesize($file)>0)$types[$extension]=true;
                }
                return true;
            };
            if(!$assets($real))return[null,'[UNKNOWN] Static asset traversal is incomplete, unreadable, or exceeds its bounds.',['path'=>$relative,'scope'=>$scopeLabel]];
            if(!isset($types['css']))$missing[]=$relative.' [nonempty CSS]';
            elseif(!isset($types['js']))return[null,'[UNKNOWN] No published JavaScript asset was observed; confirm inline, bundled or headless asset delivery for this theme.',['path'=>$relative,'scope'=>$scopeLabel]];
        }
        return[$missing===[],$missing===[]?'Representative CSS and JavaScript exist for the observed theme/locale scopes.':'Static assets are missing for the observed theme/locale scopes.',['missing'=>$missing,'scope'=>$scopeLabel,'scopes'=>$scopes,'limitation'=>'Active-store completeness, asset freshness and browser delivery require separate evidence']];
    }

    public function cronHealth(array $args): array
    {
        $recent=max(1,min(168,(int)($args['recent_hours']??24)));
        $overdue=max(1,min(1440,(int)($args['overdue_minutes']??15)));
        $snapshot=$this->ctx->get('cron_health_snapshot');
        if(!is_array($snapshot)){
            try{
                $pdo=$this->database();
                if($pdo===null)throw new \RuntimeException();
                [$db,$prefix]=$pdo;
                // Aggregate inside the database: bounded output, no job payloads or messages.
                $sql="SELECT COALESCE(SUM(status='success' AND finished_at >= UTC_TIMESTAMP() - INTERVAL $recent HOUR),0) AS successes, COALESCE(SUM(status='pending' AND scheduled_at < UTC_TIMESTAMP() - INTERVAL $overdue MINUTE),0) AS overdue FROM `{$prefix}cron_schedule` WHERE status='pending' OR (status='success' AND finished_at >= UTC_TIMESTAMP() - INTERVAL $recent HOUR)";
                $snapshot=$db->query($sql)->fetch(\PDO::FETCH_ASSOC);
            }catch(\Throwable){return[null,'[UNKNOWN] Cannot read bounded cron execution health from the deployment database.',['reason'=>'cron_health_unavailable']];}
        }
        foreach(['successes','overdue'] as $key)if(!isset($snapshot[$key])||!is_numeric($snapshot[$key])||(int)$snapshot[$key]<0)return[null,'[UNKNOWN] Cron execution health evidence is missing or malformed.',[]];
        $ok=(int)$snapshot['successes']>0&&(int)$snapshot['overdue']===0;
        return[$ok,$ok?'Recent successful cron execution exists and no pending jobs exceed the observed backlog threshold.':'Cron execution has no recent success or has overdue pending jobs.',['successes'=>(int)$snapshot['successes'],'overdue'=>(int)$snapshot['overdue'],'recent_hours'=>$recent,'overdue_minutes'=>$overdue,'scope'=>'recent cron_schedule successes and all overdue pending rows; Magebean readiness thresholds; error/missed job analysis is separate']];
    }

    private function database(): ?array
    {
        $path=$this->ctx->abs('app/etc/env.php');
        if(!is_readable($path)||filesize($path)>1048576)return null;
        $env=(static function($file){return include $file;})($path);
        $config=$env['db']['connection']['default']??null;$prefix=$env['db']['table_prefix']??'';
        if(!is_array($config)||!is_string($prefix)||!preg_match('/^[A-Za-z0-9_]*$/D',$prefix))return null;
        $host=$config['host']??'localhost';$name=$config['dbname']??'';
        if(!is_string($host)||!is_string($name)||str_contains($host,';')||str_contains($name,';'))return null;
        $db=new \PDO('mysql:host='.$host.';dbname='.$name.';charset=utf8mb4',(string)($config['username']??''),(string)($config['password']??''),[\PDO::ATTR_TIMEOUT=>2,\PDO::ATTR_ERRMODE=>\PDO::ERRMODE_EXCEPTION]);
        $version=(string)$db->getAttribute(\PDO::ATTR_SERVER_VERSION);
        $db->exec(stripos($version,'MariaDB')!==false?'SET SESSION max_statement_time=2':'SET SESSION max_execution_time=2000');
        return[$db,$prefix];
    }

    private function execute(array $command): array
    {
        if(!function_exists('proc_open'))return['complete'=>false];
        $process=@proc_open($command,[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);
        if(!is_resource($process))return['complete'=>false];
        fclose($pipes[0]);stream_set_blocking($pipes[1],false);stream_set_blocking($pipes[2],false);
        $end=microtime(true)+2;$bytes=0;$exit=null;$complete=true;
        do{
            // Discard output: filenames and diagnostic paths are unnecessary evidence.
            $bytes+=strlen((string)stream_get_contents($pipes[1]))+strlen((string)stream_get_contents($pipes[2]));
            $state=proc_get_status($process);
            if(!$state['running']){$exit=$state['exitcode'];break;}
            if(microtime(true)>$end||$bytes>65536){$complete=false;proc_terminate($process);break;}
            usleep(10000);
        }while(true);
        fclose($pipes[1]);fclose($pipes[2]);$closed=proc_close($process);
        return['complete'=>$complete,'exit'=>$exit??$closed];
    }
}
