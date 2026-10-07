<?php
declare(strict_types=1);
namespace Magebean\Engine\Checks;
use Magebean\Engine\Context;
/** Installed scheduler observations with injectable read-only collection for tests. */
final class InstalledCronCheck
{
    private ?\Closure $collect;
    public function __construct(private Context $ctx, ?callable $collect = null) { $this->collect=$collect===null?null:\Closure::fromCallable($collect); }
    public function configured(array $args): array
    {
        $sources=$this->collect!==null?($this->collect)($args):$this->sources($args);$gaps=[];$collectionErrors=[];$assessed=0;
        foreach($sources as$s){if(!($s['available']??false)||($s['complete']??true)!==true){$gaps[]=$s['name'];$collectionErrors[$s['name']]=$s['reason']??'Installed cron source is unreadable or incomplete';continue;}++$assessed;
            foreach(preg_split('/\r?\n/',(string)$s['content'])as$line){$command=$this->command(trim($line),(bool)($s['system']??false));if($command!==null&&$this->isProjectCron($command))return[true,'Installed Magento cron:run entry found for this deployment.',['source'=>$s['name'],'command'=>$command,'sources_assessed'=>$assessed]];}
        }
        if($gaps!==[]||$assessed===0)return[null,'[UNKNOWN] Cannot verify installed cron for this deployment; run with permission to read the deployment owner crontab and /etc/cron.d. Repository deployment scripts are not installed crontabs.',['unavailable_sources'=>$gaps,'sources_assessed'=>$assessed,'collection_errors'=>$collectionErrors]];
        return[false,'No Magento cron:run entry exists in the completely collected installed cron sources for this deployment.',['sources_assessed'=>$assessed]];
    }
    private function command(string $line,bool $system): ?string
    {
        if($line===''||$line[0]==='#'||preg_match('/^[A-Za-z_][A-Za-z0-9_]*\s*=/',$line))return null;
        $parts=preg_split('/\s+/',$line,$system?7:6);if(str_starts_with($line,'@')){
            $parts=preg_split('/\s+/',$line,$system?3:2);if(!in_array($parts[0],['@reboot','@hourly','@daily','@weekly','@monthly','@yearly','@annually','@midnight'],true))return null;return $parts[$system?2:1]??null;
        }
        if(count($parts)!==($system?7:6))return null;
        $bounds=[[0,59],[0,23],[1,31],[1,12],[0,7]];
        foreach(array_slice($parts,0,5)as$i=>$part)if(!$this->validField($part,$bounds[$i][0],$bounds[$i][1],$i))return null;
        return $parts[$system?6:5];
    }
    private function validField(string $field,int $min,int $max,int $index):bool
    {
        $names=$index===3?array_flip(['JAN','FEB','MAR','APR','MAY','JUN','JUL','AUG','SEP','OCT','NOV','DEC']):($index===4?array_flip(['SUN','MON','TUE','WED','THU','FRI','SAT']):[]);
        $number=static function(string $v)use($names,$index,$min,$max):?int{
            $upper=strtoupper($v);if(isset($names[$upper]))$n=$names[$upper]+($index===3?1:0);
            elseif(preg_match('/^\d+$/D',$v))$n=(int)$v;else return null;
            return $n>=$min&&$n<=$max?$n:null;
        };
        foreach(explode(',',$field)as$item){
            $step=explode('/',$item);if(count($step)>2)return false;
            if(isset($step[1])&&(!preg_match('/^\d+$/D',$step[1])||(int)$step[1]<1||(int)$step[1]>$max-$min+1))return false;
            if($step[0]==='*')continue;
            $range=explode('-',$step[0]);if(count($range)>2)return false;
            $start=$number($range[0]);if($start===null)return false;
            if(isset($range[1])){$end=$number($range[1]);if($end===null||$end<$start)return false;}
        }
        return true;
    }
    private function isProjectCron(string $command): bool
    {
        $project=rtrim(realpath($this->ctx->path)?:$this->ctx->path,'/');$quoted=preg_quote($project,'~');
        $prefix='';if(preg_match('~^cd\s+[\"\']?'.$quoted.'[\"\']?\s*&&\s*(.*)$~',$command,$m)){$command=$m[1];$prefix='relative';}
        $script=$prefix==='relative'?'(?:'.$quoted.'/)?bin/magento':$quoted.'/bin/magento';
        return preg_match('~^(?:(?:/[A-Za-z0-9_.\-/]+/)?php(?:[0-9.]+)?\s+(?:(?:-d\s+\S+|-f)\s+)*)?[\"\']?'.$script.'[\"\']?\s+cron:run(?:\s|$)~',$command)===1;
    }
    private function sources(array $args): array
    {
        $sources=[];$users=(array)($args['users']??[]);
        if(function_exists('posix_getpwuid')){foreach([@fileowner($this->ctx->path),posix_geteuid()]as$uid){if($uid!==false){$user=posix_getpwuid($uid);if(is_array($user))$users[]=$user['name'];}}}
        foreach(array_unique($users)as$user){if(!is_string($user)||!preg_match('/^[a-z_][a-z0-9_-]*[$]?$/i',$user))continue;if(function_exists('posix_getpwnam')&&posix_getpwnam($user)===false)continue;$sources[]=$this->userSource($user,max(100,(int)($args['timeout_ms']??2000)));}
        foreach(['/etc/crontab','/etc/cron.d']as$path){if(!file_exists($path)){$sources[]=['name'=>$path,'available'=>true,'content'=>'','system'=>true];continue;}
            if(is_dir($path)){$files=@scandir($path);if($files===false){$sources[]=['name'=>$path,'available'=>false];continue;}foreach($files as$f){if($f==='.'||$f==='..'||str_starts_with($f,'.')||!preg_match('/^[A-Za-z0-9_-]+$/',$f))continue;$p=$path.'/'.$f;if(!is_file($p))continue;$content=@file_get_contents($p);$sources[]=['name'=>$p,'available'=>$content!==false,'content'=>$content?:'','system'=>true];}}
            else{$content=@file_get_contents($path);$sources[]=['name'=>$path,'available'=>$content!==false,'content'=>$content?:'','system'=>true];}}
        return $sources;
    }
    private function userSource(string $user,int $timeout): array
    {
        $name='crontab:'.$user;
        // A readable installed spool is equivalent evidence when crontab is unavailable
        // or cannot switch users. Never substitute a repository deployment script.
        foreach (['/var/spool/cron/crontabs/'.$user, '/var/spool/cron/'.$user] as $spool) {
            if (!is_file($spool)) continue;
            $content = @file_get_contents($spool);
            if ($content !== false) return ['name'=>$spool,'available'=>true,'content'=>$content,'system'=>false];
        }
        if(!function_exists('proc_open'))return['name'=>$name,'available'=>false,'reason'=>'proc_open is disabled and installed spool is not readable'];
        $current = function_exists('posix_getpwuid') ? posix_getpwuid(posix_geteuid()) : false;
        $command = is_array($current) && ($current['name'] ?? '') === $user ? ['crontab','-l'] : ['crontab','-u',$user,'-l'];
        $p=@proc_open($command,[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes,null,['LC_ALL'=>'C']);if(!is_resource($p))return['name'=>$name,'available'=>false];
        fclose($pipes[0]);stream_set_blocking($pipes[1],false);stream_set_blocking($pipes[2],false);$out='';$error='';$end=microtime(true)+$timeout/1000;$exit=null;$complete=true;
        do{$out.=stream_get_contents($pipes[1]);$error.=stream_get_contents($pipes[2]);$state=proc_get_status($p);if(!$state['running']){$exit=$state['exitcode'];break;}if(microtime(true)>=$end||strlen($out)+strlen($error)>1048576){$complete=false;proc_terminate($p);break;}usleep(10000);}while(true);
        $out.=stream_get_contents($pipes[1]);$error.=stream_get_contents($pipes[2]);fclose($pipes[1]);fclose($pipes[2]);$closed=proc_close($p);if($exit===null)$exit=$closed;
        $available=$complete&&($exit===0||($exit===1&&preg_match('/^no crontab for /i',trim($error))===1));
        return['name'=>$name,'available'=>$available,'content'=>$exit===0?$out:'','system'=>false,'reason'=>$available?null:($complete?trim($error):'Cron collection timed out or exceeded output limit')];
    }
}
