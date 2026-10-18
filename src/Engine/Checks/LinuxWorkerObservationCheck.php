<?php
declare(strict_types=1);
namespace Magebean\Engine\Checks;
use Magebean\Engine\Context;

/** Observes explicitly configured Linux PHP-FPM workers, without reading environ or executing target PHP. */
final class LinuxWorkerObservationCheck
{
    public function __construct(private Context $ctx, private string $procRoot='/proc') {}

    public function xdebugModulesAbsent(array $args): array
    {
        $relative=(string)($args['policy_file']??'.magebean/php-fpm-workers.json');
        if(preg_match('~^(?:/|[A-Za-z]:)|(?:^|/)\.\.(?:/|$)~',str_replace('\\','/',$relative)))return[null,'[UNKNOWN] Worker policy must be project-relative',[]];
        $root=realpath($this->ctx->path);$file=realpath($this->ctx->abs($relative));
        if($root===false||$file===false||!str_starts_with($file,$root.'/')||!is_readable($file)||filesize($file)>65536)return[null,'[UNKNOWN] Supply a readable bounded PHP-FPM worker inventory policy',['action'=>'Provide .magebean/php-fpm-workers.json with explicit pool, pid and process start_ticks entries for the intended Linux workers.']];
        $raw=$this->read($file,65536);
        if($raw===null)return[null,'[UNKNOWN] Worker inventory could not be read completely',[]];
        $policy=json_decode($raw,true);
        $workers=$policy['workers']??null;
        if(($policy['schema_version']??null)!==1||!is_array($workers)||!array_is_list($workers)||$workers===[]||count($workers)>128)return[null,'[UNKNOWN] Worker inventory policy is missing or malformed',[]];
        $checked=[];$gaps=[];$off=[];$seen=[];
        foreach($workers as$worker){
            $pid=$worker['pid']??null;$pool=$worker['pool']??null;$expectedTicks=$worker['start_ticks']??null;
            if(!is_int($pid)||$pid<1||isset($seen[$pid])||!is_string($pool)||!preg_match('/^[A-Za-z0-9_.-]+$/D',$pool)||!is_string($expectedTicks)||!ctype_digit($expectedTicks))return[null,'[UNKNOWN] Each worker requires unique pid, pool and exact process start_ticks',[]];
            $seen[$pid]=true;$base=$this->procRoot.'/'.$pid;
            $before=$this->read($base.'/stat',8192);$cmd=$this->read($base.'/cmdline',16384);$exe=@readlink($base.'/exe');
            if($before===null||$cmd===null||!is_string($exe)||!preg_match('~^php-fpm(?:[0-9.]*)?$~',basename($exe))||trim(str_replace("\0",' ',$cmd))!=='php-fpm: pool '.$pool||$this->ticks($before)!==$expectedTicks){$gaps[]=['pid'=>$pid,'reason'=>'worker_identity_or_start_time_unverified'];continue;}
            $maps=$this->read($base.'/maps',4194304);$after=$this->read($base.'/stat',8192);
            if($maps===null||trim($maps)===''||$after===null||$this->ticks($after)!==$expectedTicks){$gaps[]=['pid'=>$pid,'reason'=>'worker_maps_unreadable_or_identity_changed'];continue;}
            $modules=[];foreach(explode("\n",$maps)as$line)if(preg_match('~(?:^|/)(xdebug[^/\s]*\.so)(?:\s|$)~i',$line,$m))$modules[]=$m[1];
            $checked[]=['pid'=>$pid,'pool'=>$pool,'start_ticks'=>$expectedTicks,'xdebug_modules'=>array_values(array_unique($modules))];
            if($modules!==[])$off[]=['pid'=>$pid,'pool'=>$pool];
        }
        $ev=['scope'=>'configured Linux PHP-FPM worker process mappings at observation time; does not prove all deployment workers are inventoried or Xdebug feature mode','policy_sha256'=>hash('sha256',$raw),'checked'=>$checked,'collection_gaps'=>$gaps];
        if($off!==[])return[false,'Xdebug binary module mapped in configured PHP-FPM worker process',$ev];
        if($gaps!==[])return[null,'[UNKNOWN] PHP-FPM worker module inventory incomplete',$ev];
        return[true,'No Xdebug binary module mapped in the configured verified PHP-FPM worker processes',$ev];
    }
    private function read(string $file,int $limit):?string
    {
        $stream=@fopen($file,'rb');if($stream===false)return null;
        $text=stream_get_contents($stream,$limit+1);fclose($stream);
        return is_string($text)&&strlen($text)<=$limit?$text:null;
    }
    private function ticks(string $stat):?string
    {
        $end=strrpos($stat,')');if($end===false)return null;
        $fields=preg_split('/\s+/',trim(substr($stat,$end+1)));
        return isset($fields[19])&&ctype_digit($fields[19])?$fields[19]:null;
    }
}
