<?php
declare(strict_types=1);
final class PharReleaseGuard
{
    public static function inspect(string $archive,string $lockFile):array
    {
        $lock=json_decode((string)file_get_contents($lockFile),true,512,JSON_THROW_ON_ERROR);
        $production=array_column($lock['packages'],null,'name');
        $phar=new Phar($archive);$prefix='phar://'.str_replace('\\','/',realpath($archive)).'/';
        $paths=[];$seen=[];$rejected=[];
        foreach(new RecursiveIteratorIterator($phar)as$file){
            if(!$file->isFile())continue;
            $path=substr(str_replace('\\','/',$file->getPathname()),strlen($prefix));$paths[]=$path;
            $parts=explode('/',$path);$allowed=in_array($path,['composer.json','composer.lock','LICENSE'],true)||in_array($parts[0],['bin','src','resources'],true);
            if($path==='vendor/autoload.php'||($parts[0]==='vendor'&&($parts[1]??'')==='composer'&&count($parts)===3))$allowed=true;
            if($parts[0]==='vendor'&&count($parts)>=4){$package=$parts[1].'/'.$parts[2];if(isset($production[$package])){$allowed=true;$seen[$package]=true;}}
            if(!$allowed||preg_match('~(?:^|/)(?:artifacts|tools|tests?|docs?|\.git|\.github|\.agents|\.codex|node_modules|cache|build)(?:/|$)|\.phar(?:\.|$)|(?:^|/)\.env(?:\.|$)~i',$path))$rejected[]=$path;
        }
        if($rejected!==[])throw new RuntimeException('Release contains forbidden/non-runtime files: '.implode(', ',array_slice($rejected,0,12)));
        $missing=array_diff(array_keys($production),array_keys($seen));
        if($missing!==[])throw new RuntimeException('Runtime packages missing from PHAR: '.implode(', ',$missing));
        foreach(['bin/magebean','vendor/autoload.php','src/Rules/requirements/magebean-catalog.json','src/Rules/requirements/internal-profiles.json']as$required)if(!in_array($required,$paths,true))throw new RuntimeException('Required file missing: '.$required);
        return ['archive_bytes'=>filesize($archive),'files'=>count($paths),'runtime_packages'=>count($production),'forbidden_files'=>0,'sha256'=>hash_file('sha256',$archive)];
    }
}
