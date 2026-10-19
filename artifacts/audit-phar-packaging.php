<?php
declare(strict_types=1);
$target=$argv[1]??dirname(__DIR__).'/magebean.phar';
$phar=new Phar($target);$prefix='phar://'.str_replace('\\','/',realpath($target)).'/';
$files=[];$groups=[];$flags=[];
foreach(new RecursiveIteratorIterator($phar)as$file){
 if(!$file->isFile())continue;
 $name=str_replace('\\','/',$file->getPathname());$name=str_starts_with($name,$prefix)?substr($name,strlen($prefix)):$name;
 $size=$file->getSize();$compressed=$file->getCompressedSize();
 $group=explode('/',$name)[0];if(str_starts_with($name,'vendor/'))$group=implode('/',array_slice(explode('/',$name),0,3));
 $groups[$group]??=['files'=>0,'bytes'=>0,'compressed_bytes'=>0];$groups[$group]['files']++;$groups[$group]['bytes']+=$size;$groups[$group]['compressed_bytes']+=$compressed;
 $row=['path'=>$name,'bytes'=>$size,'compressed_bytes'=>$compressed];$files[]=$row;
 if(preg_match('~(?:^|/)(?:tests?|docs|artifacts|\.git|\.agents|\.codex|\.github|node_modules|cache)(?:/|$)|\.phar$|(?:^|/)(?:box(?:\.one-time)?\.json|magebean-report\.html|phpstan\.neon)$~i',$name))$flags[]=$row;
}
uasort($groups,static fn($a,$b)=>$b['compressed_bytes']<=>$a['compressed_bytes']);
usort($files,static fn($a,$b)=>$b['compressed_bytes']<=>$a['compressed_bytes']);
$out=['target'=>basename($target),'archive_bytes'=>filesize($target),'file_count'=>count($files),'logical_bytes'=>array_sum(array_column($files,'bytes')),'compressed_entry_bytes'=>array_sum(array_column($files,'compressed_bytes')),'groups'=>$groups,'largest_files'=>array_slice($files,0,25),'flagged_files'=>$flags];
file_put_contents(__DIR__.'/phar-packaging-audit.json',json_encode($out,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR)."\n");
echo json_encode(array_diff_key($out,['flagged_files'=>true,'largest_files'=>true]),JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES),"\n";
echo 'Flagged files: ',count($flags),"\nLargest entries:\n";foreach(array_slice($files,0,15)as$row)echo $row['compressed_bytes'],"\t",$row['path'],"\n";
