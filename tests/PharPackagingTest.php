<?php
declare(strict_types=1);
require __DIR__.'/../tools/PharReleaseGuard.php';
$root=dirname(__DIR__);$count=0;
$assert=static function(bool$ok,string$message)use(&$count):void{++$count;if(!$ok)throw new RuntimeException($message);};
foreach(['box.json','box.one-time.json']as$name){$config=json_decode(file_get_contents($root.'/'.$name),true);$assert(!in_array('vendor',$config['directories'],true),'Vendor must not bypass dev filtering');$assert($config['finder'][0]['in']===['vendor'],'Finder must never sweep repository artifacts');$assert($config['exclude-dev-files']&&$config['dump-autoload'],'Dev exclusion requires a regenerated production autoloader');}
$report=PharReleaseGuard::inspect($root.'/magebean.phar',$root.'/composer.lock');
$runtimeCount=count(json_decode(file_get_contents($root.'/composer.lock'),true)['packages']);
$assert($report['forbidden_files']===0&&$report['runtime_packages']===$runtimeCount,'Actual release contains every runtime package and no forbidden content');
$assert($report['archive_bytes']<5000000,'Release stays below the packaging regression budget');
// Build isolated tiny archives in a child process: Phar write permission is an interpreter setting.
if(($argv[1]??'')==='--fixtures')exit(0);
$fixtureScript=tempnam(sys_get_temp_dir(),'magebean-phar-guard-');
$fixtureArchive=sys_get_temp_dir().'/magebean-guard-'.bin2hex(random_bytes(6)).'.phar';
$script=<<<'PHP'
<?php
require $argv[1].'/tools/PharReleaseGuard.php';
$archive=$argv[2];$lock=json_decode(file_get_contents($argv[1].'/composer.lock'),true);
$p=new Phar($archive);
foreach($lock['packages']as$package)$p['vendor/'.$package['name'].'/runtime.php']='<?php';
foreach(['bin/magebean','vendor/autoload.php','src/Rules/requirements/magebean-catalog.json','src/Rules/requirements/internal-profiles.json']as$file)$p[$file]='fixture';
$p->setStub('<?php __HALT_COMPILER();');
PharReleaseGuard::inspect($archive,$argv[1].'/composer.lock');
foreach(['artifacts/old.phar','box.phar','vendor/humbug/box/runtime.php','vendor/composer/pcre/runtime.php','vendor/symfony/service-contracts/Test/Test.php']as$forbidden){
 $p[$forbidden]='fixture';$rejected=false;
 try{PharReleaseGuard::inspect($archive,$argv[1].'/composer.lock');}catch(RuntimeException $e){$rejected=str_contains($e->getMessage(),'forbidden');}
 if(!$rejected)throw new RuntimeException('Did not reject '.$forbidden);
 unset($p[$forbidden]);
}
echo 'Nested archives, artifacts, dev dependencies and capitalized Test directories rejected.';
PHP;
try{
 file_put_contents($fixtureScript,$script);
 $process=proc_open([PHP_BINARY,'-d','phar.readonly=0',$fixtureScript,$root,$fixtureArchive],[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);
 fclose($pipes[0]);$out=stream_get_contents($pipes[1]);$err=stream_get_contents($pipes[2]);fclose($pipes[1]);fclose($pipes[2]);$exit=proc_close($process);
 $assert($exit===0,'Release guard rejects realistic regressions: '.$err);
 echo "PharPackagingTest: $count assertions passed; $out\n";
}finally{if(is_file($fixtureScript))unlink($fixtureScript);if(is_file($fixtureArchive))unlink($fixtureArchive);}
