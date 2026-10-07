<?php
declare(strict_types=1);
require __DIR__.'/../vendor/autoload.php';
use Magebean\Engine\Checks\Families\ComposerAdvisoryChecks;
use Magebean\Engine\Checks\GitHistoryCheck;
use Magebean\Engine\Context;
$n=0;function advisoryAssert(bool $ok,string $m):void{global$n;$n++;if(!$ok)throw new RuntimeException($m);}
$dir=sys_get_temp_dir().'/magebean-advisory-'.bin2hex(random_bytes(5));mkdir($dir);
$check=new ComposerAdvisoryChecks(new Context($dir,''));
file_put_contents($dir.'/composer.lock',json_encode(['packages'=>[]]));
advisoryAssert($check->auditApi([])[0]===null,'Empty scope is not clean evidence');
$validPackage=['name'=>'vendor/package','version'=>'1.0.0'];
foreach ([['packages'=>[$validPackage,['name'=>'broken/package']]], ['packages'=>[$validPackage],'packages-dev'=>'invalid'], ['packages'=>[$validPackage,$validPackage]], ['packages'=>[$validPackage,['name'=>'bad name','version'=>'1.0']]]] as $malformedLock) {
    file_put_contents($dir.'/composer.lock',json_encode($malformedLock));
    foreach (['auditApi','adobeSecurityPatchesApi'] as $method) {
        $result=$check->$method(['strict_scope'=>true,'endpoint'=>'invalid']);
        advisoryAssert($result[0]===null && str_contains($result[1],'composer.lock'),'Malformed lock records cannot be silently excluded from primary advisory scope');
    }
}
file_put_contents($dir.'/composer.lock',json_encode(['packages'=>[$validPackage],'packages-dev'=>[]]));
$result=$check->auditApi(['strict_scope'=>true,'endpoint'=>'invalid']);
advisoryAssert(str_contains($result[1],'endpoint'),'Complete lock scope reaches advisory endpoint validation');
$evaluate=new ReflectionMethod($check,'evaluateOsvAdvisories');
$installed=['vendor/package'=>'1.0.0'];
$affected=['package'=>['name'=>'vendor/package','ecosystem'=>'Packagist'],'versions'=>['1.0.0']];
$r=$evaluate->invoke($check,[['id'=>'TEST-1','affected'=>[$affected]]],$installed,[]);
advisoryAssert($r[0]===false,'Exact affected version must fail');
$affected['versions']=['0.9.0'];
advisoryAssert($evaluate->invoke($check,[['id'=>'TEST-1','affected'=>[$affected]]],$installed,[])[0]===true,'Exact unaffected version is clean in queried scope');
unset($affected['versions']);
advisoryAssert($evaluate->invoke($check,[['id'=>'TEST-1','affected'=>[$affected]]],$installed,[])[0]===null,'Missing version evidence is unknown');
$affected['ranges']=[['type'=>'GIT','events'=>[['introduced'=>'0'],['fixed'=>'deadbeef']]]];
advisoryAssert($evaluate->invoke($check,[['id'=>'TEST-1','affected'=>[$affected]]],$installed,[])[0]===null,'Git hash ranges cannot certify Composer version');
$affected['ranges']=[['type'=>'SEMVER','events'=>[['unknown'=>'1.0.0']]]];
advisoryAssert($evaluate->invoke($check,[['id'=>'TEST-1','affected'=>[$affected]]],$installed,[])[0]===null,'Malformed events cannot become clean evidence');
$affected['ranges']=[['type'=>'SEMVER','events'=>[['introduced'=>'0'],['fixed'=>'1.1.0']]]];
advisoryAssert($evaluate->invoke($check,[['id'=>'TEST-1','affected'=>[$affected]]],$installed,[])[0]===false,'Valid applicable range fails');
$affected['ranges']=[['type'=>'SEMVER','events'=>[['introduced'=>'0'],['fixed'=>'0.9.0']]]];
advisoryAssert($evaluate->invoke($check,[['id'=>'TEST-1','affected'=>[$affected]]],$installed,[])[0]===true,'Valid nonapplicable range passes bounded scope');
$args=['patterns'=>['AKIA[0-9A-Z]{16}'],'exclude_dirs'=>['.git'],'paths'=>['.']];
$git=new GitHistoryCheck(new Context($dir,''));
$r=$git->secretScan($args);advisoryAssert($r[0]===null && str_contains($r[1],'.git'),'Missing metadata returns concrete reason');
$missingArgs=$args;$missingArgs['paths']=['missing-source'];advisoryAssert($git->secretScan($missingArgs)[0]===null,'Configured missing paths cannot produce clean verdict');
exec('git -C '.escapeshellarg($dir).' init -q',$o,$exit);advisoryAssert($exit===0,'Fixture repository initialized');
file_put_contents($dir.'/clean.txt','ordinary text');
advisoryAssert($git->secretScan($args)[0]===true,'Empty local history plus clean working tree passes pattern criterion');
file_put_contents($dir.'/token.txt','AKIAABCDEFGHIJKLMNOP');
$r=$git->secretScan($args);advisoryAssert($r[0]===false && !str_contains($r[1],'AKIAABCDEFGHIJKLMNOP'),'Working tree pattern violation fails and is redacted');
exec('git -C '.escapeshellarg($dir).' -c user.email=qa@example.test -c user.name=QA add token.txt');
exec('git -C '.escapeshellarg($dir).' -c user.email=qa@example.test -c user.name=QA commit -qm fixture',$o,$exit);advisoryAssert($exit===0,'Fixture history committed');
unlink($dir.'/token.txt');
$r=$git->secretScan($args);advisoryAssert($r[0]===false && count($r[2]['git_history_findings'])===1,'Historical secret remains detectable after working tree removal');
advisoryAssert(str_contains($r[2]['scope'],'available local Git refs'),'Bounded history scope disclosed');
$it=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir,FilesystemIterator::SKIP_DOTS),RecursiveIteratorIterator::CHILD_FIRST);foreach($it as$f){$f->isDir()?rmdir($f->getPathname()):unlink($f->getPathname());}rmdir($dir);
echo "AdvisoryCompletionTest: $n assertions passed\n";
