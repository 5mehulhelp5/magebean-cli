<?php
declare(strict_types=1);
require __DIR__.'/../vendor/autoload.php';
use Magebean\Engine\{RequirementCatalog,RequirementPolicy,ScanPlanner,ScanRequest,ScanContext,Context};
use Magebean\Engine\Checks\CheckRegistry;
$root=sys_get_temp_dir().'/mb-migration-audit-'.bin2hex(random_bytes(5));
mkdir($root,0700);
try {
    $context=new ScanContext($root,'','',['meta'=>['target_mode'=>'LOCAL']]);
    $registry=CheckRegistry::fromContext(new Context($root,''));
    foreach(['basic','baseline','asvs-l1','asvs-l2','asvs-l3','pci'] as $profile) {
        foreach([false,true] as $manual) {
            $diagnostics=[];
            $plan=(new ScanPlanner())->planCli(new ScanRequest($context,['profile'=>$profile,'include-manual-review'=>$manual]),$registry,static function($d)use(&$diagnostics){$diagnostics[]=$d->message();});
            echo json_encode(['profile'=>$profile,'include_manual'=>$manual,'planned'=>$plan===null?null:count($plan->pack['rules']),'diagnostics'=>$diagnostics],JSON_UNESCAPED_SLASHES),PHP_EOL;
        }
    }
} finally { rmdir($root); }
