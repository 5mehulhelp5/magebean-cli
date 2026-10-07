<?php
declare(strict_types=1);
require __DIR__.'/../vendor/autoload.php';
use Magebean\Engine\{ScanPlanner,ScanRequest,ScanContext,RequirementPolicy};
use Magebean\Engine\Checks\CheckRegistry;
use Symfony\Component\Console\Tester\CommandTester;
$ctx=new ScanContext(sys_get_temp_dir(),'');$planner=new ScanPlanner();$registry=CheckRegistry::fromContext($ctx->toLegacy());
foreach([false,true] as $include){
 $plan=$planner->planCli(new ScanRequest($ctx,['profile'=>'owasp-top-10','include-manual-review'=>$include]),$registry);
 if($plan===null)throw new RuntimeException('Expected OWASP plan');
 $human=array_filter($plan->pack['rules'],[RequirementPolicy::class,'requiresHuman']);
 if(!$include&&count($human)!==0)throw new RuntimeException('Human requirements leaked into default scan');
 if($include&&count($human)===0)throw new RuntimeException('Flag must restore human requirements');
 $test=new CommandTester((new \Magebean\Application())->find('rules:list'));$test->execute(['--profile'=>'owasp-top-10','--include-manual-review'=>$include,'--no-ansi'=>true]);
 preg_match_all('/^(MB-\d+) \[/m',$test->getDisplay(),$ids);
 if($ids[1]!==array_column($plan->pack['rules'],'id'))throw new RuntimeException('Listing/scan selection differs');
}
echo "OwaspHumanSelectionTest: PASS\n";
