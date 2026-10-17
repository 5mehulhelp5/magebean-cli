<?php
declare(strict_types=1);
$console=dirname(__DIR__,2).'/console-magebean';
require $console.'/vendor/autoload.php';
$app=require $console.'/bootstrap/app.php';
$app->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();
$definitions=json_decode(file_get_contents(dirname(__DIR__).'/src/Rules/requirements/magebean-catalog.json'),true,512,JSON_THROW_ON_ERROR)['requirements'];
foreach($definitions as $definition){
 $rule=App\Models\Rule::query()->where('rule_key',$definition['id'])->firstOrFail();
 if($rule->remediation_guidance!==implode("\n",$definition['remediation']))throw new RuntimeException('Remediation mismatch: '.$rule->rule_key);
 if(($rule->standard_mapping['finding_guidance']??null)!==$definition['finding_guidance'])throw new RuntimeException('Structured guidance mismatch: '.$rule->rule_key);
}
echo count($definitions)," Magebean requirements have matching remediation and structured guidance in Console.\n";
