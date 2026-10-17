<?php
declare(strict_types=1);
$console=dirname(__DIR__,2).'/console-magebean';
require $console.'/vendor/autoload.php';
$app=require $console.'/bootstrap/app.php';
$app->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();
$catalog=json_decode(file_get_contents(dirname(__DIR__).'/src/Rules/requirements/internal-profiles.json'),true,512,JSON_THROW_ON_ERROR)['profiles'];
$profiles=App\Models\Profile::query()->where('status','active')->whereNull('deprecated_at')->with('rules')->get();
$keys=$profiles->pluck('key')->sort()->values()->all();
$expected=array_column($catalog,'id');sort($expected);
if($keys!==$expected)throw new RuntimeException('Active Console profile keys differ from CLI catalog.');
foreach($profiles as $profile){
    $source=null;foreach($catalog as $entry)if($entry['id']===$profile->key)$source=$entry;
    $ids=$profile->rules->pluck('rule_key')->sort()->values()->all();
    $expectedIds=$source['requirement_ids'];sort($expectedIds);
    if($ids!==$expectedIds)throw new RuntimeException('Profile membership differs: '.$profile->key);
    foreach($profile->rules as$rule)if(($rule->standard_mapping['family']??null)!==$source['family'])throw new RuntimeException('Imported requirement family differs: '.$rule->rule_key);
    if($profile->requirement_source_label===null)throw new RuntimeException('Profile source label missing: '.$profile->key);
    $profile->available=true;
    echo $profile->key,': ',count($ids),' requirements; source: ',$profile->requirement_source_label,PHP_EOL;
}
$html=view('console.baseline-profile-options',['pickerProfiles'=>$profiles,'pickerContext'=>'create'])->render();
if(str_contains($html,'Complete internal requirement inventory')||str_contains($html,'External deployment evidence')||preg_match('/\b\d+\s+checks\b/',$html))throw new RuntimeException('Coverage picker still offers old profile or counts checks.');
$basic=$profiles->firstWhere('key','basic');
if(count($basic->external_evidence_tasks??[])!==count($catalog['basic']['evidence_tasks']??[]))throw new RuntimeException('Basic external evidence checklist differs from CLI.');
foreach(['baseline','external'] as $key){
    $old=App\Models\Profile::query()->where('key',$key)->first();
    echo 'Removed profile ',$key,': ',$old?->status??'absent',PHP_EOL;
}
echo "Console profile keys, membership and picker match CLI catalog.\n";
