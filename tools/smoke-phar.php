<?php
declare(strict_types=1);
$archive=realpath($argv[1]??'');if(!$archive)throw new RuntimeException('Supply a built PHAR.');
require 'phar://'.$archive.'/vendor/autoload.php';
$catalog=\Magebean\Engine\RequirementCatalog::loadAll();
$root=sys_get_temp_dir().'/magebean-release-smoke-'.bin2hex(random_bytes(6));mkdir($root.'/app/code/Example',0755,true);
try{
    file_put_contents($root.'/app/code/Example/Input.php',"<?php\n\$value = \$_GET['id'];\n");
    $ctx=new \Magebean\Engine\Context($root,'');
    $registry=\Magebean\Engine\Checks\CheckRegistry::fromContext($ctx);
    foreach(['automated_source_policy','production_worker_xdebug_absent','dependency_source_policy']as$name)if(!$registry->has($name))throw new RuntimeException('Missing packaged check '.$name);
    $rule=array_column($catalog['rules'],null,'id')['MB-0014'];
    $result=(new \Magebean\Engine\ScanRunner($ctx,['rules'=>[$rule]],null,$registry))->run();
    if(empty($result['findings'][0]['risk_observation']['needs_attention']))throw new RuntimeException('Packaged source scan did not find known input fixture.');
    file_put_contents($root.'/app/code/Example/Broken.php',"<?php\nfunction broken(\n");
    $source=$registry->runResult('automated_source_policy',['kind'=>'native_unserialize','paths'=>['app/code'],'include_ext'=>['php']]);
    if(empty($source->evidence['inspection_issues']))throw new RuntimeException('Packaged source-inspection issue collector is unavailable.');
    foreach(['asvs-l1','asvs-l2','asvs-l3','pci']as$profile)\Magebean\Engine\RequirementProfileCatalog::load($profile);
    echo json_encode(['catalog_requirements'=>count($catalog['rules']),'known_source_finding'=>true,'specific_inspection_issue'=>true,'standards_profiles'=>true],JSON_THROW_ON_ERROR),"\n";
}finally{foreach(glob($root.'/app/code/Example/*')?:[]as$file)unlink($file);rmdir($root.'/app/code/Example');rmdir($root.'/app/code');rmdir($root.'/app');rmdir($root);}
