<?php
declare(strict_types=1);
require __DIR__.'/../vendor/autoload.php';
use Magebean\Engine\Context;
use Magebean\Engine\Checks\CheckRegistry;

// Read-only scanners inspect local artificial source. Payload files are never executed.
$root=sys_get_temp_dir().'/mb-scope-review-'.bin2hex(random_bytes(5));mkdir($root,0700);
$checks=['code_raw_sql','code_phtml_escaped_output','code_csrf_form_key','code_ssrf_safeguards','code_unserialize_safety','code_command_execution_safety','code_upload_safety','code_js_context_escaping'];
$payload= <<<'SOURCE'
<?php
echo $_GET['value'];
exec($_GET['command']);
unserialize($_GET['data']);
$connection->query('SELECT * FROM item WHERE id=' . $_GET['id']);
file_get_contents($_GET['url']);
move_uploaded_file($_FILES['file']['tmp_name'], $_GET['path']);
?>
<form method="post"><input name="value"></form>
<script>var value = "<?= $_GET['value'] ?>";</script>
SOURCE;
$rows=[];
try{
    foreach(['missing_scope','empty_scope','oversized_source','readable_source']as$scenario){
        if($scenario==='empty_scope')mkdir($root.'/app',0700);
        if($scenario==='oversized_source'||$scenario==='readable_source'){
            $content=$scenario==='oversized_source'?str_repeat(' ',1048577).$payload:$payload;
            file_put_contents($root.'/app/fixture.php',$content);file_put_contents($root.'/app/fixture.phtml',$content);
        }
        $registry=CheckRegistry::fromContext(new Context($root,''));
        foreach($checks as$name){$result=$registry->runResult($name,['paths'=>['app']]);$rows[]=['scenario'=>$scenario,'check'=>$name,'outcome'=>$result->outcome->value,'message'=>str_replace($root,'<FIXTURE>',$result->message),'evidence_entries'=>count($result->evidence)];}
    }
}finally{
    foreach(['fixture.php','fixture.phtml']as$file)if(is_file($root.'/app/'.$file))unlink($root.'/app/'.$file);
    if(is_dir($root.'/app'))rmdir($root.'/app');rmdir($root);
}
file_put_contents(__DIR__.'/focused-source-scope-observations.json',json_encode(['scope'=>'Synthetic local source fixtures; never executed; detector outputs only, not requirement or application conclusions. Oversized files exceed current inventory 1MiB filter.','observations'=>$rows],JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR)."\n");
foreach($rows as$row)echo $row['scenario'],' ',$row['check'],' ',$row['outcome'],PHP_EOL;
