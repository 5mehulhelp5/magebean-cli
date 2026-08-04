<?php
declare(strict_types=1);
require_once __DIR__.'/../vendor/autoload.php';
use Magebean\Engine\Pci\PciApplicabilityCompiler;
function assertPciApp(bool $c,string $m):void{if(!$c)throw new RuntimeException($m);}
$root=dirname(__DIR__);$registry=json_decode((string)file_get_contents($root.'/src/Rules/standards/pci-dss-v4.0.1.json'),true,512,JSON_THROW_ON_ERROR);$context=json_decode((string)file_get_contents($root.'/docs/examples/pci-dss-context.example.json'),true,512,JSON_THROW_ON_ERROR);$compiler=new PciApplicabilityCompiler();$unknown=$compiler->compile($registry,$context);
assertPciApp($unknown['valid']===true&&$unknown['summary']['total']===280,'Compiler must cover the complete registry');
$by=[];foreach($unknown['requirements'] as $r)$by[$r['requirement']]=$r;
assertPciApp($by['1.1.1']['status']==='NOT_DETERMINED','Unconfirmed core scope must remain undetermined');
assertPciApp($by['A1.1.1']['status']==='NOT_APPLICABLE','Disabled A1 overlay must be excluded explicitly');
assertPciApp($by['3.3.3']['status']==='NOT_APPLICABLE','Issuer-only requirement must be excluded for a merchant');
$context['scope_confirmed']=true;$context['entity_type']='service_provider';$context['overlays']=['A1'];$compiled=$compiler->compile($registry,$context);$by=[];foreach($compiled['requirements'] as $r)$by[$r['requirement']]=$r;
assertPciApp($by['1.1.1']['status']==='APPLICABLE','Confirmed core scope must compile as applicable');
assertPciApp($by['7.2.5.1']['status']==='APPLICABLE','Service-provider criterion must compile for service providers');
assertPciApp($by['A1.1.1']['status']==='APPLICABLE','Enabled A1 overlay must compile as applicable');
echo "PciApplicabilityCompilerTest: PASS\n";
