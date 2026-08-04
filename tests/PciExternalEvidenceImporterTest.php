<?php
declare(strict_types=1);
require_once __DIR__.'/../vendor/autoload.php';
use Magebean\Engine\Pci\PciExternalEvidenceImporter;
function assertPciExternal(bool $c,string $m):void{if(!$c)throw new RuntimeException($m);}
$root=dirname(__DIR__);$registry=json_decode((string)file_get_contents($root.'/src/Rules/standards/pci-dss-v4.0.1.json'),true,512,JSON_THROW_ON_ERROR);$ids=array_column($registry['requirements'],'id');$importer=new PciExternalEvidenceImporter($ids);
$valid=$importer->import($root.'/docs/examples/pci-dss-external-evidence.example.json');
assertPciExternal($valid['valid']===true,'Example evidence package must import');
assertPciExternal($valid['summary']===['items'=>1,'requirements'=>1,'credential_material_processed'=>false],'Evidence summary mismatch');
assertPciExternal(isset($valid['evidence_by_requirement']['4.2.1.1']),'Requirement evidence index is missing');
$tmp=tempnam(sys_get_temp_dir(),'pci-evidence-');$bad=json_decode((string)file_get_contents($root.'/docs/examples/pci-dss-external-evidence.example.json'),true);$bad['evidence'][0]['password']='must-never-appear';file_put_contents($tmp,json_encode($bad));$invalid=$importer->import($tmp);unlink($tmp);
assertPciExternal($invalid['valid']===false,'Credential-bearing evidence must be rejected');
assertPciExternal(str_contains(implode(' ',$invalid['errors']),'Forbidden sensitive field'),'Forbidden-field error is missing');
assertPciExternal(!str_contains(json_encode($invalid),'must-never-appear'),'Credential value leaked into importer output');
echo "PciExternalEvidenceImporterTest: PASS\n";
