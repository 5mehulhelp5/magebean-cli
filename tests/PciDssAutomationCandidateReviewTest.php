<?php
declare(strict_types=1);

function assertPciCandidateReview(bool $condition,string $message):void{if(!$condition)throw new RuntimeException($message);}
$root=dirname(__DIR__);
$review=json_decode((string)file_get_contents($root.'/src/Rules/standards/pci-dss-v4.0.1-automation-candidate-review.json'),true,512,JSON_THROW_ON_ERROR);
$registry=json_decode((string)file_get_contents($root.'/src/Rules/standards/pci-dss-v4.0.1.json'),true,512,JSON_THROW_ON_ERROR);
$triage=json_decode((string)file_get_contents($root.'/src/Rules/standards/pci-dss-v4.0.1-gap-triage.json'),true,512,JSON_THROW_ON_ERROR);
$profile=json_decode((string)file_get_contents($root.'/src/Rules/profiles/pci-dss-v4.0.1.json'),true,512,JSON_THROW_ON_ERROR);
$registryBy=[];foreach($registry['requirements'] as $r)$registryBy[$r['id']]=$r;
$mappings=[];foreach($profile['rules'] as $rule)foreach($rule['mappings'] as $m)$mappings[$m['requirement']][$rule['id']]=$m['coverage'];
assertPciCandidateReview(count($review['requirements']??[])===71,'All 71 candidates must receive criterion review');
assertPciCandidateReview(($review['summary']['decisions']??null)===['REUSE_EXISTING_RULES'=>7,'EXTERNAL_SYSTEM_EVIDENCE'=>34,'CONTEXTUAL_APPLICABILITY'=>3,'HUMAN_ONLY'=>27],'Criterion-review decision summary is stale');
$seen=[];foreach($review['requirements'] as $entry){$id=$entry['requirement'];assertPciCandidateReview(!isset($seen[$id])&&isset($registryBy[$id]),"Unknown or duplicate review {$id}");$seen[$id]=true;assertPciCandidateReview($entry['source_pdf_page']===$registryBy[$id]['source']['pdf_page'],"Source page mismatch {$id}");assertPciCandidateReview($entry['testing_methods']===$registryBy[$id]['testing_methods'],"Testing methods mismatch {$id}");assertPciCandidateReview(($entry['human_verification_required']??false)===true,"Human verification missing {$id}");assertPciCandidateReview(trim((string)$entry['human_assessment_scope'])!==''&&!str_contains($entry['human_assessment_scope'],'Provide documented evidence that'),"Human scope is generic {$id}");if($entry['decision']==='REUSE_EXISTING_RULES')assertPciCandidateReview(array_keys($mappings[$id]??[])===$entry['existing_rules'],"Mapped rules differ for {$id}");}
assertPciCandidateReview(($triage['summary']['categories']['AUTOMATION_CANDIDATE']??null)===0,'Reviewed candidates must leave the automation backlog');
assertPciCandidateReview(($registryBy['3.3.3']['entity_restriction']??null)==='issuer_or_issuing_services_only','3.3.3 issuer applicability is missing');
assertPciCandidateReview(($registryBy['7.2.5.1']['entity_restriction']??null)==='service_provider_only','7.2.5.1 service-provider applicability is missing');
echo "PciDssAutomationCandidateReviewTest: PASS\n";
