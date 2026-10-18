<?php
declare(strict_types=1);
namespace Magebean\Engine;

/** Group identical source-inspection causes for display without rewriting assessment/wire rows. */
final class SourceIssueGrouping
{
    public static function group(array $rows):array
    {
        $out=[];$positions=[];
        foreach($rows as$row){
            $remaining=[];
            foreach($row['risk_observation']['findings']??[]as$observation){
                if(($observation['kind']??'')!=='collection_issue'||empty($observation['evidence']['inspection_issue'])||empty($observation['fingerprint'])){$remaining[]=$observation;continue;}
                $key=$observation['fingerprint'];
                if(isset($positions[$key])){
                    $i=$positions[$key];$out[$i]['related_requirement_ids']=array_values(array_unique(array_merge($out[$i]['related_requirement_ids'],[$row['id']])));
                    $out[$i]['related_checks']=array_values(array_unique(array_merge($out[$i]['related_checks'],[$observation['check']])));
                    continue;
                }
                $copy=$row;$copy['severity']='info';$copy['title']=$copy['message']=$observation['message'];
                $copy['risk_observation']['findings']=[$observation];
                $copy['related_requirement_ids']=[$row['id']];$copy['related_checks']=[$observation['check']];
                $copy['requirement']['lane']='collection';$copy['requirement']['finding_guidance']=[];
                $copy['remediation']=array_values(array_filter([$observation['evidence']['collection_guidance']['action']??'']));
                $positions[$key]=count($out);$out[]=$copy;
            }
            if($remaining!==[]){$row['risk_observation']['findings']=$remaining;$out[]=$row;}
        }
        return $out;
    }
}
