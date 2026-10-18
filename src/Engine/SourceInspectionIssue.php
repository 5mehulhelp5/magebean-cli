<?php
declare(strict_types=1);
namespace Magebean\Engine;

/** Actionable analysis/collection limitations, never security vulnerability conclusions. */
final class SourceInspectionIssue
{
    private const RECIPES=[
        'local_source_unavailable'=>['Local project source is unavailable in this execution context.','Run the source check against the deployed project path in local mode, or omit this local-only check from the remote scan.'],
        'missing_source_path'=>['The configured source path does not exist.','Verify the release root and configured source paths. If this deployment intentionally has no custom source at this path, adjust scope/applicability; a missing path alone is not a vulnerability.'],
        'unreadable_directory'=>['The scanner could not enumerate this source directory.','Grant the scan identity the minimum read/traverse access needed for this directory, then rerun. Do not make application code writable or world-readable merely to satisfy inspection.'],
        'unreadable_source'=>['The scanner could not read this source file.','Check the scan identity, file read permission and read-only mount access; rerun with appropriate read access without weakening production write restrictions.'],
        'oversized_source'=>['This eligible source file exceeds the configured per-file inspection limit.','Inspect the file size and purpose. If it belongs in scope, rerun with a bounded max_file_bytes budget sufficient for this file; exclude generated artifacts only through an explicit scope decision.'],
        'source_changed_or_truncated'=>['This file changed or could not be read completely during collection.','Rerun against a stable deployed release or immutable checkout and verify that the complete file can be read within the configured budget.'],
        'symlink_not_followed'=>['This source path is a symbolic link, which the bounded collector does not follow.','Confirm the link target belongs to the assessed release and inspect it through a supported explicit source root. Do not remove a legitimate deployment symlink merely to silence the limitation.'],
        'source_outside_project'=>['This source path resolves outside the configured project root.','Verify the deployment layout and select the actual project root or a separately scoped source scan that includes the intended code.'],
        'unsupported_source_entry'=>['This filesystem entry is not a supported regular source file or directory.','Inspect its entry type and deployment purpose; use a supported regular-file source snapshot if the entry contains application code.'],
        'no_eligible_source_files'=>['The configured scope contains no eligible source files; this is not a security defect.','Confirm the source paths and extension filter. If the release intentionally has no custom code in this scope, record that applicability through scan configuration rather than treating an empty scan as proof of safety.'],
        'deadline_exceeded'=>['Source collection reached its inspection time limit before completing this scope.','Rerun a stable release with a larger bounded timeout_seconds budget or split the source scope into smaller complete scans.'],
        'entry_or_deadline_budget_exceeded'=>['Source enumeration reached its entry or time budget before completing this directory.','Split the source scope into smaller complete scans, or increase the bounded time budget where appropriate; remove generated/dependency trees from this custom-code scope only when they are genuinely outside the policy.'],
        'file_budget_exceeded'=>['Source collection reached the configured eligible-file count limit.','Split the source scope into smaller complete scans or increase max_files within the supported bound, then verify that every intended file was collected.'],
        'total_byte_budget_exceeded'=>['Source collection reached the configured total-byte limit.','Split the source scope or increase max_total_bytes within the supported bound; rerun until the intended scope is completely collected.'],
        'analysis_deadline_exceeded'=>['Static source analysis reached its time limit before finishing this file.','Rerun with a larger bounded timeout_seconds budget or split the source scope; this limit does not mean the file is malicious.'],
        'unsupported_parser'=>['No supported parser is available for this eligible file type.','Use the supported PHP/PHTML source scope for this policy, or add a real parser for the required language before claiming coverage.'],
        'malformed_php'=>['PHP source could not be parsed at the reported location.','Check the deployed file with php -l using the matching application PHP version. Correct actual syntax/build corruption, or run the scanner with a parser supporting the deployed PHP syntax; do not assume every parser mismatch is an application defect.'],
        'function_alias_requires_resolution'=>['An imported function alias cannot be resolved by this syntax-only policy analyzer.','Resolve the alias and its call target in a supported analyzer, or use a supported explicit call form where appropriate. A legitimate alias alone is not unsafe code.'],
        'indirect_callable'=>['A variable or indirect callable target cannot be resolved by this syntax-only analyzer.','Trace the callable assignment and allowed targets with an analyzer that supports this implementation. Do not replace legitimate callbacks solely to obtain a clean scan.'],
        'indirect_dispatch'=>['A dynamic dispatch API prevents proving which function is invoked.','Trace the dispatched callable and its allowed targets through a supported static-analysis or isolated integration test; the dispatch API alone is not proof of a vulnerability.'],
        'dynamic_include_target'=>['A computed include/require target cannot be resolved by this syntax-only analyzer.','Verify the target is restricted to intended installed files using a supported analyzer. If appropriate, make the installed-file map explicit; do not infer an execution vulnerability solely from a dynamic include.'],
        'assertion_expression_requires_version_resolution'=>['The assertion expression needs PHP-version-aware evaluation beyond this analyzer.','Verify the installed PHP assertion semantics and the actual expression using a compatible analyzer; do not classify ordinary assertions as code execution solely from this gap.'],
        'sql_first_argument_not_static_literal'=>['The query method receives a nonliteral first argument whose construction is unresolved.','Trace where the query argument is built and verify parameter binding through the installed database adapter. Use a supported query analyzer or an explicit static query with separately bound values where appropriate; a variable query alone does not prove SQL injection.'],
        'sql_first_argument_expression_unresolved'=>['The query first-argument expression cannot be resolved by this syntax-only analyzer.','Trace the complete query expression and binding behavior with a supported database-aware analyzer or isolated adapter test; this unresolved expression alone is not a confirmed injection.'],
    ];

    public static function fromGaps(array $inventoryGaps,array $analysisGaps,array $scope=[]):array
    {
        $raw=array_merge($inventoryGaps,$analysisGaps);$specific=false;
        foreach($raw as $gap)if(is_array($gap)&&($gap['reason']??'')!=='no_eligible_source_files'){$specific=true;break;}
        $issues=[];$seen=[];
        foreach($raw as $gap){
            if(!is_array($gap))continue;
            $reason=(string)($gap['reason']??'inspection_reason_unavailable');
            if($reason==='no_eligible_source_files'&&$specific)continue;
            $file=str_replace('\\','/',(string)($gap['file']??''));
            $line=is_int($gap['line']??null)&&$gap['line']>0?$gap['line']:null;
            $fingerprint=hash('sha256',json_encode([$reason,$file,$line],JSON_UNESCAPED_SLASHES|JSON_THROW_ON_ERROR));
            if(isset($seen[$fingerprint]))continue;$seen[$fingerprint]=true;
            [$message,$action]=self::RECIPES[$reason]??['The scanner reported an unsupported inspection limitation.','Review the reported reason and scanner compatibility, then rerun with a supported complete source scope; this limitation alone is not a security vulnerability.'];
            $location=$file!==''?$file.($line!==null?':'.$line:''):($scope!==[]?'Source scope '.implode(', ',array_filter($scope,'is_string')):'Source inspection');
            $issue=['file'=>$file,'reason'=>$reason,'message'=>$location.': '.$message,'action'=>$action,'fingerprint'=>$fingerprint];
            if($line!==null)$issue['line']=$line;
            $issues[]=$issue;if(count($issues)>=100)break;
        }
        return $issues;
    }
}
