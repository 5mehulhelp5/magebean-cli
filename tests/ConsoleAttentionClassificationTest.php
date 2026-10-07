<?php
declare(strict_types=1);
require_once __DIR__ . '/../vendor/autoload.php';
use Magebean\Console\ScanConsoleRenderer;
use Symfony\Component\Console\Output\BufferedOutput;
function expectAttention(bool $condition, string $message): void { if (!$condition) throw new RuntimeException($message); }
$findings = [];
foreach (['FAIL','MANUAL_REVIEW','UNKNOWN','PASS'] as $i => $status) {
    $findings[] = ['id'=>'MB-999' . $i,'title'=>'Specific requirement ' . $i,'severity'=>$status === 'FAIL' ? 'high' : 'critical','status'=>$status,'passed'=>$status === 'PASS' ? true : ($status === 'FAIL' ? false : null),'message'=>$status === 'MANUAL_REVIEW' ? 'Requirement observations do not establish complete conformance; independent assessment is required.' : 'Evidence for ' . $status];
}
$scan = ['summary'=>['total'=>4,'passed'=>1],'findings'=>$findings,'meta'=>['profile'=>['id'=>'basic']]];
$out = new BufferedOutput(); (new ScanConsoleRenderer())->renderPrettySummary($out,$scan,__DIR__); $text=$out->fetch();
expectAttention(str_contains($text,'FINDINGS REQUIRING ATTENTION (1)'), 'Only confirmed FAIL counts as findings requiring attention');
expectAttention(str_contains($text,'HUMAN VERIFICATION REQUIRED (1)'), 'Human review has its own count and section');
expectAttention(str_contains($text,'INCONCLUSIVE CHECKS (1)'), 'Insufficient evidence has separate section');
expectAttention(!str_contains($text,'[CRITICAL]'), 'Manual and unknown classifications must not look like confirmed critical findings');
expectAttention(str_contains($text,'Specific requirement 1') && !str_contains($text,'Requirement observations do not establish'), 'Default human list identifies requirement instead of repeating generic boilerplate');
expectAttention(str_contains($text,"--profile='basic' --rules=MB-9991"), 'Human review provides targeted evidence details command');
$scan['meta']['rules_filter'] = array_column($findings,'id');
$out = new BufferedOutput(); (new ScanConsoleRenderer())->renderPrettySummary($out,$scan,__DIR__); $text=$out->fetch();
expectAttention(str_contains($text,'Rule details') && str_contains($text,'[PASS]') && str_contains($text,'[INCONCLUSIVE]'), 'Explicit selection retains all statuses');
expectAttention(str_contains($text,'Evidence needed') && str_contains($text,'Requirement observations do not establish'), 'Explicit selection retains actual human evidence instructions');
$scan['findings'] = [$findings[1]]; $scan['summary']=['total'=>1,'passed'=>0]; $scan['meta']['rules_filter']=[];
$out = new BufferedOutput(); (new ScanConsoleRenderer())->renderPrettySummary($out,$scan,__DIR__); $text=$out->fetch();
expectAttention(!str_contains($text,'FINDINGS REQUIRING ATTENTION'), 'Manual-only scan cannot imply confirmed findings');
echo "ConsoleAttentionClassificationTest: PASS\n";
