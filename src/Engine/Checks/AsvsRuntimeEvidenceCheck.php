<?php
declare(strict_types=1);
namespace Magebean\Engine\Checks;
use Magebean\Engine\{Context, CheckResult, CheckOutcome};
use Magebean\Engine\Collectors\CollectorSet;

/** Deprecated adapter preserving legacy evidence keys and reason codes. */
final class AsvsRuntimeEvidenceCheck
{
    private readonly RuntimeEvidenceCheck $generic;
    public function __construct(Context $ctx, CollectorSet $collectors) { $this->generic=new RuntimeEvidenceCheck($ctx,$collectors); }
    public function contentType(array $args): CheckResult { return self::adapt($this->generic->contentType($args),'4.1.1','ASVS_RESPONSE_CONFIRMATION'); }
    public static function inspectResponse(array $response): array { return ['requirement'=>'4.1.1']+RuntimeEvidenceCheck::inspectResponse($response); }
    public function defaultAccounts(array $args): CheckResult { return self::adapt($this->generic->defaultAccounts(['artifact'=>'.magebean/evidence/asvs-default-accounts.json']+$args),'6.3.2','ASVS_ACCOUNT_CONFIRMATION'); }
    private static function adapt(CheckResult $result,string $id,string $reason): CheckResult
    {
        $message=str_replace('older than the permitted freshness window','older than 24 hours',$result->message);
        return CheckResult::of($result->outcome,$message,['requirement'=>$id]+$result->evidence,$result->outcome===CheckOutcome::Unknown?'ASVS_RUNTIME_EVIDENCE_MISSING':$reason);
    }
}
