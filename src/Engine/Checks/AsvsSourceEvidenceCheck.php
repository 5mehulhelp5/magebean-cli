<?php
declare(strict_types=1);
namespace Magebean\Engine\Checks;
use Magebean\Engine\{Context, CheckResult, CheckOutcome};
use Magebean\Engine\Collectors\CollectorSet;

/** Deprecated legacy adapter; canonical requirements invoke the generic check directly. */
final class AsvsSourceEvidenceCheck
{
    private readonly SourceSecurityObservationsCheck $generic;
    public function __construct(Context $ctx, CollectorSet $collectors) { $this->generic = new SourceSecurityObservationsCheck($ctx, $collectors); }
    public function run(array $args): CheckResult
    {
        $id=(string)($args['requirement']??'');
        $recipe=AsvsEvidenceRecipes::forRequirement($id);
        $result=$this->generic->run($recipe+['review'=>(string)($args['review']??'')]);
        return CheckResult::of($result->outcome,$result->message,['requirement'=>$id]+$result->evidence,
            $result->outcome===CheckOutcome::Unknown?'ASVS_SOURCE_EVIDENCE_MISSING':'ASVS_SOURCE_CONFIRMATION');
    }
}
