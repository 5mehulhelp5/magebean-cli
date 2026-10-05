<?php
declare(strict_types=1);
namespace Magebean\Engine\Checks;
use Magebean\Engine\Context;
use Magebean\Engine\Collectors\CollectorSet;
use Magebean\Engine\Checks\Families\ComposerSupport;
use Magebean\Engine\Checks\Families\ComposerAdvisoryChecks;
use Magebean\Engine\Checks\Families\ComposerRepositoryChecks;
use Magebean\Engine\Checks\Families\ComposerVersionChecks;
use Magebean\Engine\Checks\Families\ComposerPolicyChecks;

/** Compatibility facade. Rule interpretation belongs to focused families. */
final class ComposerCheck extends ComposerSupport
{
    private ComposerAdvisoryChecks $composerAdvisoryChecks;
    private ComposerRepositoryChecks $composerRepositoryChecks;
    private ComposerVersionChecks $composerVersionChecks;
    private ComposerPolicyChecks $composerPolicyChecks;
    public function __construct(Context $ctx, ?CollectorSet $collectors = null)
    {
        parent::__construct($ctx, $collectors);
        $this->composerAdvisoryChecks = new ComposerAdvisoryChecks($ctx, $this->collectors);
        $this->composerRepositoryChecks = new ComposerRepositoryChecks($ctx, $this->collectors);
        $this->composerVersionChecks = new ComposerVersionChecks($ctx, $this->collectors);
        $this->composerPolicyChecks = new ComposerPolicyChecks($ctx, $this->collectors);
    }

    public function auditApi(array $args): array
    {
        return $this->composerAdvisoryChecks->auditApi($args);
    }

    public function adobeSecurityPatchesApi(array $args): array
    {
        return $this->composerAdvisoryChecks->adobeSecurityPatchesApi($args);
    }

    public function coreAdvisoriesApi(array $args): array
    {
        return $this->composerAdvisoryChecks->coreAdvisoriesApi($args);
    }

    public function fixVersionApi(array $args): array
    {
        return $this->composerAdvisoryChecks->fixVersionApi($args);
    }

    public function auditOffline(array $args): array
    {
        return $this->composerAdvisoryChecks->auditOffline($args);
    }

    public function kevAdvisoriesApi(array $args): array
    {
        return $this->composerAdvisoryChecks->kevAdvisoriesApi($args);
    }

    public function advisoryLatencyApi(array $args): array
    {
        return $this->composerAdvisoryChecks->advisoryLatencyApi($args);
    }

    public function transitiveAuditApi(array $args): array
    {
        return $this->composerAdvisoryChecks->transitiveAuditApi($args);
    }

    public function constraintsConflictApi(array $args): array
    {
        return $this->composerAdvisoryChecks->constraintsConflictApi($args);
    }

    public function yankedOffline(array $args): array
    {
        return $this->composerVersionChecks->yankedOffline($args);
    }

    public function coreAdvisoriesOffline(array $args): array
    {
        return $this->composerAdvisoryChecks->coreAdvisoriesOffline($args);
    }

    public function fixVersion(array $args): array
    {
        return $this->composerAdvisoryChecks->fixVersion($args);
    }

    public function riskSurfaceTag(array $args): array
    {
        return $this->composerPolicyChecks->riskSurfaceTag($args);
    }

    public function yankedApi(array $args): array
    {
        return $this->composerVersionChecks->yankedApi($args);
    }

    public function marketplaceOutdatedApi(array $args): array
    {
        return $this->composerVersionChecks->marketplaceOutdatedApi($args);
    }

    public function directOutdatedApi(array $args): array
    {
        return $this->composerVersionChecks->directOutdatedApi($args);
    }

    public function vendorSupportApi(array $args): array
    {
        return $this->composerRepositoryChecks->vendorSupportApi($args);
    }

    public function abandonedApi(array $args): array
    {
        return $this->composerRepositoryChecks->abandonedApi($args);
    }

    public function releaseRecencyApi(array $args): array
    {
        return $this->composerRepositoryChecks->releaseRecencyApi($args);
    }

    public function repoArchivedApi(array $args): array
    {
        return $this->composerRepositoryChecks->repoArchivedApi($args);
    }

    public function riskyForkApi(array $args): array
    {
        return $this->composerRepositoryChecks->riskyForkApi($args);
    }

    public function matchList(array $args): array
    {
        return $this->composerPolicyChecks->matchList($args);
    }

    public function constraintsConflict(array $args): array
    {
        return $this->composerPolicyChecks->constraintsConflict($args);
    }

    public function outdatedOffline(array $args): array
    {
        return $this->composerVersionChecks->outdatedOffline($args);
    }

    public function advisoryLatency(array $args): array
    {
        return $this->composerAdvisoryChecks->advisoryLatency($args);
    }

    public function vendorSupportOffline(array $args): array
    {
        return $this->composerRepositoryChecks->vendorSupportOffline($args);
    }

    public function composer_vendor_support_offline(array $args): array
    {
        return $this->composerVendorSupportOffline($args);
    }

    public function abandonedOffline(array $args): array
    {
        return $this->composerRepositoryChecks->abandonedOffline($args);
    }

    public function releaseRecencyOffline(array $args): array
    {
        return $this->composerRepositoryChecks->releaseRecencyOffline($args);
    }

    public function repoArchivedOffline(array $args): array
    {
        return $this->composerRepositoryChecks->repoArchivedOffline($args);
    }

    public function riskyForkOffline(array $args): array
    {
        return $this->composerRepositoryChecks->riskyForkOffline($args);
    }

    public function jsonConstraints(array $args): array
    {
        return $this->composerPolicyChecks->jsonConstraints($args);
    }

    public function lockVersions(string $rootDir): array
    {
        return $this->composerPolicyChecks->lockVersions($rootDir);
    }

    public function jsonKv(array $args): array
    {
        return $this->composerPolicyChecks->jsonKv($args);
    }

    public function lockIntegrity(array $args): array
    {
        return $this->composerPolicyChecks->lockIntegrity($args);
    }
}
