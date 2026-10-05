<?php
declare(strict_types=1);
namespace Magebean\Engine\Checks;
use Magebean\Engine\Context;
use Magebean\Engine\Collectors\CollectorSet;
use Magebean\Engine\Checks\Families\CodeSearchSupport;
use Magebean\Engine\Checks\Families\CodeQueryChecks;
use Magebean\Engine\Checks\Families\PaymentSourceChecks;
use Magebean\Engine\Checks\Families\AuthorizationSourceChecks;
use Magebean\Engine\Checks\Families\DataProtectionSourceChecks;
use Magebean\Engine\Checks\Families\InputSafetySourceChecks;
use Magebean\Engine\Checks\Families\TemplateRequestSourceChecks;

/** Compatibility facade. Rule interpretation belongs to focused families. */
final class CodeSearchCheck extends CodeSearchSupport
{
    private CodeQueryChecks $codeQueryChecks;
    private PaymentSourceChecks $paymentSourceChecks;
    private AuthorizationSourceChecks $authorizationSourceChecks;
    private DataProtectionSourceChecks $dataProtectionSourceChecks;
    private InputSafetySourceChecks $inputSafetySourceChecks;
    private TemplateRequestSourceChecks $templateRequestSourceChecks;
    public function __construct(Context $ctx, ?CollectorSet $collectors = null)
    {
        parent::__construct($ctx, $collectors);
        $this->codeQueryChecks = new CodeQueryChecks($ctx, $this->collectors);
        $this->paymentSourceChecks = new PaymentSourceChecks($ctx, $this->collectors);
        $this->authorizationSourceChecks = new AuthorizationSourceChecks($ctx, $this->collectors);
        $this->dataProtectionSourceChecks = new DataProtectionSourceChecks($ctx, $this->collectors);
        $this->inputSafetySourceChecks = new InputSafetySourceChecks($ctx, $this->collectors);
        $this->templateRequestSourceChecks = new TemplateRequestSourceChecks($ctx, $this->collectors);
    }

    public function grep(array $args): array
    {
        return $this->codeQueryChecks->grep($args);
    }

    public function rawSql(array $args): array
    {
        return $this->inputSafetySourceChecks->rawSql($args);
    }

    public function piiMinimization(array $args): array
    {
        return $this->dataProtectionSourceChecks->piiMinimization($args);
    }

    public function unsafeXmlParsing(array $args): array
    {
        return $this->dataProtectionSourceChecks->unsafeXmlParsing($args);
    }

    public function hardcodedSecrets(array $args): array
    {
        return $this->dataProtectionSourceChecks->hardcodedSecrets($args);
    }

    public function apiKeyStorage(array $args): array
    {
        return $this->dataProtectionSourceChecks->apiKeyStorage($args);
    }

    public function thirdPartyLoggingSanitized(array $args): array
    {
        return $this->dataProtectionSourceChecks->thirdPartyLoggingSanitized($args);
    }

    public function saasIntegrationScoped(array $args): array
    {
        return $this->dataProtectionSourceChecks->saasIntegrationScoped($args);
    }

    public function cardholderDataStorage(array $args): array
    {
        return $this->paymentSourceChecks->cardholderDataStorage($args);
    }

    public function cardholderDataFiles(array $args): array
    {
        return $this->paymentSourceChecks->cardholderDataFiles($args);
    }

    public function cardholderDataLogs(array $args): array
    {
        return $this->paymentSourceChecks->cardholderDataLogs($args);
    }

    public function paymentMethodScope(array $args): array
    {
        return $this->paymentSourceChecks->paymentMethodScope($args);
    }

    public function checkoutRawCardCollection(array $args): array
    {
        return $this->paymentSourceChecks->checkoutRawCardCollection($args);
    }

    public function paymentScriptInventory(array $args): array
    {
        return $this->paymentSourceChecks->paymentScriptInventory($args);
    }

    public function paymentScriptIntegrity(array $args): array
    {
        return $this->paymentSourceChecks->paymentScriptIntegrity($args);
    }

    public function apiExposureMinimized(array $args): array
    {
        return $this->authorizationSourceChecks->apiExposureMinimized($args);
    }

    public function customAuthorizationChecks(array $args): array
    {
        return $this->authorizationSourceChecks->customAuthorizationChecks($args);
    }

    public function downloadExportAuthorization(array $args): array
    {
        return $this->authorizationSourceChecks->downloadExportAuthorization($args);
    }

    public function mediaExecutableCode(array $args): array
    {
        return $this->authorizationSourceChecks->mediaExecutableCode($args);
    }

    public function paymentPageTamperMonitoring(array $args): array
    {
        return $this->paymentSourceChecks->paymentPageTamperMonitoring($args);
    }

    public function securityHeadersBaseline(array $args): array
    {
        return $this->paymentSourceChecks->securityHeadersBaseline($args);
    }

    public function checkoutCspEnforced(array $args): array
    {
        return $this->paymentSourceChecks->checkoutCspEnforced($args);
    }

    public function phtmlEscapedOutput(array $args): array
    {
        return $this->templateRequestSourceChecks->phtmlEscapedOutput($args);
    }

    public function csrfFormKey(array $args): array
    {
        return $this->templateRequestSourceChecks->csrfFormKey($args);
    }

    public function ssrfSafeguards(array $args): array
    {
        return $this->inputSafetySourceChecks->ssrfSafeguards($args);
    }

    public function outboundEgressControls(array $args): array
    {
        return $this->inputSafetySourceChecks->outboundEgressControls($args);
    }

    public function unserializeSafety(array $args): array
    {
        return $this->inputSafetySourceChecks->unserializeSafety($args);
    }

    public function commandExecutionSafety(array $args): array
    {
        return $this->inputSafetySourceChecks->commandExecutionSafety($args);
    }

    public function dynamicExecutionSafety(array $args): array
    {
        return $this->inputSafetySourceChecks->dynamicExecutionSafety($args);
    }

    public function pathTraversalSafety(array $args): array
    {
        return $this->inputSafetySourceChecks->pathTraversalSafety($args);
    }

    public function uploadSafety(array $args): array
    {
        return $this->inputSafetySourceChecks->uploadSafety($args);
    }

    public function jsContextEscaping(array $args): array
    {
        return $this->templateRequestSourceChecks->jsContextEscaping($args);
    }

    public function csprngSafety(array $args): array
    {
        return $this->inputSafetySourceChecks->csprngSafety($args);
    }

    public function sensitiveLogging(array $args): array
    {
        return $this->dataProtectionSourceChecks->sensitiveLogging($args);
    }

    public function magentoApiCryptoSession(array $args): array
    {
        return $this->dataProtectionSourceChecks->magentoApiCryptoSession($args);
    }

    public function noMixedContent(array $args): array
    {
        return $this->codeQueryChecks->noMixedContent($args);
    }

    public function httpsEndpoints(array $args): array
    {
        return $this->codeQueryChecks->httpsEndpoints($args);
    }

    public function webhookSignatureValidation(array $args): array
    {
        return $this->templateRequestSourceChecks->webhookSignatureValidation($args);
    }
}
