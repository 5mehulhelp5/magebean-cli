<?php

declare(strict_types=1);

namespace Magebean\Engine\Checks;

use Magebean\Engine\Context;

final class CheckRegistry
{
    /** @var array<string, callable(array): array> */
    private array $checks = [];
    /** @var array<string, callable(string,array): array> */
    private array $prefixChecks = [];
    /** @var array<string, object> */
    private array $services = [];

    public static function fromContext(Context $ctx): self
    {
        $registry = new self();

        $fs = new FilesystemCheck($ctx);
        $phpc = new PhpConfigCheck($ctx);
        $comp = new ComposerCheck($ctx);
        $mage = new MagentoCheck($ctx);
        $http = new HttpCheck($ctx);
        $code = new CodeSearchCheck($ctx);
        $web = new WebServerConfigCheck($ctx);
        $git = new GitHistoryCheck($ctx);
        $cron = new CronCheck($ctx);
        $sys = new SystemCheck($ctx);

        $registry->services['http'] = $http;

        $registry->register('http_header', fn(array $args): array => $http->stub($args));
        $registry->registerPrefix('http_', fn(string $name, array $args): array => $http->dispatch($name, $args));

        foreach (['code_grep', 'text_grep', 'file_grep', 'grep'] as $name) {
            $registry->register($name, fn(array $args): array => $code->grep($args));
        }
        $registry->register('code_raw_sql', fn(array $args): array => $code->rawSql($args));
        $registry->register('code_phtml_escaped_output', fn(array $args): array => $code->phtmlEscapedOutput($args));
        $registry->register('code_csrf_form_key', fn(array $args): array => $code->csrfFormKey($args));
        $registry->register('code_ssrf_safeguards', fn(array $args): array => $code->ssrfSafeguards($args));
        $registry->register('code_unserialize_safety', fn(array $args): array => $code->unserializeSafety($args));
        $registry->register('code_command_execution_safety', fn(array $args): array => $code->commandExecutionSafety($args));
        $registry->register('code_dynamic_execution_safety', fn(array $args): array => $code->dynamicExecutionSafety($args));
        $registry->register('code_path_traversal_safety', fn(array $args): array => $code->pathTraversalSafety($args));
        $registry->register('code_upload_safety', fn(array $args): array => $code->uploadSafety($args));
        $registry->register('code_js_context_escaping', fn(array $args): array => $code->jsContextEscaping($args));
        $registry->register('code_csprng_safety', fn(array $args): array => $code->csprngSafety($args));
        $registry->register('code_sensitive_logging', fn(array $args): array => $code->sensitiveLogging($args));
        $registry->register('code_magento_api_crypto_session', fn(array $args): array => $code->magentoApiCryptoSession($args));
        $registry->register('code_no_mixed_content', fn(array $args): array => $code->noMixedContent($args));
        $registry->register('code_https_endpoints', fn(array $args): array => $code->httpsEndpoints($args));
        $registry->register('code_webhook_signature_validation', fn(array $args): array => $code->webhookSignatureValidation($args));
        $registry->register('code_outbound_egress_controls', fn(array $args): array => $code->outboundEgressControls($args));
        $registry->register('code_pii_minimization', fn(array $args): array => $code->piiMinimization($args));
        $registry->register('code_api_key_storage', fn(array $args): array => $code->apiKeyStorage($args));
        $registry->register('code_hardcoded_secrets', fn(array $args): array => $code->hardcodedSecrets($args));
        $registry->register('code_unsafe_xml_parsing', fn(array $args): array => $code->unsafeXmlParsing($args));
        $registry->register('code_third_party_logging_sanitized', fn(array $args): array => $code->thirdPartyLoggingSanitized($args));
        $registry->register('code_saas_integration_scoped', fn(array $args): array => $code->saasIntegrationScoped($args));
        $registry->register('code_cardholder_data_storage', fn(array $args): array => $code->cardholderDataStorage($args));
        $registry->register('code_cardholder_data_files', fn(array $args): array => $code->cardholderDataFiles($args));
        $registry->register('code_cardholder_data_logs', fn(array $args): array => $code->cardholderDataLogs($args));
        $registry->register('code_payment_method_scope', fn(array $args): array => $code->paymentMethodScope($args));
        $registry->register('code_checkout_raw_card_collection', fn(array $args): array => $code->checkoutRawCardCollection($args));
        $registry->register('code_payment_script_inventory', fn(array $args): array => $code->paymentScriptInventory($args));
        $registry->register('code_payment_script_integrity', fn(array $args): array => $code->paymentScriptIntegrity($args));
        $registry->register('code_checkout_csp_enforced', fn(array $args): array => $code->checkoutCspEnforced($args));
        $registry->register('code_security_headers_baseline', fn(array $args): array => $code->securityHeadersBaseline($args));
        $registry->register('code_payment_page_tamper_monitoring', fn(array $args): array => $code->paymentPageTamperMonitoring($args));
        $registry->register('code_media_executable_code', fn(array $args): array => $code->mediaExecutableCode($args));
        $registry->register('code_custom_authorization_checks', fn(array $args): array => $code->customAuthorizationChecks($args));
        $registry->register('code_download_export_authorization', fn(array $args): array => $code->downloadExportAuthorization($args));
        $registry->register('code_api_exposure_minimized', fn(array $args): array => $code->apiExposureMinimized($args));

        $registry->register('fs_no_world_writable', fn(array $args): array => $fs->noWorldWritable($args));
        $registry->register('file_mode_max', fn(array $args): array => $fs->fileModeMax($args));
        $registry->register('file_owner_group_matches', fn(array $args): array => $fs->fileOwnerGroupMatches($args));
        $registry->register('webroot_hygiene', fn(array $args): array => $fs->webrootHygiene($args));
        $registry->register('code_dirs_readonly', fn(array $args): array => $fs->codeDirsReadonly($args));
        $registry->register('no_directory_listing', fn(array $args): array => $fs->noDirectoryListing($args));
        $registry->register('fs_exists', fn(array $args): array => $fs->fsExists($args));
        $registry->register('security_mitigations_documented', fn(array $args): array => $fs->securityMitigationsDocumented($args));
        $registry->register('pci_manual_evidence_documented', fn(array $args): array => $fs->pciManualEvidenceDocumented($args));
        $registry->register('fs_di_compiled', fn(array $args): array => $fs->diCompiled($args));
        $registry->register('fs_static_content_deployed', fn(array $args): array => $fs->staticContentDeployed($args));
        $registry->register('fs_indexers_ready', fn(array $args): array => $fs->indexersReady($args));
        $registry->register('fs_mtime_max_age', fn(array $args): array => $fs->mtimeMaxAge($args));
        $registry->register('fs_logs_reports_not_in_webroot', fn(array $args): array => $fs->logsReportsNotInWebroot($args));
        $registry->register('fs_log_rotation_configured', fn(array $args): array => $fs->logRotationConfigured($args));

        $registry->register('system_egress_restricted', fn(array $args): array => $sys->egressRestricted($args));

        foreach (['php_array_exists', 'php_array_eq', 'php_array_neq', 'php_array_numeric_compare', 'php_array_absent'] as $name) {
            $registry->register($name, fn(array $args): array => $phpc->dispatch($name, $args));
        }
        $registry->register('php_array_key_search', fn(array $args): array => $phpc->keySearch($args));
        $registry->register('php_xdebug_disabled', fn(array $args): array => $phpc->xdebugDisabled($args));
        $registry->register('php_display_errors_disabled', fn(array $args): array => $phpc->displayErrorsDisabled($args));
        $registry->register('php_template_hints_disabled', fn(array $args): array => $phpc->templateHintsDisabled($args));
        $registry->register('php_dev_debug_config_disabled', fn(array $args): array => $phpc->devDebugConfigDisabled($args));
        $registry->register('php_third_party_debug_disabled', fn(array $args): array => $phpc->thirdPartyDebugDisabled($args));
        $registry->register('php_full_page_cache_configured', fn(array $args): array => $phpc->fullPageCacheConfigured($args));
        $registry->register('php_cache_backend_configured', fn(array $args): array => $phpc->cacheBackendConfigured($args));
        $registry->register('php_session_storage_hardened', fn(array $args): array => $phpc->sessionStorageHardened($args));
        $registry->register('php_no_file_cache_backend', fn(array $args): array => $phpc->noFileCacheBackend($args));

        $registry->register('magento_config', fn(array $args): array => $mage->stub($args));
        $registry->register('magento_admin_frontname_strong', fn(array $args): array => $mage->adminFrontNameStrong($args));
        $registry->register('magento_admin_2fa_enabled', fn(array $args): array => $mage->adminTwoFactorAuthEnabled($args));
        $registry->register('magento_admin_password_policy_strong', fn(array $args): array => $mage->adminPasswordPolicyStrong($args));
        $registry->register('magento_admin_session_timeout', fn(array $args): array => $mage->adminSessionTimeout($args));
        $registry->register('magento_admin_exposure_restricted', fn(array $args): array => $mage->adminExposureRestricted($args));
        $registry->register('magento_admin_captcha_or_rate_limit', fn(array $args): array => $mage->adminCaptchaOrRateLimit($args));
        $registry->register('magento_production_mode', fn(array $args): array => $mage->productionMode($args));
        $registry->register('magento_https_enforced', fn(array $args): array => $mage->httpsEnforced($args));
        $registry->register('magento_cookie_flags_secure', fn(array $args): array => $mage->cookieFlagsSecure($args));
        $registry->register('nginx_directive', fn(array $args): array => $web->nginxDirective($args));
        $registry->register('apache_htaccess_directive', fn(array $args): array => $web->apacheDirective($args));
        $registry->register('webserver_hsts_config', fn(array $args): array => $web->hstsConfig($args));
        $registry->register('webserver_tls_ciphers', fn(array $args): array => $web->tlsCiphers($args));

        $registry->register('composer_audit_api', fn(array $args): array => $comp->auditApi($args));
        $registry->register('composer_adobe_security_patches_api', fn(array $args): array => $comp->adobeSecurityPatchesApi($args));
        $registry->register('composer_core_advisories_api', fn(array $args): array => $comp->coreAdvisoriesApi($args));
        $registry->register('composer_fix_version_api', fn(array $args): array => $comp->fixVersionApi($args));
        $registry->register('composer_kev_advisories_api', fn(array $args): array => $comp->kevAdvisoriesApi($args));
        $registry->register('composer_transitive_audit_api', fn(array $args): array => $comp->transitiveAuditApi($args));
        $registry->register('composer_constraints_conflict_api', fn(array $args): array => $comp->constraintsConflictApi($args));
        $registry->register('composer_yanked_api', fn(array $args): array => $comp->yankedApi($args));
        $registry->register('composer_marketplace_outdated_api', fn(array $args): array => $comp->marketplaceOutdatedApi($args));
        $registry->register('composer_direct_outdated_api', fn(array $args): array => $comp->directOutdatedApi($args));
        $registry->register('composer_advisory_latency_api', fn(array $args): array => $comp->advisoryLatencyApi($args));
        $registry->register('composer_vendor_support_api', fn(array $args): array => $comp->vendorSupportApi($args));
        $registry->register('composer_abandoned_api', fn(array $args): array => $comp->abandonedApi($args));
        $registry->register('composer_release_recency_api', fn(array $args): array => $comp->releaseRecencyApi($args));
        $registry->register('composer_repo_archived_api', fn(array $args): array => $comp->repoArchivedApi($args));
        $registry->register('composer_risky_fork_api', fn(array $args): array => $comp->riskyForkApi($args));
        $registry->register('composer_audit_offline', fn(array $args): array => $comp->auditOffline($args));
        $registry->register('composer_core_advisories_offline', fn(array $args): array => $comp->coreAdvisoriesOffline($args));
        $registry->register('composer_fix_version', fn(array $args): array => $comp->fixVersion($args));
        $registry->register('composer_risk_surface_tag', fn(array $args): array => $comp->riskSurfaceTag($args));
        $registry->register('composer_match_list', fn(array $args): array => $comp->matchList($args));
        $registry->register('composer_constraints_conflict', fn(array $args): array => $comp->constraintsConflict($args));
        $registry->register('composer_yanked_offline', fn(array $args): array => $comp->yankedOffline($args));
        $registry->register('composer_outdated_offline', fn(array $args): array => $comp->outdatedOffline($args));
        $registry->register('composer_advisory_latency', fn(array $args): array => $comp->advisoryLatency($args));
        $registry->register('composer_vendor_support_offline', fn(array $args): array => $comp->vendorSupportOffline($args));
        $registry->register('composer_abandoned_offline', fn(array $args): array => $comp->abandonedOffline($args));
        $registry->register('composer_release_recency_offline', fn(array $args): array => $comp->releaseRecencyOffline($args));
        $registry->register('composer_repo_archived_offline', fn(array $args): array => $comp->repoArchivedOffline($args));
        $registry->register('composer_risky_fork_offline', fn(array $args): array => $comp->riskyForkOffline($args));
        $registry->register('composer_json_constraints', fn(array $args): array => $comp->jsonConstraints($args));
        $registry->register('composer_json_kv', fn(array $args): array => $comp->jsonKv($args));
        $registry->register('composer_lock_integrity', fn(array $args): array => $comp->lockIntegrity($args));

        $registry->register('git_history_scan', fn(array $args): array => $git->secretScan($args));
        $registry->register('crontab_grep', fn(array $args): array => $cron->crontabGrep($args));
        $registry->register('cron_magento_configured', fn(array $args): array => $cron->magentoCronConfigured($args));
        $registry->register('cron_heartbeat_recent', fn(array $args): array => $cron->heartbeatRecent($args));
        $registry->register('cron_backlog_below_threshold', fn(array $args): array => $cron->backlogBelowThreshold($args));

        return $registry;
    }

    public function register(string $name, callable $check): void
    {
        $this->checks[$name] = $check;
    }

    public function registerPrefix(string $prefix, callable $check): void
    {
        $this->prefixChecks[$prefix] = $check;
    }

    public function has(string $name): bool
    {
        if (isset($this->checks[$name])) {
            return true;
        }
        foreach ($this->prefixChecks as $prefix => $_) {
            if (str_starts_with($name, $prefix)) {
                return true;
            }
        }
        return false;
    }

    public function run(string $name, array $args): array
    {
        if (isset($this->checks[$name])) {
            return ($this->checks[$name])($args);
        }
        foreach ($this->prefixChecks as $prefix => $check) {
            if (str_starts_with($name, $prefix)) {
                return $check($name, $args);
            }
        }
        return [null, '[UNKNOWN] Unknown check: ' . $name, []];
    }

    public function transportCounts(): array
    {
        $http = $this->services['http'] ?? null;
        if (is_object($http) && method_exists($http, 'getTransportCounts')) {
            return $http->getTransportCounts();
        }
        return ['ok' => 0, 'total' => 0];
    }
}
