<?php

declare(strict_types=1);

namespace Magebean\Engine\Checks;

use Magebean\Engine\Context;

final class MagentoCheck
{
    private Context $ctx;
    public function __construct(Context $ctx)
    {
        $this->ctx = $ctx;
    }
    public function stub(array $args): array
    {
        return [true, 'MagentoCheck stub PASS'];
    }

    public function adminFrontNameStrong(array $args): array
    {
        $file = (string)($args['file'] ?? 'app/etc/env.php');
        $path = (string)($args['path'] ?? 'backend.frontName');
        $minLength = max(1, (int)($args['min_length'] ?? 8));
        $denylist = $args['denylist'] ?? [
            'admin',
            'backend',
            'administrator',
            'adminpanel',
            'magento',
            'manage',
            'cms',
            'dashboard',
        ];
        if (!is_array($denylist)) {
            $denylist = [];
        }
        $denylist = array_values(array_filter(array_map(
            static fn(mixed $value): string => strtolower(trim((string)$value)),
            $denylist
        )));

        $arr = $this->loadArray($file);
        if (isset($arr['__ERROR__'])) {
            return [false, $arr['__ERROR__']];
        }

        $value = $this->getByDotPath($arr, $path, '__NOT_FOUND__');
        if ($value === '__NOT_FOUND__') {
            return [false, "Path '$path' not found in $file"];
        }

        $evidence = [
            'file' => $file,
            'path' => $path,
            'observed' => $value,
            'min_length' => $minLength,
            'denylist' => $denylist,
        ];

        if (!is_string($value)) {
            $evidence['reason'] = 'not_string';
            return [false, "Admin frontName must be a string", $evidence];
        }

        $frontName = trim($value);
        $normalized = strtolower($frontName);
        $evidence['observed'] = $frontName;
        $evidence['length'] = strlen($frontName);

        if ($frontName === '') {
            $evidence['reason'] = 'empty';
            return [false, "Admin frontName is empty", $evidence];
        }

        if (strlen($frontName) < $minLength) {
            $evidence['reason'] = 'too_short';
            return [false, "Admin frontName is shorter than {$minLength} characters", $evidence];
        }

        if (in_array($normalized, $denylist, true)) {
            $evidence['reason'] = 'denylisted';
            return [false, "Admin frontName uses a predictable route: {$frontName}", $evidence];
        }

        if (preg_match('/^admin(?:[\W_]*\d*)?$/i', $frontName) === 1 || preg_match('/^admin[\W_\d]+/i', $frontName) === 1) {
            $evidence['reason'] = 'admin_variant';
            return [false, "Admin frontName is too close to the default /admin route", $evidence];
        }

        if (preg_match('/^[a-z0-9][a-z0-9_-]*$/i', $frontName) !== 1) {
            $evidence['reason'] = 'invalid_format';
            return [false, "Admin frontName contains unsupported characters", $evidence];
        }

        return [true, "Admin frontName is non-default and not trivially guessable", $evidence];
    }

    public function adminTwoFactorAuthEnabled(array $args): array
    {
        $file = (string)($args['file'] ?? 'app/etc/config.php');
        $coreModule = (string)($args['core_module'] ?? 'Magento_TwoFactorAuth');
        $providerModules = $args['provider_modules'] ?? [
            'Magento_GoogleAuthenticator',
            'Magento_DuoSecurity',
            'Magento_U2fKey',
            'Magento_AdminAdobeImsTwoFactorAuth',
        ];
        if (!is_array($providerModules)) {
            $providerModules = [];
        }
        $providerModules = array_values(array_filter(array_map(
            static fn(mixed $value): string => trim((string)$value),
            $providerModules
        )));

        $arr = $this->loadArray($file);
        if (isset($arr['__ERROR__'])) {
            return [false, $arr['__ERROR__']];
        }

        $modules = $this->getByDotPath($arr, 'modules', []);
        if (!is_array($modules)) {
            return [false, "Path 'modules' in $file is not an array"];
        }

        $coreEnabled = $this->moduleEnabled($modules, $coreModule);
        $enabledProviders = [];
        $disabledProviders = [];
        foreach ($providerModules as $module) {
            if ($this->moduleEnabled($modules, $module)) {
                $enabledProviders[] = $module;
            } else {
                $disabledProviders[] = $module;
            }
        }

        $evidence = [
            'file' => $file,
            'core_module' => $coreModule,
            'core_enabled' => $coreEnabled,
            'provider_modules' => $providerModules,
            'enabled_providers' => $enabledProviders,
            'disabled_or_missing_providers' => $disabledProviders,
        ];

        if (!$coreEnabled) {
            return [false, "{$coreModule} is disabled or missing", $evidence];
        }

        if ($enabledProviders === []) {
            return [false, "No enabled Magento admin 2FA provider modules found", $evidence];
        }

        return [true, "Admin 2FA core module and provider are enabled", $evidence];
    }

    public function adminPasswordPolicyStrong(array $args): array
    {
        $file = (string)($args['file'] ?? 'app/etc/config.php');
        $basePath = (string)($args['base_path'] ?? 'system.default.admin.security');
        $minLength = (int)($args['min_password_length'] ?? 12);
        $maxLockoutFailures = (int)($args['max_lockout_failures'] ?? 10);
        $maxPasswordLifetimeDays = (int)($args['max_password_lifetime_days'] ?? 90);

        $arr = $this->loadArray($file);
        if (isset($arr['__ERROR__'])) {
            return [false, $arr['__ERROR__']];
        }

        $checks = [
            'min_password_length' => [
                'paths' => $this->policyPaths($basePath, ['min_password_length', 'minimum_password_length']),
                'op' => '>=',
                'value' => $minLength,
            ],
            'lockout_failures' => [
                'paths' => $this->policyPaths($basePath, ['lockout_failures', 'max_login_failures']),
                'op' => '<=',
                'value' => $maxLockoutFailures,
            ],
            'lockout_threshold' => [
                'paths' => $this->policyPaths($basePath, ['lockout_threshold', 'lockout_time', 'lockout_duration']),
                'op' => 'present_positive',
            ],
            'password_lifetime' => [
                'paths' => $this->policyPaths($basePath, ['password_lifetime', 'password_lifetime_days']),
                'op' => '<=',
                'value' => $maxPasswordLifetimeDays,
            ],
            'password_is_forced' => [
                'paths' => $this->policyPaths($basePath, ['password_is_forced', 'force_password_change']),
                'op' => 'truthy',
            ],
        ];

        $evidence = [
            'file' => $file,
            'base_path' => $basePath,
            'requirements' => [
                'min_password_length' => $minLength,
                'max_lockout_failures' => $maxLockoutFailures,
                'max_password_lifetime_days' => $maxPasswordLifetimeDays,
            ],
            'observed' => [],
            'failures' => [],
        ];

        foreach ($checks as $name => $check) {
            [$foundPath, $value] = $this->firstExistingPath($arr, $check['paths']);
            $evidence['observed'][$name] = [
                'path' => $foundPath,
                'value' => $value,
            ];

            if ($foundPath === null) {
                $evidence['failures'][] = "{$name} missing";
                continue;
            }

            $ok = match ($check['op']) {
                '>=' => is_numeric($value) && (float)$value >= (float)$check['value'],
                '<=' => is_numeric($value) && (float)$value <= (float)$check['value'],
                'truthy' => $this->truthy($value),
                'present_positive' => is_numeric($value) && (float)$value > 0,
                default => false,
            };

            if (!$ok) {
                $evidence['failures'][] = "{$name} weak";
            }
        }

        if ($evidence['failures'] !== []) {
            return [false, "Admin password policy is weak or incomplete", $evidence];
        }

        return [true, "Admin password policy meets minimum strength requirements", $evidence];
    }

    public function adminSessionTimeout(array $args): array
    {
        $file = (string)($args['file'] ?? 'app/etc/config.php');
        $basePath = (string)($args['base_path'] ?? 'system.default.admin.security');
        $maxSeconds = (int)($args['max_seconds'] ?? 900);

        $arr = $this->loadArray($file);
        if (isset($arr['__ERROR__'])) {
            return [false, $arr['__ERROR__']];
        }

        $paths = $this->policyPaths($basePath, ['session_lifetime', 'session_timeout']);
        [$foundPath, $value] = $this->firstExistingPath($arr, $paths);
        $evidence = [
            'file' => $file,
            'base_path' => $basePath,
            'path' => $foundPath,
            'observed' => $value,
            'max_seconds' => $maxSeconds,
        ];

        if ($foundPath === null) {
            return [false, "Admin session lifetime is not configured", $evidence];
        }

        if (!is_numeric($value)) {
            $evidence['reason'] = 'not_numeric';
            return [false, "Admin session lifetime is not numeric", $evidence];
        }

        $seconds = (int)$value;
        $evidence['observed_seconds'] = $seconds;
        if ($seconds <= 0) {
            $evidence['reason'] = 'non_positive';
            return [false, "Admin session lifetime must be positive", $evidence];
        }

        if ($seconds > $maxSeconds) {
            $evidence['reason'] = 'too_long';
            return [false, "Admin session lifetime exceeds {$maxSeconds} seconds", $evidence];
        }

        return [true, "Admin session lifetime is at or below {$maxSeconds} seconds", $evidence];
    }

    private function loadArray(string $relativeFile): array
    {
        $file = $this->ctx->abs($relativeFile);
        if (!is_file($file)) {
            return ['__ERROR__' => "$relativeFile not found"];
        }

        $data = @include $file;
        if (!is_array($data)) {
            return ['__ERROR__' => "$relativeFile did not return array"];
        }

        return $data;
    }

    private function getByDotPath(array $arr, string $path, mixed $default = null): mixed
    {
        if ($path === '' || $path === '.') {
            return $arr;
        }

        $keys = explode('.', $path);
        $cur = $arr;
        foreach ($keys as $key) {
            if (!is_array($cur) || !array_key_exists($key, $cur)) {
                return $default;
            }
            $cur = $cur[$key];
        }

        return $cur;
    }

    /**
     * Support both Magento's slash-style config keys and normalized nested keys.
     */
    private function policyPaths(string $basePath, array $keys): array
    {
        $normalizedBase = str_replace('/', '.', $basePath);
        $slashBase = str_replace('.', '/', $basePath);
        $paths = [];
        foreach ($keys as $key) {
            $paths[] = $basePath . '.' . $key;
            $paths[] = $basePath . '/' . $key;
            $paths[] = $normalizedBase . '.' . $key;
            $paths[] = $slashBase . '/' . $key;
        }

        return array_values(array_unique($paths));
    }

    private function firstExistingPath(array $arr, array $paths): array
    {
        foreach ($paths as $path) {
            $value = $this->getByDotPathFlexible($arr, (string)$path, '__NOT_FOUND__');
            if ($value !== '__NOT_FOUND__') {
                return [(string)$path, $value];
            }
        }

        return [null, null];
    }

    private function getByDotPathFlexible(array $arr, string $path, mixed $default = null): mixed
    {
        $value = $this->getByDotPath($arr, $path, '__NOT_FOUND__');
        if ($value !== '__NOT_FOUND__') {
            return $value;
        }

        return $this->getByDotPath($arr, str_replace('/', '.', $path), $default);
    }

    private function truthy(mixed $value): bool
    {
        return $value === 1 || $value === true || $value === '1' || $value === 'true' || $value === 'yes';
    }

    private function moduleEnabled(array $modules, string $module): bool
    {
        if ($module === '' || !array_key_exists($module, $modules)) {
            return false;
        }

        $value = $modules[$module];
        return $value === 1 || $value === true || $value === '1';
    }
}
