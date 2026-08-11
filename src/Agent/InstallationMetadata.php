<?php
declare(strict_types=1);

namespace Magebean\Agent;

final class InstallationMetadata
{
    /** @return array{store_url:string,magento_version:string,magento_edition:string} */
    public function detect(string $root): array
    {
        $root = rtrim($root, DIRECTORY_SEPARATOR);
        [$version, $edition] = $this->product($root . '/composer.lock');
        $url = $this->storeUrl($root);

        if ($url === null || $version === null || $edition === null) {
            throw new \RuntimeException('Unable to detect Magento store URL, version and edition. Verify Magento configuration and run bin/magento successfully before pairing.');
        }

        return ['store_url' => $url, 'magento_version' => $version, 'magento_edition' => $edition];
    }

    /** @return array{0:?string,1:?string} */
    private function product(string $lockFile): array
    {
        if (!is_readable($lockFile)) return [null, null];
        $document = json_decode((string) file_get_contents($lockFile), true);
        if (!is_array($document)) return [null, null];
        foreach (['packages', 'packages-dev'] as $section) {
            foreach (($document[$section] ?? []) as $package) {
                $name = $package['name'] ?? null;
                if (!in_array($name, ['magento/product-community-edition', 'magento/product-enterprise-edition'], true)) continue;
                $version = ltrim((string) ($package['version'] ?? ''), 'v');
                return [$version !== '' ? $version : null, $name === 'magento/product-enterprise-edition' ? 'commerce' : 'open_source'];
            }
        }
        return [null, null];
    }

    private function storeUrl(string $root): ?string
    {
        foreach (['web/secure/base_url', 'web/unsecure/base_url'] as $path) {
            $command = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($root . '/bin/magento')
                . ' config:show ' . escapeshellarg($path) . ' --no-interaction 2>/dev/null';
            $lines = [];
            $status = 1;
            exec($command, $lines, $status);
            if ($status !== 0) continue;
            $candidate = trim(implode("\n", $lines));
            if (filter_var($candidate, FILTER_VALIDATE_URL) && in_array(parse_url($candidate, PHP_URL_SCHEME), ['http', 'https'], true)) {
                return rtrim($candidate, '/');
            }
        }
        return null;
    }
}
