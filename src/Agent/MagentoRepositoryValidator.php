<?php
declare(strict_types=1);
namespace Magebean\Agent;

final class MagentoRepositoryValidator
{
    public function assertValid(string $path): void
    {
        $message = 'Not a valid Magento 2 repository. Set --magento-path to the Magento 2 root containing composer.json, bin/magento and app/bootstrap.php.';
        foreach (['composer.json', 'bin/magento', 'app/bootstrap.php'] as $file) {
            if (!is_file($path . '/' . $file) || !is_readable($path . '/' . $file)) {
                throw new \RuntimeException($message);
            }
        }
        try {
            $composer = json_decode((string) file_get_contents($path . '/composer.json'), true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException $error) {
            throw new \RuntimeException($message, 0, $error);
        }
        $requires = is_array($composer) && is_array($composer['require'] ?? null) ? $composer['require'] : [];
        foreach (['magento/framework', 'magento/product-community-edition', 'magento/product-enterprise-edition', 'magento/magento2-base'] as $package) {
            if (isset($requires[$package])) {
                return;
            }
        }
        throw new \RuntimeException($message);
    }
}
