<?php
declare(strict_types=1);
// Loopback-only fixture; no Magento bootstrap, external redirects, or live API.
if (str_starts_with($_SERVER['REQUEST_URI'], '/not-magento')) {
    header('Content-Type: text/html');
    echo '<html><body>Ordinary storefront</body></html>';
    return;
}
header('Content-Type: text/html');
header('X-Magento-Version: 2.4.7');
header('X-Magento-Tags: fixture');
echo '<html><body><script type="text/x-magento-init">{}</script>Magento Open Source 2.4.7</body></html>';
