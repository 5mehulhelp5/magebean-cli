<?php
declare(strict_types=1);
namespace Magebean\Engine;

/** Trust failures do not establish whether the requested HTTP security header exists. */
final class TlsCollectionGuidance
{
    public static function steps(): array
    {
        return [
            'Check the exact HTTPS hostname and port reported in the evidence, the certificate subject/SAN, issuer, expiry and served intermediate chain from the scanner environment. Check whether an approved TLS-inspecting proxy is presenting a different certificate.',
            'For a public storefront, deploy a valid hostname-matching certificate and complete intermediate chain at the actual CDN, load balancer or origin TLS endpoint. Do not trust an unexpected self-signed certificate merely to silence the scanner.',
            'For an intentional private CA or development certificate, obtain the approved CA certificate through a trusted administrator channel and verify its fingerprint. Trust the site CA in the scanner PHP/cURL trust store: configure curl.cainfo or openssl.cafile for the PHP binary running the CLI. Keep TLS verification enabled; do not use insecure request flags.',
            'Rerun the same HTTPS probe after repairing trust. For MB-0027, inspect Strict-Transport-Security only after a successful same-host HTTPS response; a TLS trust failure does not prove that HSTS is missing. Then rerun the affected requirement.',
        ];
    }
}
