# Magebean API Reference

Magebean CLI performs most checks locally. Some dependency, package-lifecycle,
and Adobe security-patch rules call `https://api.magebean.com`.

## Data disclosure

API-backed checks send endpoint-specific data derived from the target project's
`composer.lock`. The exact request depends on the endpoint and selected rule.
Adobe package and patch alternatives are evaluated locally.

### `POST /v1/osv/advisories`

The CLI sends:

- request schema and the `Packagist` ecosystem;
- Composer package names and installed versions, possibly limited by the
  selected rule's package scope;
- client name and CLI version.

Example:

```json
{
  "schema_version": "magebean-osv-request-v1",
  "ecosystem": "Packagist",
  "packages": [
    {
      "name": "vendor/package",
      "version": "1.2.3"
    }
  ],
  "client": {
    "name": "magebean-cli",
    "version": "1.0.0"
  }
}
```

### `POST /v1/packages/status`

The CLI sends:

- request schema;
- Composer package names and installed versions.

The package list can include all locked packages or a subset such as direct
dependencies, Magento modules, or packages relevant to the selected rule.

Example:

```json
{
  "schema_version": "magebean-package-status-request-v1",
  "packages": [
    {
      "name": "vendor/package",
      "version": "1.2.3"
    }
  ]
}
```

### `POST /v1/adobe/security-patches`

The CLI sends:

- the detected Magento product (`adobe-commerce` or
  `magento-open-source`) and installed Magento version;
- empty `evidence.packages` and `evidence.patch_artifacts` containers required
  by the v1 API schema;
- client name and CLI version.

Example:

```json
{
  "schema_version": "magebean-adobe-patch-request-v1",
  "product": "magento-open-source",
  "installed_version": "2.4.8-p1",
  "evidence": {
    "packages": {},
    "patch_artifacts": []
  },
  "client": {
    "name": "magebean-cli",
    "version": "1.0.0"
  }
}
```

After the API returns `alternative_rules`, the CLI evaluates installed package
constraints, applied patch identifiers, relative paths, and file fingerprints

The request body fields are listed above. HTTPS infrastructure also receives
standard connection and HTTP metadata, plus authorization headers when a token
is configured.

To prevent these API disclosures, block outbound access to
`api.magebean.com` or do not select rules that use these endpoints. Such rules
may return `UNKNOWN` when their remote dataset is unavailable.
