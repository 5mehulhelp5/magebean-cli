# PHAR packaging audit — 2026-10-18

Read-only manifest and compressed-entry inspection of `magebean.phar`: **26,982,575 bytes**, **3,450 files**, 60,211,612 uncompressed payload bytes. No build configuration or release binary was changed.

| Unnecessary runtime payload | Compressed entry bytes | Approx. MB |
|---|---:|---:|
| `artifacts/` (52 files, including two older PHARs) | 15,908,386 | 15.91 |
| `box.phar` (build tool) | 2,659,004 | 2.66 |
| Composer require-dev packages / transitive dev packages | 6,599,106 | 6.60 |
| **Subtotal** | **25,166,496** | **25.17** |

These disjoint categories account for approximately **93.3% of archive size**. Entry compressed sizes exclude PHAR manifest/stub overhead. Remaining size after subtracting these entries is 1,816,079 bytes; a real clean-build size still requires rebuilding and smoke-testing, so this is an estimate rather than a measured optimized binary.

The nested old binaries alone consume 7,734,256 and 7,728,186 compressed bytes (`artifacts/magebean-internal-qa.phar` and `artifacts/magebean-one-time.phar`). Vendor dev payload includes `humbug/box`, `jetbrains/phpstorm-stubs`, `thecodingmachine/safe`, php-scoper and related tooling. Other incidental root files include `magebean-report.html`, Box configs and `phpstan.neon`. The audit enumerates paths and sizes only, not report or credential contents.

Runtime packages according to composer.lock: composer/semver, psr/container, symfony/console, symfony/deprecation-contracts, symfony/polyfill-ctype, symfony/polyfill-intl-grapheme, symfony/polyfill-intl-normalizer, symfony/polyfill-mbstring, symfony/service-contracts, symfony/string. Their combined compressed package payload is **323,363 bytes**. `src/` is **1,169,494 compressed bytes**. Catalogs and their compatibility metadata should not be removed indiscriminately.

Cause: `box.json` includes all `vendor` through `directories`, then appends a `finder` rooted at `.`. That finder does not exclude `artifacts/` or `box.phar`. Finder exclusions do not filter files already included through `directories`; this is documented in the installed Box `doc/configuration.md`. Consequently, excluding vendor dev files only in a finder is insufficient when the whole vendor tree is separately selected. `box.one-time.json` also explicitly selects the entire vendor tree and should follow the same production-dependency build policy.

Recommended fix: use a strict runtime allow-list, remove the repository-root finder, package a clean Composer `--no-dev` dependency/autoload tree from isolated staging (preserving the developer workspace), and explicitly reject nested PHARs/artifacts/build tools in a release manifest check. Keep the Box executable outside the selected runtime inputs. Verify CLI startup, all profiles, agent commands and catalog counts before replacing the release PHAR.

Machine-readable full manifest aggregation and flagged paths: `phar-packaging-audit.json`. Reproduce with `php artifacts/audit-phar-packaging.php`; this command only inspects the archive and writes the audit report.
