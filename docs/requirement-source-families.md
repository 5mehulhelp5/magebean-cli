# Requirement source families

The active catalog separates three sources of assessment criteria:

| Family | Authority | Profiles | Requirements |
|---|---|---|---:|
| `magebean` | Magebean deployment and application security criteria | Basic, Hardening, OWASP Top 10 | 117 |
| `asvs` | OWASP ASVS 5.0.0, one requirement per document clause | ASVS L1 / L2 / L3 | 345 |
| `pci` | PCI DSS 4.0.1, one requirement per document clause | PCI readiness | 280 |

The physical files are `src/Rules/requirements/magebean-catalog.json`, `asvs-catalog.json` and `pci-catalog.json`. They are authoritative for runtime loading. `internal-catalog.json` remains a compatibility aggregate and must mirror all three exactly.

Basic, Hardening and OWASP contain only Magebean requirements. An OWASP Top 10 profile describes Magebean's security coverage categories; it is not an ASVS document profile. ASVS and PCI clauses retain their own version, reference, criterion and source provenance. Profiles cannot mix the families, including custom profiles.

Technical checks may be reused across families when their arguments and observation scope match. Assessment conclusions remain independent: a successful Magento setting check cannot certify an entire ASVS or PCI clause. Human evidence gates still apply; this migration does not promote automation or establish compliance.

The active inventory is 742. Source-family separation restored independent source-bound definitions (729 at that migration); the Basic Adobe review adds thirteen Magebean definitions using fresh IDs MB-0773–MB-0785. Basic now selects 37 technical requirements and six external evidence task groups. Retired IDs remain reserved. Historical allocation redirects and semantic-consolidation records preserve their original values; active legacy selectors resolve source-bound replacements recorded in `family-separation-manifest.json`. Historical assessment results must not be copied into new clauses as if they were fresh conclusions.

Earlier automation/profile audit artifacts describe the catalog at their recorded revision. Their counts and cross-family unions are superseded by this source-family model; they remain historical evidence, not the current inventory contract.

Deploy the CLI catalog and Console importer together, then re-import the catalog into Console. Verify seven customer profiles and family membership after import. Existing assessments retain their historical requirement revisions. This catalog migration does not rebuild the PHAR.
