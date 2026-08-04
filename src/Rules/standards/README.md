# Standards registries

Standards registries provide canonical requirement identifiers and applicability metadata independently from Magebean rule mappings. They do not select scan rules and do not claim compliance.

## PCI DSS v4.0.1

`pci-dss-v4.0.1.json` is derived from the official June 2024 document in `docs/PCI-DSS-v4_0_1.pdf`. It contains:

- 12 principal requirements;
- 63 core objective groups;
- 250 core Defined Approach requirement IDs;
- 30 additional requirement IDs across overlays A1, A2, and A3;
- testing-method categories, entity restrictions, effective-date metadata, approach availability, source pages, and source fingerprints.

The registry intentionally does not reproduce full PCI DSS requirement text. Requirement interpretation and assessment must use the official standard, applicability notes, testing procedures, and the applicable PCI validation program.

`pci-dss-v4.0.1-coverage.json` records evidence coverage for all 280 requirements; 35 currently have DIRECT, PARTIAL, or SUPPORTING Magebean evidence.

`pci-dss-v4.0.1-gap-triage.json` classifies the 245 unmapped requirements. The automation-candidate backlog is zero after the criterion review in `pci-dss-v4.0.1-automation-candidate-review.json`.

`pci-dss-v4.0.1-requirement-02-review.json` records the Requirement 2 decisions. MB-R371 implements the 2.2.2 hybrid evidence contract in `pci-dss-v4.0.1-2.2.2-evidence.schema.json`; complete evidence still cannot produce a PCI compliance conclusion.

`pci-dss-v4.0.1-context.schema.json` and `pci-dss-v4.0.1-external-evidence.schema.json` define the applicability and external-evidence inputs used by the PCI report workflow.

The three Appendix A overlays are not enabled globally:

- `A1`: multi-tenant service providers;
- `A2`: qualifying legacy card-present POS POI TLS environments;
- `A3`: designated entities subject to supplemental validation.

Run the semantic integrity check with:

```bash
php tests/PciDssRegistryTest.php
php tests/PciDssCoverageMatrixTest.php
php tests/PciDssGapTriageTest.php
php tests/PciDssRequirement02ReviewTest.php
php tests/PciDssRequirement022EvidenceDesignTest.php
```
