<!-- WHY: Evaluates optional vulnerability scanning and evidence-gated VEX generation without conflating package inventory changes with code-level vulnerability proof. -->
# RQ-0008: OSV SBOM Comparison and VEX Evidence

## Status

Open

## Current boundary

The Maven plugin emits a post-elision CycloneDX SBOM when configured trimming runs. It records component and trim provenance, but has no OSV-Scanner integration, CVE-to-class mapping, or VEX generator. OSV-Scanner can match package coordinates from CycloneDX SBOMs against its vulnerability data ([official SBOM scanning usage](https://google.github.io/osv-scanner/usage/scan-source)); that package-level result does not identify which class or method a CVE affects.

## Research questions

1. Should the plugin optionally invoke OSV-Scanner against both a baseline SBOM and the post-elision SBOM, or should scanning remain an external CI step?
2. If it is integrated, how should scanner version, vulnerability database revision/time, target inventory, and outputs be recorded so pre/post results are comparable and reproducible?
3. Can the difference be reported only as findings no longer matched to the post-elision component inventory, without implying exploitability or code-level remediation?
4. What should happen when the scanner, network, or vulnerability database is unavailable: skip explicitly, warn, or fail? How can offline use remain clear and auditable?
5. Is there reliable vulnerability data that maps a CVE to specific classes or members, and can that map be linked to verified trim output strongly enough to support a CycloneDX VEX `code_not_present` statement?

## Options

1. Keep scanner execution external. Users scan the generated SBOM or final package in their CI security stage and retain scanner-owned results.
2. Add opt-in plugin orchestration for pinned scanner versions and explicit pre/post inventories, but emit package-level finding deltas only.
3. Add separate, opt-in VEX generation only when a vulnerability-to-code mapping and verified removed-code evidence support the chosen VEX status and justification. Otherwise emit no VEX statement.

## Benefits and costs

Integration could make the tested post-elision inventory easier to assess and could show which package findings no longer match that inventory. It adds scanner startup time, network/database access or database maintenance, version and database drift, output storage, and policy for failures and offline builds. A changed or missing package finding is only an inventory delta; it does not prove that vulnerable code was removed or that the product is unaffected.

## Evidence gates

- Compare scans of explicitly identified baseline and post-elision CycloneDX inventories using the same scanner version and a recorded database revision or timestamp.
- Label results as package-level findings; do not infer class-level status from an absent package finding or an elision decision.
- Generate VEX only when vulnerability data maps the CVE to code with sufficient precision and verified trim evidence establishes that mapped code is absent from the final component. Ambiguous mappings, incomplete code evidence, or scanner findings alone must produce no VEX statement.
- Test both positive and negative cases, including version-level findings that remain after trimming and imprecise vulnerability mappings that must not produce `code_not_present`.

## Decision requested

Determine whether optional scanner orchestration provides enough reproducibility and workflow value to justify its compute, network/database, and failure-policy costs. Keep package-level comparison and evidence-backed VEX generation as separate capabilities.

---

## Implementation Work Package

This investigation is decomposed into actionable implementation tracks in work package [WP-VEX-01](../handovers/2026-10-27-wp-vex-01-vulnerability-assessment-and-vex-evidence.md).
