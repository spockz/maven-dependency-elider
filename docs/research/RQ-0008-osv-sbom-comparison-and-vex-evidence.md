<!-- WHY: Evaluates optional vulnerability scanning and evidence-gated VEX generation without conflating package inventory changes with code-level vulnerability proof. -->
# RQ-0008: OSV SBOM Comparison and VEX Evidence

## Status

Open

## Current boundary

The Maven plugin emits a post-elision CycloneDX SBOM when configured trimming runs. The core now provides strict vulnerability-symbol mapping parsing/merging, an explicit-source cache with offline fallback, and a fail-closed omitted-code proof API that can create immutable attestation values from verified archive evidence. The Maven plugin does not yet load POM overrides or connect this proof API to trimming, and VEX serialization and OSV-Scanner integration remain pending. OSV-Scanner can match package coordinates from CycloneDX SBOMs against its vulnerability data ([official SBOM scanning usage](https://google.github.io/osv-scanner/usage/scan-source)); that package-level result does not identify which class or method a CVE affects.

## Track 3 evidence status

The external `make scan-sbom` harness compares machine-readable OSV-Scanner results for the example's baseline and post-elision CycloneDX inventories. It records a common scanner executable/version, separate start and completion timestamps for each scan, the SHA-256 of each input SBOM, the raw scan JSON, and the package-level delta. Each SBOM is hashed before and after its scan; a changed file aborts comparison, and classification uses the in-memory inventory parsed from the bytes whose hash is recorded. It requests offline vulnerability matching so both scans use the scanner's shared local cache. OSV-Scanner does not expose a database revision in this workflow, so identical database contents are not claimed or independently verified. The harness accepts exit status `1` only when valid JSON contains findings and accepts status `0` only when JSON has no findings; inconsistent output, other nonzero statuses, malformed JSON, and status `1` without findings are execution/result errors. A finding is called eliminated only if the associated component is absent from the post-elision SBOM; if that component remains but the finding is not returned, the report labels it separately. Older OSV-Scanner output without PURLs is resolved against the input inventory by Maven coordinate and version; if multiple PURL variants match, the finding remains unclassified.

An eliminated finding means that the baseline package finding did not match a package finding in the post-elision inventory. It is not evidence that vulnerable code was removed or that a product is unaffected, and the harness emits no VEX. This resolves the decoupled CI workflow question in favor of an external comparison gate while leaving VEX eligibility subject to the separate symbol-evidence gates below.

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
- Core proof requires exact group, artifact, version, type, and classifier identity, HIGH mapping confidence, matching archive digests, mapped classes present in the original, and mapped plus original nested classes absent from the trimmed archive. Scope is ignored for package identity. The mapping's `versionRangeSpec` is retained as metadata only; Maven `ComparableVersion` range evaluation and applicability matching are not implemented here.
- Strict JSON input rejects unknown/duplicate fields and trailing documents. Cache refresh uses a caller-supplied HTTP(S) URI, bounded lock/body waits, streamed temporary files, atomic replacement, and cache/seed fallback. No remote feed is selected and the bundled seed is empty.
- Plugin wiring, POM override loading, Maven version-range matching, scanner orchestration, and CycloneDX VEX serialization are pending.

## Implemented evidence and architectural alignment

The proof API is constrained by the per-JAR provenance and original-artifact immutability invariants in [ADR-0003, Invariants](../adr/0003-proguard-core-intra-jar-trimming-and-cyclonedx-pedigree.md#invariants). [OmittedCodeProof.java](../../elider-core/src/main/java/io/github/spockz/elider/model/OmittedCodeProof.java) verifies exact artifact identity and recorded digests before and after inspecting each archive; [OmittedCodeProofTest.java](../../elider-core/src/test/java/io/github/spockz/elider/model/OmittedCodeProofTest.java) covers successful proof, surviving mapped and nested classes, digest mutation, identity mismatch, and a mapped class absent from the original.

Mapping ingestion and refresh are implemented in [VulnerabilityMappingReader.java](../../elider-core/src/main/java/io/github/spockz/elider/scanner/VulnerabilityMappingReader.java) and [VulnerabilityCacheManager.java](../../elider-core/src/main/java/io/github/spockz/elider/scanner/VulnerabilityCacheManager.java). Their tests are [VulnerabilityMappingReaderTest.java](../../elider-core/src/test/java/io/github/spockz/elider/scanner/VulnerabilityMappingReaderTest.java) and [VulnerabilityCacheManagerTest.java](../../elider-core/src/test/java/io/github/spockz/elider/scanner/VulnerabilityCacheManagerTest.java); these cover strict JSON, override precedence, offline/cache fallback, bounded refresh, temporary-file cleanup, and replacement of an existing longer temporary file.

## Decision requested

Determine whether optional scanner orchestration provides enough reproducibility and workflow value to justify its compute, network/database, and failure-policy costs. Keep package-level comparison and evidence-backed VEX generation as separate capabilities.

---

## Implementation Work Package

This investigation is decomposed into actionable implementation tracks in work package [WP-VEX-01](../handovers/2026-10-27-wp-vex-01-vulnerability-assessment-and-vex-evidence.md).
