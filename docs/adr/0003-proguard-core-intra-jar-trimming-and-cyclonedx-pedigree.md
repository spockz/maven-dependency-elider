<!-- WHY: Records the architectural decision to use ProGuard Core for intra-JAR dependency trimming, signature stripping, and recording provenance via CycloneDX 1.6 pedigree. -->
# ADR-0003: ProGuard Core-Driven Intra-JAR Trimming and CycloneDX Pedigree

* **Status**: Accepted
* **Date**: 2026-10-29 (MRJAR decision added)
* **Last Updated**: 2026-11-17

<!-- semedit-adr-metadata:v1 keys=summary,description,role,scope,area,languages; do not change key names or order. -->
| Key | Value |
| :--- | :--- |
| summary | Use ProGuard Core to trim unreferenced classes from retained dependency JARs, vertically shade supported MRJAR tiers, sanitize signatures, and record provenance via CycloneDX 1.6 pedigree. |
| description | Select com.guardsquare:proguard-core under Apache 2.0 to compute transitive intra-JAR link closure from runtime, source, and framework roots; elevate compiler-target MRJAR classes and union closure through the Maven runtime release; output separate trimmed JARs, strip invalidated signatures, swap in-memory artifact files, and emit schema-valid CycloneDX pedigree. |
| role | architecture |
| scope | build-lifecycle |
| area | plugin-core |
| languages | java |

## Context

While whole-artifact elision (ADR-0001) successfully removes completely unused JARs, enterprise applications frequently retain large third-party libraries while actively using only a small percentage of their classes (e.g., using only 10 out of 200 classes in `commons-compress` or `netty`). The unused classes often contain dormant CVEs (such as deserialization gadgets or obsolete protocol parsers) that trigger false-positive scanner alerts.

Previous attempts at custom link-closure algorithms risk missing complex JVM bytecode relationships (such as invokedynamic bootstraps, inner class attributes, generic type signatures, and constant pool constraints), causing runtime `NoClassDefFoundError` or `VerifyError`. Furthermore, altering a signed JAR without stripping signatures causes `java.lang.SecurityException`, and altering bytecode without recording provenance causes checksum verifiers and vulnerability scanners to misattribute or reject the resulting artifacts.

## Decision

Adopt **`com.guardsquare:proguard-core:9.4.0`** (licensed under Apache License 2.0) as the underlying engine to perform intra-JAR dependency trimming:

1. **Root Set Formulation**:
   Construct the root set $R$ for each retained dependency by combining:
   * Positive runtime telemetry (CDS class lists, `-Xlog:class+load`, JFR `jdk.ClassLoad`, JaCoCo execution probes).
   * Compiled application bytecode roots (direct type references, supertypes/interfaces, field/method/generic signatures, and annotations in compiled production classes; compile-time inlined constants require explicit `elide.retainedArtifacts`).
   * Dynamic entry points (Java SPI `META-INF/services/*` and GraalVM `reflect-config.json`; `META-INF/spring-autoconfigure-metadata.properties` is not read as a root-generation fallback).

2. **Per-JAR Intra-Link Closure**:
   Load the candidate dependency JAR into a `ProgramClassPool` and the surrounding classpath (JDK and other dependencies) into a `LibraryClassPool`. Use ProGuard Core's visitor graph and `ClassReferenceInitializer` to compute the transitive fixed-point closure of required internal classes within the dependency JAR, preserving all required compilation and runtime metadata (`Signature`, `Exceptions`, `InnerClasses`, `EnclosingMethod`, and annotations).

3. **Archive Sanitization & Signature Stripping**:
   Stream the retained classes and non-class resources into `target/elided-artifacts/<artifactId>-<version>-trimmed.jar`.
   Following `maven-shade-plugin` standard practices:
   * Strip digital signature block files (`META-INF/*.SF`, `META-INF/*.DSA`, `META-INF/*.RSA`, `META-INF/SIG-*`).
   * Cleanse `META-INF/MANIFEST.MF` by purging section digest headers.
   * Preserve all non-class resources (`META-INF/services/`, license and NOTICE files, XML schemas, properties).
   * **Multi-Release Archive Sanitization and Vertical Shading**: For a retained candidate with `META-INF/versions/`, select each class's effective baseline version $V_{\text{base}} = \max\{v \in S(C) \mid v \le T\}$ and write that implementation at the archive root. Omit superseded lower-version bytecodes. Preserve every physical class entry above $T$ byte-for-byte, including higher-tier overrides and helpers. Keep `Multi-Release: true` if and only if versioned entries remain; otherwise remove the attribute so the output is a standard single-release archive.

4. **In-Memory Redirection (ADR-0002)**:
   Redirect the in-memory artifact file pointer via `artifact.setFile(trimmedJarPath)` during the default `process-classes` phase ([ADR-0010](0010-process-classes-lifecycle-and-bytecode-completeness.md)) so that downstream packaging plugins (`maven-shade-plugin`, `spring-boot-maven-plugin:repackage`, assembly) bundle the trimmed JARs into terminal distributions without bespoke adapters.

5. **CycloneDX 1.6 Pedigree Provenance**:
   Emit schema-valid CycloneDX 1.6 SBOM records for each trimmed dependency:
   * `component.hashes`: The actual SHA-256 digest of the trimmed file on disk.
   * `component.pedigree.ancestors`: The original upstream Maven Central coordinate and original Central SHA-256 digest.
   * `component.pedigree.patches`: Unofficial patch descriptor noting the count of pruned classes.
   * `component.properties`: Structured metrics: `elider:status=trimmed`; logical `elider:retainedClasses` and `elider:totalClasses`, counting unique binary classes across all tiers; and physical `elider:inputPhysicalEntries` and `elider:outputPhysicalEntries`, counting ZIP entries. `elider:mrjarStatus=elevated_and_trimmed` identifies a transformed MRJAR. An unchanged MRJAR has no trim record; if a component-level status is emitted for it, use `passed_through`. Ordinary single-release trim records use `not_multi_release`.

6. **Multi-Release Vertical Shading**:
   * When `trimJars=true`, use the Maven compiler `--release` value as the target tier $T$. Reject a target newer than the Maven runtime release $R$.
   * Elevate the effective class definitions at $T$ to the root, remove superseded lower-tier definitions, and analyze each class-tier breakpoint from $T$ through $R$ in its own platform and sibling context. Union retained classes and cross-artifact reachability before writing output.
   * Preserve every class entry above $T$ byte-for-byte, except versioned `module-info.class` entries, which are removed from trimmed output. Analyze class-tier breakpoints through $R$ to union intra-JAR and sibling closure; entries above $R$ remain preserved but their sibling links are unverified. `elide.mrjarStrategy=pass-through` opts a multi-release candidate out of archive transformation.
   * Keep `Multi-Release: true` when versioned entries remain and remove it when the result is a single-release archive. Root module descriptors continue to use the classpath pass-through policy.
   * Keep SPI descriptors at root using 3-state reconciliation (`UNCHANGED`, `REPLACED`, `OMIT`): retain provider names present in the global retained class set (preserving duplicate provider declarations when another retained archive supplies the provider, and retaining root providers viable in an upper MRJAR tier), preserve unknown or external provider names, omit descriptors left with zero retained/unknown providers, and do not emit versioned `META-INF` resources.

## Invariants

* **Apache 2.0 Compatibility**: Only `proguard-core` (Apache 2.0) may be embedded as a compile/runtime dependency; GPL-licensed `proguard-base` must not be bundled.
* **Per-JAR Boundary Preservation**: Trimming must produce separate, individually attributable trimmed JARs for each dependency; whole-program monolithic flattening is prohibited.
* **Link Closure Completeness**: In the target view and analyzed tier breakpoints through $R$, no retained class may reference an omitted superclass, interface, field type, method descriptor, or other required class in the same or a trimmed sibling JAR.
* **MRJAR Closure Completeness**: Every analyzed class-tier breakpoint between $T$ and $R$ contributes to the unioned closure. Class entries above $T$ remain physically intact; entries above $R$ are outside the sibling-link proof boundary.
* **JEP 238 Multi-Release Structural Integrity**: Every surviving higher-tier public or protected override has its target-baseline implementation at the root. Trimmed output must pass `jar --validate` without missing-base warnings.
* **Upper-Tier Forward-Execution Preservation**: Class entries above $T$ and their internal helpers pass through byte-for-byte because their closure is not used to prune those tiers. This preserves forward execution on newer JREs; sibling links above $R$ remain unverified.
* **Logical and Physical Metrics**: Class totals count unique logical class names across tiers; input and output ZIP-entry totals count physical entries.
* **Original Immutability**: See [ADR-0002](0002-in-memory-artifact-mutation-for-downstream-packaging-transparency.md) (`Original Immutability`); all trimmed outputs are isolated under `target/elided-artifacts/`.
* **Signature Sanitization**: Any trimmed JAR containing signature block files must have those signatures stripped to prevent JVM class-loading security exceptions.

## Consequences

* Unreferenced classes and dormant vulnerability gadgets in the trimmed baseline and lower tiers are physically omitted from final fat JARs, Spring Boot executable archives, and container images. A multi-tier omission claim is made only when the mapped vulnerable class is absent from the root and every versioned tier; classes preserved above $T$ are not claimed removed.
* Vertical shading retains the target baseline required by surviving overrides and preserves every upper-tier class and helper byte-for-byte, allowing distributions to retain newer-JRE behavior while removing proven-unreachable code from tiers that are transformed.
* Downstream vulnerability scanners consuming the CycloneDX 1.6 SBOM can reconcile the trimmed JAR's disk hash while maintaining verifiable ancestry back to the official Maven Central package.
* Trimming requires additional build-time analysis. The existing single-release JMH operation measured a same-request warmed cache hit at 0.093 ms and a fresh-context cache hit at 93.465 ms; only the warmed operation meets the $<10\text{ ms}$ target. These measurements do not establish whole-build latency or MRJAR cache performance. See [RQ-0003](../research/RQ-0003-sub-10ms-maven-fast-path-invariant-and-benchmarking.md).

## Dated Amendment: 2026-11-08 Shared Cross-Artifact Liveness

ProGuard Core remains the class-file/archive transformation library, while the redundant direct `DirectTrim*` pipeline, keep-all poison pills on unresolved dynamic roots, empty-root `100%` class fallbacks, and `forcedUnchanged` promotion inflation are removed. Whole-artifact candidate selection and retained-class trimming consume the same cross-artifact liveness closure and analyzed dataset; see [ADR-0013](0013-compiler-decoupling-multi-jdk-portability-and-report-driven-liveness.md) for the canonical `closedWorld` opt-in contract.

Local-variable descriptors and generic signatures in `LocalVariableTable` and `LocalVariableTypeTable` are debug metadata, not runtime linkage edges. They do not create liveness edges or block analysis when the named type is absent. A class observed independently or explicitly rooted remains live. Stack-map frame types remain structural because bytecode verification can require them.

## Dated Amendment: 2026-11-17 Tier-Shared Reference Indexing and Lazy Graph Isolation

When analyzing multiple candidate and unchanged-program archives against the same release-tier classpath, reference-graph construction follows these principles:

1. **Compute once per invariant scope, overlay the delta**: Index library-role edges (`includeMethodBodies = false`) once lazily per unique-owner tier (`TierLibraryIndex`), and overlay each target archive's `ProgramClass` graph (`includeMethodBodies = true`) via read-only views rather than re-indexing all sibling JARs per target.
2. **Share immutable templates, isolate mutable state on demand**: Keep shared JDK and sibling `LibraryClass` templates immutable, cloning and linking them lazily per target (`LazyPlatformClassPool`) only when referenced so parallel workers never race on ProGuard's mutable `subClasses` arrays or clone unused classes.
3. **Query presence without materializing; wrap without copying**: Check target existence (`hasClass`) without instantiating `LibraryClass` objects, wrap owned maps in place as unmodifiable views, and allocate auxiliary collector sets only when non-empty.
4. **Optimize the common invariant, fall back cleanly on exceptions**: Use the shared tier index only when class owners in the tier are unique; fall back transparently to the isolated per-target path when duplicate class owners require target-specific precedence.
5. **Prove optimizations with end-to-end profiles and differential baselines**: Validate custom parsers and graph optimizations with differential tests and JMH benchmarks against verbatim baselines, and measure full-build JFR/GraalVM profiles to separate allocation savings from parallel CPU and wall-clock impact.

## Dated Amendment: 2026-11-19 Target Runtime Per Analysis Tier

[ADR-0015 slice 2](0015-forbidden-code-policy-and-evidence-bounded-cve-assessment.md#slice-2-shared-target-runtime-platform-for-analysis-and-trimming) will replace the active-Maven-runtime class-table assumption with an explicit list of runtime inputs. Analyze the actual multi-release view of every listed runtime, union their cross-artifact closure, and preserve the higher-tier entries as specified above. Report the analyzed runtime coverage; do not claim linkage verification for unlisted releases. An explicitly configured compiler target absent from the list triggers a prominent coverage warning, not a requirement to supply it. Unavailable required evidence for a listed runtime must not authorize unsafe pruning. The current implementation still uses the active runtime until that slice is implemented.
