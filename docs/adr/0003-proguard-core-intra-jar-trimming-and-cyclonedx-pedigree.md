<!-- WHY: Records the architectural decision to use ProGuard Core for intra-JAR dependency trimming, signature stripping, and recording provenance via CycloneDX 1.6 pedigree. -->
# ADR-0003: ProGuard Core-Driven Intra-JAR Trimming and CycloneDX Pedigree

* **Status**: Accepted
* **Date**: 2026-10-29 (MRJAR decision added)

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
   * Source compilation roots (direct type references in `src/main/java`, inlined constants, erased type bounds, and annotations).
   * Dynamic entry points (Java SPI `META-INF/services/*`, GraalVM `reflect-config.json`, and Spring auto-configuration condition classes).

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
   Redirect the in-memory artifact file pointer via `artifact.setFile(trimmedJarPath)` during the `INITIALIZE` phase so that downstream packaging plugins (`maven-shade-plugin`, `spring-boot-maven-plugin:repackage`, assembly) bundle the trimmed JARs into terminal distributions without bespoke adapters.

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
   * Keep SPI descriptors at root. Filter provider names removed from the globally retained class set, preserve unknown or external provider names, and do not emit versioned `META-INF` resources.

## Invariants

* **Apache 2.0 Compatibility**: Only `proguard-core` (Apache 2.0) may be embedded as a compile/runtime dependency; GPL-licensed `proguard-base` must not be bundled.
* **Per-JAR Boundary Preservation**: Trimming must produce separate, individually attributable trimmed JARs for each dependency; whole-program monolithic flattening is prohibited.
* **Link Closure Completeness**: In the target view and analyzed tier breakpoints through $R$, no retained class may reference an omitted superclass, interface, field type, method descriptor, or other required class in the same or a trimmed sibling JAR.
* **MRJAR Closure Completeness**: Every analyzed class-tier breakpoint between $T$ and $R$ contributes to the unioned closure. Class entries above $T$ remain physically intact; entries above $R$ are outside the sibling-link proof boundary.
* **JEP 238 Multi-Release Structural Integrity**: Every surviving higher-tier public or protected override has its target-baseline implementation at the root. Trimmed output must pass `jar --validate` without missing-base warnings.
* **Upper-Tier Forward-Execution Preservation**: Class entries above $T$ and their internal helpers pass through byte-for-byte because their closure is not used to prune those tiers. This preserves forward execution on newer JREs; sibling links above $R$ remain unverified.
* **Logical and Physical Metrics**: Class totals count unique logical class names across tiers; input and output ZIP-entry totals count physical entries.
* **Original Immutability**: Original JARs in the local repository cache (`~/.m2/repository`) must never be modified. All trimmed outputs are isolated under the project build directory (`target/elided-artifacts/`).
* **Signature Sanitization**: Any trimmed JAR containing signature block files must have those signatures stripped to prevent JVM class-loading security exceptions.

## Consequences

* Unreferenced classes and dormant vulnerability gadgets in the trimmed baseline and lower tiers are physically omitted from final fat JARs, Spring Boot executable archives, and container images. A multi-tier omission claim is made only when the mapped vulnerable class is absent from the root and every versioned tier; classes preserved above $T$ are not claimed removed.
* Vertical shading retains the target baseline required by surviving overrides and preserves every upper-tier class and helper byte-for-byte, allowing distributions to retain newer-JRE behavior while removing proven-unreachable code from tiers that are transformed.
* Downstream vulnerability scanners consuming the CycloneDX 1.6 SBOM can reconcile the trimmed JAR's disk hash while maintaining verifiable ancestry back to the official Maven Central package.
* Trimming requires additional build-time analysis. The existing single-release JMH operation measured a same-request warmed cache hit at 0.093 ms and a fresh-context cache hit at 93.465 ms; only the warmed operation meets the $<10\text{ ms}$ target. These measurements do not establish whole-build latency or MRJAR cache performance. See [RQ-0003](../research/RQ-0003-sub-10ms-maven-fast-path-invariant-and-benchmarking.md).
