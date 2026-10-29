<!-- WHY: Records the architectural decision to use ProGuard Core for intra-JAR dependency trimming, signature stripping, and recording provenance via CycloneDX 1.6 pedigree. -->
# ADR-0003: ProGuard Core-Driven Intra-JAR Trimming and CycloneDX Pedigree

* **Status**: Accepted
* **Date**: 2026-10-25

<!-- semedit-adr-metadata:v1 keys=summary,description,role,scope,area,languages; do not change key names or order. -->
| Key | Value |
| :--- | :--- |
| summary | Use ProGuard Core to trim unreferenced classes from retained dependency JARs, sanitize signatures, and record provenance via CycloneDX 1.6 pedigree. |
| description | Select com.guardsquare:proguard-core under Apache 2.0 to compute transitive intra-JAR link closure from runtime, source, and framework roots; output separate trimmed JARs, strip invalidated signatures, swap in-memory artifact files, and emit schema-valid CycloneDX pedigree. |
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

4. **In-Memory Redirection (ADR-0002)**:
   Redirect the in-memory artifact file pointer via `artifact.setFile(trimmedJarPath)` during the `INITIALIZE` phase so that downstream packaging plugins (`maven-shade-plugin`, `spring-boot-maven-plugin:repackage`, assembly) bundle the trimmed JARs into terminal distributions without bespoke adapters.

5. **CycloneDX 1.6 Pedigree Provenance**:
   Emit schema-valid CycloneDX 1.6 SBOM records for each trimmed dependency:
   * `component.hashes`: The actual SHA-256 digest of the trimmed file on disk.
   * `component.pedigree.ancestors`: The original upstream Maven Central coordinate and original Central SHA-256 digest.
   * `component.pedigree.patches`: Unofficial patch descriptor noting the count of pruned classes.
   * `component.properties`: Structured metrics (`elider:status=trimmed`, `elider:retainedClasses`, `elider:totalClasses`).

## Invariants

* **Apache 2.0 Compatibility**: Only `proguard-core` (Apache 2.0) may be embedded as a compile/runtime dependency; GPL-licensed `proguard-base` must not be bundled.
* **Per-JAR Boundary Preservation**: Trimming must produce separate, individually attributable trimmed JARs for each dependency; whole-program monolithic flattening is prohibited.
* **Link Closure Completeness**: No class may be emitted whose internal superclasses, interfaces, field types, or method descriptors within that same JAR are omitted.
* **Original Immutability**: Original JARs in the local repository cache (`~/.m2/repository`) must never be modified. All trimmed outputs are isolated under the project build directory (`target/elided-artifacts/`).
* **Signature Sanitization**: Any trimmed JAR containing signature block files must have those signatures stripped to prevent JVM class-loading security exceptions.

## Consequences

* Unreferenced classes and dormant vulnerability gadgets are physically omitted from final fat JARs, Spring Boot executable archives, and container images.
* Downstream vulnerability scanners consuming the CycloneDX 1.6 SBOM can reconcile the trimmed JAR's disk hash while maintaining verifiable ancestry back to the official Maven Central package.
* Trimming requires additional build-time analysis. This overhead is mitigated by caching the trimmed outputs using the original JAR's SHA-256 and root fingerprint, preserving the $<10\text{ ms}$ fast-path overhead on subsequent builds.
