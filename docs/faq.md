<!-- WHY: Answers practical user questions about configuring elision, interpreting its results, and understanding supported boundaries. -->
# User FAQ

This page covers user-facing configuration, outcomes, compatibility limits, and practical concerns. For implementation rationale, benchmark evidence, and contributor decisions, see the [Contributor Decision Register and Engineering FAQ](contributor-decisions-and-faq.md).

## Using Elision

### What does the plugin remove?

Elision can remove unused dependency artifacts from a compatible Maven resolver graph and can optionally remove unused classes from retained dependency JARs. It does not edit your POM or rewrite dependency declarations. Whole-artifact removal requires the production core extension and a unique compatible TEST graph capture; if either is unavailable, the goal keeps the whole-artifact candidates and reports them separately from effective drops.

### How do I enable elision?

Configure a supported trace file and set `-Delide.skip=false`. See [Maven plugin usage](plugin-usage.md) for trace formats, JAR trimming options, and examples.

For the repository examples, use `-Delide.mode=baseline` or `-Delide.mode=elision` with the same POM. `elision` activates the example profile; `baseline` is the default. This makes it easy to compare the two packaged outputs without maintaining separate POMs.

### How can I see the dependencies effective after elision?

With the core extension in `.mvn/extensions.xml` and an active, initialize-bound elider execution in the POM, run the bare tree goal:

```sh
./mvnw -Delide.skip=false -Delide.traceFiles=/path/to/trace.log dependency:tree
```

The production sequence is fixture-verified for Maven CLI 3.9.11 and Dependency Plugin 3.8.1: the extension schedules the configured elider before a bare `dependency:tree` request, and repeated tree goals show the dropped leaf absent while retaining the used dependency. The test includes a skipped-elision control that shows both dependencies. The verified case is a single-project leaf graph; automatic preparation rejects multi-project reactors. If you run `mvn test`, Maven reaches `INITIALIZE` through its normal lifecycle, so no separate `initialize` goal is needed. A later Maven invocation computes a fresh plan; it does not restore the prior session's plan from the report. See [the integration tests](../dependency-elider-maven-plugin/src/test/java/io/github/spockz/elider/plugin/DependencyContextLifecycleIT.java#L583) and [RQ-0006](research/RQ-0006-maven-artifact-view-consistency-and-early-resolution-hooks.md).

### Why did a raw dependency candidate remain in my build?

The goal removes a whole artifact only when it can bind one unambiguous initial TEST graph to the Maven artifact inventory and later validate the exact source graph before projection. Install and load the production core extension from `.mvn/extensions.xml`; missing, ambiguous, or changed graph evidence leaves raw candidates retained. The report lists raw candidates separately from effective whole-artifact drops. Retained JAR class trimming can still run when whole-artifact removal fails closed.

### What does the nonmutating `analyze` summary mean?

It reports artifacts that would be elided by that analysis and the exact sum of their original on-disk JAR sizes. The byte total is an estimate of possible savings; the final package delta may differ. `analyze` uses trim-disabled options and does not predict intra-JAR class removal. It does not mutate Maven artifact views or package output.

### How can I keep a dependency JAR unchanged?

Set `elide.trimSkipArtifacts` to the exact resolved coordinate, such as `groupId:artifactId:version:jar:`. The JAR remains byte-identical and is protected from whole-artifact elision. Its classes can still cause linked classes in other trim candidates to be retained. See [Maven plugin usage](plugin-usage.md) for the Spring example.

### How can I retain an artifact from whole-artifact elision?

Set `elide.retainedArtifacts` to its `groupId:artifactId`, for example `-Delide.retainedArtifacts=org.example:library`. This retains a matching artifact in the current graph; it does not promise that the original JAR bytes remain unchanged. Use `elide.trimSkipArtifacts` when byte-identical preservation is required. The former `elide.excludedArtifacts` property and `<excludedArtifacts>` element are rejected because this setting controls retention rather than Maven dependency exclusions.

### How can I request that a dependency be removed?

The ban policy uses exact `groupId:artifactId` identities. An Analyze-only invocation, with or without the core extension, predicts outcomes and never applies bans. If the same Maven invocation also selects `elide`, its selected policy injects exclusions before collection and Analyze observes that shared graph; Elide owns enforcement. `elide` applies only a validated plan: with the extension, selected exclusions are injected before collection and checked against the original-input audit; without it, Elide uses isolated current-model Resolver planning. In that no-extension ban operation, Elide may also evaluate unrelated trace-derived drops after graph and content closure succeeds; ordinary no-extension runs without bans keep those candidates. A matched or pre-resolution-excluded request requires complete source roots (`elide.sourceRootsComplete=true`) or complete production class output (`elide.productionClassesComplete=true`); these assertions are mutually exclusive. A requested identity matching an unsupported Maven scope or artifact type, a direct dependency, a retained obligation, or an unresolved class/resource/provider link fails before publication. Unmatched requests are reported distinctly, do not fail by themselves, and do not prove absence. Enforcement covers this project's resolved views and generated outputs; it does not rewrite consumer POMs or promise changes to plugin realms or annotation-processor paths.

The original dependency model is frozen before exclusion injection; original-input Resolver audit resolution happens later using that capture and remains read-only. Audit evidence is not a promise that every resolver request is intercepted or that all consumers see the ban. An `elide` enforcement failure occurs before reports, generated outputs, Maven artifact views, or the resolver plan are published. See [ADR-0012](adr/0012-dual-layer-ban-policy-and-retention-naming.md).

### What if a dependency JAR changes during or between Maven builds?

The elider uses exact content digests to identify dependency JARs and the active runtime's system-module descriptors and class resources. It does not inspect `ct.sym` or JMOD layouts. Concurrent edits to dependency or platform inputs during a Maven invocation are unsupported and can make that invocation nondeterministic. A later invocation recalculates content identity, so changed inputs are recognized. Maven's resolution-time checksum verification does not lock files for the rest of the build. See [ADR 0004](adr/0004-assume-resolved-inputs-stable-during-build.md).

### What happens if a dependency contains multi-release implementation classes?

When `elide.trimJars=true`, the plugin uses the Maven compiler release as the baseline target, elevates its effective classes to the JAR root, and trims the target view. Higher-tier entries remain unchanged, while class bodies at tier breakpoints through the Maven runtime release contribute to sibling dependency closure. This analysis also uses an MRJAR configured for `pass-through` as an unchanged program input when another dependency is trimmed. Tiers above that runtime are preserved without linkage analysis. SPI descriptors stay at the root and provider names for removed classes are filtered. Set `-Delide.mrjarStrategy=pass-through` to keep the original MRJAR byte-identical; references from tiers above the Maven runtime remain outside the sibling-closure proof. Root module descriptors follow the existing classpath pass-through policy; versioned module descriptors are removed from trimmed output.

### What happens to reports and outputs if publication fails?

A failure before the publication commit restores the previous reports, output generation, Maven artifact views, and resolver plan. If backup cleanup fails after publication commits, Maven reports that cleanup error while the new reports and outputs remain active.

### What if my application runs on a different JDK than Maven?

MRJAR linkage analysis uses the configured target release for the baseline and the active Maven runtime release as its upper analysis boundary. The JDK class table describes that active runtime; it does not validate API availability for an older target. If the deployed application uses a newer JDK, higher-tier entries are preserved but their references to sibling JARs are not included in the analyzed closure. Run the build with the deployment JDK to verify those links. Pass-through preserves the MRJAR bytes but does not preserve sibling dependencies referenced only from unanalysed tiers.

### What if generated sources are not available before `INITIALIZE`?

Leave `elide.sourceRootsComplete=false`, the default. This conservatively keeps compile-visible JARs and their classes available for trimming. Set it to `true` only when all production and generated sources are available before the elider runs and no later generator adds compile references.

For a project that generates production code during the build, enable the Maven extension and set `elide.productionClassesComplete=true`, or bind `dependency-elider:elide` to `process-classes`. The elider then uses the compiled output after `compile`; the directory must contain at least one `.class` file. It also attributes Java sources from the compile roots and unions those references with bytecode references, which keeps dependencies used only through inlined primitive or `String` constants. The attribution classpath includes the compiled output and disables annotation processing, so processors do not run again.

If compile roots are missing or empty, contain unsupported source languages (`.kt`, `.kts`, `.scala`, `.groovy`), use unsupported compiler/platform settings, or fail javac attribution, the summary reports conservative fallback and retains all compile-visible artifacts and their indexed classes. This may retain source-only unused dependencies. These source references do not become bytecode/runtime evidence: class-use categories and VEX claims keep their existing evidence boundaries, and test-only source references are not covered. A direct `mvn dependency-elider:elide` goal does not run the lifecycle or establish trusted capture, so it keeps conservative precondition-proof checks. `skipTests` does not skip test compilation, and compiler processor safeguards still apply to `testCompile`.

### What happens to JARs with a root `module-info.class`?

On the classpath, such JARs are kept byte-identical with a warning. Set `-Delide.failOnUnsupportedModuleInfo=true` to fail instead. JPMS module-path behavior is not supported.

### What happens when the plugin encounters metadata or an archive layout it does not understand?

It fails before changing Maven artifact pointers rather than assuming unknown metadata is unused. Multi-release JARs use the configured `elide.mrjarStrategy` (vertical shading by default or byte-identical pass-through), while root-module-info JARs follow the module-info policy above. Unsupported metadata outside those policies still fails closed.

### What happens when a dependency has an unsupported native-image argument?

Syntactically valid arguments outside the audited GraalVM Native Image 21.0.12+7.1 inventory are accepted without inferred class roots. The plugin does not promise that arbitrary future options cannot declare roots. Recognized class, package, configuration, and indirection inputs must be modeled; malformed values or unreadable referenced configuration fail with an error rather than being ignored. See [ADR-0009](adr/0009-permissive-graalvm-native-image-metadata-ingestion.md) for the modeled boundary.

Native Image resource-bundle names from `-H:IncludeResourceBundles` and configuration descriptors accept the same Unicode family-name grammar, including locale suffixes; only indexed bundle classes become class roots.

### Does removing classes make a vulnerability finding go away?

Not necessarily. Many vulnerability tools report by artifact coordinates and version, even when some classes have been removed. Omitted-code proof accepts validated effective-POM `HIGH` assertions and live-verified structured CNA claims, but only when every mapped class is present in the original artifact and physically absent from the exact retained, trimmed artifact. Structured claims additionally require unambiguous exact CNA product/version selection, corroborating current OSV+CNA affected-version evidence, and a complete byte-equal reproduction of the exact ordinary JAR from its matching Java `sources` archive under the supported pinned compiler image. Cached labels, heuristic candidates, a package/version finding, or an unused artifact alone are insufficient. The tool trusts the CNA's assertion that its declared source files/routines are affected; it does not independently establish vulnerability truth or declaration completeness. Snapshot-aware assessment can classify a CVE as inactive only after a complete opted-in inventory proves both the exact prerequisite coordinate and class absent for the exact affected version. Incomplete inventories, missing opt-in, low-confidence mappings, or a class found in any declared provider produce no inactive classification or precondition VEX. The Maven goal wires this inventory into assessment and transactional publication; if a provider or output changes during staging, publication aborts and restores prior outputs. The inventory assertion will not cover providers added by later packaging or deployment runtime mechanisms. Inspect and scan the final packaged artifact, and assess the advisory's affected code and exploit conditions separately. See [RQ-0008](research/RQ-0008-osv-sbom-comparison-and-vex-evidence.md) and [RQ-0013](research/RQ-0013-precondition-gated-vex-and-multi-artifact-exploitability.md).

### What does the conventional Java source-layout option do?

`elide.assumeConventionalJavaSourceLayout` defaults to `true` and permits the specific `src/main/java/` root translation when matching a structured CNA path to its exact-version sources archive. Set it to `false` to require an exact archive path. The setting is retained in verified proof provenance and the saved report, but it does not waive complete source-to-class reproduction or physical omission proof. Unresolved claims remain review-only; an owner can verify the mapping and configure an exact POM `vulnerableClasses` assertion. A filename or `SourceFile` attribute alone is not complete attribution. The `report` goal replays the assumption and proof provenance from the last successful run, independent of current Maven configuration.

The report also retains package-only and heuristic advisory candidates as review rows. Each row names the exact assessed component and reports applicability from preserved OSV claims; unsupported ranges stay unresolved. Inventory disposition describes whether that component was removed, trimmed, or unchanged and does not claim mitigation. Verify the source and exact artifact before adding any POM mapping.

The saved report's `policy` section records canonical `retainedArtifacts`, `banishedDependencies`, and the SHA-256 identity of the operation that produced the snapshot. `appliedBans` records each request as `FORCED_ABSENT_AFTER_RESOLUTION`, `EXCLUDED_BEFORE_RESOLUTION`, or `UNMATCHED`, with the original and effective artifact matches. `rawDroppedCoordinates` excludes artifacts removed because of an explicit ban; whole-artifact drop metrics still describe every artifact absent from the final Maven view.

### What happens if an advisory maps multiple vulnerable classes that do not exist in an older version?

The verification engine currently fails closed: `OmittedCodeProof` requires all mapped vulnerable classes to be present in the original dependency JAR before certifying that trimming removed them. In cases like Jackson Core (`CVE-2026-68494`), a vulnerability fix across a broad version range touches classes that were only introduced in later minor versions (such as `StreamConstraintsException` added in Jackson 2.15), meaning older affected versions (like Jackson 2.14) do not contain all mapped symbols. In such cases, the elider conservatively omits the CVE from being considered "avoided" or emitting a VEX statement.

If an engineer deems this overly conservative because the absent class is irrelevant to their version, they can override the mapping directly in `pom.xml` under `<configuration><vulnerabilityMappings>`:

```xml
<vulnerabilityMappings>
  <vulnerabilityMapping>
    <cveId>CVE-2026-68494</cveId>
    <groupId>com.fasterxml.jackson.core</groupId>
    <artifactId>jackson-core</artifactId>
    <versionRangeSpec>[2.14.0,2.15.0)</versionRangeSpec>
    <vulnerableClasses>
      <vulnerableClass>com.fasterxml.jackson.core.async.ByteArrayFeeder</vulnerableClass>
    </vulnerableClasses>
    <sourceAdvisoryUrl>https://github.com/FasterXML/jackson-core/pull/1611</sourceAdvisoryUrl>
    <confidenceLevel>HIGH</confidenceLevel>
  </vulnerabilityMapping>
</vulnerabilityMappings>
```

We are actively evaluating how to interpret multiple mapped classes (e.g. conjunction vs. disjunction) across version ranges and whether the elider must remain as strict as it is today.

### Why is vulnerable code retained due to `META-INF/services/` (ServiceLoader SPI), and how do conservative exclusions work?

Java Service Provider Interface (SPI) entries in `META-INF/services/` declare provider implementations loaded dynamically at runtime via `java.util.ServiceLoader`. Omitting these providers without proof can cause runtime `ServiceConfigurationError` exceptions.

However, treating every declared SPI provider as an unconditional root retains unused transitive functionality. For example, `com.fasterxml.jackson.core:jackson-core` declares `JsonFactory` in `META-INF/services/com.fasterxml.jackson.core.JsonFactory`. Retaining `JsonFactory` forces retention of `NonBlockingJsonParser` and its interface `ByteArrayFeeder`, preventing trimming-based remediation of CVE-2026-68494 even when `ServiceLoader` is never invoked.

Maven Dependency Elider uses static analysis (similar to GraalVM SubstrateVM) to detect positive proof of `ServiceLoader` usage:

1. **Positive Proof of Use**: The scanner analyzes application bytecode for calls to `ServiceLoader.load(...)` or `ServiceLoader.loadInstalled(...)` where the service parameter is either a constant class/string literal or points to a `static final` constant field. When a service factory in a dependency JAR matches an observed call, the SPI entry is proven in use and retained as a legitimate root.
2. **Conservative Fallback (`elide.conservativeServiceLoaderRoots`, default `true`)**: When negative proof is unavailable (the service interface is not observed statically, but reflection or dynamic loading might still occur), unproven SPI providers are retained by default for runtime safety.
3. **Conservative CVE Exclusions**: If a CVE's vulnerable code survives in a trimmed JAR solely because unproven SPI roots preserved it, the CVE is excluded from "Mitigated CVEs" and instead reported under `Potentially conservative CVE exclusions:` with the unproven SPI roots identified and an actionable POM override snippet.
4. **Disabling Conservative Fallback**: If you know your application does not use dynamic SPI lookups for that library, disable the fallback to prune unproven SPI entries and allow vulnerable code to be trimmed:

```xml
<configuration>
  <conservativeServiceLoaderRoots>false</conservativeServiceLoaderRoots>
</configuration>
```

Or pass `-Delide.conservativeServiceLoaderRoots=false` on the command line. When disabled, unproven SPI entries are not treated as roots, allowing unused classes (such as Jackson's `ByteArrayFeeder`) to be pruned and the CVE to be proven absent.

## Compatibility and Performance

### What Java versions and target compilation levels are supported?

There is an important distinction between the JDK running Maven and your application's compilation target:

* **Build Runtime (JDK executing Maven)**: Requires **JDK 21 or newer**. The plugin is implemented in Java 21 LTS using modern language features (such as Records, pattern matching, and sequenced collections) and requires a Java 21+ JVM process to run inside Maven.
* **Application Compilation Target (Target Bytecode)**: Supports compilation targets from **Java 1.1 up through Java 27** (class-file major versions 45 through 71), including **Java 25** (version 69). A project can compile with `<release>8</release>`, `<release>11</release>`, `<release>17</release>`, `<release>21</release>`, or `<release>25</release>` and use intra-JAR trimming, reachability link closure, and whole-artifact elision normally, provided Maven itself is executed with JDK 21+.
* **Bytecode Engine Compatibility**: The pinned bytecode engine (`com.guardsquare:proguard-core:9.4.0`) natively supports class-file versions through Java 27 (major version 71), fully supporting Java 25 class-file analysis.

### What Kotlin features are supported?

Kotlin support is limited to JVM class files and the Kotlin metadata ProGuard Core can read. There is no Kotlin source compiler or Kotlin source-reference scanner.

| Kotlin feature | Status | Boundary and evidence |
| :--- | :--- | :--- |
| Kotlin-compiled dependency bytecode | Supported as JVM bytecode | Class reachability uses normal JVM linkage. This does not make missing Kotlin or coroutine types implicitly optional. |
| `kotlin.Metadata` on sibling library classes | Parsed and validated; not a reachability source | Metadata-bearing siblings are reparsed per context because ProGuard mutates metadata. Malformed metadata fails closed. [`LibraryArchiveTemplates`](../elider-core/src/main/java/io/github/spockz/elider/trimmer/LibraryArchiveTemplates.java#L61) and a real Kotlin class resource are covered by [`ArchiveSnapshotTemplateTest`](../elider-core/src/test/java/io/github/spockz/elider/trimmer/ArchiveSnapshotTemplateTest.java#L148), but parsing is not Kotlin metadata reachability support. |
| Class references encoded only in Kotlin metadata | Not followed | The [reference visitor](../elider-core/src/main/java/io/github/spockz/elider/trimmer/ProGuardReferenceVisitors.java#L49) does not traverse metadata-only names, and trim candidates are read without initializing Kotlin metadata in [`ArchiveSnapshot`](../elider-core/src/main/java/io/github/spockz/elider/trimmer/ArchiveSnapshot.java#L142). Do not rely on Kotlin reflection or downstream Kotlin compilation metadata to keep otherwise unreferenced classes. |
| Kotlin application source (`.kt`, `.kts`) | Not source-scanned | The [source scanner](../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/JavaSourceReferenceScanner.java#L105) reads `.java` files only. When `elide.sourceRootsComplete=true`, Kotlin files in those roots now fail closed with a diagnostic. Leave it `false` for Kotlin sources; the default conservatively retains compile-visible classes. |
| Missing optional Kotlin/coroutine references in a library | Explicit pass-through only | A reachable missing reference in an archive being transformed fails closed. For a retained owner that must remain unchanged, use `elide.trimSkipArtifacts`; for an MRJAR, `elide.mrjarStrategy=pass-through` is also available. The unchanged owner still contributes resolved links to sibling trim candidates. Ensure an artifact you need is retained independently. |
| Kotlin metadata in a supplied JDK class table | Unsupported | The internal runtime-module snapshot rejects metadata-bearing JDK classes. This is separate from parsing metadata on sibling library classes. |

The Spring regression test uses synthetic Java bytecode that references an absent `kotlin.coroutines.Continuation`; it verifies pass-through policy, not Kotlin compiler output or Kotlin source scanning. Kotlin compiler and plugin-version combinations have not been independently verified.

### How much build time does elision add?

Three baseline-first `clean verify` cycles measured Basic at a median 2.262 seconds without elision and 4.224 seconds with it; the median of the three paired differences was +1.977 seconds. Spring Boot measured medians of 4.106 seconds and 24.523 seconds, with a median paired difference of +20.417 seconds. These are descriptive observations, not stable performance guarantees or isolated causal estimates. The fresh-context trim-cache operation remains above the <10 ms target; the repeated same-request cache hit is below it. Elision remains under active development and should not be used to remove dependencies from production builds. See [RQ-0003](research/RQ-0003-sub-10ms-maven-fast-path-invariant-and-benchmarking.md) for measurement details.
