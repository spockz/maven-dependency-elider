<!-- WHY: Answers practical user questions about configuring elision, interpreting its results, and understanding supported boundaries. -->
# User FAQ

This page covers configuration, report outcomes, and compatibility. For design rationale and benchmarks, see the [Contributor Decision Register and Engineering FAQ](contributor-decisions-and-faq.md).

## Using Elision

### What does the plugin remove?

Elision automatically removes unused dependency JARs from the build's resolved Maven artifact view (requiring the core extension and a valid `TEST` graph capture) and prunes unused classes from retained JARs (`elide.trimJars=true`)—giving you smaller, cleaner artifacts and OpenVEX/SBOM proofs without manually maintaining `<exclusions>` or auditing transitive trees by hand. If whole-artifact removal cannot bind an unambiguous graph, raw candidates are kept and reported separately.

### How do I enable elision?

Configure a trace file and set `-Delide.skip=false`. See [Maven plugin usage](../dependency-elider-maven-plugin/src/site/markdown/usage.md) for trace formats and options. For the repository examples, use `-Delide.mode=baseline` (default) or `-Delide.mode=elision`.

### How can I see the dependencies effective after elision?

With the core extension in `.mvn/extensions.xml` and an active elider execution, run:

```sh
./mvnw -Delide.skip=false -Delide.traceFiles=/path/to/trace.log dependency:tree
```

For single-project modules, the extension schedules elision before `dependency:tree` so dropped leaves disappear from the output (multi-project reactors are rejected). Each invocation computes a fresh plan. See [the integration tests](../dependency-elider-maven-plugin/src/test/java/io/github/spockz/elider/plugin/DependencyContextLifecycleIT.java) and [RQ-0006](research/RQ-0006-maven-artifact-view-consistency-and-early-resolution-hooks.md).

### Why did a raw dependency candidate remain in my build?

Whole-artifact removal requires the core extension (`.mvn/extensions.xml`) and an unambiguous, unchanged `TEST` graph capture. If graph evidence is missing, ambiguous, or stale, whole-artifact drops fail closed and remain in the build (class-level JAR trimming can still run).

### What does the nonmutating `analyze` summary mean?

It forecasts whole-artifact drops and on-disk JAR byte savings in a read-only pass. By default, `elide.trimJars=false`. Enable `elide.trimJars=true` to preview intra-JAR class pruning. The full list is in `target/dependency-elider-analysis-report.json`.

### How can tests compile against classes removed from production dependencies?

For the tested Maven 3.9.11 classpath setup with exactly one opted-in project, enable the core extension and run
`mvn clean test -Delide.testCompilationView=true` with `elide` bound before `testCompile`.
Elider temporarily exposes the original allowed dependencies to the test compiler, restores the
production view afterward, and prepares missing classes for Surefire in
`target/elider/test-additions.jar`. The addition is test-only; it does not enter the production
package, resolver plan, SBOM or VEX. See [isolated test view usage](../dependency-elider-maven-plugin/src/site/markdown/usage.md#isolated-test-compilation-and-runtime-view).

### Why does test-view preparation ask me to run `mvn clean test`?

The saved test-view freshness manifest binds test sources and output, production output,
dependency JAR contents, compiler execution settings and runtime options. If any checked input
changes in a build without `clean`, Elider refuses to reuse the previous test observation or
addition. `-DskipTests` still compiles and prepares tests; `-Dmaven.test.skip=true` skips
compilation and leaves test results unavailable. A needed class from a signed, sealed,
multi-release or modular JAR may require a view that the automatic class-only addition cannot
supply, so preparation fails explicitly. Resources already preserved in the trimmed production
JAR remain available to tests; changed or missing dependency resources fail preparation.

### What does `report` say about test-only additions?

The test-view report is separate from the production snapshot at
`target/elider/test-view-report.json`. `report` replays its saved original-versus-effective inputs
and added classes only when its project and production-report digest match. An analysis report,
missing test report, changed production report, failed preparation or caller-supplied additions JAR is labeled
unavailable or unverified. A test addition is not production code-absence proof or vulnerability
mitigation.

### How can I keep a dependency JAR unchanged?

Set `elide.trimSkipArtifacts` to `groupId:artifactId[:version[:type[:classifier]]]`; omitted `version` or `classifier` parts (or `*`) act as wildcards. The JAR stays byte-identical and cannot be dropped, though its live classes still retain linked classes in trim candidates. See [Maven plugin usage](../dependency-elider-maven-plugin/src/site/markdown/usage.md).

### How can I retain an artifact from whole-artifact elision?

Set `elide.retainedArtifacts` to `groupId:artifactId` (e.g. `-Delide.retainedArtifacts=org.example:library`). This keeps the artifact in the graph, though its classes may still be trimmed unless also listed in `elide.trimSkipArtifacts`. The legacy `elide.excludedArtifacts` setting is rejected.

### How can I request that a dependency be removed?

Configure bans using exact `groupId:artifactId` identities (`elide.banishedDependencies`). `analyze` only forecasts bans; `elide` enforces them (injecting exclusions before collection when the core extension is loaded, or via isolated resolver planning otherwise) and fails before publication if a ban targets a direct dependency, retained obligation, unsupported scope/type, or unresolved link. Unmatched bans do not fail and do not prove absence. Complete production classes (`elide.productionClassesComplete=true` or `process-classes`) are required. See [ADR-0012](adr/0012-dual-layer-ban-policy-and-retention-naming.md).

### What if a dependency JAR changes during or between Maven builds?

Elider hashes dependency JARs and runtime system-module descriptors/classes by content digest. Concurrent edits during a single Maven run are unsupported; subsequent runs recalculate digests and pick up changes. See [ADR 0004](adr/0004-assume-resolved-inputs-stable-during-build.md).

### What happens if a dependency contains multi-release implementation classes?

With `elide.trimJars=true` and default `elide.mrjarStrategy=vertical-shading`, Elider elevates classes for the effective compiler target release to the JAR root, preserves higher-tier entries unchanged, strips versioned `module-info.class`, and filters `META-INF/services/` for removed providers. Set `-Delide.mrjarStrategy=pass-through` to keep MRJARs byte-identical. Sibling closure covers the views of the selected runtime images.

### What happens to reports and outputs if publication fails?

Any failure before publication commits rolls back the previous reports, generated outputs, Maven artifact views, and resolver plan.

### What if my application runs on a different JDK than Maven?

Supply the installed runtime home or its ZIP or `tar.gz` archive in
`elide.runtimeInputs`. You can list several images. An explicit compiler target
outside the inspected releases triggers a warning in both the original report and
replay. A missing required platform prevents unsafe pruning. Images are analysis
inputs outside application packages and SBOMs.
[Runtime inputs and archive preparation](../dependency-elider-maven-plugin/src/site/markdown/usage.md#runtime-inputs)

### What if production output is not ready at `process-classes`?

Elider runs at `process-classes` by default and derives production roots from compiled `.class` files (`elide.sourceRootsComplete=true` is rejected). For direct `analyze` or `elide` invocations, run `compile` first and pass `-Delide.productionClassesComplete=true` (plus `-DskipTests=true` if lifecycle reaches tests). Java sources are not scanned, so retain compile-time-inlined constants explicitly via `elide.retainedArtifacts`. For physical prerequisite proofs, set `elide.preconditionClassPathComplete=true` (`analyze` never writes VEX files; only `elide` does).

### What happens to JARs with a root `module-info.class`?

Classpath JARs with a root `module-info.class` are kept byte-identical with a warning. Set `-Delide.failOnUnsupportedModuleInfo=true` to fail instead. JPMS module-path execution is unsupported.

### What happens when the plugin encounters metadata or an archive layout it does not understand?

It fails closed before modifying Maven artifact pointers rather than assuming unknown metadata is unused, outside the configured MRJAR and `module-info.class` policies.

### What happens when a dependency has an unsupported native-image argument?

Syntactically valid arguments outside the audited GraalVM Native Image 21.0.12+7.1 inventory are accepted without inferring class roots; malformed values or unreadable referenced configs fail closed. See [ADR-0009](adr/0009-permissive-graalvm-native-image-metadata-ingestion.md).

### Why use Dependency Elider alongside GraalVM Native Image?

* **Smaller `native-image` input**: Drops unused JARs and prunes unreachable classes before GraalVM compilation while preserving `META-INF/native-image/**` and tracing-agent roots.
* **OpenVEX and SBOM proofs**: Emits CycloneDX SBOMs (`dependency-elider-sbom.cdx.json`) and OpenVEX documents (`dependency-elider.openvex.json`) proving omitted vulnerable artifacts and classes.

### Does removing classes make a vulnerability finding go away?

Not automatically. Package scanners still see the original coordinate unless the whole JAR is dropped. Elider emits a physical omission proof (`DECLARED_CODE_ABSENT`) only when an exact component/version's attributable declared classes are verified absent from the final artifact (package matches or `REVIEW_LEAD` heuristics cannot establish proof). Prerequisite proofs (`PREREQUISITES_ABSENT`) require `elide.preconditionClassPathComplete=true`. Only `elide` publishes CycloneDX/OpenVEX files. See [RQ-0008](research/RQ-0008-osv-sbom-comparison-and-vex-evidence.md) and [RQ-0013](research/RQ-0013-precondition-gated-vex-and-multi-artifact-exploitability.md).

### Can I fail a build when a forbidden class or method survives?

Yes. In your POM, select `forbiddenSymbols` or set `forbidDeclaredCode=true` on a vulnerability
mapping, then enable `-Delide.failOnForbiddenCode=true`. Exact method rules identify the
overload by parameter types. Elide checks effective production outputs at `process-classes`,
including unchanged JARs and retained multi-release entries. Analyze predicts the same scope.
Unknown evidence, including unproven Java-runtime reachability, is reported and does not fail
the build. VEX still requires an applicable CVE and complete omission proof. [Forbidden-code configuration](../dependency-elider-maven-plugin/src/site/markdown/usage.md#forbidden-code-policy)

The [runnable examples](../dependency-elider-maven-plugin/src/site/markdown/usage.md#runnable-forbidden-code-examples)
use benign Base64 and ZIP inputs. The Java4Shell decoder variant violates the rule because its
bytecode calls the exact configured method. The plain-text variant reports `UNKNOWN` because
the check cannot rule out indirect calls. A missing target runtime image leaves version
applicability unknown while still allowing the exact call to violate policy. The Commons Compress
rule reports a pass when the stream class is omitted, a violation when its method survives, and
`NOT_APPLICABLE` at the fixed version.

### Which sources produce vulnerability findings?

OSV Maven snapshots, CVE List v5, POM manual mappings, adopted Maven mapping catalogs, and optional Snyk lookups ([Snyk configuration](../dependency-elider-maven-plugin/src/site/markdown/usage.md#optional-snyk-package-findings)) merge into one finding model. Missing/unsupported Maven identities stay unresolved rather than being guessed.

### How do I adopt a shared vulnerability mapping catalog?

Pass `-Delide.vulnerabilityMappingCatalogs=groupId:artifactId:version[:type[:classifier]]` with a pinned release (no ranges or `SNAPSHOT`s). The artifact must contain `META-INF/elider/vulnerability-mappings.json`. Catalogs are data-only (excluded from classpath/SBOM) and fail closed if missing or malformed; `report` replays the saved SHA-256 and catalog metadata.

### How are findings merged, and do manual mappings take priority?

Automatic code paths normalize into sets and affected ranges combine by union (preserving gaps). Merge priority is **POM/manual > catalog > automatic**: manual mappings override supplied fields for their scope while allowing omitted fields to be enriched (`LOW`/`MEDIUM` manual intent stays review-only). In POM mappings, `versionRangeSpec` is evidence scope only (`assertsAffected` defaults to `false`; set `true` to assert affectedness).

### What does the conventional Java source-layout option do?

`elide.assumeConventionalJavaSourceLayout` (default `true`) translates Java source paths to class names when attributing advisories. The saved report records this setting, the `policy` identity, `appliedBans`, and `InventoryDisposition` (`REMOVED`, `RETAINED_AND_TRIMMED`, `RETAINED_UNCHANGED`), which `report` replays verbatim.

### How does the report distinguish the analysis target from the Maven runtime?

`executionEnvironment.targetRelease` records the effective compiler target (`release`, then `target`, then the Maven JVM's feature release if unset). `executionEnvironment.runtimeRelease` records the JDK running Maven. `executionEnvironment.runtimeCoverage` records the selected images, their inspection outcomes and the releases analyzed. `report` replays the saved coverage and any warning about an uncovered compiler target.

### What happens if an advisory maps multiple vulnerable classes that do not exist in an older version?

Omitted-code proof requires every declared class to exist in the original JAR; missing classes leave that mapping unresolved. To scope a correction in `pom.xml`:

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

An empty `<vulnerableClasses/>` clears the mapping in scope; omitting it allows automatic enrichment.

### Why can `META-INF/services/` retain declared vulnerable code?

`META-INF/services/` entries are loaded dynamically via `ServiceLoader`. By default (`elide.conservativeServiceLoaderRoots=true`), Elider keeps statically proven `ServiceLoader.load(...)` providers *plus* unproven SPI providers to avoid `ServiceConfigurationError` (which can transitively keep vulnerable classes). Disable the fallback with `-Delide.conservativeServiceLoaderRoots=false` (or `<conservativeServiceLoaderRoots>false</conservativeServiceLoaderRoots>`) if unobserved dynamic SPI lookups are not needed.

## Compatibility and Performance

### What Java versions and target compilation levels are supported?

* **Build Runtime**: Requires **JDK 21+** to run Maven.
* **Target Bytecode**: Supports **Java 1.1 through Java 27** (class-file major versions 45–71, via `proguard-core:9.4.0`).

### What Kotlin features are supported?

Kotlin is analyzed strictly as JVM bytecode (no `.kt`/`.kts` source scanning).

| Kotlin feature | Status | Boundary and evidence |
| :--- | :--- | :--- |
| Kotlin-compiled dependency bytecode | Supported as JVM bytecode | Uses normal JVM linkage; missing optional Kotlin/coroutine types are not implicitly ignored. |
| `kotlin.Metadata` on sibling library classes | Parsed and validated; not a reachability source | Reparsed per context; malformed metadata fails closed ([`LibraryArchiveTemplates`](../elider-core/src/main/java/io/github/spockz/elider/trimmer/LibraryArchiveTemplates.java#L61), [`ArchiveSnapshotTemplateTest`](../elider-core/src/test/java/io/github/spockz/elider/trimmer/ArchiveSnapshotTemplateTest.java#L148)). |
| Class references encoded only in Kotlin metadata | Not followed | Not traversed by [the reference visitor](../elider-core/src/main/java/io/github/spockz/elider/trimmer/ProGuardReferenceVisitors.java#L49) or [`ArchiveSnapshot`](../elider-core/src/main/java/io/github/spockz/elider/trimmer/ArchiveSnapshot.java#L142). |
| Kotlin application source (`.kt`, `.kts`) | Not source-scanned | Source-only references (e.g. inlined constants) are not inferred; retain explicitly if needed. |
| Missing optional Kotlin/coroutine references in a library | Opt-in pass-through fallback | Trimming fails closed by default. Set `elide.trimPassThroughOnUnresolved=true` to keep candidates with unresolved references unchanged. Use `elide.trimSkipArtifacts` or `elide.mrjarStrategy=pass-through` to configure specific pass-through behavior. |
| Kotlin metadata in a supplied JDK class table | Unsupported | Rejected on internal runtime-module snapshots. |

### How much build time and memory does elision add?

* **`elide.trimJars=false`**: Streams retained JARs with ASM without ProGuard pools (`example-spring-boot-app` runs in `~7 s` under `-Xmx512m`).
* **`elide.trimJars=true`**: Builds ProGuard `ClassPool`s and per-candidate closures (pass-through JARs still stream with ASM). The measured same-request warm cache hit was below 10 ms. A fresh Maven request incurs additional setup and validation.

See [RQ-0003](research/RQ-0003-sub-10ms-maven-fast-path-invariant-and-benchmarking.md) for benchmark methodology; elision remains experimental for production builds.
