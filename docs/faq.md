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

The production sequence is fixture-verified for Maven CLI 3.9.11 and Dependency Plugin 3.8.1: the extension schedules the configured elider before a bare `dependency:tree` request, and repeated tree goals show the dropped leaf absent while retaining the used dependency. The test includes a skipped-elision control that shows both dependencies. The verified case is a single-project leaf graph; automatic preparation rejects multi-project reactors. If you run `mvn test`, Maven reaches `INITIALIZE` through its normal lifecycle, so no separate `initialize` goal is needed. A later Maven invocation computes a fresh plan; it does not restore the prior session's plan from the report. See [the integration tests](../dependency-elider-maven-plugin/src/test/java/io/github/spockz/elider/plugin/DependencyContextLifecycleIntegrationTest.java#L583) and [RQ-0006](research/RQ-0006-maven-artifact-view-consistency-and-early-resolution-hooks.md).

### Why did a raw dependency candidate remain in my build?

The goal removes a whole artifact only when it can bind one unambiguous initial TEST graph to the Maven artifact inventory and later validate the exact source graph before projection. Install and load the production core extension from `.mvn/extensions.xml`; missing, ambiguous, or changed graph evidence leaves raw candidates retained. The report lists raw candidates separately from effective whole-artifact drops. Retained JAR class trimming can still run when whole-artifact removal fails closed.

### What does the nonmutating `analyze` summary mean?

It reports artifacts that would be elided by that analysis and the exact sum of their original on-disk JAR sizes. The byte total is an estimate of possible savings; the final package delta may differ. `analyze` uses trim-disabled options and does not predict intra-JAR class removal. It does not mutate Maven artifact views or package output.

### How can I keep a dependency JAR unchanged?

Set `elide.trimSkipArtifacts` to the exact resolved coordinate, such as `groupId:artifactId:version:jar:`. The JAR remains byte-identical and is protected from whole-artifact elision. Its classes can still cause linked classes in other trim candidates to be retained. See [Maven plugin usage](plugin-usage.md) for the Spring example.

### What if a dependency JAR changes during or between Maven builds?

The elider uses exact content digests to identify dependency and JDK platform inputs. The stable-input assumption covers dependency JARs, the selected JDK's `ct.sym` or JMODs, its `release` metadata, and the selected archive inventory. Concurrent edits to those files during a Maven invocation are unsupported and can make that invocation nondeterministic. A later invocation recalculates selection and content identity, so changed inputs are recognized. Maven's resolution-time checksum verification does not lock files for the rest of the build. See [ADR 0004](adr/0004-assume-resolved-inputs-stable-during-build.md).

### What happens if a dependency contains multi-release implementation classes?

That JAR is kept byte-identical and skipped as a trim target with a warning. Other supported JARs can still be trimmed. Set `-Delide.failOnUnsupportedMultiRelease=true` if encountering such a JAR should fail the build.

### What happens to reports and outputs if publication fails?

A failure before the publication commit restores the previous reports, output generation, Maven artifact views, and resolver plan. If backup cleanup fails after publication commits, Maven reports that cleanup error while the new reports and outputs remain active.

### What if my application runs on a different JDK than Maven?

Multi-release analysis currently uses the JDK feature release running Maven. If the deployed application uses a different JDK, its selected multi-release implementation has not been verified by that analysis. Run analysis with the deployment JDK or configure affected JARs for pass-through until that runtime is covered.

### What if generated sources are not available before `INITIALIZE`?

Leave `elide.sourceRootsComplete=false`, the default. This conservatively keeps compile-visible JARs and their classes available for trimming. Set it to `true` only when all production and generated sources are available before the elider runs and no later generator adds compile references.

### What happens to JARs with a root `module-info.class`?

On the classpath, such JARs are kept byte-identical with a warning. Set `-Delide.failOnUnsupportedModuleInfo=true` to fail instead. JPMS module-path behavior is not supported.

### What happens when the plugin encounters metadata or an archive layout it does not understand?

It fails before changing Maven artifact pointers rather than assuming unknown metadata is unused. Multi-release and root-module-info JARs have the explicit pass-through policies described above, with strict failure options available.

### Does removing classes make a vulnerability finding go away?

Not necessarily. Many vulnerability tools report by artifact coordinates and version, even when some classes have been removed. The current omitted-code proof is limited to high-confidence mappings whose vulnerable classes and nested classes are verified absent from a retained, trimmed archive; a package/version finding or unused artifact alone is insufficient. Maven assessment applies `versionRangeSpec` before attempting proof. The current report may list a CVE as inactive based on a missing prerequisite coordinate, but that finding does not prove that the exact prerequisite class is absent and is not VEX evidence. Precondition-gated VEX is accepted for implementation but is not available yet. It will require an exact prerequisite class, explicit complete-inventory opt-in, and fail-closed verification across application classes/resources and effective dependency archives. That inventory assertion will not cover providers added by later packaging or deployment runtime mechanisms. Inspect and scan the final packaged artifact, and assess the advisory's affected code and exploit conditions separately. See [RQ-0008](research/RQ-0008-osv-sbom-comparison-and-vex-evidence.md) and [RQ-0013](research/RQ-0013-precondition-gated-vex-and-multi-artifact-exploitability.md).

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

### How much build time does elision add?

Three baseline-first `clean verify` cycles measured Basic at a median 2.262 seconds without elision and 4.224 seconds with it; the median of the three paired differences was +1.977 seconds. Spring Boot measured medians of 4.106 seconds and 24.523 seconds, with a median paired difference of +20.417 seconds. These are descriptive observations, not stable performance guarantees or isolated causal estimates. The fresh-context trim-cache operation remains above the <10 ms target; the repeated same-request cache hit is below it. Elision remains under active development and should not be used to remove dependencies from production builds. See [RQ-0003](research/RQ-0003-sub-10ms-maven-fast-path-invariant-and-benchmarking.md) for measurement details.
