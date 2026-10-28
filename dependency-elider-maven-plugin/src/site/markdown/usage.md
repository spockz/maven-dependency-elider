<!-- WHY: Documents the usable Maven goal and the lifecycle safety boundary for plugin consumers. -->
# Maven plugin usage

The nonmutating `analyze` goal reads explicit runtime trace files and reports artifacts that would be elided by this analysis. It also reports the exact sum of their original on-disk JAR sizes as an estimate; the final package delta may differ. It does not mutate Maven's artifact sets, classpaths, or packaged output. By default it does not run intra-JAR trimming; pass `-Delide.trimJars=true` with the same trim options used by `elide` to calculate dry-run trim records and code-absence proofs.

For practical configuration and compatibility questions, see the [User FAQ](https://github.com/spockz/maven-dependency-elider/blob/main/docs/faq.md). Implementation rationale and benchmark evidence are in the [Contributor Decision Register and Engineering FAQ](https://github.com/spockz/maven-dependency-elider/blob/main/docs/contributor-decisions-and-faq.md).

First, install this repository's plugin and core dependency using the repository wrapper:

```sh
./mvnw -pl dependency-elider-maven-plugin -am install
```

Then, from the consumer project, invoke the goal with that project's Maven binary or wrapper:

```sh
mvn io.github.spockz:dependency-elider-maven-plugin:0.1.0-SNAPSHOT:analyze \
  -Delide.traceFiles=target/classes.log
```

Pass multiple trace paths as a comma-separated `elide.traceFiles` value. Supported readers recognize class-loading logs (`.log` or `.txt`), CDS lists (`.lst`), JFR recordings (`.jfr`), GraalVM reflection configuration (`.json`), and JaCoCo execution data (`.exec`). Every supplied file must be supported and readable. The merged trace set must be nonempty and match at least one class in a supplied JAR dependency; an individual file may contribute no matching observation when another supplied file provides a match. Malformed or unsupported evidence fails the goal.

`elide.excludedArtifacts` accepts global retention coordinates in `groupId:artifactId[:version[:type[:classifier]]]` form. Type defaults to `jar`; an omitted version matches every version. Matching ignores Maven scope. The default is empty.

Only resolved regular JAR files are scanned. Non-JAR artifact types remain retained. The analysis currently considers `compile` and `runtime` scopes as candidates, and excludes all others from elision.

The `analyze` summary reports raw artifacts that would be elided by its analysis and the exact sum of their original on-disk JAR sizes as an estimate; the final package delta may differ. With `elide.trimJars=true`, it also simulates trimming and reports mapped CVE components that would leave the inventory and CVEs whose vulnerable classes would be proven absent. Component removal is package-inventory evidence, while a code-proof result requires a HIGH-confidence mapping and archive inspection. The `elide` summary distinguishes raw candidates from effective whole-artifact drops. Exact whole-artifact removal requires a unique compatible pre-elision Maven graph capture; if the production core extension or matching graph evidence is unavailable, the effective drop set is empty and raw candidates remain retained. The trim-disabled `elide` summary marks class, method, and field stages as not run. When `elide.trimJars=true`, `elide` reports program classes removed from retained JARs and the sum of their uncompressed omitted `.class` entry payload bytes. That total excludes module descriptors and archive sanitation metadata. Methods and fields remain marked as unrun; the summary reports validated trim-cache hits and analysis runs.

After a successful lifecycle run with `elide` enabled, the `report` goal reads its saved result without repeating dependency analysis. By default, `elide` writes `target/dependency-elider-report.json`; set `-Delide.summaryFile=/path/to/report.json` to change the location. Invoke the report from the same project checkout:

```sh
mvn io.github.spockz:dependency-elider-maven-plugin:0.1.0-SNAPSHOT:report
```

The report shows raw whole-artifact candidates separately from effective whole JAR drops. Dropped-JAR metrics include artifact count, original on-disk JAR bytes, `.class` entry count, and uncompressed `.class` entry payload bytes. Retained-JAR trimming has separate class and payload-byte totals; dropped-JAR classes are excluded from those trimmed totals, and persisted reports reject any coordinate listed in both categories. Both categories exclude root and versioned `module-info.class` entries and archive sanitation metadata. The report renders the saved mediated TEST graph as deterministic shortest dependency paths with retained, class-trimmed, protected, and effective-drop statuses. It fails clearly if that graph was unavailable when `elide` ran. Byte totals use binary units such as KiB and MiB. The snapshot identifies the project's GAV, canonical directory, and last successful elision timestamp. A failure before publication leaves the prior snapshot active; `report` labels it as the last successful run. If backup cleanup fails after publication commits, the goal reports that error while the new snapshot and outputs remain active. The goal reads only the saved snapshot and does not revalidate changed sources, dependencies, or traces or invoke Maven dependency resolution/tree collection.

Each persisted format has an independent schema version 1: the top-level elision report, graph-capture session store, resolver-plan session store, class-usage report, and trim cache. Format identity and required fields distinguish these records; schema numbers are not plugin release versions. Unsupported values and incompatible pre-release field shapes are rejected with rerun guidance. No migration or backward-compatibility promise is provided for unreleased drafts.

The `analyze` and `elide` goals also write a deterministic class-usage analysis report to `target/dependency-elider-class-usage.json` by default. Set `-Delide.reportFile=/path/to/report.json` to choose another location. This is distinct from the persisted elision snapshot at `target/dependency-elider-report.json`, configured with `-Delide.summaryFile`, which is consumed by `dependency-elider:report`. The class-usage report lists classes by their complete static and runtime evidence groups, along with a per-class category. Static scanning is opt-in because it examines only the application production output explicitly supplied through `-Delide.productionOutput=target/classes`; it does not inspect test output. When that option is omitted, the report sets `staticEvidenceAvailable` to `false`, leaves the three static-dependent group values `null`, and labels each class as having unknown static evidence. It never labels a class runtime-only or unused without a completed scan.

The `elide` goal runs in `INITIALIZE` with test dependency resolution. For whole-artifact removal, load the packaged production core extension through the consumer's `.mvn/extensions.xml`; it captures the initial mediated TEST graph and applies a source-fingerprint-bound projection to a later compatible resolver graph. If the graph is missing, ambiguous, or differs from the captured source, the resolver fails before changing that graph and the whole-artifact decision fails closed. The direct dependency-artifact membership is preserved; retained artifact objects may receive trimmed file pointers. With the extension and an active initialize-bound elider execution, a bare `dependency:tree` request automatically schedules elision before tree collection. This is fixture-verified for a single-project leaf graph on Maven CLI 3.9.11 and Dependency Plugin 3.8.1; automatic preparation rejects multi-project reactors. Ordinary lifecycle commands such as `mvn test` already pass through `INITIALIZE` and need no separate initialization goal. At `INITIALIZE`, production sources may not include generated files, and annotation processors or generators may add compile references later. Therefore `elide.sourceRootsComplete` defaults to `false`: the plugin skips source attribution and conservatively retains every effective compile-classpath JAR and all of its indexed classes. This can reduce whole-artifact and intra-JAR elision, while preserving compile visibility when source coverage is unknown.

After installing the plugin, add the production core extension to the consumer's `.mvn/extensions.xml`:

```xml
<extensions>
  <extension>
    <groupId>io.github.spockz</groupId>
    <artifactId>dependency-elider-maven-plugin</artifactId>
    <version>0.1.0-SNAPSHOT</version>
  </extension>
</extensions>
```

Without this extension, whole-artifact candidates remain in the effective dependency set, although retained-JAR trimming can still run.

Set `-Delide.sourceRootsComplete=true` only when every production and generated source is already present before `INITIALIZE`, and no later processor or generator will introduce compile references. With this assertion, the plugin resolves current Java source references using the effective Maven compiler `release` or `source`/`target` and supported encoding settings. Unsupported compiler modes, selected JDK toolchains, unresolved settings, source-generation lifecycle executions, and empty or missing source roots fail before mutation. Regardless of this setting, pruning still requires at least one supplied dependency class to match runtime trace evidence; source-only matches cannot replace that runtime guard.

Supported service, Spring, and native-image metadata roots protect both the declaring JAR and indexed provider JARs from whole-artifact elision even when `elide.trimJars=false`. If a root has multiple scanned owners, all matching JARs are kept; if no owner is found, the plugin conservatively keeps the scanned JAR inventory. Setting `-Delide.trimJars=true` additionally trims classes from retained dependency JARs during `INITIALIZE`. The plugin combines runtime observations, compiler source roots, optional production bytecode references, `META-INF/services` providers, supported Graal reflection/proxy metadata, and optional comma-separated `-Delide.trimRoots=package.Type,...` roots. It propagates links across retained sibling JARs before writing artifact pointer changes. Unknown native-image class metadata, unsupported compiler modes, unresolved links, and unsupported JAR layouts fail before publication. Closure recognizes JVM signature-polymorphic `MethodHandle.invoke`/`invokeExact` and `VarHandle` operations only when the corresponding native-varargs declaration exists; call-site descriptor classes remain closure roots and unresolved descriptor classes remain fatal. Trimmed JARs are written under `target/elided-artifacts/` with coordinate-safe names; original JARs remain intact. Retained artifact objects in Maven's resolved/project views and matching objects in the preserved direct dependency set receive the trimmed file.

By default, retained JARs with versioned implementation classes pass through unchanged. The plugin creates a class-only projection of their effective entries for the current JVM release, then analyzes every projected class body as a root so links into trim candidates remain reachable. The projection release is `Runtime.version().feature()` and is included in the cache fingerprint; deployments on a different Java release are not covered by that closure. `-Delide.failOnUnsupportedMultiRelease=true` fails instead of using this pass-through behavior.

Retained classpath JARs with a root `module-info.class` also pass through unchanged by default. The plugin validates the descriptor, omits it only from an ephemeral class-only projection, and analyzes every remaining class body as a root. This closure covers classpath use; it does not resolve JPMS module readability or module-path linkage. Set `-Delide.failOnUnsupportedModuleInfo=true` to fail before artifact pointer mutation. The core candidate trimmer still rejects root module descriptors. Versioned module-info-only entries remain eligible for classpath sanitization.

Use `-Delide.trimSkipArtifacts=groupId:artifactId:version[:type[:classifier]],...` for another retained JAR that must remain byte-identical. Configured pass-through classes are analyzed as roots against retained siblings; unresolved external links owned by those unchanged classes are tolerated, while missing links in trimmed candidates or reachable ordinary sibling classes still fail before artifact mutation. The original input path, coordinate, ordered classpath position, and exact bytes remain in the cache fingerprint. A configured coordinate must match a resolved compile/runtime JAR. This setting also pins its artifact against whole-artifact pruning. The Spring fixture uses pass-through entries for `spring-boot` (optional CRaC references), `spring-boot-autoconfigure` (optional AMQP/Quartz references), `spring-web` (optional Jetty references), `spring-context` (optional Java Money references), `spring-context-support` (optional Quartz references), `spring-beans` (its optional SnakeYAML references are tolerated from this unchanged owner; SnakeYAML itself is whole-artifact-pruned), `spring-aop` (optional AspectJ and Kotlin references), `spring-expression` (optional Kotlin reflection references), `groovy-templates` (optional SpotBugs annotation metadata), and `micrometer-observation` (optional Micrometer Context references), plus `micrometer-commons` (optional `javax.annotation` references). It adds Boot-managed Jakarta Validation, Freemarker, Groovy, WebJars Locator, Reactive Streams, Reactor Core, Micrometer Context, JSTL and JSR-305, SpotBugs annotation, and XStream 1.4.21 APIs as trim candidates so their optional edges resolve; Groovy Templates remains byte-identical as an explicit pass-through, and `spring-webmvc` still trims. Retained JARs with root module descriptors use the automatic module-info pass-through policy above.

With trimming enabled, the plugin writes a CycloneDX 1.6 SBOM to `target/dependency-elider-sbom.cdx.json`; set `-Delide.sbomFile=/path/to/bom.json` to choose another path. Trimmed component provenance includes the original component and digest. The global trim cache binds ordered candidate and sibling JAR content digests, sorted roots, the selected platform signature digest, engine/schema versions, and each trimmed output digest. Repeated single-artifact lifecycle tests measured 95.2 to 99.1 ms for validated warm hits under GraalVM JDK 21. The <1.5 ms target remains unmet; exact content validation and cross-JAR link closure remain enabled, and a cache hit skips ProGuard analysis.

Trimming also writes the original resolved dependency inventory to `target/baseline-sbom.cdx.json` before Maven's artifact views are changed. Set `-Delide.baselineSbomFile=/path/to/baseline.json` to change it. Whole-artifact drops remain in this baseline, while post-elision inventory reflects retained components and exact trimmed JAR hashes. When the build has an output directory, the post-elision SBOM is also staged at `META-INF/sbom/application.cdx.json` and `META-INF/native-image/sbom.json` below that directory. The first location follows Spring Boot's application SBOM convention used by its [Actuator SBOM endpoint](https://docs.spring.io/spring-boot/3.3/api/rest/actuator/sbom.html); the second is the classpath resource location described by [GraalVM Native Image SBOM documentation](https://www.graalvm.org/latest/security-guide/native-image/sbom/). This stages SBOM files for packaging and native-image classpaths; it does not establish that a native image embeds the file or that VEX is embedded.

The optional local vulnerability index has no built-in remote feed. Configure an HTTP(S) source you trust with `-Delide.cveIndexUri=https://example.invalid/index.json`; normal build refresh is skipped for offline Maven sessions, and download or cache-refresh failures warn and fall back to a valid cached index or the bundled seed. The default cache is under the operating system's user cache directory, outside `~/.m2`; override it with `-Delide.cveCacheDirectory=/path/to/cache`. The default freshness interval is 24 hours and can be changed with `-Delide.cveCacheTtlHours=48`; `-Delide.cveForceSync=true` bypasses freshness during normal builds. To explicitly refresh, run `mvn io.github.spockz:dependency-elider-maven-plugin:0.1.0-SNAPSHOT:update-cve-index -Delide.cveIndexUri=...`. The projectless update goal always requests a fresh download, requires a configured URI, fails while Maven is offline, and fails if that refresh cannot update the cache; only normal elision builds use cached or bundled fallback.

Project mappings can supplement or override the cache. An explicit range uses Maven version range syntax; a bare recommended version is treated as an exact version. A missing range uses the mapping's `version` as an exact constraint. Only HIGH confidence mappings can produce VEX, and only when the exact artifact identity and version range match a retained trim record and archive inspection proves every mapped class and original nested class absent from the trimmed JAR. For example:

```xml
<configuration>
  <trimJars>true</trimJars>
  <vulnerabilityMappings>
    <vulnerabilityMapping>
      <cveId>CVE-2026-10001</cveId>
      <groupId>org.example</groupId>
      <artifactId>affected-library</artifactId>
      <version>1.2.3</version>
      <versionRangeSpec>[1.2.0,1.3.0)</versionRangeSpec>
      <vulnerableClasses>
        <vulnerableClass>org.example.affected.VulnerableHandler</vulnerableClass>
      </vulnerableClasses>
      <sourceAdvisoryUrl>https://example.invalid/advisory</sourceAdvisoryUrl>
      <confidenceLevel>HIGH</confidenceLevel>
    </vulnerabilityMapping>
  </vulnerabilityMappings>
</configuration>
```

Verified mappings add CycloneDX vulnerability analysis to the post-elision SBOM and write `target/dependency-elider.openvex.json`; set `-Delide.vexFile=/path/to/vex.json` to select another output. Unmapped findings, mappings for whole-artifact drops, nonmatching ranges, retained mapped classes, and failed archive proofs produce no VEX. In particular, removing Janino does not prove Logback's CVE-2025-11226 code absent: Logback remains package-level inventory and no VEX is emitted without a Logback symbol mapping and a matching trim record.

## Compare OSV-Scanner SBOM inventories

`make scan-sbom` builds both CVE examples and compares each baseline SBOM with its post-elision SBOM using OSV-Scanner. Install OSV-Scanner first, then run the target. Both scans use `--offline-vulnerabilities` against the same local scanner cache and request JSON output. The comparison is package-level: it reports findings no longer matched to a package in the post-elision inventory and findings that remain. It does not establish that vulnerable code was removed, that the application is unaffected, or create VEX.

The target writes `baseline-scan.json`, `post-elision-scan.json`, and `comparison-report.json` under each fixture's `target/sbom-comparison/`. The report records the exact scanner version and executable, separate start/completion timestamps for each scan, both SBOM SHA-256 hashes, and whether the database revision was exposed. Each input is hashed before and after its scan; a content change aborts comparison so the reported inventory is the one scanned. A finding is labeled eliminated only when its component is absent from the post-elision SBOM; a finding that is no longer returned while the component remains is reported separately. Generic Maven findings that match multiple component variants, such as ordinary and classifier PURLs, are left unclassified. OSV-Scanner does not currently expose a database revision in this workflow, so the report leaves it unknown; offline mode uses the same local database cache but does not independently prove its revision. See [OSV-Scanner SBOM usage](https://google.github.io/osv-scanner/usage/scan-source) and [RQ-0008](../../../docs/research/RQ-0008-osv-sbom-comparison-and-vex-evidence.md) for the evidence boundary.

`elide.skip` is a Boolean Maven user property (`-Delide.skip=true|false`). The CVE example fixtures bind the goal and default this property to `true` so baseline packaging remains available. Set it to `false` and supply `-Delide.traceFiles=...` to apply elision. Missing, malformed, unsupported, or unmatched trace evidence fails the goal.
