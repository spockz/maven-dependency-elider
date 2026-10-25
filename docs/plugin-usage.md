<!-- WHY: Documents the usable Maven goal and the lifecycle safety boundary for plugin consumers. -->
# Maven plugin usage

The `analyze` goal reads explicit runtime trace files and reports whole artifacts that the core policy would elide. It does not mutate Maven's artifact sets, classpaths, or packaged output.

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

The summary reports whole-artifact elisions over the complete pre-analysis Maven artifact count. Surgical classes, methods, and fields are reported as zero with an unrun stage and N/A denominators. Cache status is unavailable.

Both goals also write a deterministic class usage report to `target/dependency-elider-class-usage.json` by default. Set `-Delide.reportFile=/path/to/report.json` to choose another location. The report lists classes by their complete static and runtime evidence groups, along with a per-class category. Static scanning is opt-in because it examines only the application production output explicitly supplied through `-Delide.productionOutput=target/classes`; it does not inspect test output. When that option is omitted, the report sets `staticEvidenceAvailable` to `false`, leaves the three static-dependent group values `null`, and labels each class as having unknown static evidence. It never labels a class runtime-only or unused without a completed scan.

The `elide` goal runs in `INITIALIZE` with test dependency resolution. It requires explicit trace inputs and applies the validated whole-artifact decision to Maven's resolved and direct artifact views before later lifecycle phases.

`elide.skip` is a Boolean Maven user property (`-Delide.skip=true|false`). The CVE example fixtures bind the goal and default this property to `true` so baseline packaging remains available. Set it to `false` and supply `-Delide.traceFiles=...` to apply elision. Missing, malformed, unsupported, or unmatched trace evidence fails the goal.
