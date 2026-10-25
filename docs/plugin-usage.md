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

The `elide` goal is declared for `INITIALIZE` with test dependency resolution, but always fails before reading or mutating Maven project state. It will remain disabled until a forked Maven 3.9 end-to-end build proves that mutation survives subsequent resolution, compile/test classpath construction, and Shade packaging. Maven 4 compatibility remains unverified.
