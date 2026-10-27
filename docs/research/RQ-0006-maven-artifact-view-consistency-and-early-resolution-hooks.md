<!-- WHY: Investigates whether Maven consumers can observe inconsistent direct and resolved dependency views after elision, and whether earlier resolver hooks justify their lifecycle cost. -->
# RQ-0006: Maven Artifact-View Consistency and Early Resolution Hooks

* **Status**: Open
* **Category**: Maven Lifecycle & Resolver Integration
* **Date**: 2026-10-25
* **Last Updated**: 2026-10-27

Abbreviations: Abstract Syntax Tree (AST), Build Extension (BE), Core Extension (CE), Dependency Elision (DE), Project Object Model (POM), Repository Session Decorator (RSD), Software Bill of Materials (SBOM).

---

## 1. Context & Research Questions

The `elide` mojo runs during `INITIALIZE`. It can update the resolved artifact view used by standard classpaths and packagers, and point retained artifact objects at trimmed JARs. Maven also exposes a direct-dependency view. Keeping both views consistent is the documented contract, but an experiment found that changing the direct-artifact set causes Maven to resolve the POM graph again for later dependency-resolving goals. That resolution can restore original artifacts and file paths. Leaving the direct set unchanged avoids that same-session re-resolution in the tested Maven context, but then a direct-view consumer can still observe an elided dependency.

The product objective includes giving engineers a dependable view of the dependencies effective for each project. The standard `dependency:tree` goal is a natural place to inspect that inventory, so it should omit artifacts elision removes. The `dependency-elider:report` goal now reports persisted whole-artifact and class-trimming totals, but its snapshot does not preserve Maven-mediated dependency paths or the full original graph. The lifecycle integration question remains whether an earlier resolver hook can provide an effective graph to Maven's standard consumers while retaining enough pre-elision information for a path-aware audit report.

### Primary Research Questions

* **RQ-0006.1**: Which downstream Maven goals read the direct dependency view, the resolved dependency view, or trigger a fresh resolution after `INITIALIZE`?
* **RQ-0006.2**: Can a same-session build produce a demonstrable failure or wrong result when the direct and resolved views differ, beyond a mismatch in diagnostic output?
* **RQ-0006.3**: Does pruning both views at `INITIALIZE` cause Maven to restore the original graph or artifact paths before compilation or packaging? Which lifecycle transitions trigger that behavior?
* **RQ-0006.4**: If a concrete failure warrants earlier integration, which public extension point provides stable per-project redirection and filtering across repeated resolution, reactor projects, and supported Maven versions?
* **RQ-0006.5**: If no consequential consumer failure is found, can the current simpler behavior remain with the limitation clearly documented and surfaced?
* **RQ-0006.6**: Can an early resolver integration make ordinary `dependency:tree` show the post-elision effective dependency graph, while preserving the original mediated paths and per-artifact elision outcomes for a path-aware audit report?

---

## 2. Current Evidence

### 2.1 Basic Fixture

In the Basic example on Maven 3.9.11, replacing the resolved/project artifact views while leaving the original direct-artifact set unchanged allowed the standard `maven-dependency-plugin:build-classpath` probe and Maven Shade to consume the trimmed Commons Compress JAR and omit Commons Codec. The shaded application ran successfully. Commons Compress shrank from 1,117,221 bytes to 110,843 bytes; the shaded JAR shrank from 2,738,745 bytes to 1,360,150 bytes.

This proves the resolved-view path for those two tested consumers in one Maven session. It also exposes an actual model mismatch: Commons Codec remains in the project's direct dependency view while being absent from the resolved classpath and shaded package. No downstream goal that fails because it reads the direct view has been identified yet.

### 2.2 Re-resolution When Both Views Are Pruned

An earlier Basic fixture run updated the direct and resolved sets consistently. A later `prepare-package` classpath probe and Shade still received the original Commons Compress and Commons Codec repository paths. Maven 3.9.11's `org.apache.maven.lifecycle.internal.DependencyContext` uses the dependency-artifact set's identity and size when deciding whether its cached resolution remains current. Replacing that set invalidated the cache. The resolver then resolved from the POM graph and repopulated original artifacts.

This is a reproducible lifecycle failure for the transparent-trimming goal: consistent mutation at `INITIALIZE` did not persist through the tested later resolver invocation. It did not break application execution, but it silently lost the requested artifact reduction in the package. The current workaround restores correct bytes for the two tested packaging consumers by retaining the direct set, at the cost of direct/resolved view consistency.

### 2.3 `dependency:tree` After `INITIALIZE`

On the Basic fixture, a single Maven invocation ran `initialize` followed by `maven-dependency-plugin:3.8.1:tree`, with elision active and a baseline trace supplied. The log confirms the elide mojo ran and removed one of twelve whole artifacts. The dependency tree still listed `commons-codec:commons-codec:1.19.0`, although the tested post-elision classpath and shaded package omit it.

This is a concrete difference between the current dependency-tree report and the artifact view consumed by the tested classpath and packager. The standard tree goal cannot be treated as an authoritative post-elision inventory in the current integration. Apache describes `dependency:tree` as the resolved dependency tree Maven uses, so having it show effective dependencies is a product goal, not just an ADR consistency preference. This example does not show that the final package retained Commons Codec; the package test proves the opposite.

The same-session command is still useful to ensure elision executes before the report:

```sh
./mvnw -f examples/example-basic-app/pom.xml \
  -Delide.skip=false \
  -Delide.traceFiles=/path/to/baseline-classes.log \
  -Delide.trimJars=true \
  -Delide.sourceRootsComplete=true \
  -Dmaven.compiler.proc=none \
  -Delide.excludedArtifacts=commons-io:commons-io,org.apache.commons:commons-lang3 \
  initialize org.apache.maven.plugins:maven-dependency-plugin:3.8.1:tree
```

The command's order causes Maven to execute the lifecycle through `INITIALIZE`, then invokes the tree goal in the same session. It does **not** make the tree honor elision, as the Commons Codec result demonstrates. For now, use the tested effective classpath or packaged archive when answering which artifacts are actually present.

The desired split is: standard `dependency:tree` displays the effective post-elision dependency graph; a path-aware audit report uses the pre-elision, Maven-mediated graph plus retained/elided outcomes to explain original paths and decisions. The existing `dependency-elider:report` goal only reads saved totals and does not provide that path-aware audit. An early hook would need to snapshot graph edges and node metadata before filtering, then expose the filtered graph to later resolutions. The report may consume that snapshot from Maven session state in the same invocation or from a saved report model in a later invocation; that scope is still to be decided. A filtered inventory alone is insufficient to reconstruct the original paths.

### 2.4 Remaining Consumers

No specific plugin has yet been shown to produce an incorrect application result by consuming `getDependencyArtifacts()` while packaging uses `getArtifacts()`. The dependency-tree mismatch is now reproduced as a diagnostic/reporting difference, not an application or package failure. Direct-dependency analysis, publication, vulnerability reports, repeated goals, separate task segments, and fresh resolver calls remain candidates to investigate. A discrepancy in a report may be acceptable if that report intentionally describes the declared POM graph; reports must distinguish that graph from the actual post-elision classpath and package.

### 2.5 Maven 3.9.9 Cache-Key Diagnostic

[`DependencyContextReResolutionTest`](../../dependency-elider-maven-plugin/src/test/java/io/github/spockz/elider/plugin/DependencyContextReResolutionTest.java) directly exercises the project's Maven core 3.9.9 `DependencyContext` with `MavenProject` fixtures and snapshots each direct and resolved artifact's object, coordinate, file path, and SHA-256. The focused Surefire result is at `dependency-elider-maven-plugin/target/surefire-reports/TEST-io.github.spockz.elider.plugin.DependencyContextReResolutionTest.xml`. This test uses the project dependency version (3.9.9); the wrapper CLI is Maven 3.9.11, which is a separate runtime and is not the core exercised by the test. It establishes three cache-key behaviors:

* Replacing only `project.getArtifacts()` leaves the direct artifact collection untouched and does not make `DependencyContext.isResolutionRequiredForCurrentProject()` true.
* Replacing `project.getDependencyArtifacts()` with a new collection invalidates the cache even when the collection has the same size and equal coordinates.
* Mutating the direct collection's size in place invalidates the cache; calling `synchronizeWithProjectState()` records the new collection and size, after which the cache check is clean again.

This is a focused test of Maven's lifecycle cache component, not an end-to-end lifecycle reproduction. Lifecycle-level evidence is now recorded separately below. In particular, a resolver graph transformation must not assume that removing a node's entire subtree is safe: descendants can remain required through another mediated path.

### 2.6 Maven 3.9.11 lifecycle fixture

[`DependencyContextLifecycleIntegrationTest`](../../dependency-elider-maven-plugin/src/test/java/io/github/spockz/elider/plugin/DependencyContextLifecycleIntegrationTest.java) invokes the project wrapper in separate child processes and asserts its runtime as Maven 3.9.11. Its standalone helper plugin is under `src/test/fixtures`, and its Mojo sources are in the plugin `src/test/java` tree; the helper POM points only to that test package, so no test goals enter the published plugin. The helper is compiled against Maven Core 3.9.9, the version cached and managed by the project; this is distinct from the child CLI runtime. Bootstrap and consumer builds use a per-test local repository and generated `file:` repository entries for the existing user cache, with Maven Central fallback, without writing into that cache. Child logs and the isolated tree snapshots are retained under `dependency-elider-maven-plugin/target/lifecycle-probe-evidence/` (tree snapshots use `tree/lifecycle-probe/`); lifecycle phase TSV snapshots are under `dependency-elider-maven-plugin/src/test/fixtures/lifecycle-probe/consumer/target/lifecycle-probe/`. The test compares the resolved-only phase snapshot bytes before and after the separate tree process to ensure the process does not overwrite another process's identity-token namespace.

The fixture snapshots the same `MavenProject` identity before mutation, immediately after mutation, in a `requiresDependencyResolution=NONE` observer, and in a later `requiresDependencyResolution=TEST` probe. Stable tokens assigned through an `IdentityHashMap` distinguish project, collection, and artifact object references without relying on hash-code uniqueness. Each artifact record includes coordinates, normalized path, and SHA-256; paths are Base64-encoded in TSV so tabs or newlines cannot corrupt fields. The normal baseline had both dependencies and their original repository paths/hashes before and immediately after the first TEST-resolution Mojo; the NONE observer's `getArtifacts()` was empty, while the direct set still contained both entries; the later TEST probe again had both original artifacts. In Maven 3.9.11, [`MojoExecutor.ensureDependenciesAreResolved`](https://github.com/apache/maven/blob/maven-3.9.11/maven-core/src/main/java/org/apache/maven/lifecycle/internal/MojoExecutor.java) sets a null artifact filter for a Mojo with no resolution requirement; [`MavenProject.getArtifacts`](https://github.com/apache/maven/blob/maven-3.9.11/maven-core/src/main/java/org/apache/maven/project/MavenProject.java) applies that filter to its lazily rebuilt view. Therefore the observer's zero-size resolved view is a per-Mojo filter effect, not evidence that Maven discarded the backing resolved artifacts.

The resolved-only control applies file-pointer updates to identity-distinct direct and resolved artifacts, then updates `setResolvedArtifacts` and `setArtifacts` while leaving direct collection membership unchanged. At the later TEST probe, the resolved view retained only `keep-library` at the transformed file path and hash; the direct view still contained both coordinates, with the keep artifact pointing at the transformed file. The full mutation additionally replaces the direct collection with its retained one-coordinate set. At the later TEST probe, that direct view remained pruned, and the resolved view contained only `keep-library` at its original repository path and hash. This demonstrates that Maven's later resolution uses the modified direct dependency set as input and resolves its retained coordinate again; it does not restore the removed direct coordinate. The resolved backing collection alone is insufficient to infer later results. The test re-hashes both original fixture JARs after all three lifecycle modes and the separate tree invocation, confirming their stored bytes were unchanged.

The same fixture invokes `dependency:tree` separately after `initialize`; the tree still reports both POM coordinates in the resolved-only control. This remains distinct from the direct/resolved artifact-view observations and does not establish safe graph pruning. The focused command passed 4 tests (1 lifecycle integration and 3 cache-key tests):

```sh
JAVA_HOME=$PWD/.scratch/toolchains/graalvm-jdk-21.0.12+7.1 ./mvnw --batch-mode --no-transfer-progress \
  -pl dependency-elider-maven-plugin -am \
  -Dtest=DependencyContextLifecycleIntegrationTest,DependencyContextReResolutionTest \
  -Dsurefire.failIfNoSpecifiedTests=false test
```

The Surefire reports are `dependency-elider-maven-plugin/target/surefire-reports/TEST-io.github.spockz.elider.plugin.DependencyContextLifecycleIntegrationTest.xml` and `dependency-elider-maven-plugin/target/surefire-reports/TEST-io.github.spockz.elider.plugin.DependencyContextReResolutionTest.xml`. Retained verification output is in `target/wp-resolve-slice-1.2-focused.log`, `target/wp-resolve-slice-1.2-lint.log`, `target/wp-resolve-slice-1.2-make-check.log`, and `target/wp-resolve-slice-1.2-test-examples.log`. The fixture does not exercise a real Shade/package consumer, arbitrary transitive descendants, Maven 4, or a resolver decorator. Those remain open before production resolver integration; subtree pruning remains unsafe absent a descendant-retention policy.

`JAVA_HOME=$PWD/.scratch/toolchains/graalvm-jdk-21.0.12+7.1 MARKDOWNLINT=$PWD/.scratch/tools/node_modules/.bin/markdownlint-cli2 make check` passed after the lifecycle fixture was added: 149 core tests and 87 plugin tests, with formatting, Checkstyle, PMD, SpotBugs, and Markdown lint clean. The retained log is `target/wp-resolve-slice-1.3-make-check.log`.

### 2.7 Maven 3.9.11 test-only resolver decorator

The same integration test now bootstraps a test-only core extension, registered by the consumer's `.mvn/extensions.xml`. The extension JAR contains an explicit `META-INF/sisu/javax.inject.Named` component index for `ResolverGraphProbe`, annotated `@Named("default")`, `@Priority(10)`, and `@Singleton`. A separate Plexus role hint provides a concrete `DefaultProjectDependenciesResolver` delegate. The fixture checks the packaged component index and verifies at runtime that the container selects the decorator and that its concrete delegate is a different resolver instance.

One baseline invocation confirms both synthetic coordinates appear in the serialized dependency tree. A second fresh invocation activates the decorator and invokes `dependency:tree` twice in the same Maven process. For each call, the ordered graph input is `drop-library, keep-library`, the resolver filter rejects both artifacts, and the output graph contains only `keep-library`. The test checks each serialized tree output independently. This matches the [`maven-dependency-tree` 3.3.0 `DefaultDependencyGraphBuilder`](https://github.com/apache/maven-dependency-tree/blob/maven-dependency-tree-3.3.0/src/main/java/org/apache/maven/shared/dependency/graph/internal/DefaultDependencyGraphBuilder.java) path used by the goal: tree collection rejects artifact resolution, so absent candidate JAR files in a cold repository cannot be treated as proof that a node is unused. For these tree requests, `DependencyResolutionResult.getDependencies()` is empty before and after the in-place graph change. The test does not clone a result wrapper or establish consistency of separate lists and error associations for general resolver consumers.

The fixture also installs a test-only `EventSpy` indexed in the same core-extension JAR. Maven 3.9.11's [`LifecycleDependencyResolver`](https://github.com/apache/maven/blob/maven-3.9.11/maven-core/src/main/java/org/apache/maven/lifecycle/internal/LifecycleDependencyResolver.java) emits a `DependencyResolutionRequest` through the EventSpy dispatcher immediately before its lifecycle resolver call. In the `prepare-package` fixture, the spy records two TEST-filter requests: first with both direct artifacts accepted, then after the fixture's direct-set mutation with only `keep-library` accepted. Neither request token appears at the resolver decorator, and the fixture observes no decorator call in that lifecycle process. This establishes that the indexed component selected for direct `ProjectDependenciesResolver` lookup is not intercepting these live lifecycle requests in the tested Maven 3.9.11 setup. The lifecycle snapshots independently show that, after the direct set was pruned, later resolution loads `keep-library` from its original repository path and hash.

The EventSpy's tree-process record is a separate lifecycle collection request: its token differs from the later direct resolver call made by `dependency:tree`. The test asserts these are distinct paths and does not claim that EventSpy observes the tree goal's direct resolver call. Tree transformation remains demonstrated by the actual serialized output and decorator event. The fixture transforms only a synthetic direct leaf with no children and calls a separate `DefaultProjectDependenciesResolver` delegate. The packaged Sisu index is checked, and the runtime event proves that the container-selected decorator and delegate are different instances. It does not prove descendant retention, package behavior, error remapping, reactor isolation, or compatibility beyond Maven 3.9.11. Never infer unused status from a missing artifact in a tree-only request.

Focused verification passed 5 tests (2 lifecycle integration tests and 3 cache-key tests). The Surefire evidence is at `dependency-elider-maven-plugin/target/surefire-reports/TEST-io.github.spockz.elider.plugin.DependencyContextLifecycleIntegrationTest.xml` and `.../TEST-io.github.spockz.elider.plugin.DependencyContextReResolutionTest.xml`. The baseline and repeated-active logs are `dependency-elider-maven-plugin/target/resolver-probe-evidence/tree-baseline.log` and `dependency-elider-maven-plugin/target/resolver-probe-evidence/tree-repeated-active.log`; lifecycle EventSpy evidence and artifact snapshots are in `dependency-elider-maven-plugin/target/resolver-probe-evidence/lifecycle-direct-and-resolved.log` and `dependency-elider-maven-plugin/target/resolver-probe-evidence/direct-and-resolved-snapshots/`. The test run is retained at `target/wp-resolve-slice-1.3-focused.log`. The fixture asserts that both resolver extension classes are absent from the standalone helper-plugin JAR and re-hashes both original synthetic JARs after the runs.

### 2.8 Maven 3.9.11 test-only repository session decorator

The same fixture registers an additional uniquely named Sisu `RepositorySessionDecorator`. In the lifecycle subprocess, the EventSpy stores each live TEST request's identity token in that request's `RepositorySystemSession.getData()` immediately before Maven calls `ProjectDependenciesResolver`. The decorator consumes and logs the same token. The before-mutation lifecycle resolution reaches the decorator with `plan=none`, preserving both original artifacts and their paths/hashes.

In a separate run, the test-only `initialize` Mojo first mutates the direct and resolved views, then writes the fixed keep-library replacement path into the Maven repository session data. The later TEST request is captured as token 2; the decorator sees the plan, returns a distinct `DefaultRepositorySystemSession` copy with a wrapping `WorkspaceReader`, and the reader returns the replacement only for the exact `io.github.spockz.elider.test:keep-library:jar::1.0.0` coordinate. Later snapshots show the retained direct and resolved artifact at the replacement path and hash. The test re-hashes the original repository JARs and confirms both files remained unchanged.

`ResolverSessionProbeTest` checks wrong group, artifact, classifier, extension, and version variants all delegate their artifact and version lookup; it also verifies that the wrapped reader exposes the underlying workspace repository. The fixture does not alter `ProjectArtifactsCache` or the existing graph transformer. This is a test-only, single-project, sequential proof of a possible later-resolution mechanism. It does not establish reactor isolation, concurrent behavior, arbitrary packaging consumers, or broader compatibility. The test sources remain outside the published plugin and helper-plugin artifacts.

The focused command passed 7 tests, including the lifecycle probe, exact workspace-reader tests, and cache-key tests; output is `target/wp-resolve-slice-1.4-focused.log`. The later-phase evidence is in `dependency-elider-maven-plugin/target/resolver-probe-evidence/lifecycle-session-decorator.log` and `dependency-elider-maven-plugin/target/resolver-probe-evidence/session-decorator-snapshots/`. Full `make check` passed with 149 core and 89 plugin tests, formatting, Checkstyle, PMD, SpotBugs, and Markdown lint; output is `target/wp-resolve-slice-1.4-make-check.log`.

`JAVA_HOME=$PWD/.scratch/toolchains/graalvm-jdk-21.0.12+7.1 make test-examples` also passed all four example lifecycle checks; its log is `target/wp-resolve-slice-1.3-test-examples.log`. This existing example target installs the current SNAPSHOT to `/home/node/.m2/repository`; the standalone lifecycle fixture uses an isolated repository.

### 2.9 Production retained-JAR plan implementation

The production plugin now contains an immutable JDK-only project plan and versioned session-data store, a publisher called after trim outputs, project views, and the report validate, and a uniquely indexed `EliderRepositorySessionDecorator`. Session data contains only standard JDK maps, lists, strings, and integers so the plugin and core-extension realms do not depend on sharing custom classes. Each retained replacement carries its expected SHA-256 digest; publication verifies the digest and the reader verifies it again before returning the replacement file. Empty plans replace prior same-project entries, preventing a repeated no-trim execution from leaving a stale replacement active. The decorator returns the original session when no project plan or no replacements exist; with a plan it copies the session, wraps the existing workspace reader, and substitutes only exact retained JAR GAVCE paths. It forwards Maven's `MavenWorkspaceReader.findModel` to an existing Maven workspace reader. Malformed payloads, missing files, and changed output digests fail explicitly.

Focused tests cover payload round-trip and project isolation, JDK-only payload values, malformed schema/plan rejection, no-plan session identity, session copying, exact GAVCE artifact replacement with delegated lookup/model behavior, Maven's GACE-family `findVersions` semantics, and post-plan file digest changes. The decorator merges planned versions into the delegate's version list for matching group, artifact, extension, and classifier, even when the requested version is blank or differs from the planned version. The wrapper delegates Maven's model lookup API, but same-GAV behavior across reactor modules and reactor isolation remain unverified. `ProjectArtifactsCache` is unchanged.

For production slice 2.1, the focused `ElideMojoTest`, plan-store, and decorator suite passed 29/29; log: `target/wp-resolve-slice-2.1-focused.log`. Full `make check` passed with 149 core and 94 plugin tests, formatting, Checkstyle, PMD, SpotBugs, and Markdown lint; log: `target/wp-resolve-slice-2.1-make-check.log`. The tests use Maven Core 3.9.9; the lifecycle evidence summarized above uses the Maven 3.9.11 wrapper CLI.

### 2.10 Packaged production extension activation

The production plugin was installed into a per-test local repository, and an isolated Maven 3.9.11 consumer loaded it through `.mvn/extensions.xml`. The test inspects the installed plugin JAR to confirm its Sisu index names `EliderRepositorySessionDecorator`, that the class is packaged, and that resolver-probe and helper Mojo classes are absent. A separate test-only seed extension was loaded in both A/B consumers; its one-shot EventSpy wrote only the versioned JDK payload into the live `RepositorySystemSession` before the production decorator ran. It compares direct artifact file paths and hashes around payload seeding and fails if they change.

The positive consumer loaded both the seed helper and production extension. The test-only EventSpy seeded the payload before the first TEST-resolution request, and the production decorator applied the replacement to that same first request. The post-lifecycle probe snapshot recorded keep-library at the replacement JAR path and SHA-256 in both direct and resolved artifact views. The otherwise identical negative consumer loaded only the seed helper; it kept the repository JAR path and SHA-256. Both repository fixture JARs were re-hashed unchanged. This proves packaged component activation and first-request retained-JAR substitution for the tested single-project Maven 3.9.11 consumer. It does not prove a fresh re-resolution after the production Mojo publishes its plan, actual `ElideMojo` publication in a consumer, whole-artifact drops, graph pruning or tree consistency, packager outputs, reactor behavior, concurrency, or other Maven versions.

The combined focused Maven command passed 33 plugin tests: the 3 lifecycle integration tests, 26 `ElideMojoTest` tests, 2 decorator tests, and 2 publisher tests. The Surefire report is `dependency-elider-maven-plugin/target/surefire-reports/TEST-io.github.spockz.elider.plugin.DependencyContextLifecycleIntegrationTest.xml`; child logs and isolated repo are under `dependency-elider-maven-plugin/target/production-extension-evidence/`. Tests cover successful `ElideMojo` publication, skip/no-trim clearing, output failure preserving the previous payload after the class-usage report succeeds, and updating one project's plan without dropping another project's entry. The focused `ElideMojoTest` rerun passed 26/26. Final `make check` passed with 149 core and 99 plugin tests, formatting, Checkstyle, PMD, SpotBugs, and Markdown lint; log: `dependency-elider-maven-plugin/target/wp-resolve-slice-2.2-fixup-make-check.log`.

### 2.11 Packaged `elide` publication followed by TEST resolution

The isolated Maven 3.9.11 consumer now runs a TEST-resolution probe at `validate`, invokes the installed production `elide` goal at `initialize`, then invokes TEST-resolution probes at `process-resources` and `prepare-package`. The actual goal trims keep-library's unused class, drops the unused drop-library leaf from its resolved view, writes its summary and SBOM, and publishes the JDK-only plan. The test-only EventSpy does not seed a plan. Its collision-free identity tokens show request 1 with no plan before the goal and distinct request 2 with the published plan after the elision summary.

The test computes repository and trimmed JAR hashes separately for each child run, then compares that run's snapshots and JSON outputs against those values. The generated JAR retains `KeepEntry` and omits `UnusedEntry`. Parsed summary JSON reports the consumer project identity, one dropped artifact, and one pruned class. Parsed SBOM identifies the keep-library component, matches that run's trimmed hash, and records that run's original hash as its ancestor. The original repository JAR hashes remain unchanged. Exact per-run values are in the retained snapshots and SBOMs under `dependency-elider-maven-plugin/target/production-mojo-evidence/`.

With the production core extension enabled, the later TEST resolved view contains the trimmed JAR path and hash. Without the production extension, the later TEST resolved view returns the original repository path and hash while the direct artifact still points to the trimmed output. A test-only helper removes exactly the known direct drop leaf between snapshots to trigger the subsequent resolution; it does not establish production direct-view consistency or graph policy. Evidence logs, reports, snapshots, and isolated repository are under `dependency-elider-maven-plugin/target/production-mojo-evidence/`. The Surefire report is `dependency-elider-maven-plugin/target/surefire-reports/TEST-io.github.spockz.elider.plugin.DependencyContextLifecycleIntegrationTest.xml`.

The focused consumer test passed 1/1. Final `make check` passed with 149 core and 100 plugin tests, formatting, Checkstyle, PMD, SpotBugs, and Markdown lint; log: `dependency-elider-maven-plugin/target/wp-resolve-slice-2.3-make-check.log`. Evidence is bounded to this single-project Maven 3.9.11 fixture. Mediated graph capture, descendant retention, dependency-tree consistency, package outputs beyond this JAR, reactor behavior, concurrency, and other Maven versions remain open.

### 2.12 Packaged post-mediation graph capture prototype

Slice 3.1 adds a separate indexed `RepositorySessionDecorator` that copies the repository session and chains the existing `DependencyGraphTransformer`. It delegates once, captures the delegate's returned graph as detached JDK-only values, and returns that same graph object. It does not filter nodes or change project artifact views. The structural fingerprint covers ordered topology, relocation sequences, and captured node semantics; plan presence, plan fingerprint, plan generation, and capture generation are stored separately. Schema v2 keeps both plan observations and snapshots in session data with compare-and-set updates, isolated between sessions. Snapshot loading validates required nested fields and types, root/node/edge/winner references, reachability, fingerprints, project identity, and capture-generation consistency. Plan generation records decoration-time state and is not required to increase in capture-completion order.

The production plugin JAR is installed in the isolated lifecycle fixture, and its Sisu index/class assertions cover the graph-capture decorator. On Maven CLI 3.9.11, the positive consumer's `graph-initial.tsv` contains exactly three reachable nodes rooted at consumer `n0`, with edges `n0→n1` and `n0→n2` for `drop-library` and `keep-library`. `graph-later.tsv` preserves that original capture and appends a present-plan capture with generation 1, rooted at consumer `n0`, with exactly the keep-library child and edge `n0→n1`. The test-only post-elide Mojo removes the known direct drop leaf to trigger that subsequent request, so this is not evidence of production graph filtering. The negative consumer has no production extension and records no graph snapshot. The dynamic graph fingerprints and provenance rows are retained under `dependency-elider-maven-plugin/target/production-mojo-evidence/`.

Focused unit coverage passed 23/23 across `ResolverArtifactGraphSnapshotTest`, `ResolverArtifactGraphSnapshotStoreTest`, `EliderMediatedGraphCaptureDecoratorTest`, `ResolverArtifactGraphSnapshotRoundTripTest`, and `ResolverArtifactGraphTopologyValidationTest`. It covers null-root and nullable-optional round trips, replacement-root artifact identity, exact-once delegation, relocation order, deep JDK-only freezing, self-consistent malformed nested schema/reference/fingerprint rejection, mutually exclusive conflict-winner forms, child-edge consistency, concurrent distinct captures in one session, per-session same-project isolation, delayed plan provenance, and non-monotonic plan generations when transformations complete out of order. The packaged lifecycle integration passed 4/4 and asserts exact node and edge topology for both captures. `make check` passed with 149 core and 123 plugin tests, formatting, Checkstyle, PMD, SpotBugs, and Markdown lint; log: `dependency-elider-maven-plugin/target/wp-resolve-3.1-review-fix-null-and-validator-make-check.log`. The worktree used the cached Markdown linter via `MARKDOWNLINT=../../tools/node_modules/.bin/markdownlint-cli2`. This establishes capture behavior only for this Maven 3.9.11 single-project fixture. It does not define an effective-graph selection policy, remove dependencies, prove `dependency:tree` consistency, or establish reactor/concurrent lifecycle support. Whole-artifact graph pruning remains blocked on a descendant-retention policy.

---

## 3. Integration Options

| Option | Benefits | Drawbacks / risks |
| :--- | :--- | :--- |
| **A. Keep the `INITIALIZE` mojo mutation** | Smallest implementation; ordinary plugin configuration; no startup extension; already produces correct Basic classpath and Shade bytes in the tested Maven session. | Direct and resolved views can disagree; fully pruning both views triggers re-resolution in the tested lifecycle; behavior may depend on which Maven goals execute next. |
| **B. Bind a lifecycle participant earlier through a Maven core extension** | Runs before regular project goals and can prepare state for the session; can potentially coordinate project graph changes before consumers run. | Still needs dependency artifacts to compute the plan; an earlier hook does not by itself intercept every later resolver call; may require a two-stage plan and carefully timed file availability. |
| **C. Use resolver and repository-session decorators in a core extension** | The priority-indexed `ProjectDependenciesResolver` is selected for direct `dependency:tree` calls; the packaged production `RepositorySessionDecorator` is discovered by an isolated consumer. A separate A/B lifecycle fixture proves actual `elide` plan publication and trimmed-JAR use on a distinct later TEST request. | The fixture is one single-project Maven 3.9.11 case and uses a test-only direct-leaf removal to trigger later resolution. Whole-artifact filtering and graph pruning remain deferred. General result-list/error consistency, reactor isolation, concurrent behavior, and package-consumer outputs remain unproven. |
| **D. Load the plugin as a build extension (`<extensions>true>`)** | Keeps extension declaration in the POM and can reuse the plugin artifact. | Build extensions load later than core extensions; timing may be too late for the resolver component being changed. Must be experimentally proven before selecting. |
| **E. Keep the current behavior and document the boundary** | Avoids architectural and compatibility costs until a consequential consumer is found; lets the examples validate the core product behavior now. | Users that rely on direct-view consumers or fresh resolution may see original dependencies; this remains a known lifecycle limitation rather than a general transparency guarantee. |

---

## 4. Benefits and Costs of Moving Earlier

The main benefit of an earlier resolver integration is to make Maven's ordinary dependency reports and consumers use the effective retained graph, including after Maven resolves dependencies again. Engineers could inspect `dependency:tree` to see which dependencies remain for the project. A future path-aware audit report could explain those decisions by combining saved pre-elision mediated paths with retained/elided status and reasons. The existing `dependency-elider:report` goal reports totals only. This separates an effective inventory from an audit trail without asking one tree to serve both purposes.

The cost is moving from a normal plugin goal to Maven startup infrastructure. A core extension must be loaded before project resolution, persist or reconstruct each project's plan at the correct time, preserve dependency mediation, avoid cross-project state leaks, and support the project's Maven version range. A lifecycle participant alone may run earlier but may not intercept later resolution. A `RepositorySessionDecorator` is the more direct candidate, but its behavior and version compatibility require integration tests.

Do not implement the earlier hook solely to make the state look consistent. First demonstrate an observable failure or establish that the product must guarantee consistency for all Maven consumers. If the only current user-visible paths are the tested classpath and packagers, the extension cost may outweigh a documented limitation.

---

## 5. Evidence Plan and Decision Checkpoints

1. Extend the cache-key unit diagnostic with a fixture-level recorder that captures the Maven-mediated graph, direct and resolved artifact identities, and file hashes immediately before filtering and after a later dependency-resolving goal. The unit diagnostic alone does not close this checkpoint.
2. Compare normal dependency resolution with a prototype graph transformer across `maven-compiler-plugin`, `maven-dependency-plugin` classpath/tree/copy goals, Surefire, Shade, and Spring Boot repackage. Verify `dependency:tree` excludes elided nodes while retained transitive artifacts stay visible with meaningful paths, and capture effective classpaths, package entries, and hashes.
3. Preserve the pre-filter mediated graph with node identity, parent edges, scopes, conflict/selection metadata, and artifact coordinates. Join it with retained/elided outcomes and reasons; verify `mvn-dep-elider:report` reconstructs the original paths without treating the old graph as effective inventory.
4. Test the report from the same Maven session and from a later invocation. Decide whether the extension hands off a session snapshot or writes a versioned report model; bind it to project identity and input graph so stale reports are detectable.
5. Repeat selected goals in a separate Maven task segment and a fresh Maven invocation. Include a direct dependency, a transitive dependency with a retained child, and an artifact whose file pointer is trimmed.
6. Verify reactor isolation, repeated resolution, dependency mediation, plugin compatibility, and the supported Maven 3/Maven 4 range. Compare extension startup and build costs against the current `INITIALIZE` implementation.

### Decision Checkpoints

* [ ] **Checkpoint 1 (Effective Tree)**: Prove whether a resolver graph hook can make `dependency:tree` show only the artifacts effective after elision while retaining needed transitive dependencies.
* [ ] **Checkpoint 2 (Report Snapshot)**: Prove that enough pre-filter graph structure and elision outcomes can be retained for a separate report to show original Maven paths and retained/elided status.
* [ ] **Checkpoint 3 (Resolution Persistence)**: Establish which lifecycle transitions restore original artifacts after consistent `INITIALIZE` mutation and whether the early hook intercepts them.
* [ ] **Checkpoint 4 (Earlier Hook Tradeoff)**: Compare the minimal lifecycle mutation with an early resolver hook using the same fixture, Maven versions, and verification artifacts.
* [ ] **Checkpoint 5 (Adopt or Document)**: Decide whether the effective-tree product goal justifies implementing the earlier hook, based on compatibility, startup and build costs, graph correctness, and report handoff evidence.

---

## 6. Implementation Work Package

This investigation is decomposed into executable implementation tracks in work package [WP-RESOLVE-01](../handovers/2026-10-27-wp-resolve-01-maven-lifecycle-and-graph-consistency.md).
