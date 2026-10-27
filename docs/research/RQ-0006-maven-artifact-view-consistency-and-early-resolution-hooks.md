<!-- WHY: Investigates whether Maven consumers can observe inconsistent direct and resolved dependency views after elision, and whether earlier resolver hooks justify their lifecycle cost. -->
# RQ-0006: Maven Artifact-View Consistency and Early Resolution Hooks

* **Status**: Open
* **Category**: Maven Lifecycle & Resolver Integration
* **Date**: 2026-10-25
* **Last Updated**: 2026-10-26

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

---

## 3. Integration Options

| Option | Benefits | Drawbacks / risks |
| :--- | :--- | :--- |
| **A. Keep the `INITIALIZE` mojo mutation** | Smallest implementation; ordinary plugin configuration; no startup extension; already produces correct Basic classpath and Shade bytes in the tested Maven session. | Direct and resolved views can disagree; fully pruning both views triggers re-resolution in the tested lifecycle; behavior may depend on which Maven goals execute next. |
| **B. Bind a lifecycle participant earlier through a Maven core extension** | Runs before regular project goals and can prepare state for the session; can potentially coordinate project graph changes before consumers run. | Still needs dependency artifacts to compute the plan; an earlier hook does not by itself intercept every later resolver call; may require a two-stage plan and carefully timed file availability. |
| **C. Register `RepositorySessionDecorator` in a core extension** | Maven's [3.9.4 API](https://maven.apache.org/components/ref/3.9.4/maven-core/apidocs/org/apache/maven/project/RepositorySessionDecorator.html) lets an extension customize each project's Resolver session. A composed [Resolver graph transformer](https://maven.apache.org/components/resolver-1.x/apidocs/org/eclipse/aether/collection/DependencyGraphTransformer.html) could enforce the retained inventory on each resolution. If it governs the graph used by `dependency:tree`, that goal can become the effective-dependency view engineers expect. The hook can also snapshot the pre-filter mediated graph and elision outcomes for `mvn-dep-elider:report`. | Requires early-loaded `.mvn/extensions.xml` (or Maven installation/CLI configuration), not just the ordinary plugin; more packaging/bootstrap and reactor state; must preserve Maven mediation and retained descendants; graph transformation semantics for tree output and report snapshot handoff must be proven; Maven itself labels the session decorator API work in progress; Maven 4 compatibility must be verified. |
| **D. Load the plugin as a build extension (`<extensions>true>`)** | Keeps extension declaration in the POM and can reuse the plugin artifact. | Build extensions load later than core extensions; timing may be too late for the resolver component being changed. Must be experimentally proven before selecting. |
| **E. Keep the current behavior and document the boundary** | Avoids architectural and compatibility costs until a consequential consumer is found; lets the examples validate the core product behavior now. | Users that rely on direct-view consumers or fresh resolution may see original dependencies; this remains a known lifecycle limitation rather than a general transparency guarantee. |

---

## 4. Benefits and Costs of Moving Earlier

The main benefit of an earlier resolver integration is to make Maven's ordinary dependency reports and consumers use the effective retained graph, including after Maven resolves dependencies again. Engineers could inspect `dependency:tree` to see which dependencies remain for the project. A future path-aware audit report could explain those decisions by combining saved pre-elision mediated paths with retained/elided status and reasons. The existing `dependency-elider:report` goal reports totals only. This separates an effective inventory from an audit trail without asking one tree to serve both purposes.

The cost is moving from a normal plugin goal to Maven startup infrastructure. A core extension must be loaded before project resolution, persist or reconstruct each project's plan at the correct time, preserve dependency mediation, avoid cross-project state leaks, and support the project's Maven version range. A lifecycle participant alone may run earlier but may not intercept later resolution. A `RepositorySessionDecorator` is the more direct candidate, but its behavior and version compatibility require integration tests.

Do not implement the earlier hook solely to make the state look consistent. First demonstrate an observable failure or establish that the product must guarantee consistency for all Maven consumers. If the only current user-visible paths are the tested classpath and packagers, the extension cost may outweigh a documented limitation.

---

## 5. Evidence Plan and Decision Checkpoints

1. Add a fixture diagnostic that records the Maven-mediated graph, direct and resolved artifact identities, and file hashes immediately before filtering and after each dependency-resolving goal.
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
