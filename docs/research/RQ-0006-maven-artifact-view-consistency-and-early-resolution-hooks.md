<!-- WHY: Investigates whether Maven consumers can observe inconsistent direct and resolved dependency views after elision, and whether earlier resolver hooks justify their lifecycle cost. -->
# RQ-0006: Maven Artifact-View Consistency and Early Resolution Hooks

* **Status**: Open
* **Category**: Maven Lifecycle & Resolver Integration
* **Date**: 2026-10-25
* **Last Updated**: 2026-10-25

Abbreviations: Abstract Syntax Tree (AST), Build Extension (BE), Core Extension (CE), Dependency Elision (DE), Project Object Model (POM), Repository Session Decorator (RSD), Software Bill of Materials (SBOM).

---

## 1. Context & Research Questions

The `elide` mojo runs during `INITIALIZE`. It can update the resolved artifact view used by standard classpaths and packagers, and point retained artifact objects at trimmed JARs. Maven also exposes a direct-dependency view. Keeping both views consistent is the documented contract, but an experiment found that changing the direct-artifact set causes Maven to resolve the POM graph again for later dependency-resolving goals. That resolution can restore original artifacts and file paths. Leaving the direct set unchanged avoids that same-session re-resolution in the tested Maven context, but then a direct-view consumer can still observe an elided dependency.

The immediate product objective is to make the Basic and Spring Boot examples trim, package, and run. The lifecycle integration question is separate: does an inconsistent view break a real downstream consumer or produce an incorrect build result often enough to justify an earlier Maven extension point?

### Primary Research Questions

* **RQ-0006.1**: Which downstream Maven goals read the direct dependency view, the resolved dependency view, or trigger a fresh resolution after `INITIALIZE`?
* **RQ-0006.2**: Can a same-session build produce a demonstrable failure or wrong result when the direct and resolved views differ, beyond a mismatch in diagnostic output?
* **RQ-0006.3**: Does pruning both views at `INITIALIZE` cause Maven to restore the original graph or artifact paths before compilation or packaging? Which lifecycle transitions trigger that behavior?
* **RQ-0006.4**: If a concrete failure warrants earlier integration, which public extension point provides stable per-project redirection and filtering across repeated resolution, reactor projects, and supported Maven versions?
* **RQ-0006.5**: If no consequential consumer failure is found, can the current simpler behavior remain with the limitation clearly documented and surfaced?

---

## 2. Current Evidence

### 2.1 Basic Fixture

In the Basic example on Maven 3.9.11, replacing the resolved/project artifact views while leaving the original direct-artifact set unchanged allowed the standard `maven-dependency-plugin:build-classpath` probe and Maven Shade to consume the trimmed Commons Compress JAR and omit Commons Codec. The shaded application ran successfully. Commons Compress shrank from 1,117,221 bytes to 110,843 bytes; the shaded JAR shrank from 2,738,745 bytes to 1,360,150 bytes.

This proves the resolved-view path for those two tested consumers in one Maven session. It also exposes an actual model mismatch: Commons Codec remains in the project's direct dependency view while being absent from the resolved classpath and shaded package. No downstream goal that fails because it reads the direct view has been identified yet.

### 2.2 Re-resolution When Both Views Are Pruned

An earlier Basic fixture run updated the direct and resolved sets consistently. A later `prepare-package` classpath probe and Shade still received the original Commons Compress and Commons Codec repository paths. Maven 3.9.11's `org.apache.maven.lifecycle.internal.DependencyContext` uses the dependency-artifact set's identity and size when deciding whether its cached resolution remains current. Replacing that set invalidated the cache. The resolver then resolved from the POM graph and repopulated original artifacts.

This is a reproducible lifecycle failure for the transparent-trimming goal: consistent mutation at `INITIALIZE` did not persist through the tested later resolver invocation. It did not break application execution, but it silently lost the requested artifact reduction in the package. The current workaround restores correct bytes for the two tested packaging consumers by retaining the direct set, at the cost of direct/resolved view consistency.

### 2.3 Known Unknowns

No specific plugin has yet been shown to produce an incorrect application result by consuming `getDependencyArtifacts()` while packaging uses `getArtifacts()`. Maven dependency reports, direct-dependency analysis, publication, vulnerability reports, repeated goals, separate task segments, and fresh resolver calls remain candidates to investigate. A discrepancy in a report may be acceptable if that report intentionally describes the declared POM graph; the research must distinguish declared-dependency reporting from claims about the actual packaged classpath.

---

## 3. Integration Options

| Option | Benefits | Drawbacks / risks |
| :--- | :--- | :--- |
| **A. Keep the `INITIALIZE` mojo mutation** | Smallest implementation; ordinary plugin configuration; no startup extension; already produces correct Basic classpath and Shade bytes in the tested Maven session. | Direct and resolved views can disagree; fully pruning both views triggers re-resolution in the tested lifecycle; behavior may depend on which Maven goals execute next. |
| **B. Bind a lifecycle participant earlier through a Maven core extension** | Runs before regular project goals and can prepare state for the session; can potentially coordinate project graph changes before consumers run. | Still needs dependency artifacts to compute the plan; an earlier hook does not by itself intercept every later resolver call; may require a two-stage plan and carefully timed file availability. |
| **C. Register `RepositorySessionDecorator` in a core extension** | Public Maven 3 API is called when Maven prepares a project resolver session; a per-project workspace reader can map coordinates to trimmed files, while graph transformation can enforce the retained inventory on each resolution. This directly addresses pointer clearing and repeat resolution. | Requires early-loaded `.mvn/extensions.xml` (or Maven installation/CLI configuration), not just the ordinary plugin; more packaging/bootstrap and reactor state; must preserve Maven mediation and retained descendants; Maven documents the SPI as work in progress; Maven 4 compatibility must be verified. |
| **D. Load the plugin as a build extension (`<extensions>true>`)** | Keeps extension declaration in the POM and can reuse the plugin artifact. | Build extensions load later than core extensions; timing may be too late for the resolver component being changed. Must be experimentally proven before selecting. |
| **E. Keep the current behavior and document the boundary** | Avoids architectural and compatibility costs until a consequential consumer is found; lets the examples validate the core product behavior now. | Users that rely on direct-view consumers or fresh resolution may see original dependencies; this remains a known lifecycle limitation rather than a general transparency guarantee. |

---

## 4. Benefits and Costs of Moving Earlier

The main benefit of an earlier resolver integration is not merely satisfying an ADR. It can make each Maven consumer receive one coherent retained graph and artifact mapping, including after Maven clears file pointers and resolves dependencies again. That can prevent packages, reports, or later tasks from disagreeing about which dependencies remain.

The cost is moving from a normal plugin goal to Maven startup infrastructure. A core extension must be loaded before project resolution, persist or reconstruct each project's plan at the correct time, preserve dependency mediation, avoid cross-project state leaks, and support the project's Maven version range. A lifecycle participant alone may run earlier but may not intercept later resolution. A `RepositorySessionDecorator` is the more direct candidate, but its behavior and version compatibility require integration tests.

Do not implement the earlier hook solely to make the state look consistent. First demonstrate an observable failure or establish that the product must guarantee consistency for all Maven consumers. If the only current user-visible paths are the tested classpath and packagers, the extension cost may outweigh a documented limitation.

---

## 5. Evidence Plan and Decision Checkpoints

1. Add a fixture diagnostic that records both direct and resolved artifact identities and file hashes immediately after `INITIALIZE` and after each dependency-resolving goal.
2. Compare both-view mutation with resolved-view-only mutation across `maven-compiler-plugin`, `maven-dependency-plugin` classpath/tree/copy goals, Surefire, Shade, and Spring Boot repackage. Capture the actual POM graph, effective classpaths, package entries, and hashes.
3. Repeat selected goals in a separate Maven task segment and a fresh Maven invocation. Include a direct dependency, a transitive dependency with a retained child, and an artifact whose file pointer is trimmed.
4. Identify whether any direct-view mismatch changes compilation, runtime contents, SBOM meaning, dependency reports, or publication output. Separate intended declared-graph reporting from accidental resurrection of original packaged bytes.
5. Prototype the core-extension option only against a reproduced failure or an explicit product requirement. Verify session-decorator invocation, workspace lookup, graph filtering, repeated resolution, reactor isolation, and the supported Maven 3/Maven 4 range.

### Decision Checkpoints

* [ ] **Checkpoint 1 (Concrete Consumer)**: Identify at least one downstream consumer whose result is wrong or misleading because it reads the view elision did not update.
* [ ] **Checkpoint 2 (Resolution Persistence)**: Establish which lifecycle transitions restore original artifacts after consistent `INITIALIZE` mutation.
* [ ] **Checkpoint 3 (Earlier Hook Tradeoff)**: Compare the minimal lifecycle mutation with an early resolver hook using the same fixture and verification artifacts.
* [ ] **Checkpoint 4 (Adopt or Document)**: Implement an earlier hook only if the reproduced impact or product guarantee justifies its costs; otherwise document the limitation, affected Maven usage, and mitigation.
