# Active Work Packages Orchestration Status

* **Work packages**:
  * **WP-RESOLVE-01**: Maven lifecycle & dependency graph consistency (`docs/handovers/2026-10-27-wp-resolve-01-maven-lifecycle-and-graph-consistency.md`).
  * **WP-VEX-01**: Vulnerability assessment, SBOM comparison, OS-cached symbol index, and evidence-gated VEX (`docs/handovers/2026-10-27-wp-vex-01-vulnerability-assessment-and-vex-evidence.md`).
* **Owning session**: Primary coordinating session.
* **Base**: `main` at `c8074ff`.
* **Initial baseline**: clean; `JAVA_HOME=$PWD/.scratch/toolchains/graalvm-jdk-21.0.12+7.1 make check` passed (149 core, 82 plugin tests; static analysis and Markdown lint clean).

---

## 1. WP-RESOLVE-01 Track Ledger

| Track | State | Scope |
| :--- | :--- | :--- |
| Track 1: Maven Lifecycle & Re-Resolution Harness | READY FOR IMPLEMENTATION | Diagnostic test harness proving re-resolution behavior. |
| Track 2: `EliderProjectDependenciesResolver` Decoration | READY FOR IMPLEMENTATION | Post-download Aether result interception and root pruning. |
| Track 3: Direct-View & Graph Handoff Synchronization | READY FOR IMPLEMENTATION | Consistent artifact-view mutation without cache invalidation. |
| Track 4: Reporting and Path Preservation | READY FOR IMPLEMENTATION | Handoff mediated paths to audit report. |
| Track 5: Example Fixtures & Verification Gates | READY FOR IMPLEMENTATION | `dependency:tree` and packaging verification on test examples. |

---

## 2. WP-VEX-01 Track Ledger

| Track | State | Scope |
| :--- | :--- | :--- |
| Track 1: Baseline SBOM Generation & Inventory Model | READY FOR IMPLEMENTATION | Pre-elision baseline SBOM capture alongside post-elision SBOM. |
| Track 2: CVE-to-Symbol Evidence Ingestion Model | READY FOR IMPLEMENTATION | Auto-refreshing OS cache (`~/.cache/...`), 24h TTL, POM overrides, and omitted-code proof engine. |
| Track 3: Decoupled OSV SBOM Comparison Gate | READY FOR IMPLEMENTATION | CI script and Makefile target comparing pre/post elision inventories. |
| Track 4: Evidence-Gated CycloneDX & OpenVEX Generation | READY FOR IMPLEMENTATION | Dual VEX emission, Spring Boot `META-INF/sbom/` and GraalVM staging. |
| Track 5: Reference CVE Fixtures & End-to-End Gates | READY FOR IMPLEMENTATION | End-to-end verification against Logback/Janino and Compress fixtures. |

---

## Architectural Constraints & Invariants

* **Maven Aether types remain in plugin integration**: `elider-core` remains pure Java / Maven-agnostic.
* **Cache locations adhere to OS standards**: Shared cache in standard OS directories (XDG on Linux: `~/.cache/dependency-elider/`, macOS: `~/Library/Caches/...`, Windows: `%LOCALAPPDATA%`) or project `target/`—never `.m2`.
* **Zero Hallucinated VEX**: Strict all-or-nothing policy on mapped symbols + inner classes (`Outer$*`).
* **Zero Build Failure on Outage**: Network failure or cold cache outage falls back to bundled classpath seed catalog (`seed-mappings.json`).
* **Clean Gates**: Every slice must pass `make check` and `make test-examples`.

---

## Track 1 Diagnostic Update

* Implemented the component-level cache-key diagnostic. The test exercises Maven core 3.9.9, the Maven core dependency managed by the root POM; the wrapper CLI version is 3.9.11 and is not the test runtime.
* Focused cache-key Surefire report: `dependency-elider-maven-plugin/target/surefire-reports/TEST-io.github.spockz.elider.plugin.DependencyContextReResolutionTest.xml` (3 tests, no failures/errors). It exercises Maven Core 3.9.9; the wrapper CLI is a separate Maven 3.9.11 runtime.
* Slice 1.2 adds a test-only standalone helper Maven plugin and `pom`-packaging consumer fixture. The test asserts child wrapper Maven 3.9.11, uses an isolated local repository plus generated cached-repository/pluginRepository entries with Maven Central fallback, and writes Maven settings through `XMLStreamWriter`. No helper Mojo enters the published plugin artifact. Helper Mojo sources share the plugin test source set so repository formatting and analysis cover them; the helper POM compiles only that package. Phase TSV paths are Base64-encoded, and child processes are killed on timeout or interruption.
* Focused command passed: `JAVA_HOME=$PWD/.scratch/toolchains/graalvm-jdk-21.0.12+7.1 ./mvnw --batch-mode --no-transfer-progress -pl dependency-elider-maven-plugin -am -Dtest=DependencyContextLifecycleIntegrationTest,DependencyContextReResolutionTest -Dsurefire.failIfNoSpecifiedTests=false test` (4 tests: 1 lifecycle integration, 3 cache-key).
* Measured with per-process `IdentityHashMap` tokens for project, collection, and artifact references: the before and immediate TEST-scope baseline has both direct/resolved coordinates and original paths/hashes. The NONE-scope observer sees the same MavenProject and unchanged direct set, while `getArtifacts()` is empty; the later TEST-scope probe again has both original artifacts. Resolved-only transformation leaves direct membership at two and later retains only the transformed keep JAR. Full transformation prunes the direct set to keep-library; later resolution has only that coordinate at its original repository path/hash. The separate dependency:tree command still reports both declared coordinates. Both original fixture JAR hashes are rechecked after all modes and the tree invocation and remain unchanged.
* The tree process uses `target/lifecycle-probe-evidence/tree/lifecycle-probe/` for its before/immediate snapshots. The focused test byte-compares the earlier resolved-only phase files after this separate process to verify evidence isolation across identity-token namespaces.
* Lifecycle test report: `dependency-elider-maven-plugin/target/surefire-reports/TEST-io.github.spockz.elider.plugin.DependencyContextLifecycleIntegrationTest.xml`; child logs: `dependency-elider-maven-plugin/target/lifecycle-probe-evidence/`; phase snapshots: `dependency-elider-maven-plugin/src/test/fixtures/lifecycle-probe/consumer/target/lifecycle-probe/`.
* Retained gate logs: `target/wp-resolve-slice-1.2-focused.log`, `target/wp-resolve-slice-1.2-lint.log`, `target/wp-resolve-slice-1.2-make-check.log`, and `target/wp-resolve-slice-1.2-test-examples.log`.
* `JAVA_HOME=$PWD/.scratch/toolchains/graalvm-jdk-21.0.12+7.1 MARKDOWNLINT=$PWD/.scratch/tools/node_modules/.bin/markdownlint-cli2 make check` passed: 149 core tests and 86 plugin tests, plus formatting, Checkstyle, PMD, SpotBugs, and Markdown lint.
* `JAVA_HOME=$PWD/.scratch/toolchains/graalvm-jdk-21.0.12+7.1 MARKDOWNLINT=$PWD/.scratch/tools/node_modules/.bin/markdownlint-cli2 make test-examples` passed; lifecycle checks passed for all 4 examples. The repository's example cycle installs the current SNAPSHOT into `/home/node/.m2/repository`; the standalone lifecycle fixture itself used only its isolated repository and file-repository fallback.
* Remaining prerequisites before production resolver integration: real package consumer assertions for this transformed-view behavior, mediated graph/tree result adaptation, retained-descendant cases, and supported-version/reactor compatibility. Never drop a graph subtree solely because its root is unused.
