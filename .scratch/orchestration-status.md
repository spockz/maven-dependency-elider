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
