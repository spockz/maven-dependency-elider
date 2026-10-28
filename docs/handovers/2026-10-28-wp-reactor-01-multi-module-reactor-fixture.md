<!-- WHY: Defines engineering work package WP-REACTOR-01 for verifying multi-module Maven reactor elision and multi-threaded execution. -->
# WP-REACTOR-01: Multi-Module Reactor Fixture and Concurrency Verification

## Status

Approved for Implementation

## Context

ADR-0001 and ADR-0002 establish single-project CLI 3.9.11 verification while noting that multi-module consumer reactors remain unverified.
[RQ-0012](../research/RQ-0012-multi-module-reactor-elision-and-concurrency.md) investigates reactor state coordination, inter-module dependency resolution, and multi-threaded Maven builder (`mvn -T`) execution.

## Objective

Deliver `examples/example-multi-module-reactor`:

1. Aggregator parent POM with three modules:
   - `reactor-common`: Shared utility library declaring an unused external dependency (e.g. `commons-codec`) and a trimmed dependency (`commons-compress`).
   - `reactor-service`: Middleware module depending on `reactor-common`.
   - `reactor-app`: Application module packaging an executable fat JAR with Maven Shade Plugin.
2. Verify both single-threaded (`mvn clean verify`) and multi-threaded (`mvn -T 4 clean verify`) builds.
3. Validate that each module produces independent, valid schema-1 `dependency-elider-report.json` snapshots.
4. Integrate into `examples/run-elision-cycle.sh` and root `Makefile`.

## Invariants & Guardrails

- **Zero ~/.m2 Cache Pollution**: All generated/trimmed archives and caches reside strictly in module `target/` directories or standard OS user cache directories.
- **Fail-Closed Snapshot Integrity**: Module snapshots must strictly conform to schema version 1.
- **Deterministic Reporting**: Inter-module trimming must yield deterministic byte and class counts regardless of thread scheduling.
