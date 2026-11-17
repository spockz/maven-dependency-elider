<!-- This ADR records the cache publication contract because concurrent edits during a Maven build are outside the build's determinism guarantee. -->

# ADR 0004: Assume Resolved Inputs Stay Stable During a Maven Invocation

## Status

Accepted

## Context

The elider computes content digests for dependency archives and JDK platform sources used to identify cached results. A reviewer identified a time-of-check/time-of-use race: an input archive could change after its per-artifact publication check while another result is being published. The earlier archive-based platform implementation used `ct.sym`, JDK `release` metadata, and a selected JMOD inventory when that fallback was used. Those are historical implementation details; [ADR-0013](0013-compiler-decoupling-multi-jdk-portability-and-report-driven-liveness.md) defines the current platform snapshot contract.

Preventing every concurrent edit to a local repository or project output during a build would require repeated content checks or a transactional publication mechanism spanning all inputs and outputs. Maven compilation and dependency resolution do not provide a general guarantee that resolved files cannot be modified by another process after resolution. Maven Resolver verifies artifact integrity during resolution, but that check does not lock the artifact for the rest of the invocation.

Concurrent edits to files used by a build make that build nondeterministic regardless of the elider. Protecting against this unsupported condition with repeated full archive digests would add I/O to the common path without making concurrent builds deterministic.

## Decision

Treat resolved dependency inputs as stable for the duration of one Maven invocation. For current JDK platform identity, capture the active runtime's standard-module snapshot once per analysis context as specified in [ADR-0013](0013-compiler-decoupling-multi-jdk-portability-and-report-driven-liveness.md), and materialize isolated JDK class tables from those parsed templates. Do not rehash inputs at publication time solely to detect concurrent edits. Keep output publication safe against incomplete writes, independently of input stability checks.

Earlier statements in this ADR about normalized platform source paths, release/source-selection evidence, JMOD inventories, and `ct.sym` reads describe the replaced archive-based design. They are not current requirements; see [ADR-0013](0013-compiler-decoupling-multi-jdk-portability-and-report-driven-liveness.md). The configured target release remains a separate responsibility and does not select a historical JDK class table.

If an input changes after identity capture, the current invocation may use a mixture of earlier identity decisions and later live contents; behavior is unsupported and may be nondeterministic. A later invocation recomputes source selection and content digests and therefore will not reuse a result keyed to the prior content.

## Consequences

- The elider avoids repeated reads of every input archive solely for a race that Maven itself does not prevent.
- Builds that concurrently modify resolved archives remain outside the determinism guarantee, as they are for other Maven consumers such as the compiler.
- The cache remains content-addressed: changed content produces a different cache identity on the next invocation.
- The active-runtime identity snapshot is reused across the analysis context while each consumer receives an isolated JDK class table ([ADR-0013](0013-compiler-decoupling-multi-jdk-portability-and-report-driven-liveness.md)).
- Input stability is an invocation-level assumption; output staging and atomic replacement still protect against exposing partially written trimmed archives.

## References

- [Maven Resolver expected checksums](https://maven.apache.org/resolver/expected-checksums.html)
