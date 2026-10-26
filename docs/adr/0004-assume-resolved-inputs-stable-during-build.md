<!-- This ADR records the cache publication contract because concurrent edits during a Maven build are outside the build's determinism guarantee. -->

# ADR 0004: Assume Resolved Inputs Stay Stable During a Maven Invocation

## Status

Accepted

## Context

The elider computes content digests for dependency archives and JDK platform sources used to identify cached results. A reviewer identified a time-of-check/time-of-use race: an input archive could change after its per-artifact publication check while another result is being published. Platform inputs include `ct.sym`, the JDK `release` metadata, and the selected JMOD inventory and files when the JMOD fallback is used.

Preventing every concurrent edit to a local repository or project output during a build would require repeated content checks or a transactional publication mechanism spanning all inputs and outputs. Maven compilation and dependency resolution do not provide a general guarantee that resolved files cannot be modified by another process after resolution. Maven Resolver verifies artifact integrity during resolution, but that check does not lock the artifact for the rest of the invocation.

Concurrent edits to files used by a build make that build nondeterministic regardless of the elider. Protecting against this unsupported condition with repeated full archive digests would add I/O to the common path without making concurrent builds deterministic.

## Decision

Treat resolved dependency inputs and selected JDK platform inputs as stable for the duration of one Maven invocation. Compute and use exact content digests needed for cache identity. For platform inputs, retain normalized source paths, release/source-selection evidence, deterministic JMOD inventory, and SHA-256 identities; platform archive bytes need not be retained in memory. On a cache miss, parse the recorded selected live paths without repeating selection or digest work. Do not rehash inputs at publication time solely to detect concurrent edits. Keep output publication safe against incomplete writes, independently of input stability checks.

If an input changes after identity capture, the current invocation may use a mixture of earlier identity decisions and later live contents; behavior is unsupported and may be nondeterministic. A later invocation recomputes source selection and content digests and therefore will not reuse a result keyed to the prior content.

## Consequences

- The elider avoids repeated reads of every input archive solely for a race that Maven itself does not prevent.
- Builds that concurrently modify resolved archives remain outside the determinism guarantee, as they are for other Maven consumers such as the compiler.
- The cache remains content-addressed: changed content produces a different cache identity on the next invocation.
- The platform identity snapshot stores paths, selection evidence, and digests rather than retaining the selected archive bytes; platform parsing uses the selected live paths under the same invocation-level stability assumption.
- Input stability is an invocation-level assumption; output staging and atomic replacement still protect against exposing partially written trimmed archives.

## References

- [Maven Resolver expected checksums](https://maven.apache.org/resolver/expected-checksums.html)
