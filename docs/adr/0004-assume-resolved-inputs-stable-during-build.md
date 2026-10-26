<!-- This ADR records the cache publication contract because concurrent edits during a Maven build are outside the build's determinism guarantee. -->

# ADR 0004: Assume Resolved Inputs Stay Stable During a Maven Invocation

## Status

Accepted

## Context

The elider computes a content digest for each input archive to identify the archive content and its cached trimmed result. A reviewer identified a time-of-check/time-of-use race: an input archive could change after its per-artifact publication check while another result is being published.

Preventing every concurrent edit to a local repository or project output during a build would require repeated content checks or a transactional publication mechanism spanning all inputs and outputs. Maven compilation and dependency resolution do not provide a general guarantee that resolved files cannot be modified by another process after resolution. Maven Resolver verifies artifact integrity during resolution, but that check does not lock the artifact for the rest of the invocation.

Concurrent edits to files used by a build make that build nondeterministic regardless of the elider. Protecting against this unsupported condition with repeated full archive digests would add I/O to the common path without making concurrent builds deterministic.

## Decision

Treat resolved input files as stable for the duration of one Maven invocation. Compute and use the content digest needed for cache identity, but do not rehash all inputs at publication time solely to detect concurrent edits. Keep output publication safe against incomplete writes, independently of input stability checks.

If an input changes after its digest is calculated, the current invocation may use results based on the earlier contents. A later invocation computes the new content digest and therefore will not reuse a result keyed to the old content.

## Consequences

- The elider avoids repeated reads of every input archive solely for a race that Maven itself does not prevent.
- Builds that concurrently modify resolved archives remain outside the determinism guarantee, as they are for other Maven consumers such as the compiler.
- The cache remains content-addressed: changed content produces a different cache identity on the next invocation.
- Input stability is an invocation-level assumption; output staging and atomic replacement still protect against exposing partially written trimmed archives.

## References

- [Maven Resolver expected checksums](https://maven.apache.org/resolver/expected-checksums.html)
