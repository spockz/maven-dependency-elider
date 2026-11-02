<!-- WHY: Defines repository-wide requirements for persisted formats, tooling, test efficiency, and generated examples. -->
# Repository Agent Instructions

## Persisted formats and protocols

- Keep plugin release versions separate from schema or protocol versions for persisted data.
- While a format has not been published in a `maven-dependency-elider` release, evolve it without incrementing its schema or protocol version. Keep each current unreleased format at version 1.
- Once a released format is changed, increment that format's version before releasing the change. Version each persisted format independently.
- Do not add compatibility aliases or migrations for unreleased draft formats. Reject malformed or incompatible payloads explicitly.
- Update the format's writer, reader, validator, fixtures, and documentation together. Document any compatibility or migration promise in an ADR before making it.

## Tooling and implementation languages

- Do not use Python in this project. Node.js is permitted for the existing verification tooling: `markdownlint-cli2` via `make tools` and `make lint-markdown`, and `scripts/compare-sbom-inventories.js` plus its test via `make scan-sbom` and `make test-sbom-comparison`.
- Tooling should stick to shell when simple and orchestrating commands, be implemented as part of Java unit/integration tests, or be built as a Go program.
- Tooling such as applicable Java versions can be found in `.scratch/toolchains` of the main clone/worktree.

## Test efficiency and assertion coverage

- Minimize test runtime while preserving every distinct scenario, behavioral coverage, assertion strength, and useful failure diagnostics.
- Share expensive fixture construction, setup, and production execution across as many compatible assertions as possible. Reuse immutable fixtures and read-only results; retain separate executions when the scenario's inputs, lifecycle, isolation, or behavior require them.
- Aggregate independent assertions about a shared scenario so one failure does not suppress the rest and collected failures fail the test. In Java, use JUnit `assertAll` with a separate executable for each independent assertion or a nested `assertAll` for a group. Multiple sequential assertions inside one executable still stop at its first failure.
- Add assertion failure messages or group headings when they explain the invariant, why values must agree, or scenario context not evident from the assertion and test name. Omit messages that merely restate the comparison or repeat expected/actual values. Use JUnit message arguments and `assertAll` headings, or AssertJ `.as(...)` before the assertion, preserving the framework's expected/actual diagnostics. Use lazy message/description suppliers when constructing diagnostic text is expensive.
- Scope prerequisite checks and potentially failing result extraction to their dependent assertion group. A failed prerequisite must be reported and may stop dependent checks, while unrelated groups continue. Check for setup or argument evaluation outside assertion aggregation that could prevent otherwise independent observations from running.
- Keep shared fixtures immutable or give each mutating scenario an isolated copy. Preserve valid resource lifetimes, cleanup, repeatability, and independence from test order and concurrent execution.
- Evaluate test optimizations with comparable timings and preserved scenario/assertion coverage, accounting for their effect on parallel execution. Fewer test methods or a shared setup helper alone do not establish less runtime work.

## Generated command examples

- When a change affects an example fixture, its documented Maven command, or the output shown in README or plugin usage, refresh the generated examples with `make update-transcripts` (`go run scripts/update-transcripts.go --update`) before wrapping up.
- Review and include the generated documentation changes. Do not hand-edit content inside transcript marker blocks; update the manifest or fixture setup, then regenerate with `make update-transcripts`.
- Use `make check-transcripts` to check for drift without rewriting documentation.
