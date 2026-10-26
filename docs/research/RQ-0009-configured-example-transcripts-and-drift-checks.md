<!-- WHY: Evaluates generated invocation transcripts as a way to keep documented examples aligned with tested Maven and plugin behavior. -->
# RQ-0009: Configured Example Transcripts and Drift Checks

## Status

Open

## Current boundary

The example reactor executes real Maven packaging and runtime scenarios, while README output and invocation examples are maintained separately. There is no generator/update/check command that captures those configured runs into checked-in documentation. The user-provided reference is [Draft/open PR #651](https://github.com/tetratelabs/built-on-envoy/pull/651). Its proposed pattern describes configured invocations and arguments, local execution, transcript capture, conservative volatile-output normalization, explicit update/check targets, and CI checking. This research note has not established that the PR is merged or independently verified its exact implementation; evaluate the proposal against this repository's needs.

## Research questions

1. Which configured invocations should be documented, including Maven goal, project/profile, plugin version, arguments, toolchain, and relevant environment?
2. Should generated transcripts include full output, conservatively trimmed selected sections, or structured result summaries alongside the captured process exit code?
3. How should volatile output such as timestamps, temporary paths, and environment-specific paths be normalized without hiding meaningful changes in goals, dependencies, warnings, or outcomes?
4. Should the generator run only with locally available dependencies, and how should it report network, repository, tool-version, or environment failures?
5. What should user-facing docs contain, and what generator configuration, normalization rules, and update workflow belong in contributor documentation?

## Options

1. Keep prose and representative command output hand-maintained; continue testing behavior through `make test-examples`.
2. Add declarative invocation configuration and a local update command that executes each invocation and captures output, with a separate check command that compares generated content without rewriting it. Run check mode in CI.
3. Generate only stable structured summaries or selected output blocks, leaving narrative and volatile diagnostics hand-written.

## Benefits and risks

Generated output could keep Maven commands, plugin versions, summaries, and documented outcomes aligned with actual invocations. It can also provide reviewable evidence when plugin behavior changes. It adds build time, local dependency and network requirements, toolchain/version sensitivity, and nondeterminism from timestamps, paths, ordering, and host configuration. Broad output filters can conceal meaningful warnings or behavior changes, while overly narrow filters can make updates noisy and discourage review.

## Evidence gates

- Store each invocation's working directory, executable, arguments, profile/property inputs, expected exit status, and capture target in reviewed configuration.
- Make update mode run locally and show all changed transcript content; make check mode fail on stale output and never rewrite files.
- Test volatile-output normalization with known path/time examples and prove that changed dependency versions, warnings, exit codes, and result lines remain detectable.
- Run the check target in CI with explicit Maven/JDK versions and document whether dependency resolution is offline, cached, or network-dependent. Preserve command failure details rather than converting unavailable runs into empty output.
- Keep user docs focused on supported commands and outcomes; put configuration schema, filtering rules, and regeneration instructions in contributor docs.

## Decision requested

Determine whether reproducible captured output is valuable enough to justify maintaining invocation configuration and normalization. If adopted, keep generation/update explicit, checking nonmutating, filters narrow and tested, and generated evidence tied to the exact tested toolchain and invocation.
