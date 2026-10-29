<!-- WHY: Evaluates generated invocation transcripts as a way to keep documented examples aligned with tested Maven and plugin behavior. -->
# RQ-0009: Configured Example Transcripts and Drift Checks

## Status

Open: implementation is in place; cold-cache/network behavior and repeated CI-run evidence remain to be recorded.

## Current boundary

The example reactor executes real Maven packaging and runtime scenarios. Configured transcripts are declared in [`scripts/transcripts-manifest.json`](../../scripts/transcripts-manifest.json) and maintained by [`scripts/update-transcripts.go`](../../scripts/update-transcripts.go). `make update-transcripts` explicitly updates marked README and plugin usage regions; `make check-transcripts` regenerates them and reports drift without writing documentation. The check still runs Maven preparation and goals: `target` outputs, the local Maven repository, and ignored `.scratch` evidence/report files may change. Dependencies can require configured remote repositories when absent from the local cache, and failures include captured process output.

The repository forbids new Node.js and Python tooling, so the runner uses only the Go standard library. Its setup script packages the checked-in fixtures with `-Dmaven.test.skip=true`, captures class-load traces, and produces elision snapshots without invoking test goals. It pins two deliberately incomplete vulnerability mappings in a copied fixture cache and uses Maven offline mode for analysis and elision, while baseline dependency provisioning may use configured repositories. Each CVE-bearing analysis/report invocation requires its expected CVE ID in captured output. The report transcript keeps three mediated-graph rows and marks omitted rows with a count and SHA-256 digest. The displayed `report` command reruns the full graph without transcript elision; a dedicated expansion target remains open/deferred. The runner preserves warnings, errors, and other goal output, removing only known Maven scan/build boilerplate. It normalizes only the exact `Snapshot: last successful elide run at`, Maven `Total time` and `Finished at`, PID fields, repository-root and generated-evidence paths, and trailing whitespace; path suffixes and unrelated timestamp/temp-path values remain visible. `make check` runs transcript checking after its parallel Maven checks to avoid concurrent writes to fixture targets.

The user-provided reference is [Draft/open PR #651](https://github.com/tetratelabs/built-on-envoy/pull/651). Its exact implementation has not been independently verified; the local runner adopts the configured invocation, explicit update/check, and CI gate pattern with repository-specific constraints.

## Research questions

1. Which configured invocations should be documented, including Maven goal, project/profile, plugin version, arguments, toolchain, and relevant environment?
2. Is retaining all plugin-goal output with only Maven boilerplate removal the right balance, given that only report graph rows are elided?
3. Are normalization of the exact snapshot timestamp, Maven `Total time` and `Finished at`, PID fields, repository/evidence paths, and trailing whitespace sufficiently narrow across supported CI/local environments?
4. Should the generator require a warm local Maven repository, or should CI explicitly prefetch dependencies? The current setup fails with full command output if Maven cannot resolve inputs.
5. Should a dedicated expansion target be added when rerunning the displayed report command already prints the full graph?

## Options

1. Keep prose and representative command output hand-maintained; exercise example behavior separately.
2. Add declarative invocation configuration and explicit update/check modes; **selected** with a Go standard-library runner and a serial `make check` gate.
3. Generate only structured summaries or selected output blocks, leaving diagnostics hand-written; not selected because it could hide new plugin output.

## Benefits and risks

Generated output could keep Maven commands, plugin versions, summaries, and documented outcomes aligned with actual invocations. It can also provide reviewable evidence when plugin behavior changes. It adds build time, local dependency and network requirements, toolchain/version sensitivity, and nondeterminism from timestamps, paths, ordering, and host configuration. Broad output filters can conceal meaningful warnings or behavior changes, while overly narrow filters can make updates noisy and discourage review.

## Evidence gates

- The manifest records each invocation's working directory, executable, arguments, expected exit status, goal, target document, and output elision limit.
- Update mode prints changed transcript content before writing; check mode compares without writing documentation and fails when stale.
- Omitted report graph rows contribute to a digest so any hidden-row change affects the generated block. Warnings, errors, shown dependency versions, result lines, and process exit status remain observable.
- The full `report` goal prints the unelided graph, so the command shown in the transcript is the current expansion path. A dedicated graph expansion target is deferred unless review demonstrates a need.
- CI uses Java 21, Go 1.24.4, and the Maven wrapper. Cold dependency resolution may contact configured repositories; failures remain visible rather than becoming empty transcripts.
- The first local generation attempt reached the CVE analysis goal and failed because its trim configuration lacked the fixture's Spring and Micrometer `trimSkipArtifacts` set. After aligning that configuration and pinning the cache, `make update-transcripts` completed locally on Java 21 and refreshed the README and plugin usage regions. The test-free setup verified the Spring `/api/hello` endpoint before accepting its runtime trace.
- User docs focus on supported commands/outcomes. Contributor docs explain the manifest, markers/placeholders, normalization, graph elision, pinned cache limitations, update/check usage, and Maven side effects.
- Tests were not added or run in this session. Static Go, shell, JSON, whitespace, and Markdown checks passed. The non-writing check mode, cold dependency resolution, and repeated CI runs remain open evidence gates.

## Decision requested

The repository has adopted reproducible captured output and explicit update/check modes. Remaining research concerns dependency provisioning, cross-environment repeatability, and whether review will justify a dedicated graph expansion target beyond rerunning the displayed report goal. Keep the check non-mutating with respect to checked-in documentation, preserve command failures, and tie each transcript to its exact configured invocation.
