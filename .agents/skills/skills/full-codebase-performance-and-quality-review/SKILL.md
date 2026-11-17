---
name: full-codebase-performance-and-quality-review
description: >-
  Perform a comprehensive whole-codebase review for completeness, module-boundary
  seams, code duplication, repeated computation, archaic Java patterns, and
  unnecessary cache/disk re-work instead of passing results forward, combined with
  Java Flight Recorder (JFR) CPU profiling of slow tests.
---

<!-- WHY: Defines a repeatable, evidence-backed full-codebase quality and JFR profiling review across all Maven modules. -->

# Full Codebase Performance and Quality Review

Use this skill when asked to review the **entire codebase** for completeness, duplication, repeated computation, archaic Java idioms, or relying on caches/disk re-reads instead of passing computed results forward, paired with JFR profiling of test execution.

Keep source files unchanged during the review; only apply edits when the user explicitly asks to fix findings.

## 1. Ground Rules and Scope

1. Read `AGENTS.md` and the root `pom.xml` first to confirm JDK targets (JDK 21+), tooling constraints (no Python), and the active `<modules>` list.
2. Cover **all** modules in the reactor (e.g., `elider-core`, `elider-native-image`, `elider-maven-lifecycle`, `dependency-elider-maven-plugin`, `elider-benchmarks`, `examples`), not just recent commits or a single diff.
3. Never report an unverified guess: every finding must cite exact file paths, line ranges, symbol names, and observed behavior from files read or profiler output in the current session.

## 2. Parallel Static Code Review

Spawn read-only `research` subagents in parallel, partitioned by module group (for example: core/native-image/lifecycle libraries in one agent, plugin/mojowiring/benchmarks/examples in another). Instruct each subagent to inspect all five categories below using `rg` and `read_file`:

### A. Completeness and Module-Boundary Seams

- Unused `<dependency>` entries in any module's `pom.xml`.
- Leftover empty stubs/tombstone files or dead forwarding wrappers (methods only called by tests or trivial pass-throughs).
- Duplicated logic split across a module boundary (e.g., `elider-core` vs `elider-native-image` or `elider-maven-lifecycle` vs `dependency-elider-maven-plugin`).
- Unwired capabilities, half-migrated abstractions, or redundant map operations (e.g., `putIfAbsent` immediately followed by `put`).

### B. Code Duplication and Repeated Computation

- Duplicate hashing/digest helpers (e.g., manual `MessageDigest.getInstance("SHA-256")` + `HexFormat` instead of shared `HexDigest`, or computing SHA-256 + SHA-1 when only SHA-256 is consumed).
- Duplicate payload/JSON/XML validation or path-resolution helpers within or across packages.
- Uncompiled `String.matches(...)` in loops or validation helpers instead of precompiled `Pattern`s or shared validators (`HexDigest.isLowercaseHex`, `AsciiBinaryClassName`, etc.).
- Repeated `JarFile` / `ZipFile` opens, archive walks, or ASM `ClassReader` constructions over the same in-memory `byte[]` or file path.

### C. Relying on Cache / Disk / Re-work Instead of Passing Results Forward

- Writing intermediate artifacts or projections to disk and immediately re-opening them with `JarFile` / `Files.read*` instead of passing the already-computed in-memory model forward.
- Computing fingerprints or SHA-256 digests into a local map and discarding it, forcing downstream stages to re-read and re-hash the same files.
- Recomputing environment, policy, pass-through, or duplicate-class plans inside fixed-point loops or across sequential pipeline stages instead of attaching them to the request/context object.
- Deep-copying or re-freezing immutable pools/tables (such as `ClassPool` or JDK class tables) per candidate when an immutable snapshot can be shared or built directly.

### D. Archaic Java Patterns (JDK 21+)

- `Enumeration` + `while (hasMoreElements())` or `Iterator` + `while (hasNext())` over `JarFile`, `ZipFile`, or JSON fields where `stream()` / enhanced-for / `archive.size()` is cleaner.
- Legacy classes such as `java.util.StringTokenizer` instead of `String.split("\\s+")` or `Pattern`.
- Redundant wrapping (`Collections.unmodifiableList(new ArrayList<>(...))`, `Collections.unmodifiableSet(new LinkedHashSet<>(new TreeSet<>(...)))`, `TreeSet` copied into `Set.copyOf(...)` which discards order). Preserve `Collections.unmodifiableList` when `null` elements must be accepted for downstream validation.
- Verbose `instanceof` + cast or chained `if/else` chains where JDK 21 pattern matching or `switch` expressions are clearer.

## 3. JFR CPU Profiling of Slow Tests

Run a Java Flight Recorder (JFR) profile on the slowest unit tests in parallel with the `research` subagents:

1. Identify the slowest Surefire test classes (from recent build logs or a test run).
2. Run Surefire in a single fork with JFR `profile` settings using the repository's JDK 21+ toolchain:

   ```sh
   JAVA_HOME="$PWD/.scratch/toolchains/<jdk>" ./mvnw -pl <module> test \
     -Dtest=<SlowTest1>,<SlowTest2>,... \
     -Dsurefire.forkCount=1 \
     -DargLine="-XX:StartFlightRecording=filename=/tmp/elider-test-profile.jfr,settings=profile,dumponexit=true"
   ```

3. Inspect `/tmp/elider-test-profile.jfr` with `jfr`:

   ```sh
   "$JAVA_HOME/bin/jfr" view hot-methods /tmp/elider-test-profile.jfr | head -n 60
   "$JAVA_HOME/bin/jfr" print --events jdk.ExecutionSample --stack-depth 25 /tmp/elider-test-profile.jfr \
     | grep -E "io\.github\.spockz\.elider\." \
     | sed 's/^[[:space:]]*//' | sort | uniq -c | sort -nr | head -n 45
   ```

4. Cross-reference the top JFR frames (exact sample counts and percentages) with the static review findings to distinguish real CPU/I/O bottlenecks from minor style issues.

## 4. Reporting Format

Organize the final review by impact:

1. **JFR Profiler Hotspots**: Top methods/call stacks with exact sample counts, percentages, and root cause.
2. **Relying on Cache / Disk / Re-computation**: Pipeline stages that discard or re-compute work instead of passing results forward.
3. **Duplication & Unnecessary Computation**: Repeated helpers, unused hash algorithms, and uncompiled regexes.
4. **Completeness & Module-Boundary Seams**: Unused dependencies, stubs, dead wrappers, and cross-module leaks.
5. **Archaic Java Patterns**: JDK 21+ cleanups (noting any intentional constraints such as null-tolerant lists).

Wait for user confirmation before editing files unless the user explicitly asked for fixes up front.
