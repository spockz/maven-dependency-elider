<!-- WHY: Records the bounded integration review and root verification for approved follow-ups. -->
# Closeout Integration Review

Status: APPROVED for bounded session closeout.

Final source integration: `main` at
`efd5a265c1cc44b72cf813c30424e4b0978816b2`, with a clean working tree at review.
No unresolved integration blockers remain. This approval covers the current
whole-artifact implementation and evidence/report follow-ups; it does not mark
the original RQ-0004 plan complete.

Reviewed approved branch implementations: telemetry `eeee4a8`/`fa8093b`,
classifier `7a04b8e`, plugin `869a516`/`29adc6d`, and reference applications
`df30d24`/`976a3a2`/`51e2224`, together with existing review receipts, then checked
their rebased final root integration. No implementation blocker was found in the
evidence-classification integration.

## Compiler verification gap, resolved

The reference runner proves retained application code compiles, removed classes
are absent from Surefire's runtime classpath, removed entries are absent from
packages, and packaged applications run. These observations do not prove removed
dependencies are absent from javac's compile classpath. The existing plugin
architecture receipt explicitly requires a negative source-compilation probe.

Commit `efd5a26` resolves this gap in the existing runner. It uses a temporary
basic-fixture copy with a main-source reference to Commons Codec `Hex` and the
unchanged baseline trace stored outside `target`. An active-elision `clean compile`
must fail with the compiler's missing-package diagnostic; the same source must
compile successfully with elision skipped and produce the probe class. A generic
build failure cannot satisfy the assertion. The unchanged trace is explicitly
checked for absence of Commons Codec observations.

The rebased approved implementation commits are scanner `74b6f3f`, classifier
`b1227de`, elide `642b15d`, report `ce1a73d`, lifecycle `732d37e`, usage evidence
`99a64b2`, receipt `1b47e7b`, and compiler proof `efd5a26`. Branch `make check` and
`make test-examples` passed according to the implementer receipts relayed by the
integrator. Final root checks also passed, as recorded below. The dedicated Track 8
reviewer approved the compiler probe.

## Integration invariants checked

- Production bytecode evidence feeds only `ClassUsageReport`; `DependencyPruner`
  still receives the runtime trace and retains whole observed JARs.
- Missing static evidence produces unknown classifications and null report
  fields. Explicit invalid production output fails rather than reporting absence.
- The report retains the distinction between application references with and
  without runtime observation. Runtime-only evidence makes no causal claim.
- The Spring runner preserves production bytecode, traces, and baseline mail JAR
  bytes outside `target` before the active `clean verify` build.
- Report checks require every observed Jakarta/Angus Mail class in the runtime-only
  group, no mail application reference, and Commons Codec `Hex` in the neither group.
- Final nested mail JAR names, SHA-256 digests, and bytes must equal baseline.
  This verifies whole-JAR retention; intra-JAR slicing remains deferred.

## Combined root verification

- Clean: passed, exit 0, 1.130 seconds.
- Repository formatting and `make check`: passed, exit 0, 21.305 seconds. The log
  shows formatting, Java analyzers, Markdown lint with zero issues, and core/plugin
  tests.
- `make test-examples`: passed, exit 0, 16.551 seconds. Its log confirms the compiler
  negative/control probe and all four fixture cycles completed. The runner requires
  baseline and active builds, Surefire assertions, archive/report/mail-JAR checks,
  and packaged runtime/HTTP checks.
- `git diff --check`: passed during final review; working tree was clean.
- README and plugin usage agree on enabled whole-artifact `elide`, report-only
  bytecode evidence, and deferred intra-JAR slicing. The closeout handover draft
  preserves the original plan's outstanding work and verification limits.

Reviewed evidence: `.scratch/closeout-verification.json`,
`.scratch/closeout-integrated-check.log`, and
`.scratch/closeout-integrated-examples.log`. Execution used the selected GraalVM
JDK 25.0.5 and Maven Daemon 1.0.6 with embedded Maven 3.9.16. Subsequent changes are
limited to durable documentation/log preservation and must receive the integrator's
final `make check`; source changes require renewed review.

## Remaining original-plan work

Maven plugin cache integration and lifecycle overhead proof, provenance emission,
Maven 4 compatibility, and CVE scanner outcomes remain incomplete or unverified.
Source-aware/intra-JAR trimming remains explicitly deferred. These are recorded
scope boundaries, not blockers for this bounded session closeout.
