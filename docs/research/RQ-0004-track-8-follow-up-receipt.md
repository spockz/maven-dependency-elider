# RQ-0004 Track 8 Follow-Up Receipt

## Scope

Track 8 now has a repeatable Maven lifecycle path for `example-basic-app`,
`example-spring-boot-app`, `example-cve-unused-app`, and
`example-cve-safe-class-app`. The two CVE fixtures remain outside the default reactor.

`make test-examples` installs the local plugin, packages each fixture with elision skipped,
runs it with class-load logging into a temporary directory outside `target`, then invokes Maven
again with `clean verify`, explicit trace paths, and elision enabled. Surefire checks the resolved
test classpath; the runner checks baseline and final archive contents and launches the packaged
applications. The Spring Boot fixture is exercised through `GET /api/hello`.

The Spring Boot fixture declares unused BOM-managed Commons Codec and `spring-boot-starter-mail`.
Its baseline class-load trace observes mail classes, while the copied production application
bytecode contains no direct mail references. The test passes that baseline output to the active
build with `-Delide.productionOutput` and directs the JSON report outside `target`. Assertions
require observed mail classes in `runtimeObservedWithoutApplicationReference`, Commons Codec's
`Hex` class in `neitherReferencedNorObserved`, and the complete Spring mail runtime artifacts in
the final Boot JAR. The runner preserves the baseline nested mail JAR bytes before the active
`clean` and compares both names and SHA-256 digests afterward. This does not establish why mail
classes were loaded. The endpoint is still verified over HTTP, and Commons Codec is removed from
the final archive.

The `elision-test` profile is activated by `-Delide.skip=false`; default example builds therefore
do not need the unpublished plugin installed. The test runner installs it before elision builds.
Shade signature metadata is excluded from fat JARs so runtime verification remains valid after
repacking signed dependencies. Failed test runs preserve their traces and archive listings in the
reported temporary evidence directory.

## Verification

- `make test-examples` — passed all four fixtures, baseline and elided package checks, classpath
  assertions, class usage report checks, and packaged runtime checks. Each baseline and elided
  build passed 9 Surefire tests: 2 basic, 3 Spring Boot, and 2 in each CVE fixture.
- `make check` — passed with exit code 0 after the Track 5 rebase and documentation updates,
  including Java lint, SpotBugs, Markdown lint, 88 core tests, and 27 plugin tests.
- Root `make check` after `mvnd clean` — passed formatting, Checkstyle, PMD, SpotBugs, Markdown
  lint, and core/plugin tests. The repository's `make tools` target installed Markdown lint locally.
- `git diff --check` — passed.
- Independent Track 8 review — approved. The reviewer verified the final archive contents and
  Surefire results (two tests per fixture in elided mode).

OSV-Scanner was not run by this receipt; CVE scanner outcomes remain documented expectations, not
verified results.

## Usage Evidence Classification Follow-Up

Track 8 follow-up commit: `976a3a23109fd7793f7d9dc0ed5b713ab70dc8b0`, rebased on Track 5 report
commit `29adc6d02718c63b1adceee13ddb68a5fac4390a`. The independent Track 8 reviewer approved the
final evidence checks after confirming mail classification, exact nested-JAR integrity, and
acceptance checklist consistency.

Track 5 added production bytecode scanning and the class usage JSON report in commit `29adc6d`.
Track 8 now supplies the preserved Spring production output and class-load trace to that report,
and checks the result in the packaged fixture lifecycle.

The report distinguishes application-bytecode referenced; runtime-observed without an application
bytecode reference; and neither referenced nor observed. It keeps unknown static evidence distinct
when a production-class scan is unavailable or incomplete. Runtime-only evidence does not prove
framework causation, and neither-evidence classification does not prove universal unreachability.
The classification is report-only: runtime-observed classes continue to retain their complete
dependency JARs, with no intra-JAR deletion.
