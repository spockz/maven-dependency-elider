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

Direct BOM-managed Commons Codec replaces `spring-boot-starter-mail` as the unused Spring Boot
candidate. A baseline trace showed that Boot's mail auto-configuration loads mail API classes,
including when the app does not send mail, so removing those mail libraries would not be supported
by the trace. The current fixture demonstrates removal of an unused BOM-managed library from the
Boot archive while preserving endpoint behavior. It does not establish unused-starter removal.

The `elision-test` profile is activated by `-Delide.skip=false`; default example builds therefore
do not need the unpublished plugin installed. The test runner installs it before elision builds.
Shade signature metadata is excluded from fat JARs so runtime verification remains valid after
repacking signed dependencies. Failed test runs preserve their traces and archive listings in the
reported temporary evidence directory.

## Verification

- `make test-examples` — passed all four fixtures, baseline and elided package checks, classpath
  assertions, and packaged runtime checks.
- Root `make check` after `mvnd clean` — passed formatting, Checkstyle, PMD, SpotBugs, Markdown
  lint, and core/plugin tests. The repository's `make tools` target installed Markdown lint locally.
- `git diff --check` — passed.
- Independent Track 8 review — approved. The reviewer verified the final archive contents and
  Surefire results (two tests per fixture in elided mode).

OSV-Scanner was not run by this receipt; CVE scanner outcomes remain documented expectations, not
verified results.
