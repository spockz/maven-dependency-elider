<!-- WHY: Defines the work package specification, track decomposition, and committable slices for automated command transcript capture and README documentation drift enforcement (RQ-0009). -->
# Work Package Handover: WP-TRANSCRIPT-01 Automated Command Transcripts and Documentation Drift

* **Status**: Ready for Implementation
* **Owning Thread / Session**: Primary Coordinating Session
* **Date**: 2026-10-28
* **Target Branch / Base**: `main`
* **Related Research Questions**:
  * [RQ-0009: Configured Example Transcripts and Drift Checks](../research/RQ-0009-configured-example-transcripts-and-drift-checks.md)
  * [RQ-0004: Maven Dependency Elider Engine and Plugin Implementation Handover](../research/RQ-0004-maven-dependency-elider-implementation-handover.md)
  * [RQ-0007: Maven Plugin Documentation Site and GitHub Pages Publishing](../research/RQ-0007-maven-plugin-site-and-github-pages.md)
* **Related Architecture Decisions**:
  * [ADR-0005: Versioning Released Persisted Formats](../adr/0005-released-format-versioning.md)

---

## 1. Executive Summary & Non-Negotiable Invariants

### 1.1 Objective

Eliminate manual copying and drift between documented CLI outputs and actual plugin execution. Implement a deterministic, automated transcript generator that executes configured Maven goals—with special emphasis on the non-mutating `analyze` goal alongside `report` and `elide`—normalizes volatile elements (timestamps, temporary directory paths, elapsed wall-clock times), injects the output into delimited blocks in `README.md` and documentation markdown, and enforces non-mutating drift checking in CI (`make check`).

### 1.2 Non-Negotiable Invariants

1. **Non-Mutating Check Gate Invariant**: `make check-transcripts` (or `make check-drift`) must **never** modify files. It executes the configured invocations, normalizes the outputs, compares them against checked-in documentation files, and exits with a non-zero exit code if any discrepancy or drift is detected.
2. **Explicit Update Invariant**: Documentation modification occurs **only** when explicitly invoked via `make update-transcripts` (or similar).
3. **Conservative Volatile Normalization**: Only volatile runtime values (ISO-8601 timestamps, Maven build duration `[0.472 s]`, `Finished at: ...`, temporary path hashes, and Java process PIDs) may be normalized to stable placeholders (e.g., `<TIMESTAMP>`, `<BUILD_TIME>`, `<TEMP_DIR>`). Crucial output lines—exit status, warning diagnostics, dropped JAR counts, byte savings, pruned class numbers, and CVE lines—must remain exact and unedited.
4. **Reproducible Local Fixture Isolation**: Configured invocations must execute against checked-in repository fixtures (`examples/example-basic-app`, `examples/example-spring-boot-app`, etc.) using the Maven wrapper (`./mvnw`) and local repository artifacts without requiring external network access or unpinned remote repositories.
5. **Clean Markdown Integration**: Injected blocks in `README.md` and documentation must use HTML comment delimiters (`<!-- BEGIN:transcript:... -->` and `<!-- END:transcript:... -->`) that render cleanly in GitHub-flavored markdown and pass `make lint-markdown` with zero errors.

---

## 2. Track Decomposition & Directed Acyclic Graph (DAG)

```text
┌────────────────────────────────────────────────────────┐
│ Track 1: Declarative Manifest & Normalization Engine   │
└──────────────────────────┬─────────────────────────────┘
                           │
             ┌─────────────┴─────────────┐
             ▼                           ▼
┌──────────────────────────┐┌──────────────────────────┐
│ Track 2: Command Invoc-  ││ Track 3: Document        │
│ ations (analyze/report)  ││ Delimiter Injection      │
└────────────┬─────────────┘└────────────┬─────────────┘
             │                           │
             └─────────────┬─────────────┘
                           ▼
┌────────────────────────────────────────────────────────┐
│ Track 4: Makefile Targets, CI Enforcement & Tests      │
└────────────────────────────────────────────────────────┘
```

---

## 3. Track Specifications & Committable Slices

### Track 1: Declarative Manifest & Normalization Engine

**Goal**: Implement a robust Node.js or Python CLI tool to drive transcript capture, regex-based volatile normalization, and text substitution.

* **Slice 1.1: Declarative Invocations Manifest**
  * Create `scripts/transcripts-manifest.json` defining command suites:

    ```json
    {
      "invocations": [
        {
          "id": "analyze-basic-app",
          "targetDocument": "README.md",
          "marker": "sample-analyze-output",
          "workingDirectory": "examples/example-basic-app",
          "command": "./mvnw",
          "args": ["dependency-elider:analyze", "-Delide.traceFiles=../../.scratch/traces/basic.log"],
          "expectedExitCode": 0,
          "filterRegex": "^(\\[INFO\\]|Dependency Elider)"
        },
        {
          "id": "report-basic-app",
          "targetDocument": "README.md",
          "marker": "sample-report-output",
          "workingDirectory": "examples/example-basic-app",
          "command": "./mvnw",
          "args": ["dependency-elider:report"],
          "expectedExitCode": 0
        }
      ]
    }
    ```

* **Slice 1.2: Volatile Normalizer Engine**
  * Create `scripts/update-transcripts.js` (and unit tests in `scripts/update-transcripts.test.js`):
    * Replaces timestamps matching `[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z` with `<TIMESTAMP>`.
    * Replaces absolute paths pointing into the user's workspace or `/tmp` with `<PROJECT_ROOT>` or `<TEMP_DIR>`.
    * Replaces Maven execution duration lines (`Total time:  0.472 s`, `Finished at: ...`) with deterministic text.
    * Replaces variable memory numbers or thread timings in trace reports.

---

### Track 2: Command Invocations (Especially `analyze` & `report`)

**Goal**: Configure and capture authoritative transcripts for the primary CLI goals.

* **Slice 2.1: `analyze` Goal Transcripts**
  * Target: `dependency-elider:analyze` on `example-basic-app` and `example-cve-unused-app`.
  * Demonstrates dry-run elision predictions:
    * Artifacts that would be elided.
    * Estimated original JAR bytes saved.
    * Program class entries in JARs that would be dropped.
    * CVE components that would be removed from inventory.
    * CVEs whose vulnerable code would be proven absent by trimming.
  * Captures output without mutating the workspace or altering build artifacts.
* **Slice 2.2: `report` Goal Transcripts**
  * Target: `dependency-elider:report` after successful `elide` execution across the 4 example apps.
  * Captures:
    * Dropped JAR counts and byte savings.
    * Pruned class entries and byte reductions from retained JARs.
    * CVE inventory removal and code-absence lines.
    * Mediated dependency tree rows (`[RETAINED]`, `[EFFECTIVE_DROP]`, `[RETAINED, CLASS_TRIMMED]`).

---

### Track 3: Document Delimiter Injection

**Goal**: Inject transcripts safely into documentation without breaking layout or manual prose.

* **Slice 3.1: Delimiter Markers in `README.md` and `usage.md`**
  * Place HTML comment delimiters around the code blocks:

    ````markdown
    <!-- BEGIN:transcript:analyze-basic-app -->
    ```text
    [INFO] Project: io.github.spockz:example-basic-app:0.1.0-SNAPSHOT
    ...
    ```
    <!-- END:transcript:analyze-basic-app -->
    ````

  * Verify that GitHub markdown renders the enclosed text block normally while hiding the comment markers.
* **Slice 3.2: Multi-File Target Support**
  * Allow targeting both root `README.md` and plugin documentation pages (`dependency-elider-maven-plugin/src/site/markdown/usage.md`).
  * Ensure `scripts/generate-site-index.sh` continues to synchronize `README.md` to `target/generated-site/markdown/index.md` smoothly.

---

### Track 4: Makefile Targets, CI Enforcement & Tests

**Goal**: Integrate transcript verification into the project's quality gates.

* **Slice 4.1: Makefile Targets**
  * Add `update-transcripts`:

    ```makefile
    update-transcripts: ## Re-run configured commands, normalize outputs, and update documentation
        $(NODE) scripts/update-transcripts.js --update
        $(MAKE) --no-print-directory site
    ```

  * Add `check-transcripts`:

    ```makefile
    check-transcripts: ## Verify that documentation transcripts match current command outputs
        $(NODE) scripts/update-transcripts.js --check
    ```

* **Slice 4.2: CI & `make check` Gate Integration**
  * Add `check-transcripts` to `check-ci` in `Makefile`.
  * Verify that a deliberate edit to a transcript block in `README.md` causes `make check-transcripts` to fail with a clear diff.
* **Slice 4.3: Unit Test Suite for Transcript Runner**
  * Add `scripts/update-transcripts.test.js` using Node.js built-in test runner (`node --test`).
  * Test missing markers, unmatched exit codes, path normalization, and check-mode non-mutation.

---

## 4. Verification Protocol

```sh
# 1. Run transcript engine unit tests
node --test scripts/update-transcripts.test.js

# 2. Update all documentation transcripts
make update-transcripts

# 3. Verify non-mutating check mode passes
make check-transcripts

# 4. Verify markdown linting across all updated documents
make lint-markdown
```
