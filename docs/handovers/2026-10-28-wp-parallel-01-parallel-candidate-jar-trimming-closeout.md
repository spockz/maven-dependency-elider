<!-- WHY: Records implementation, review, and remaining verification for WP-PARALLEL-01. -->
# WP-PARALLEL-01 Closeout: Parallel Candidate JAR Trimming

Status date: 2026-10-29

## Verdict

**Incomplete.** The implementation and independent code review are complete, and Java compilation and static analysis pass. The example lifecycle benchmarks show a directional Spring Boot improvement at 12 workers, but their timing method and run-order spread do not support a firm performance claim. Bit-exact parity and dedicated behavioral checks remain pending.

## Work package

- **Source:** [WP-PARALLEL-01 handover](2026-10-28-wp-parallel-01-parallel-candidate-jar-trimming.md)
- **Research:** [RQ-0003, Slice 7.8](../research/RQ-0003-sub-10ms-maven-fast-path-invariant-and-benchmarking.md)
- **Base revision:** `c15974c` (`main`)
- **Track:** Candidate analysis, archive sanitization, and the shared platform-pool seam.

## Implemented

- Effective in-memory candidate and unchanged-program preparation now uses bounded parallel workers. Fixed-point closure runs in parallel rounds and merges roots serially in canonical coordinate order; Maven classpath precedence remains unchanged.
- Candidate archive sanitization and analysis stages use a configurable worker cap, defaulting to four, further bounded by available processors and pending work. The mapper keeps only one worker-sized window in flight, collects values by input index, cancels active tasks on failure, and keeps staged-output cleanup safe if workers outlast the caller's cancellation grace period.
- Prepared archive outputs are registered by each worker before completion, so failure cleanup owns successful sibling outputs as well as the failing operation's staging directory.
- JDK platform pools are exposed through `readFrozen` for read-only sharing. Each graph still copies platform signatures and constructs candidate and library pools locally.
- Trim records, passthrough coordinates, effective analysis maps, and cache entries use canonical coordinate ordering. Worker failures share one `IOException` wrapper while retaining their cause and message.

## Verification and review

- `make fmt` passed with the configured JDK.
- `./mvnw -pl dependency-elider-maven-plugin -am -DskipTests compile` passed.
- `make lint-java` passed: Spotless, Checkstyle, PMD, and SpotBugs were clean.
- Final `git diff --check` passed after source and documentation edits.
- The critical architect and dedicated track reviewer approved the implementation diff. Receipts are in `.scratch/reviews/parallel-01-architect.md` and `.scratch/reviews/parallel-01-slice-7.8.md`.
- The Gemini review bridge is unavailable in this session; the independent agent review was used as the documented fallback.

### Example lifecycle benchmark (2026-10-29)

The repository's `make test-examples` target ran three times at each `-Delide.trimWorkers` value (1, 4, 12). Each invocation used GraalVM 21.0.12, Maven 3.9.11, Maven reactor `-T 12`, offline dependency resolution, and `clean verify` for baseline and elision on all four fixtures. Java reported 24 available processors with no CPU quota. Every run passed all four fixture lifecycle checks. `clean` removed each example's trim manifest before its elision build; operating-system and Maven dependency caches remained warm. Each repetition used the same worker order: 12, 1, 4.

The example runner times each `clean verify` with `date +%s%N` and reports wall-clock durations. Hyperfine was absent and not cached locally; installing it would require a network request, but the managed environment's network-policy file and environment-status tool were unavailable. The results below are therefore directional. The repeated ranges also overlap, and the fixed worker order may introduce cache/order effects.

| Example | Workers | Elision `clean verify` samples (s) | Median (s) | Range (s) |
| :--- | ---: | :--- | ---: | :--- |
| Basic | 1 | 7.268, 5.392, 5.827 | 5.827 | 5.392–7.268 |
| Basic | 4 | 7.054, 5.376, 6.379 | 6.379 | 5.376–7.054 |
| Basic | 12 | 5.559, 6.757, 6.452 | 6.452 | 5.559–6.757 |
| Spring Boot | 1 | 37.105, 36.363, 31.899 | 36.363 | 31.899–37.105 |
| Spring Boot | 4 | 36.825, 32.962, 22.485 | 32.962 | 22.485–36.825 |
| Spring Boot | 12 | 18.566, 20.127, 31.415 | 20.127 | 18.566–31.415 |

Spring Boot's median full `clean verify` time was 44.7% lower at 12 workers than at 1 (36.363 s to 20.127 s, about 1.81x). The 4-worker median was 9.4% lower than 1 worker, but the sample ranges are broad. Basic showed no speedup as the worker cap increased. These timings include the Maven lifecycle, elider, compilation, and tests; they are not Surefire-only test durations. This comparison does not measure bit-exact output parity or compare against the pre-parallel revision.

The final Spring Boot JAR size varied from 32,646,364 to 32,646,368 bytes across runs. The example runner verifies archive contents, but this benchmark did not save or compare output hashes; bit-exact reproducibility remains unverified, and the size variation is not attributed to a worker count here.

## Remaining acceptance evidence

- Add focused behavioral checks for peer cancellation, temporary archive cleanup after a sibling failure, bounded worker count, fixed-point propagation, and stable failure wrapping.
- Compare sequential and parallel sanitized archive bytes and hashes, including manifests and preserved resources.
- Run the full repository `make check` gate. For a firm performance claim, repeat the example comparison with an approved hyperfine installation and counterbalanced worker order.

The nine `make test-examples` benchmark runs passed. No new tests were added; focused concurrency tests, bit-exact parity checks, the full `make check` gate, and a robust hyperfine timing remain pending.

## Integration state

Changes remain uncommitted in the active managed worktree. The full-check gate was not run, so the track was not merged or marked verified. The implementation is ready for the remaining behavioral and performance verification.
