<!-- This handover splits the remaining performance and cache-policy work into reviewable slices on the integration branch. -->

# Intra-JAR Trimming Performance Follow-Up

Status date: 2026-10-26  
Integration branch: `work-package/wp-trim-01`  
Starting revision: `41f0607`

## Completed slices

| Slice | Result | Evidence |
| --- | --- | --- |
| 2.6b: cache sibling library declarations | Complete and reviewed. Metadata-free declarations are reused through immutable templates; metadata-bearing classes are reparsed into context-local state. | `make fmt && make check` passed; example fixtures and fixed-point output checks passed. |
| 6.5: named baseline and elision modes | Complete and reviewed. One example POM selects baseline or elision with `-Delide.mode`. | `make test-examples` passed; baseline omitted the elider goal and elision mode ran it. |
| 6.4: post-2.6b performance evidence | Recorded. | Three matched warm cycles: Basic median overhead +2.038 s; Spring +22.716 s. JFR showed ProGuard `ClassPool` TreeMap lookup and descriptor enumeration as hot paths. |
| 7.1 and 7.2: cache mutation protection and exact content identity | Complete and reviewed. | Existing cache checks and full repository gate passed. |
| 6.6: post-2.6c/7.3 performance evidence | Complete and reviewed. | Three matched warm cycles: Basic median overhead +1.972 s; Spring +20.337 s. All four fixtures passed. Separate JFR profiles and Maven-process RSS are recorded in RQ-0003. |

## Slice tracking

| Slice | Track | Status | Depends on | Acceptance evidence |
| --- | --- | --- | --- | --- |
| 2.6c: frozen graph-local class lookup index | ProGuard graph construction | Complete and reviewed (`ed6a33d`) | 2.6b | Full check passed (137 core, 66 plugin). The implementation keeps sorted TreeMap storage, indexes the same `Clazz` instances after final pool assembly, and blocks membership mutation after freeze. The reviewer approved precedence, iteration, identity, inherited resolution, and unresolved-link behavior. |
| 7.3: publish under invocation-level input stability | Cache publication | Complete and reviewed (`dbf7214`, `c49fe04`) | ADR 0004 | Compute SHA-256 and SHA-1 in one read per normalized input and reuse path-bound provenance. Remove source rehashes that only detect concurrent edits. Preserve cache-output validation, staged/published-output digest checks, temp staging, and atomic moves. Full check passed (140 core, 66 plugin). |
| 8.1: decision and contributor-doc closeout | Documentation | Complete and reviewed | 7.3 and 6.6 | ADR 0004 is indexed; user FAQ and contributor decision register record the invocation-level input-stability contract and retained output/cache integrity checks. The contributor entry links the measured context in RQ-0003. Markdown lint and `git diff --check` passed. |
| 6.7: post-7.3 warm-cache JMH and profile | Cache performance evidence | Complete; measurement only | 7.3 | GraalVM JDK 21.0.12+7.1, JMH 1.37, two forks, three 1 s warmups and five 1 s measurements: raw measured iterations 92.761, 93.108, 92.939, 92.705, 92.598 and 92.667, 92.855, 92.735, 92.397, 92.648 ms/op; mean 92.741, median 92.720, 99.9% CI ±0.294, range 92.397–93.108. One op calls production `MavenDependencyTrimmer.trim` for one tiny candidate after cache population; it computes dynamic roots and the fingerprint (including platform input discovery and SHA-256), loads and validates the cache manifest, and hashes the cached trimmed output. The candidate's SHA-256 and SHA-1 are captured together and reused. It is not a Maven invocation; the benchmark passes a null Maven session. The target remains <10 ms. A separate profile JFR included fixture setup/warmup and measurement (42 execution samples; 959 allocation samples). `platformInputs` appeared in 13/42 execution stacks; `fingerprint` in 11/42. Allocation samples highlighted ZIP entry iteration/central-directory setup and ASM class reading, but include setup and are sampled estimates. Recommended next bounded slice: prepare an immutable, exact JDK platform input/release snapshot once per Maven session and reuse it for fingerprinting and platform analysis, without metadata-only identity or cross-session reuse; adapt the JMH fixture to model that invocation context, then retime. JFR: `/tmp/elider-6.7-warm-cache.jfr`; benchmark build and raw output were local, not committed. |
| 7.4: immutable platform source capture | Core platform reader | Planned | 7.3 | Introduce an immutable snapshot that captures the selected platform sources and the bytes/digests in the same read. Record release, source kind, normalized source identity, and content identity for `ct.sym` or the ordered JMOD fallback. Platform class parsing must consume only captured snapshot content, never capture a digest and later reopen the live path. Materialize fresh mutable ProGuard pools/classes for every analysis; do not add global caches or share initialized pools. Preserve fail-closed behavior for missing, unreadable, malformed, or unsupported platform inputs, and clean up failed partial captures. Tests must cover distinct releases and same-size/restored-mtime source changes, prove the reader consumes the captured bytes, verify missing/corrupt-source failures, and assert fresh pool/class identities. |
| 7.5: Maven-session ownership and cache-context benchmarks | Plugin/cache performance | Planned | 7.4 | Store completed immutable platform snapshots in Maven-session-owned context, keyed by normalized JDK home plus release/source identity; publish atomically only after full capture and never expose partial state. A null-session standalone caller captures a fresh snapshot per trim call and gets no global reuse. Keep cache identity bound to release and all selected `ct.sym`/ordered JMOD content; propagate capture failures without falling back to live reopen or an incomplete digest. Tests must prove same-session snapshot reuse, new-session isolation, concurrent atomic publication, retry/no publication after failure, and fresh mutable analysis pools despite snapshot reuse. Extend JMH with separate warmed-session cache hits and fresh single-project/session runs; report snapshot preparation cost separately from warmed per-hit latency. Run focused/full checks and parity tests before proposing any conclusion about the <10 ms target. |

## Performance evidence and interpretation

The sampled `TreeMap.getEntry` calls occur in ProGuard `ClassPool.getClass`; our graph-building path and ProGuard's reference initializers determine how often those calls occur. The frozen index in 2.6c changes lookup service while preserving the pool's class objects and sorted storage. The reported sample share is not a predicted end-to-end speedup.

The latest post-2.6c/7.3 end-to-end overhead is about +2 seconds for Basic and +20 seconds for Spring; the post-2.6b measurements remain as a prior checkpoint. Both 2.6c and 7.3 landed between those measurements, so the difference does not establish either slice's individual effect. The warm cache microbenchmark remains above its 10 ms target. Keep these measurements distinct: per-operation microbenchmark results do not represent Maven invocation overhead.

## Decision: input stability during a Maven invocation

Resolved input files are assumed stable during one Maven invocation. Compute each content digest needed for the cache identity, but do not repeat full input hashing at publication solely to defend against concurrent edits. Such edits already make a Maven build nondeterministic. Continue staging cache outputs and atomically publishing complete outputs so a failed write cannot leave a partial result.

The ADR records this decision in `docs/adr/0004-assume-resolved-inputs-stable-during-build.md`.
