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
| 6.6: post-2.6c/7.3 performance evidence | Complete. | Three matched warm cycles: Basic median overhead +1.972 s; Spring +20.337 s. All four fixtures passed. Separate JFR profiles and Maven-process RSS are recorded in RQ-0003. |

## Open slices

| Slice | Track | Owner | Depends on | Acceptance evidence |
| --- | --- | --- | --- | --- |
| 2.6c: frozen graph-local class lookup index | ProGuard graph construction | Complete, independently reviewed (`ed6a33d`) | 2.6b | Full check passed (137 core, 66 plugin). The implementation keeps sorted TreeMap storage, indexes the same `Clazz` instances after final pool assembly, and blocks membership mutation after freeze. The reviewer approved precedence, iteration, identity, inherited resolution, and unresolved-link behavior. |
| 7.3: publish under invocation-level input stability | Cache publication | Implemented; re-review pending (`dbf7214`, `c49fe04`) | ADR 0004 | Compute SHA-256 and SHA-1 in one read per normalized input and reuse path-bound provenance. Remove source rehashes that only detect concurrent edits. Preserve cache-output validation, staged/published-output digest checks, temp staging, and atomic moves. Full check passed (140 core, 66 plugin); independent re-review remains. |
| 8.1: decision and contributor-doc closeout | Documentation | Open | 7.3 and 6.6 | Carry ADR 0004 into this branch; update the user FAQ, contributor decision FAQ, and research notes with the input-stability contract and measured result ranges. Run Markdown lint and `git diff --check`. |

## Performance evidence and interpretation

The sampled `TreeMap.getEntry` calls occur in ProGuard `ClassPool.getClass`; our graph-building path and ProGuard's reference initializers determine how often those calls occur. The frozen index in 2.6c changes lookup service while preserving the pool's class objects and sorted storage. The reported sample share is not a predicted end-to-end speedup.

The latest post-2.6c/7.3 end-to-end overhead is about +2 seconds for Basic and +20 seconds for Spring; the post-2.6b measurements remain as a prior checkpoint. Both 2.6c and 7.3 landed between those measurements, so the difference does not establish either slice's individual effect. The warm cache microbenchmark remains above its 10 ms target. Keep these measurements distinct: per-operation microbenchmark results do not represent Maven invocation overhead.

## Decision: input stability during a Maven invocation

Resolved input files are assumed stable during one Maven invocation. Compute each content digest needed for the cache identity, but do not repeat full input hashing at publication solely to defend against concurrent edits. Such edits already make a Maven build nondeterministic. Continue staging cache outputs and atomically publishing complete outputs so a failed write cannot leave a partial result.

The ADR records this decision in `docs/adr/0004-assume-resolved-inputs-stable-during-build.md`.
