<!-- WHY: Keeps implementation decisions, evidence, compatibility assumptions, and operational answers visible without replacing the detailed ADR and research records. -->
# Decision Register and FAQ

This page is the running index for behavior-affecting implementation decisions and recurring compatibility questions. ADRs remain the authority for accepted architecture; research questions track unresolved investigations. Record whether a statement is verified, an adopted policy, or an open assumption.

## Decision Register

| Topic | Current decision or behavior | Why it matters | Evidence / status |
| :--- | :--- | :--- | :--- |
| Intra-JAR engine | Use `com.guardsquare:proguard-core:9.1.10` under Apache 2.0; do not add GPL `proguard-base`. | Preserves the license boundary while using bytecode-aware class pools and reference closure. | Adopted in ADR-0003; dependency/license check in `make check`. |
| Source roots vs. bytecode closure | Keep a source reference scanner for Java source roots; use ProGuard Core for classfile closure. ProGuard Core does not replace Java source attribution. | A source-only compile reference may not appear in loaded bytecode, and ProGuard analyzes classfiles rather than Java source syntax. | Implemented in Tracks 1–2; source scanner and closure tests. |
| Source completeness | `elide.sourceRootsComplete` defaults to `false`; conservatively retain compile-visible classes. Set it to `true` only when production and generated sources are present before `INITIALIZE`. | Annotation processors or later generators can introduce references after the mojo runs. | Adopted contract in the work package and plugin usage docs. |
| Candidate scopes | Trim compile/runtime JARs only. Leave test/provided/system artifacts untouched by intra-JAR trimming. | Production source and runtime evidence do not establish completeness for test or provided-only consumers. | Implemented and covered by a test-scope multi-release regression. |
| Whole-artifact vs. per-JAR trimming | Whole-artifact elision and per-JAR class trimming are separate decisions. A retained JAR can remain unchanged, be trimmed, or be skipped under an explicit safety policy. | An unsupported archive must not force unrelated supported JARs to remain untrimmed or break the build by default. | Track 6 implementation in progress. |
| Configured pass-through JARs | `elide.trimSkipArtifacts` keeps selected retained compile/runtime JARs byte-identical, but analyzes their effective classes as roots so links into other trim candidates stay reachable. | Some libraries have optional references absent from the runtime graph; trimming those owners can fail safely or remove an optional integration that the consumer may use. | Implemented with exact-coordinate matching and content-bound cache inputs; Spring example verification in progress. |
| Multi-release trim targets | Default to pass-through with a warning for retained JARs containing versioned implementation classes; `-Delide.failOnUnsupportedMultiRelease=true` opts into hard failure. Keep the original artifact bytes. Module-info-only versioned entries may continue through the existing narrow supported path. | Trimming one effective variant without accounting for other class variants can remove live implementation code. | Policy selected by the user; implementation and end-to-end evidence pending. Core candidate analyzer remains fail-closed. |
| Multi-release sibling analysis | Use an analysis-only effective class view for the selected runtime release, leave the original sibling JAR unchanged, and conservatively root its effective classes so their outgoing links retain classes in trimmed siblings. | An unchanged but unanalysed library can call classes in a trimmed artifact. | Projection path in progress. Current examples select the running GraalVM JDK feature version (21); other deployment runtimes are not yet covered. |
| Compiler release vs. runtime release | Use compiler settings for the platform API pool; use the selected runtime feature for multi-release entry selection. Do not assume `--release` always equals the JVM that runs the packaged application. | The compiler target controls available APIs, while the runtime selects multi-release implementations. | JDK 21 example path is under verification; broader runtime selection is an open compatibility question. |
| Unsupported native-image metadata | Parse only understood metadata shapes and options; reject unknown class metadata before changing Maven artifact pointers. Preserve supported metadata resources in outputs. | Treating unknown reflection/resource instructions as harmless can silently remove dynamically reached classes or resources. | Narrow Tomcat/Spring forms added with positive and fail-closed tests; Track 6 verification in progress. |
| Maven artifact views | The current same-session example path keeps the original direct dependency set and updates the resolved/project view and file pointers. This avoids Maven 3.9.11's re-resolution shortcut invalidation in the tested sequence. | A direct-view consumer can still observe an elided dependency; consistent mutation triggers re-resolution and restores original paths in the tested lifecycle. | Basic MDEP/Shade experiment; lifecycle research is [RQ-0006](research/RQ-0006-maven-artifact-view-consistency-and-early-resolution-hooks.md). |
| Earlier resolver integration | Do not add a core extension solely to satisfy model consistency. First identify a consequential consumer failure or an explicit product guarantee; compare startup extension costs in RQ-0006. | A core extension can intercept repeated resolution but changes project setup, timing, and Maven compatibility. | Open research decision; Maven 3 `RepositorySessionDecorator` is a candidate, Maven 4 is unverified. |
| Cache validation | Validate original candidate/sibling inputs and trimmed outputs by content digest; do not substitute mtime/size checks to meet the latency target. | Local artifacts and snapshots can change while filesystem metadata remains unchanged. | Correctness policy adopted. Measured warm path is about 93–99 ms, exceeding both the <10 ms work-package target and <1.5 ms design target; documented deviation. |
| Archive boundaries and signatures | Keep one output JAR per Maven coordinate. When an archive is modified, strip invalidated signature blocks and manifest section digests; preserve non-class resources. | Shading or flattening would lose coordinate boundaries and signature files would no longer authenticate the modified bytes. | Implemented in Tracks 2–4 with archive and SBOM tests. |
| Provenance | Emit the modified component's actual digest and record the source component/digest and trimming patch in CycloneDX 1.6 pedigree. | Consumers need to distinguish the modified bytes from the upstream release. | Implemented in Track 4 with pinned schema validation. |

## FAQ

### What happens when a retained JAR contains versioned implementation classes?

By default, keep that JAR byte-identical and warn that it was skipped as a trim target. Continue trimming other supported JARs. Set `-Delide.failOnUnsupportedMultiRelease=true` to make encountering such a target fail the build before Maven artifact pointers are changed. Track 6 still needs to verify the full Spring package and runtime path.

### When should I configure `elide.trimSkipArtifacts`?

Use an exact resolved compile/runtime JAR coordinate when that artifact must remain byte-identical, for example because its reachable classes contain optional external references. The plugin still analyzes its classes as roots and retains linked classes in other candidates. It does not make unresolved references in ordinary trim candidates acceptable, and it pins the artifact against whole-artifact pruning.

### What if the packaged application runs on a different JDK than the one running Maven?

The JDK version controls which `META-INF/versions/N` classes the JVM loads. Current example analysis selects the executing JDK feature version (21). If deployment targets differ, the analysis does not yet prove closure for those variants. The safe future choices are to configure the runtime release explicitly, compute the union of references across supported release variants, or leave affected dependencies and their linked code unchanged.

### Can we keep all multi-release entries and analyze only the base classes?

No. Keeping the bytes avoids changing that JAR, but base-class references may omit calls made by the effective versioned class body. Use an effective runtime view and treat its classes as roots for cross-artifact closure, or compute a union across all supported variants. Otherwise a referenced class in another trimmed JAR can still be removed.

### Can ProGuard Core scan our Java sources instead of the source scanner?

No. ProGuard Core handles classfiles and their references. Java source attribution is a separate compile-time concern, so the plugin keeps a source scanner for source roots and ProGuard Core for bytecode link closure.

### What if generated sources are not present at `INITIALIZE`?

Leave `elide.sourceRootsComplete=false`; this conservatively pins compile-visible JARs and their classes for trimming. Use `true` only when every production/generated source is already available and no later processor or generator adds compile references.

### Why can the direct and resolved Maven dependency views differ?

The current tested same-session path preserves the direct set so Maven does not re-resolve the original graph, while classpath and packaging consumers use the pruned resolved view. A direct-view plugin may still report an elided dependency. If both views are pruned, the tested Maven 3.9.11 lifecycle resolves the original POM graph again and restores original classpaths. See [RQ-0006](research/RQ-0006-maven-artifact-view-consistency-and-early-resolution-hooks.md) for impact tests and earlier-hook options.

### Why is a validated cache hit slower than the target?

The cache verifies content fingerprints for candidate and sibling JARs plus the output digest. That exact validation measured roughly 93–99 ms in the current JDK 21 runs, above the <10 ms target. The implementation keeps the correctness check and records the performance target as unmet rather than trusting file timestamps.

### What happens when metadata or an archive layout is unknown?

Fail closed before Maven artifact pointers change, unless the policy explicitly classifies that artifact as unchanged/pass-through. Unknown dynamic class metadata is not treated as an empty root set. Multi-release target pass-through is a specific exception, with strict failure available; it does not imply that every unsupported archive shape is safe to skip.

### Why not shade everything into one JAR before analysis?

Each dependency remains a distinct JAR keyed to its Maven coordinate. This preserves per-artifact provenance, digest accounting, class ownership, and the ability to report which dependency changed.

## Updating This Page

Add each material work-package decision to the table with its current status, rationale, and evidence. Add an FAQ entry when the decision creates a recurring “what if” or version/platform boundary. Distinguish verified behavior from adopted policy and untested assumptions; link detailed ADRs, research questions, tests, and user-facing options rather than duplicating their full contents.
