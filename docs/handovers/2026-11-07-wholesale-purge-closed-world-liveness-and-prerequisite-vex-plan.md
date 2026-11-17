<!-- WHY: Provides a step-by-step execution playbook for wholesale removal of obsolete code, closed-world liveness vs ProGuard, shared vulnerability mapping catalogs, and prerequisite VEX publication. -->
# Handover Plan: Wholesale Purge, Closed-World Liveness vs. ProGuard, and Prerequisite VEX

**Date**: 2026-11-07
**Baseline Revision**: `2e41e43b83c32b0235eae301fc2f140b77a138e5`
**Predecessor Handover**: [2026-11-06-cve-evidence-and-inventory-assessment.md](2026-11-06-cve-evidence-and-inventory-assessment.md)

**Preserved Worktree Changes**: Do **not** revert or overwrite uncommitted changes in `scripts/fixtures/vulnerability-snapshots/`, `scripts/prepare-example-vulnerability-cache.sh`, `Makefile`, `TranscriptCachePreparationTest.java`, `MavenElisionReportGenericRenderer.java`, `docs/research/RQ-0017*`, `docs/research/RQ-0020*`, `docs/research/RQ-0021*`, or `docs/handovers/2026-11-06-cve-evidence-and-inventory-assessment.md`.

---

## 1. Current-State Audit Matrix

| Surface | Status | Code & Test Evidence | Discrepancy / Root Cause | Required Alignment |
| --- | --- | --- | --- | --- |
| **Liveness & Artifact Decisions** | **Partially Implemented (Split & Over-Conservative)** | [DependencyPruner](../../elider-core/src/main/java/io/github/spockz/elider/engine/DependencyPruner.java), [MavenAnalysisPreparation](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenAnalysisPreparation.java), [ElisionReachabilityEngine](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/ElisionReachabilityEngine.java), [PreparedAnalysisState](../../elider-core/src/main/java/io/github/spockz/elider/trimmer/PreparedAnalysisState.java), [SingleReleaseTrimInventory](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/SingleReleaseTrimInventory.java), [DynamicRootOrchestrator](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/DynamicRootOrchestrator.java), [SpringMetadataRoots](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/SpringMetadataRoots.java) | 1. Whole-JAR pruning and class trimming run as separate passes bolted together by `ElisionReachabilityEngine`. 2. `SpringMetadataRoots.readMetadata` parses `META-INF/spring-autoconfigure-metadata.properties` and adds optional `.ConditionalOnClass` targets as required dynamic roots. 3. `DynamicRootOrchestrator.dynamicRootArtifactOwners` (`:240-242`), `SingleReleaseTrimInventory.DynamicRootContext.route` (`:338-345`), and `TierRootResolution.addDynamicRoot` (`:121-128`) retain **100% of JARs in the inventory** whenever any dynamic root is unowned by a dependency JAR. 4. `ElisionReachabilityEngine` (`:104, :141-142`) marks cross-JAR reached (`newlyReachedDrops`), `ancestorPromoted`, and graph-protected JARs as `forcedUnchanged`, keeping 100% of their dead classes untrimmed and turning all their dead classes into reachability roots. 5. Empty-root candidate fallbacks (`PreparedAnalysisState:82`, `SingleReleaseTrimInventory:374`, `TierCandidatePlanner:56`) turn `0` live roots into 100% live roots. 6. `JaCoCoTraceReader:48-55` includes unexecuted classes (`!record.hasHits()`). 7. `SingleReleaseArchiveWriter:166-176` never applies `ServiceDescriptorFilter`. 8. No `closedWorld` runtime trace policy exists. | Compute one unified class/owner/resource liveness closure before making whole-JAR and class-trimming decisions. Remove `SpringMetadataRoots.readMetadata`, the unresolved-root keep-all poison pill, `forcedUnchanged` promotion inflation, and empty-root 100% fallbacks. Trim 0-live-class ancestor-promoted JARs down to resource/manifest-only stubs when `trimJars=true`. Implement the opt-in `closedWorld` runtime trace mode. |
| **Advisory Discovery & Cache** | **Partially Implemented** | [OsvVulnerabilityFindingAdapter](../../elider-core/src/main/java/io/github/spockz/elider/scanner/OsvVulnerabilityFindingAdapter.java), [CveVulnerabilityFindingAdapter](../../elider-core/src/main/java/io/github/spockz/elider/scanner/CveVulnerabilityFindingAdapter.java), [CveListFindingIndexer](../../elider-core/src/main/java/io/github/spockz/elider/scanner/CveListFindingIndexer.java), [GenericFindingCacheManager](../../elider-core/src/main/java/io/github/spockz/elider/scanner/GenericFindingCacheManager.java) | Record isolation, `PARTIAL`/`STALE`/`ERROR` source health, and unsupported Maven identity diagnostics are implemented. Automatic adapters omit `prerequisiteGroups` because upstream prose is unstructured. | Preserve source facts, unbound/review-only text leads, and source health through the common pipeline without inventing Maven coordinates or prerequisites from prose. |
| **Reconciliation & Shared Mapping Catalog** | **Partially Implemented (Core Codec and Maven Resolver Added; Final Verification Pending)** | [GenericFindingReconciler](../../elider-core/src/main/java/io/github/spockz/elider/model/GenericFindingReconciler.java), [ManualVulnerabilityMappingContributionAdapter](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/ManualVulnerabilityMappingContributionAdapter.java), [GenericVulnerabilityFinding](../../elider-core/src/main/java/io/github/spockz/elider/model/GenericVulnerabilityFinding.java), [VulnerabilityMappingCatalogReader](../../elider-core/src/main/java/io/github/spockz/elider/scanner/VulnerabilityMappingCatalogReader.java), [VulnerabilityMappingCatalogWriter](../../elider-core/src/main/java/io/github/spockz/elider/scanner/VulnerabilityMappingCatalogWriter.java), [MavenVulnerabilityMappingCatalogResolver](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenVulnerabilityMappingCatalogResolver.java) | Core schema-v1 catalog parsing/writing, partial row health, typed prerequisite groups, confidence persistence, explicit pinned Maven artifact resolution, and report adoption/replay are implemented. Final full-suite/static verification and review remain. | Preserve the implemented distinction between supplemental **evidence scope** and **affected-version assertions** (`assertsAffected=false` by default, including exact-version fallback). Keep catalog resolution data-only and isolated from application dependencies. |
| **Inventory, Applicability & Attribution** | **Implemented (Runtime-Only Elide and Analyze Proof)** | [ElideMojo](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/ElideMojo.java), [AnalyzeMojo](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/AnalyzeMojo.java), [MavenVulnerabilityAssessment](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenVulnerabilityAssessment.java), [PreconditionProof](../../elider-core/src/main/java/io/github/spockz/elider/model/PreconditionProof.java) | Both goals can assess a complete current runtime inventory independent of `trimJars`; direct invocations require `elide.productionClassesComplete=true` and physical capture. Analyze records physical absence when `elide.preconditionClassPathComplete=true`; it still labels absence caused only by planned removals as a forecast. Test outputs and test-scoped dependency archives are excluded from the proof scan; scope rows remain in dependency decisions and SBOMs. Baseline inventory is optional for proving absence and is retained for attribution only. | Inspect the complete current/final runtime inventory in both goals. Apply prerequisite group operators to exact class presence, allow complete final/current absence proof when baseline inspection is unavailable, preserve `UNKNOWN` attribution when its cause cannot be established, and keep plan-only removals non-authoritative. |
| **Publication, SBOM/VEX & Replay** | **Partially Implemented (Gated on `trimJars`)** | [MavenElisionOutputPublisher](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenElisionOutputPublisher.java), [CycloneDxSbomGenerator](../../elider-core/src/main/java/io/github/spockz/elider/metadata/CycloneDxSbomGenerator.java), [OpenVexGenerator](../../elider-core/src/main/java/io/github/spockz/elider/metadata/OpenVexGenerator.java) | `MavenElisionOutputPublisher` gates baseline/final SBOM, OpenVEX, output manifest, and stale-VEX cleanup on `request.files().trimJars()`. | Decouple SBOM/VEX publication, staging, and stale-VEX cleanup from `trimJars` while keeping original JARs untouched when `trimJars=false`. Emit CycloneDX `not_affected` / `requires_dependency` and matching OpenVEX for verified retained components. |
| **Lifecycle & Packaging Guards** | **Partially Implemented** | [ElideMojo](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/ElideMojo.java), [EliderPluginConfiguration](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/EliderPluginConfiguration.java), [EliderLifecycleParticipant](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/EliderLifecycleParticipant.java), [ProductionAnalysisInputs](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/ProductionAnalysisInputs.java), [MavenPreconditionGenerationGuard](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenPreconditionGenerationGuard.java) | 1. Default phase is still `initialize`. 2. Source-free modules fail at `process-classes` when `target/classes` is absent or has `0` `.class` files. 3. `MavenPreconditionGenerationGuard` checks `trustedProcessClasses` before `phaseIndex > requestedPhaseIndex` (`:1212` vs `:1244`), rejects `spring-boot-maven-plugin:repackage`, ignores `maven.test.skip=true`, and fails when `dependency-elider-maven-plugin` omits an explicit `<phase>`. | Default `elide` to `process-classes` across Mojo, lifecycle participant (with tail priority ordering), tree preparation, and ban activation. Support source-free modules. Fix `MavenPreconditionGenerationGuard` phase cutoffs, implicit phases, `maven.test.skip=true`, and `spring-boot-maven-plugin:repackage` boundary modeling. |

---

## 2. Architecture of Closed-World Liveness vs. ProGuard (`proguard-core`)

### 2.1 What `proguard-core` Does Today vs. What Elider Controls

1. **Archive Writing ([ArchiveSanitizer](../../elider-core/src/main/java/io/github/spockz/elider/trimmer/ArchiveSanitizer.java), [SingleReleaseArchiveWriter](../../elider-core/src/main/java/io/github/spockz/elider/trimmer/SingleReleaseArchiveWriter.java), [MultiReleaseArchiveWriter](../../elider-core/src/main/java/io/github/spockz/elider/trimmer/MultiReleaseArchiveWriter.java))**:
   - Owned 100% by Elider (not ProGuard). Copies a `.class` entry from the original JAR into the trimmed JAR iff its internal name is in `Set<String> retainedClasses`.
2. **Graph Traversal ([PreparedAnalysisState](../../elider-core/src/main/java/io/github/spockz/elider/trimmer/PreparedAnalysisState.java), [SingleReleaseClosureAnalyzer](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/SingleReleaseClosureAnalyzer.java), [TierClosureAnalyzer](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/TierClosureAnalyzer.java))**:
   - Owned 100% by Elider. Walks `Map<String, Set<String>> edges` in a worklist loop starting from `retainedRoots`.
3. **Class Reference Extraction ([ReferenceGraphIndexer](../../elider-core/src/main/java/io/github/spockz/elider/trimmer/ReferenceGraphIndexer.java) + [ProGuardReferenceVisitors](../../elider-core/src/main/java/io/github/spockz/elider/trimmer/ProGuardReferenceVisitors.java))**:
   - Uses `com.guardsquare:proguard-core` (`ClassPool`, `ClassSuperHierarchyInitializer`, `ClassReferenceInitializer`, `CompleteReferencedClassVisitor`) to build `Map<String, Set<String>> edges` (`Class A -> Set<Class B>`) and `unresolvedProgramReferences` / `unresolvedLibraryReferences`.

### 2.2 Why `proguard-core` Currently Over-Retains When Given a Complete Trace

- Originally ([ADR-0003](../adr/0003-proguard-core-intra-jar-trimming-and-cyclonedx-pedigree.md)), Elider constructed **seed roots** (from `target/classes`, `META-INF/services/*`, `spring.factories`, or partial traces) and fed them into `proguard-core`'s `CompleteReferencedClassVisitor` (`ReferencedClassVisitor`), which walks **every constant-pool entry** of a class (`clazz.constantPoolEntriesAccept(this)`).
- Because a `.class` file has one shared constant pool for the entire class, `CompleteReferencedClassVisitor` visits every class referenced inside **every dead method and unexecuted branch** of that class.
- Furthermore, `RecordingInvalidReferenceVisitor` throws `UnresolvedReferenceException` if any constant-pool reference inside a retained class points to an omitted class.

### 2.3 How the New `closedWorld` Flag (`-Delide.closedWorld=true` / `<closedWorld>true</closedWorld>`) Works

When the user provides runtime evidence and enables `closedWorld = true`, they assert that the evidence bounds the workload being optimized. The option does not independently prove that every class loaded by the JVM appears in the trace; JaCoCo probe hits cannot establish that fact.

1. **Default Conservative Mode (`closedWorld = false`)**:
   - Treats `target/classes`, runtime traces, explicit `trimRoots`, and active dynamic metadata (`META-INF/services/*`, `spring.factories`, `AutoConfiguration.imports`, conditional `META-INF/native-image/**`) as **seed roots**.
   - Feeds those seed roots into `proguard-core`'s `CompleteReferencedClassVisitor` to retain the full transitive static constant-pool closure across all methods and branches.
2. **Closed-World Mode (`closedWorld = true`)**:
   - The supplied evidence represents the user's declared workload boundary. Do not interpret enabling this option as automatic proof of a complete class-load record.
   - **No `proguard-core` method-body constant-pool search (`CompleteReferencedClassVisitor`) is performed to pull in untraced classes**: if class `A` was loaded in the trace and references class `B` inside an unexecuted method/branch, and `B` was **not** in the trace (nor an explicit/active dynamic root), `B` is **not** added to `retainedClasses`, and its owning JAR `jar-b` is elided if no other class in `jar-b` is live.
   - **Only Structural Linkage Edges (`structuralEdges`) are traversed unconditionally**: For any root (including JaCoCo instruction-level traces or explicit `trimRoots` that may omit pure interfaces/superclasses without executable code), `proguard-core` visits class-header/declaration structures required to load and link the class (`ClassHierarchyTraveler` for superclasses/interfaces, `MemberDescriptorReferencedClassVisitor` for field/method descriptors, `SignatureAttributeReferencedClassVisitor` for generic signatures, and `ExceptionHandlerConstantVisitor` for `try`/`catch` exception handler types in `CodeAttribute.exceptions`), plus code-body edges (`CompleteReferencedClassVisitor`) **only when the target class is itself in the closed-world allowed set** (`tracedClasses ∪ explicitRoots ∪ activeDynamicRoots`). Types named only by `LocalVariableTable` or `LocalVariableTypeTable` debug metadata do not create liveness edges; an independently observed or explicit root still remains live. Stack-map frame types remain structural.
   - **Selective unresolved-reference handling**: In `closedWorld = true`, suppress an unresolved target only when typed reference evidence proves it is a non-structural method-body target excluded from the allowed set. In either mode, ignore types present only in local-variable debug metadata. Structural or allowed-target unresolved references, malformed bytecode, and unclassified failures remain errors.
   - **Application bytecode (`target/classes`) scoping in `closedWorld = true`**: When a non-empty runtime trace is supplied and `closedWorld = true`, `target/classes` only roots dependency classes that were either observed in the runtime trace, structurally linked by a traced application class, or explicitly rooted — unexecuted application methods in `target/classes` do not pull in untraced dependency JARs.

---

### 2.4 Architectural Clarifications from Independent Review

The `closedWorld` option is an explicit, workload-specific trimming contract. It uses the user's assertion that the supplied evidence covers the workload being optimized. It cannot promise that transformed archives load on every compliant JDK 21+ installation: JVMs may resolve symbolic references eagerly or lazily, and verification may load types referenced by uncalled method bodies and stack-map frames. Preserve the full static closure in default mode and whenever documentation claims portable loadability.

Closed-world admission fails explicitly when `closedWorld` is enabled without trace files, when files are empty, malformed, unreadable, detectably incomplete, or when their normalized classes are wholly irrelevant to the analyzed application/dependency inventory. Do not silently fall back to conservative mode or interpret unusable evidence as an empty world. Preserve each input kind through admission and reporting rather than using a merged non-empty class set as proof of completeness. Class-load logs, CDS class lists, and JFR class-load recordings are load evidence. JaCoCo input is binary `.exec` execution evidence only; exclude no-hit records and never describe probes as a complete class-load record. The reader does not support XML or CSV. Enabling `closedWorld` asserts the supplied workload evidence is the intended bound; reports must still identify its evidence kind and boundary.

The closure query must distinguish conservative mode from an explicitly supplied allowed-class set, including the empty-set case. Include both mode and normalized allowed-set identity in reusable analysis state and trim-policy identity; changing either must recompute traversal. Traverse structural references regardless of allowed-set membership. Traverse other references only when their targets belong to the allowed set. Ignore an unresolved method-body target only when typed reference evidence identifies it as an excluded, non-structural target. Local-variable debug descriptors and signatures do not create liveness edges or require target resolution. Missing structural or allowed-target links, malformed bytecode, unclassified linkage failures, and reference-extraction failures remain fatal. Do not parse formatted diagnostic strings to decide which unresolved references to suppress.

Keep explicit roots and active dynamic roots. An unknown dynamic-root owner may add a focused diagnostic but must not retain every archive. Removing `SpringMetadataRoots.readMetadata` must not remove active service, Spring factories/imports, native-image, or resource roots required elsewhere in the accepted policy. Empty liveness sets must not be converted to all classes or all artifacts.

Service descriptor processing uses three outcomes: unchanged, replacement bytes, and omission. Existing `ServiceDescriptorFilter.filter()` returns `Optional.empty()` for unchanged input, so do not interpret it as a request to omit the descriptor. Decide provider retention against the global retained-class set across all archives and all effective MRJAR tiers. Preserve duplicate provider declarations where another archive supplies the provider, and preserve unknown/external provider names. Do not emit versioned `META-INF` descriptors. A user-provided trace from one runtime cannot justify removing a provider needed by another effective tier in the supported archive view.

These limits are behavioral boundaries, not optional documentation polish. Tests must include real transformed archives loaded and invoked in a fresh JVM or isolated class loader on available standard JDK 21 and 25 installations, plus an uncalled method containing verification-relevant type relationships. Passing those examples demonstrates the captured workloads only; it does not establish universal verifier behavior.

Supplemental version evidence never establishes affectedness or unaffectedness by itself. A scope-only mapping can provide code/prerequisite metadata only inside an independently asserted affected range; missing affected evidence has its own `NO_AFFECTED_ASSERTION` outcome and cannot create VEX. Keep prerequisite operator, full member set, version scope, priority, review intent, and row provenance atomic through merge. Preserve the current every-pair-absent proof rule as default `ANY_OF`; explicit `ALL_OF` is a separately documented contract. Conflicting equal-priority groups remain unresolved.

Verified prerequisite evidence is based on the complete current/final runtime inventory. A complete baseline is useful only to attribute why a prerequisite is absent; absence in a complete current/final inventory remains proof even when the class was already absent in the baseline or baseline inspection is unavailable. Incomplete baseline evidence yields `UNKNOWN` attribution, while an incomplete current/final inventory suppresses proof. Analyze can record physical proof from the current inventory; only its planned removals remain forecasts. Analyze does not publish VEX files. Catalog coordinates are explicitly adopted Maven build inputs, isolated from application dependencies, with computed artifact digest, schema, stable row IDs, advisory references, selected rows, exclusions, and adoption origin saved for offline replay. A digest identifies observed bytes but does not authenticate the publisher.

---

## 3. Slice 0: Wholesale `git rm` of 91 Obsolete/Over-Engineered Files & Exact Caller Edits

Complete this slice before feature work. The end state removes all **91 tracked files (~15,000+ lines)**, but only after replacement tests and caller migrations establish which accepted guarantees remain. Work through clusters as reviewable commits; do not delete behavior-bearing tests before their replacement assertions fail for the intended reason.

### Step 0.1: Add Replacement Tests for Preserved Guarantees

Treat the eight behavior groups as separate TDD sub-slices. For each affected cluster, first add or migrate its focused acceptance test, run it against the current implementation, then make the minimum caller/production change and remove that cluster's files. A behavior-neutral deletion may have a passing characterization test before the refactor; a behavioral change must first fail for its intended reason. Commit each green cluster before moving to the next. Keep the existing supported boundary while removing duplicate verification, compatibility code, or orchestration layers:

1. **Strict persisted evidence**: OSV record/evidence round trips remain valid; deleted `STRUCTURED_SOURCE_CLASS` and `CORROBORATED_SOURCE_CLASS_CANDIDATE` evidence tags and the superseded `cnaAffectedEntries` shape are rejected explicitly at schema version 1. Do not add compatibility constructors or aliases for the unreleased draft.
2. **Precondition inventory**: exact class providers in application output, retained and staged dependency archives, shaded providers, duplicate providers, and effective MRJAR tiers determine each prerequisite member's present/absent state before its atomic group's operator is evaluated. Incomplete baseline inventory yields `UNKNOWN` attribution; incomplete actual final inventory blocks physical absence proof and yields `UNKNOWN`. A prerequisite class found only in test sources/output must not be treated as absent when a later `test-compile` may still create that provider.
3. **VEX and report publication**: retained-component prerequisite proof emits the existing CycloneDX/OpenVEX forms only after inspecting a complete actual staged effective output inventory; an analysis prediction is never presented as physical proof. Baseline completeness is needed for causal attribution, not final absence: if baseline is incomplete but actual final inventory is complete, physical proof may succeed with `UNKNOWN` attribution. An incomplete final inventory suppresses the statement with its reason. A failed write surfaces as an error. When proof no longer succeeds, delete only an unchanged output recorded as plugin-owned. Preserve modified and unowned configured VEX files and report that preservation. Keep all internal unreleased persisted formats at version 1.
4. **Ban enforcement**: a surviving application/library/provider reference, including an upper MRJAR tier or alternate class provider, rejects a ban before reports, artifact views, or resolver-plan publication. Retain strict final absence and closure validation while reducing redundant freshness passes.
5. **Effective trim route**: both duplicate policies preserve their current class contents and diagnostics; unmatched duplicates still fail; dynamic roots supplied with analysis are reused without rescanning; pass-through and MRJAR behavior remain observable through the effective-analysis route.
6. **Compiler environment**: inherited Maven properties, configured target selection, and standard platform-option precedence remain covered through surviving APIs after AST scanner removal.
7. **Removed source-completeness property**: an explicit `elide.sourceRootsComplete=true` fails with migration guidance before `SourceRootCompleteness` and its caller are deleted.
8. **Ban publication boundary**: requested-ban validation inspects staged archive bytes and final class/resource/provider closure before replacing generated outputs or publishing Maven artifact views or resolver plans. Inject a staged retained banned class and assert publication is rejected without changing prior output files or Maven views.

### Step 0.2: Run `git rm` on All 91 Files

Run the following `git rm` commands from the repository root:

```bash
# Cluster A: Entire elider.cache package (10 files), obsolete cache benchmark, and 11 extant dead files/resources
git rm \
  elider-core/src/main/java/io/github/spockz/elider/cache/BoundedByteArrayOutputStream.java \
  elider-core/src/main/java/io/github/spockz/elider/cache/ElisionCache.java \
  elider-core/src/main/java/io/github/spockz/elider/cache/ElisionCacheCodec.java \
  elider-core/src/main/java/io/github/spockz/elider/cache/ElisionCacheReader.java \
  elider-core/src/main/java/io/github/spockz/elider/cache/ElisionCacheWriter.java \
  elider-core/src/main/java/io/github/spockz/elider/cache/ElisionDecisionValidator.java \
  elider-core/src/main/java/io/github/spockz/elider/cache/FingerprintEngine.java \
  elider-core/src/main/java/io/github/spockz/elider/cache/FingerprintValues.java \
  elider-core/src/test/java/io/github/spockz/elider/cache/ElisionCacheConcurrencyTest.java \
  elider-core/src/test/java/io/github/spockz/elider/cache/ElisionCacheTest.java \
  elider-benchmarks/src/main/java/io/github/spockz/elider/benchmark/ElisionCacheBenchmark.java \
  elider-core/src/test/resources/vulnerability-mappings/requires-class-v1.json \
  dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenMappingApplicability.java \
  dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenMissingPrerequisite.java \
  dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenTrimOutputWriter.java \
  dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/SourceRepositoryOrigin.java \
  dependency-elider-maven-plugin/src/test/java/io/github/spockz/elider/plugin/MavenAdversarialSourceArchiveFixtures.java \
  dependency-elider-maven-plugin/src/test/java/io/github/spockz/elider/plugin/MavenSourceCorrespondenceTestArtifacts.java \
  dependency-elider-maven-plugin/src/test/java/io/github/spockz/elider/plugin/MavenMultiSourceResolverFixture.java \
  dependency-elider-maven-plugin/src/test/java/io/github/spockz/elider/plugin/CveRecordFormatSchema.java \
  dependency-elider-maven-plugin/src/test/resources/schema/cve-record-format-5.2.0-bundled.json \
  dependency-elider-maven-plugin/src/test/resources/schema/README.md

# Cluster B: Pre-ADR-0014 Raw Scope Evaluators in elider.applicability (10 files)
git rm \
  elider-core/src/main/java/io/github/spockz/elider/applicability/CnaClaimSetValidator.java \
  elider-core/src/main/java/io/github/spockz/elider/applicability/CnaClaimStatusMapper.java \
  elider-core/src/main/java/io/github/spockz/elider/applicability/CnaRangeChangeValidator.java \
  elider-core/src/main/java/io/github/spockz/elider/applicability/CnaRangeClaimEvaluator.java \
  elider-core/src/main/java/io/github/spockz/elider/applicability/CnaRawScopeEvaluator.java \
  elider-core/src/main/java/io/github/spockz/elider/applicability/MavenRawScopeApplicability.java \
  elider-core/src/main/java/io/github/spockz/elider/applicability/OsvRangeEvaluator.java \
  elider-core/src/main/java/io/github/spockz/elider/applicability/OsvRawScopeEvaluator.java \
  elider-core/src/test/java/io/github/spockz/elider/applicability/MavenRawScopeApplicabilityTest.java \
  elider-core/src/test/java/io/github/spockz/elider/applicability/OsvMavenEcosystemIdentityTest.java

# Cluster C: Pre-ADR-0014 Structured Source Proof, Corroboration & Explicit Evidence (19 files)
git rm \
  elider-core/src/main/java/io/github/spockz/elider/model/CorroboratedSourceClassCandidate.java \
  elider-core/src/main/java/io/github/spockz/elider/model/CurrentStructuredClaimSetValidator.java \
  elider-core/src/main/java/io/github/spockz/elider/model/LiveStructuredSourceValidator.java \
  elider-core/src/main/java/io/github/spockz/elider/model/StructuredClaimClassResolver.java \
  elider-core/src/main/java/io/github/spockz/elider/model/StructuredProofProvenance.java \
  elider-core/src/main/java/io/github/spockz/elider/model/StructuredSourceClassEvidence.java \
  elider-core/src/main/java/io/github/spockz/elider/model/StructuredSourceProofRequest.java \
  elider-core/src/main/java/io/github/spockz/elider/model/ExplicitClassMappingEvidence.java \
  elider-core/src/main/java/io/github/spockz/elider/model/ExplicitPrerequisiteEvidence.java \
  elider-core/src/main/java/io/github/spockz/elider/model/VersionScopeMatcher.java \
  elider-core/src/main/java/io/github/spockz/elider/scanner/CnaAffectedEntryCodec.java \
  elider-core/src/main/java/io/github/spockz/elider/scanner/CnaAffectedEntryReader.java \
  elider-core/src/main/java/io/github/spockz/elider/scanner/CnaVersionClaimReader.java \
  elider-core/src/test/java/io/github/spockz/elider/model/LiveStructuredSourceBoundaryTest.java \
  elider-core/src/test/java/io/github/spockz/elider/model/LiveStructuredSourceValidatorTest.java \
  elider-core/src/test/java/io/github/spockz/elider/model/StructuredClaimClassResolverTest.java \
  elider-core/src/test/java/io/github/spockz/elider/model/ExplicitEvidenceTestSupport.java \
  elider-core/src/test/java/io/github/spockz/elider/scanner/AdvisoryEvidenceImmutabilityTest.java \
  elider-core/src/test/java/io/github/spockz/elider/scanner/CorroboratedSourceClassCodecTest.java

# Cluster D: Pre-Compile JavacTask AST Source Scanners & Source Guards (7 files)
git rm \
  dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/JavaSourceReferenceScanner.java \
  dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/SourceRootCompleteness.java \
  dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenSourceDeclarationScanner.java \
  dependency-elider-maven-plugin/src/test/java/io/github/spockz/elider/plugin/JavaSourceReferenceScannerTest.java \
  dependency-elider-maven-plugin/src/test/java/io/github/spockz/elider/plugin/AnalysisEnvironmentCompilerSettingsTest.java \
  dependency-elider-maven-plugin/src/test/java/io/github/spockz/elider/plugin/AnalysisEnvironmentCompilerSettingsTestSupport.java \
  dependency-elider-maven-plugin/src/test/java/io/github/spockz/elider/plugin/AnalysisEnvironmentInheritedUserPropertiesTest.java

# Cluster E, F, G: Over-Engineered Transaction/Journal/Backup/Double-Hash Verifiers (22 files)
git rm \
  dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenOutputTransaction.java \
  dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenOutputFileJournal.java \
  dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenOutputFileMover.java \
  dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenOutputFileCleanup.java \
  dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenOutputTargetPaths.java \
  dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenPreconditionStages.java \
  dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenPreconditionOutputState.java \
  dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenGeneratedOutputManifest.java \
  dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenGeneratedOutputEntry.java \
  dependency-elider-maven-plugin/src/test/java/io/github/spockz/elider/plugin/MavenOutputTransactionTest.java \
  dependency-elider-maven-plugin/src/test/java/io/github/spockz/elider/plugin/ADR0008MavenPreconditionPublicationTest.java \
  dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/TrimOutputGenerationCommitHandle.java \
  dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/TrimOutputGenerationFileOps.java \
  dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/TrimOutputGenerationPublisher.java \
  dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/PreparedOutputPublisher.java \
  dependency-elider-maven-plugin/src/test/java/io/github/spockz/elider/plugin/MavenElisionServiceEffectiveOutputTransactionTest.java \
  dependency-elider-maven-plugin/src/test/java/io/github/spockz/elider/plugin/MavenElisionServiceEphemeralRollbackTest.java \
  dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenBanAuditFreshnessVerifier.java \
  dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenBanPublicationVerifier.java \
  dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenBanFinalOutputVerifier.java \
  dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenBanPublicationGraphVerifier.java \
  dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenBanRetainedProviderClosure.java

# Cluster H: Redundant DirectTrim* / ProGuardTrimEngine Pipeline (11 files)
git rm \
  dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/DirectTrimOutput.java \
  dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/DirectTrimPreparation.java \
  dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/DirectTrimCache.java \
  dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/DirectTrimAnalysis.java \
  dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/DirectArchiveStaging.java \
  dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/DirectCandidatePlanner.java \
  dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/ProGuardTrimEngine.java \
  dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/PassThroughAnalysisLibraries.java \
  dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/TrimOutputCoordinator.java \
  dependency-elider-maven-plugin/src/test/java/io/github/spockz/elider/plugin/NativeImageDirectPublicationInputMutationTest.java \
  dependency-elider-maven-plugin/src/test/java/io/github/spockz/elider/plugin/DuplicateClassDirectTrimTest.java
```

### Step 0.3: Exact Caller Cleanups in `elider-core`

1. [OsvSnapshotIndexer.java](../../elider-core/src/main/java/io/github/spockz/elider/scanner/OsvSnapshotIndexer.java):
   - Remove `import io.github.spockz.elider.applicability.MavenRawScopeApplicability;`.
   - At line 975, replace `MavenRawScopeApplicability.isMavenEcosystem(ecosystem)` with:

     ```java
     ecosystem != null
         && ("maven".equalsIgnoreCase(ecosystem)
             || ecosystem.toLowerCase(Locale.ROOT).startsWith("maven:"))
     ```

   - At line 383, remove the empty `cnaEntries` argument passed to `new OsvAdvisoryRecord(...)`.
2. [AdvisoryEvidence.java](../../elider-core/src/main/java/io/github/spockz/elider/model/AdvisoryEvidence.java):
   - Change the `permits` clause to:
     `permits PackageAdvisoryEvidence, HeuristicCandidateEvidence`
3. [OsvAdvisoryRecord.java](../../elider-core/src/main/java/io/github/spockz/elider/model/OsvAdvisoryRecord.java):
   - Remove the `List<CnaAffectedEntry> cnaAffectedEntries` record component and remove `validateStructuredEntryLink` / `validateCorroboratedEntryLink`. Do not keep a compatibility constructor for this unreleased draft.
4. [AdvisoryEvidenceReader.java](../../elider-core/src/main/java/io/github/spockz/elider/scanner/AdvisoryEvidenceReader.java) & [AdvisoryEvidenceWriter.java](../../elider-core/src/main/java/io/github/spockz/elider/scanner/AdvisoryEvidenceWriter.java):
   - Remove `CnaAffectedEntryReader` / `CnaAffectedEntryCodec` calls and `STRUCTURED_SOURCE_CLASS` / `CORROBORATED_SOURCE_CLASS_CANDIDATE` branches.
5. Clean up test references in:
   - `elider-core/src/test/java/io/github/spockz/elider/model/OmittedCodeProofTest.java` (remove `explicitClassEvidenceRetainsPomOrigin` at lines 47–58).
   - `elider-core/src/test/java/io/github/spockz/elider/model/ADR0008PreconditionProofTest.java` (remove `explicitPrerequisiteEvidenceRetainsPomOrigin` at lines 84–91).
   - `elider-core/src/test/java/io/github/spockz/elider/scanner/AdvisoryEvidenceCodecTest.java`, `OsvSnapshotFixtures.java`, `OsvSnapshotIndexerTest.java`, `VulnerabilityCacheRecordFixture.java`, and `dependency-elider-maven-plugin/src/test/java/io/github/spockz/elider/plugin/MavenAssessmentFixtures.java`: remove test cases/arguments for deleted `StructuredSourceClassEvidence`, `CorroboratedSourceClassCandidate`, `ExplicitClassMappingEvidence`, `ExplicitPrerequisiteEvidence`, and `cnaAffectedEntries`.

### Step 0.4: Exact Caller Cleanups in `dependency-elider-maven-plugin`

1. [ProductionAnalysisInputs.java](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/ProductionAnalysisInputs.java):
   - At lines 77–97, replace the `if (sourceRootsComplete)` branch with throwing `new IOException("elide.sourceRootsComplete is no longer supported; bind elide to process-classes")`.
   - Remove `ProductionOutputFingerprint.fingerprint` double-check at lines 236–239.
2. [MavenPreconditionProviderRoots.java](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenPreconditionProviderRoots.java):
   - Remove `SourceRootCompleteness.hasUnknownSourceGeneration` (lines 74–77).
   - Remove `addSourceRoots` (lines 105–117) and `addSourceProviders` / `MavenSourceDeclarationScanner` (lines 269–288) — at `process-classes`, only compiled output directories (`production-output`, `test-output`, `configured-production-output`) and resource directories (`production-resource`, `test-resource`) are scanned as runtime class/resource providers.
   - Remove `LinkOption.NOFOLLOW_LINKS`, `Files.isSymbolicLink`, and `verifyCapturedRootDigests` double-hashing (lines 80–93, 208–220, 329–388).
3. [AnalyzeMojo.java](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/AnalyzeMojo.java) & [MavenElisionOutputPublisher.java](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenElisionOutputPublisher.java):
   - Remove cross-file transaction/journal/rollback orchestration. Write each report, SBOM, and VEX through a simple same-directory temporary file and replacement so a failed write never exposes a partial file. Keep I/O failures explicit. Document that outputs across different paths are no longer an all-or-nothing transaction.
   - Remove the `MavenGeneratedOutputManifest` and `MavenGeneratedOutputEntry` classes, but retain their required ownership behavior as a small digest-backed registry owned by `MavenGeneratedOutputs`: stale VEX cleanup may delete only a path previously emitted by this plugin whose current bytes still match the recorded digest. Preserve modified or unowned custom outputs and report that choice. Keep the registry's unreleased format at version 1 and reject malformed shapes.
   - Remove duplicate freshness passes, not proof obligations. Validate the complete inventory once from its captured inputs, preserve concrete incompleteness, and run strict ban identity/graph/bytecode/resource/provider absence checks before any report, SBOM, VEX, artifact-view, or resolver-plan publication. Move necessary checks into one clear boundary if their current helper classes are removed.
4. [MavenPreconditionInventory.java](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenPreconditionInventory.java):
   - Remove `MavenPreconditionOutputState`, `MavenPreconditionStages`, and repeated `verifyFresh(...)` rehashing. Keep one complete baseline/final inventory capture and exact provider search.
5. [TrimGenerationPublisher.java](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/TrimGenerationPublisher.java), [EffectiveOutputStaging.java](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/EffectiveOutputStaging.java), [TrimResult.java](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/TrimResult.java):
   - Remove `TrimOutputGenerationPublisher`, `TrimOutputGenerationCommitHandle`, `PreparedOutputPublisher`, and duplicate `verifyEffectiveInputs(...)` rehashing. Keep simple staged archive writes and replacement in the `generation` directory, explicit write failures, and `JarTrimCache.storeCache(...)` after successful output creation.
6. [ElisionReachabilityEngine.java](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/ElisionReachabilityEngine.java), [MavenBanPlan.java](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenBanPlan.java), [MavenElideExecution.java](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenElideExecution.java):
   - Remove repeated `banPlan.verifyAuditBytesFresh()` and `MavenArtifactInventory.verifyPreparedInventory(prepared)` calls inside the loop under ADR-0004's stable-input assumption. Preserve one pre-publication ban check covering supported Maven views, every effective MRJAR tier, alternate class providers, and retained resource/service obligations. Fold the logic of deleted `MavenBanRetainedProviderClosure` into the surviving closure boundary. Remove `requiresTierAwareMrjarTrim(...)` only after its MRJAR proof coverage has migrated to that boundary.
7. [MavenDependencyTrimmer.java](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenDependencyTrimmer.java) & [MavenElisionService.java](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenElisionService.java):
   - Remove `MavenDependencyTrimmer.trim(TrimRequest)` and route `MavenElisionService.finish(PreparedAnalysis)` directly to `finishEffectiveOutputs(finishAnalysis(prepared))`.
   - Call `EffectiveTrimOutput.trimEffectivePrepared(...)` directly instead of `TrimOutputCoordinator.trimPrepared(...)`.
8. Migrate remaining callers before deleting their support classes:
   - `MavenGeneratedOutputs` callers in `MavenTrimOutputWriter`, `ElideMojo`, and `MavenElisionOutputPublisher` still use output defaults, generated paths, stale-output cleanup, and ownership digests. Preserve these contracts in the simplified owner registry.
   - `TrimOutputCoordinator.PendingOutput` and `publishOutputs` are used by `ParallelTrimExecutor`, `EffectiveOutputStaging`, and `DirectArchiveStaging`. Preserve duplicate resolution (`DuplicateClasses.resolveRetained` and `withToleratedDuplicates`), staged-output cleanup, and pass-through behavior when routing directly through `EffectiveTrimOutput`.
   - `MavenElideExecution` and `MavenEffectiveAnalysisReport` own generation handles/cleanup; migrate those paths before removing the handles.
   - Update `EffectiveTrimOutput` and `MavenDependencyTrimmerTest` to exercise the effective route directly, including dynamic-root reuse and upper-tier MRJAR closure.
   - Migrate `MavenBanAuditContextTest` from the removed freshness method while retaining its upper-MR-tier closure scenario.
9. Run `make test-core` and `make test-plugin` to confirm clean compilation and green replacement tests before Slice 1.
10. In [CONTRIBUTING.md](../../CONTRIBUTING.md), remove the runnable `ElisionCacheBenchmark` command and description. Point current cache-benchmark instructions to the existing `MavenTrimCacheBenchmark` and its actual methods, `validatedMavenTrimCacheHit` and `validatedFreshMavenTrimCacheHit`. Preserve the old three-row timing table only under an explicit historical label; do not relabel its measurements as production trim-cache results.

### Step 0.5: Update the Decision and Research Records

Update ADR-0004 to record that resolved inputs are captured once and outputs retain simple per-file replacement safety. Update ADR-0008 and ADR-0012 with the preserved inventory and ban-proof boundaries. Review ADR-0010, ADR-0013, and ADR-0014 for the source-free module, standard-JDK, and strict unreleased-format decisions. Record relevant new evidence in RQ-0003, RQ-0017, RQ-0020, and RQ-0021; leave unrelated RQs untouched. RQ-0003 should state that the obsolete standalone cache benchmark is retired with its dead cache API while the production `MavenTrimCacheBenchmark` remains; preserve the old core-cache measurements as historical only.

---

## 4. Slice 1: Unified Liveness, `closedWorld` Mode vs. ProGuard, and Maximum Sound Trimming

### Step 1.1: Write Failing Tests First (TDD)

Create/update tests in:

- `elider-core/src/test/java/io/github/spockz/elider/trace/JaCoCoTraceReaderTest.java`:
  - Build binary `.exec` input with JaCoCo's execution-data writer; assert a class record with no hit probes is excluded and a hit record is included. XML and CSV are not supported trace inputs.
- `dependency-elider-maven-plugin/src/test/java/io/github/spockz/elider/plugin/ClosedWorldTraceAdmissionTest.java`:
  - With `closedWorld=true`, missing trace configuration, an empty file/list, malformed or truncated data, an unreadable path, a detectably incomplete recording, or a trace containing no classes relevant to the analyzed inventory fails explicitly. A metadata root alone does not satisfy trace admission.
  - Keep source kinds for class-load logs, CDS lists, JFR events, and JaCoCo `.exec`; reports identify which kind was used. JaCoCo is recorded as execution evidence, not complete class-load evidence.
  - Changing mode or the normalized allowed-class set with the same requested roots recomputes closure and produces the same result as a fresh prepared state.
- `elider-core/src/test/java/io/github/spockz/elider/trimmer/DependencyJarTrimmerTest.java`:
  - Assert that calling `analyze(...)` with `retainedRoots = Set.of()` returns `retainedClasses = Set.of()` (`0` retained classes), **not** all classes in the JAR.
  - Assert that service filtering distinguishes unchanged bytes, replacement bytes, and omission. Remove a provider only when no retained archive supplies it; keep duplicate declarations for providers supplied elsewhere and unknown/external provider names. If every known provider is removed, omit the descriptor.
  - Assert **Conservative (`closedWorld = false`) vs. Closed-World (`closedWorld = true`)**:
    - Build a fixture with `jar-a` containing `com.example.LiveA` (which `extends com.example.BaseA` in `jar-a`, has a method `used()` and an unexecuted method `unused()` that calls `com.other.UnusedB.run()` in `jar-b`) and `com.example.DeadA`.
    - When `closedWorld = false` and `LiveA` is in the trace: `LiveA` and `BaseA` are retained in `jar-a`, `DeadA` is trimmed, and `com.other.UnusedB` is in `reachableLibraryClasses()`.
    - When `closedWorld = true` and `LiveA` + `BaseA` are in the allowed set (while `UnusedB` is **not**): retain `LiveA` and `BaseA`, trim `DeadA`, omit `UnusedB`, and allow only a typed body-only unresolved edge to that excluded target. Retain an available untraced superclass/interface through structural traversal. A missing structural target, a missing allowed target, malformed bytecode, and an unclassified extraction failure still fail.
    - Load the transformed archives in a fresh JVM or isolated class loader and invoke `LiveA.used()` with `jar-b` absent. Add a second live class with an uncalled method containing a frame/catch-type relationship. Run representative cases on available standard JDK 21 and 25 installations; document these as workload tests, not universal verification proof.
  - **Observed-workload boundary**: add a closed-world fixture whose untraced method is invoked after trimming and assert the resulting missing-class/linkage failure. Document this as the expected consequence of a user-supplied workload bound; default conservative mode retains static closure.
- `dependency-elider-maven-plugin/src/test/java/io/github/spockz/elider/plugin/SpringMetadataRootsTest.java` & `DependencyDynamicRootsTest.java`:
  - Assert that `META-INF/spring-autoconfigure-metadata.properties` inside a JAR is **ignored** and does not add any owner or `.ConditionalOnClass` classes to dynamic roots.
  - Assert that an unknown external root produces a focused diagnostic and does **not** cause `DynamicRootOrchestrator.dynamicRootArtifactOwners` or `SingleReleaseTrimInventory` to retain unrelated JARs. Preserve recognized Spring factories/imports, services, native-image roots, and resource roots.
- `elider-core/src/test/java/io/github/spockz/elider/trimmer/MultiReleaseArchivePlanTest.java`:
  - For root service descriptors shared across MRJAR tiers, retain provider names viable in any supported effective tier and preserve the root-only `META-INF` behavior.
- `dependency-elider-maven-plugin/src/test/java/io/github/spockz/elider/plugin/MavenElisionServiceEffectiveReportTest.java`:
  - **Cross-JAR reached JAR trimming**: `target/classes` -> `jar-a:LiveA` -> `jar-b:LiveB` (where `jar-b` also has `DeadB` and `DeadB` references `jar-c:DeadC`). Assert `jar-a` and `jar-b` are retained and trimmed to only `LiveA` and `LiveB` (`DeadB` is trimmed out), and `jar-c` is **elided** (because `jar-b` is no longer marked `forcedUnchanged`).
  - **Ancestor-promoted 0-live-class JAR**: `project -> jar-a -> jar-b` (where `jar-a` has `0` live classes and `DeadA -> jar-d:DeadD`, while `jar-b` has `LiveB`). Assert `jar-a` is `ANCESTOR_PROMOTED`, `jar-d` is **elided**, and when `trimJars = true`, `jar-a` is trimmed to `0` `.class` entries while keeping its `META-INF/MANIFEST.MF` and resources.
  - **`closedWorld = true` end-to-end**: With `closedWorld = true`, `jar-b` referenced only from an unexecuted method in `jar-a` (and absent from the trace) is **elided** by `elide` and predicted as elided by `analyze`.
  - **Trim-off parity**: with `trimJars = false`, exercise the same closure and reporting inputs through `analyze` and `elide`; assert no retained archive bytes change, dropped artifacts are absent from the effective view, and class/provider/resource accounting agrees.
  - **Additional effective-output cases**: assert extra physically retained classes remain available to closure, resource-only archives and service/resource roots follow the declared policy, duplicate providers obey both duplicate policies and preserve unmatched-duplicate failure, explicit-retention decisions remain intact, and pass-through inputs are unchanged.
  - **MRJAR analysis/publication parity**: assert `analyze` and `elide` select the same supported base and upper-tier closure, while the published archives preserve effective classes and root-only service descriptors across tiers.

### Step 1.2: Production Implementation for Slice 1

1. **Drop `SpringMetadataRoots.readMetadata` & `SPRING_METADATA`**:
   - In [SpringMetadataRoots.java](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/SpringMetadataRoots.java): Delete lines 17–26 (`CONDITIONAL_MARKER`, `ORDERING_MARKERS`, `WEB_APPLICATION_TYPES`) and lines 72–178 (`readMetadata` and all its helpers).
   - In [DependencyDynamicRoots.java](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/DependencyDynamicRoots.java): Delete `SPRING_METADATA` (line 29), `jarClasses` (lines 214, 226), and the `else if (SPRING_METADATA.equals(name))` branch (lines 268–272).
2. **Drop Unresolved Dynamic-Root Keep-All Poison Pills**:
   - In [DynamicRootOrchestrator.java](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/DynamicRootOrchestrator.java):
     - Delete lines 99–101 (`if (effective.declaresRoots()) { declaringArtifacts.add(candidate.coordinate()); }`) so `declaringArtifacts` only contains archives where `scan.requiresArtifactRetention()` is true.
     - Delete lines 240–242 (`if (!unresolvedRoots.isEmpty()) { inventory.stream().map(ArtifactFileRef::coordinate).forEach(result::add); }`).
   - In [SingleReleaseTrimInventory.java](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/SingleReleaseTrimInventory.java):
     - In `DynamicRootContext.route` (lines 338–345), when `owner == null`, simply `return;` (delete `droppedArtifacts.addAll(droppedArtifactCoordinates(inventory, layout));` and delete helper `droppedArtifactCoordinates` at lines 276–282).
   - In [TierRootResolution.java](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/TierRootResolution.java):
     - In `addDynamicRoot` (lines 121–128), delete the `if (!found ...)` block that adds unretained candidates to `reachableArtifacts`.
3. **Drop Empty-Root -> 100%-Classes Fallbacks & `forcedUnchanged` Promotion Inflation**:
   - In [PreparedAnalysisState.java](../../elider-core/src/main/java/io/github/spockz/elider/trimmer/PreparedAnalysisState.java):
     - At lines 82–85, change:

       ```java
       if (roots.isEmpty()) {
         return new DependencyJarTrimmer.TrimAnalysis(
             candidateClassNames.size(), Set.of(), Set.of(), Set.of());
       }
       ```

   - In [SingleReleaseTrimInventory.java](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/SingleReleaseTrimInventory.java):
     - Delete lines 374–376 (`if (roots.isEmpty()) { roots.addAll(inventory.classesByArtifact().getOrDefault(candidate, Set.of())); }`).
   - In [TierCandidatePlanner.java](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/TierCandidatePlanner.java):
     - Delete lines 56–58 (`if (roots.isEmpty() && !targetClasses.isEmpty()) { roots.addAll(targetClasses); }`).
   - In [ElisionReachabilityEngine.java](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/ElisionReachabilityEngine.java):
     - Delete `forcedUnchanged.addAll(newlyReachedDrops);` (line 104) and `addUnchangedPolicyArtifacts(evaluation, forcedUnchanged);` (lines 105, 121, 139–143).
     - When `newlyReachedDrops` are promoted in `finishAnalysis`, merge `DiscoveredTrimRoots.from(prepared.resolvedSnapshots(), analysis.candidateRoots())` into `discoveredRoots` and re-run `analyzeInMemory` with the newly promoted JARs treated as trimmable candidates (not `forcedUnchanged`).
     - After the reachability loop converges, any retained JAR that has `0` live classes (such as an `ANCESTOR_PROMOTED` JAR) keeps `retainedClasses = Set.of()` when `trimJars = true` so `SingleReleaseArchiveWriter` strips all its `.class` entries while keeping its manifest and resources.
4. **Fix `JaCoCoTraceReader` & Service Descriptor Filtering**:
   - In [JaCoCoTraceReader.java](../../elider-core/src/main/java/io/github/spockz/elider/trace/JaCoCoTraceReader.java) at lines 48–55:

     ```java
     for (final CoverageRecord record : records) {
       if (!record.hasHits()) {
         continue;
       }
       final String className = TraceData.normalizeToDot(record.className());
       loadedClasses.add(className);
       ...
     ```

   - Replace the ambiguous `Optional<byte[]>` result from `ServiceDescriptorFilter` with an explicit result representing unchanged, replacement bytes, or omission. An unchanged descriptor is copied as-is; replacement writes the filtered bytes; omission skips the entry.
   - Pass the global retained provider set to both `SingleReleaseArchiveWriter` and `MultiReleaseArchiveWriter`, assembled across all artifacts and effective MRJAR tiers. Preserve an external/unknown provider and any declaration whose provider class survives in another archive. Do not emit versioned `META-INF` descriptors.
5. **Implement `closedWorld` Mode in `elider-core` and `dependency-elider-maven-plugin`**:
   - In [ProGuardReferenceVisitors.java](../../elider-core/src/main/java/io/github/spockz/elider/trimmer/ProGuardReferenceVisitors.java):
     - Add visitors that collect structural reference evidence, including:
       - Superclass and interfaces (`new ClassHierarchyTraveler(false, true, true, false, classVisitor)`),
       - Field and method descriptors (`new AllMemberVisitor(new MemberDescriptorReferencedClassVisitor(classVisitor))`),
       - Class and member `Signature` attributes (`new AllAttributeVisitor(true, new SignatureAttributeReferencedClassVisitor(classVisitor))`),
       - Exception handler `catch_type` constants (`new AllMethodVisitor(new AllAttributeVisitor(new AllExceptionInfoVisitor(new ExceptionHandlerConstantVisitor(new ReferencedClassVisitor(classVisitor)))))`).
     - These visitor categories do not prove universal JDK verification safety. Keep trace trimming workload-scoped and preserve default static closure.
   - In [ReferenceGraph.java](../../elider-core/src/main/java/io/github/spockz/elider/trimmer/ReferenceGraph.java) & [ReferenceGraphIndexer.java](../../elider-core/src/main/java/io/github/spockz/elider/trimmer/ReferenceGraphIndexer.java):
     - Store structurally typed reference edges and unresolved evidence (source class, target class, and reference kind), rather than only target-name sets and formatted diagnostic strings. Preserve full-reference edges for conservative traversal.
   - In [PreparedAnalysisState.java](../../elider-core/src/main/java/io/github/spockz/elider/trimmer/PreparedAnalysisState.java):
     - Distinguish conservative mode from a closed-world query with an explicit API such as `Optional<Set<String>>`: absent policy means conservative static traversal; present policy means trace-bounded traversal, including a deliberate empty set. Do not overload empty roots or `null` to switch modes.
     - Traverse structural references unconditionally and non-structural references only when their target is in the normalized allowed set. Suppress an unresolved target only when typed evidence classifies it as an excluded body-only reference; structural, allowed-target, malformed, and unclassified failures remain errors.
     - Recompute closure when roots, mode, or allowed set changes. Reuse requires the full normalized query identity, not root equality alone.
   - Preserve trace kind through `RuntimeTraceReader`/`CompositeTraceReader` and the analysis model. Reject closed-world mode with no trace input, empty/malformed/unreadable/incomplete data, or no relevant application/dependency classes. JaCoCo `.exec` contributes hit classes only and remains explicitly labeled execution evidence.
   - Expose `<closedWorld>` (`@Parameter(property = "elide.closedWorld", defaultValue = "false") boolean closedWorld`) on `ElideMojo` and `AnalyzeMojo`; thread the mode and allowed set through `ElisionAnalysisModel`, `MavenElisionPolicyIdentity`, `MavenAnalysisPreparation`, and `SingleReleaseClosureAnalyzer` / `TierClosureAnalyzer`. Cache identity includes trace evidence kind and the normalized allowed-class set.
   - Save the selected mode and evidence kind/boundary in the report so `report` replay shows the same analysis contract. Keep persisted report schema at version 1 while unreleased; update its writer, reader, validator, fixture, and documentation together.

---

## 5. Slice 2: Supplemental Evidence Scope vs. Affected Assertions & Shared Maven Mapping Catalog

### Step 2.1: Write Failing Tests First (TDD)

- `elider-core/src/test/java/io/github/spockz/elider/model/GenericVulnerabilityFindingTest.java`:
  - Test a contribution with `VersionCoverageClaim.evidenceScope("[1.5.18]")` and `PrerequisiteClaim("org.codehaus.janino:janino", "org.codehaus.janino.ClassBodyEvaluator")` merged with independent OSV/CVE affected-version assertions. The example catalog is limited to the Logback versions inspected in the preserved research; broader class/version scope requires new bytecode and advisory review recorded in RQ-0020/RQ-0021.
    - Reports `applicability("1.5.18") == AFFECTED` and `effectivePrerequisitesFor("1.5.18")` contains Janino.
    - Add explicit unaffected claims for Logback 1.5.19 and 1.3.16, then assert those versions are `NOT_AFFECTED`; the broad supplemental scope alone cannot assert a negative result.
  - Test that scope-only contributions inside and outside their scope return a distinct `NO_AFFECTED_ASSERTION` result, never establish `AFFECTED` or `NOT_AFFECTED`, and cannot emit VEX. Scope supplies supplemental fields only when an independent contribution establishes `AFFECTED`. An unaffected-only assertion returns `NOT_AFFECTED` only inside its asserted range; outside that range, absent a matching affected, unresolved, or explicit unaffected assertion, the result is `NO_AFFECTED_ASSERTION`. Fixed Logback versions 1.3.16 and 1.5.19 remain explicitly unaffected through their own claims.
  - Include the original regression shape: an evidence-only scope `(,1.6.0)` overlaps independently asserted vulnerable ranges but extends beyond them. Versions 1.5.18, 1.5.19, and 1.3.16 follow only the independent affected/unaffected assertions; the supplemental scope neither fills the affected-range gaps nor creates a negative assertion by itself.
  - Test affected-applicability precedence: a matching supported affected assertion remains `AFFECTED` despite overlapping unaffected or unresolved assertions (the unresolved group still blocks verification); with no matching affected assertion, an applicable unresolved assertion returns `UNRESOLVED`; an unaffected-only matching assertion returns `NOT_AFFECTED`; evidence-scope-only input returns `NO_AFFECTED_ASSERTION`.
  - Test priority ordering: `MergePriority.MANUAL` (POM) > `MergePriority.CATALOG` > `MergePriority.AUTOMATIC` independently for `codeGroup` and prerequisite groups, regardless of contribution list order. Cover reordered and duplicate rows, overlapping and disjoint scopes, POM supplied/omitted/empty groups, same-priority operator conflicts, and manual `REVIEW_ONLY` intent overriding catalog intent.
- `elider-core/src/test/java/io/github/spockz/elider/scanner/VulnerabilityMappingCatalogCodecTest.java`:
  - Test reading, writing, and validating `META-INF/elider/vulnerability-mappings.json` (`schemaVersion: 1`), rejecting unsupported schema, malformed top-level containers, missing resources, invalid catalog IDs, duplicate row IDs, and systemic decode failures explicitly. Require stable `mappingId` per row; preserve advisory-only vulnerability IDs and aliases, component `type`/`classifier`, affected versus evidence-scope ranges, class/file/routine code locators, prerequisite groups, confidence, review intent, and advisory URI. LOW/MEDIUM confidence maps to `REVIEW_ONLY`; HIGH confidence does not itself grant proof eligibility, and an explicit review-only intent remains review-only. Preserve omitted fields versus explicitly empty arrays through round-trip. Deduplicate equivalent semantic rows independent of order while preserving all provenance. Preserve ambiguous alias relationships for the common reconciler, which retains disputed CVEs separately and marks ambiguous identities review-only. A malformed row may preserve unrelated valid rows for review with `PARTIAL` source health; source health alone does not alter proof eligibility. Any selected incomplete or malformed declaration blocks proof under the same common declaration-completeness rules for catalog, POM, and automatic findings.
- `dependency-elider-maven-plugin/src/test/java/io/github/spockz/elider/plugin/MavenVulnerabilityMappingCatalogTest.java`:
  - Test resolving only explicitly configured data-only catalog coordinates via Maven `RepositorySystem`; require a concrete released version and reject ranges, `LATEST`/`RELEASE`, and `-SNAPSHOT` coordinates so adoption is reproducible. Cover a locally pinned artifact, cached offline success, required missing-artifact/offline-cache failure (never empty success), and exact version/type/classifier selection. Deduplicate repeated configured coordinates so each artifact resolves once. Across distinct catalogs, deduplicate byte-equivalent rows independent of order while retaining all source provenance; a reused `mappingId` with different semantic fields is an unresolved mapping conflict, never order-wins. Assert isolation from application dependencies, compile/runtime classpaths, `PreconditionClassInventory`, packaged libraries, and CycloneDX components. Save the selected catalog GAV/type/classifier, computed artifact SHA-256, schema version, row IDs, advisory URIs, exclusions, and adoption provenance in report evidence; `report` replay uses saved evidence without resolving the catalog again, even after repository bytes change or disappear.
  - Cover missing metadata resource, corrupt artifact/container, unsupported schema, duplicate row IDs, malformed rows/`PARTIAL` status, advisory-only identity and alias bridges, exact digest recording, and unchanged common physical-proof gating. The computed digest records observed artifact bytes; it is not treated as publisher authentication or compared to a fabricated expected digest. Verify one mapping containing both vulnerable-code and prerequisite fields preserves their independent scopes and provenance.
  - Add a valid row plus an unrelated malformed row: source health is `PARTIAL`, but the valid row receives the same assessment and proof eligibility as the same complete declaration from POM or automatic input. A malformed/ambiguous effective row remains unresolved under the common declaration-completeness rule, independent of source.

### Step 2.2: Production Implementation for Slice 2

1. **Supplemental Evidence Scope (`VersionCoverageClaim` & `GenericVulnerabilityFinding`)**:
   - In [VersionCoverageClaim.java](../../elider-core/src/main/java/io/github/spockz/elider/model/VersionCoverageClaim.java):
     - Add `public static VersionCoverageClaim evidenceScope(final String mavenRange)` using `VersionApplicability.EVIDENCE_SCOPE`.
     - Add `VersionApplicability.NO_AFFECTED_ASSERTION` as a result distinct from `NOT_AFFECTED`. It is a query result, not a persisted claim status; strict readers reject it inside a `VersionCoverageClaim`.
   - In [GenericVulnerabilityFinding.java](../../elider-core/src/main/java/io/github/spockz/elider/model/GenericVulnerabilityFinding.java):
     - `applicability(final String version)` considers independently asserted `AFFECTED`, explicit `NOT_AFFECTED`, and `UNRESOLVED` ranges in this order: a matching supported affected assertion returns `AFFECTED`; otherwise an applicable unresolved assertion returns `UNRESOLVED`; otherwise a matching explicit unaffected assertion returns `NOT_AFFECTED`; otherwise return `NO_AFFECTED_ASSERTION`. Omission outside an affected range is not proof of inapplicability because no completeness marker exists; this follows the source-independent scope contract in [ADR-0014](../adr/0014-source-independent-vulnerability-findings.md).
     - For a matching affected contribution with a matching unresolved predicate, retain the known code/prerequisite declarations for reporting, mark each supplied affected group `UNRESOLVED`, and refuse aggregate proof for that group. A matching unresolved manual contribution selects its supplied groups ahead of lower-priority automatic groups even when it has no matching affected predicate of its own; preserve those manual declarations for review. An omitted manual group remains eligible for lower-priority enrichment, consistent with [ADR-0014](../adr/0014-source-independent-vulnerability-findings.md). Keep proof eligibility tied to each selected group status and overall applicability.
     - `positivelyApplicable(...)` may use `EVIDENCE_SCOPE` to supply supplemental fields only when merged applicability is independently `AFFECTED`; an evidence-scope-only finding never becomes reassuring or proof-bearing.
     - Propagate `NO_AFFECTED_ASSERTION` through assessment, report schema-v1 writer/reader/validator/renderers, fixtures, and docs. It produces no CycloneDX or OpenVEX VEX statement.
   - In [ManualVulnerabilityMappingContributionAdapter.java](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/ManualVulnerabilityMappingContributionAdapter.java):
     - Add `boolean assertsAffected` (default `false`) to `VulnerabilityMappingConfig`. When `assertsAffected == false` (the default for supplemental code/prerequisite mappings), emit `VersionCoverageClaim.evidenceScope(spec)`; when `assertsAffected == true`, emit `VersionCoverageClaim.affected(spec)`.
2. **Add `CATALOG` Priority & Origin**:
   - In [MergePriority.java](../../elider-core/src/main/java/io/github/spockz/elider/model/MergePriority.java): Add `CATALOG` between `AUTOMATIC` and `MANUAL`.
   - In [EvidenceOrigin.java](../../elider-core/src/main/java/io/github/spockz/elider/model/EvidenceOrigin.java): Add `CATALOG`.
   - In [GenericVulnerabilityFinding.java](../../elider-core/src/main/java/io/github/spockz/elider/model/GenericVulnerabilityFinding.java): resolve supplied groups by scoped field priority: `MANUAL` first, then `CATALOG`, then `AUTOMATIC`. Omitted fields can be enriched from a lower-priority source; explicit empty fields clear lower-priority values. Review intent is resolved independently and a manual LOW/MEDIUM `REVIEW_ONLY` policy cannot be bypassed by catalog confidence.
3. **Implement `VulnerabilityMappingCatalog` in `elider-core` & Resolver in Plugin**:
   - Create `elider-core/src/main/java/io/github/spockz/elider/scanner/VulnerabilityMappingCatalog.java` reading/writing `META-INF/elider/vulnerability-mappings.json`:

     ```json
     {
       "schemaVersion": 1,
       "catalogId": "io.github.spockz:elider-vulnerability-mappings",
       "mappings": [
         {
           "vulnerabilityId": "CVE-2025-11226",
           "aliases": [],
           "mappingId": "logback-cve-2025-11226-classbodyevaluator-1.5.18",
           "advisoryUri": "https://nvd.nist.gov/vuln/detail/CVE-2025-11226",
           "groupId": "ch.qos.logback",
           "artifactId": "logback-core",
           "type": "jar",
           "classifier": "",
           "versionClaims": [
             {
               "range": "[1.5.18]",
               "status": "EVIDENCE_SCOPE"
             }
           ],
           "confidenceLevel": "HIGH",
           "intent": "AUTO_VERIFY",
           "prerequisiteGroups": [
             {
               "operator": "ANY_OF",
               "members": [
                 {
                   "requiresDependency": "org.codehaus.janino:janino",
                   "requiresClass": "org.codehaus.janino.ClassBodyEvaluator"
                 }
               ]
             }
           ]
         }
       ]
     }
     ```

     - Add a separate stable row for the inspected `1.5.11` Logback version with a `versionClaims` entry `{ "range": "[1.5.11]", "status": "EVIDENCE_SCOPE" }`; do not widen the evidence scope to all versions below a release boundary without new review. The schema must preserve the current `VulnerabilityFindingContribution` contract, including advisory-only IDs and aliases, GAV type/classifier, source-version claims, class/file/routine `CodeReference`s, confidence label, `AssessmentIntent`, optional code/prerequisite groups, and missing-versus-explicitly-empty fields. `codeGroup` is an optional array of declared/heuristic claim kind and reference kind/value/original spellings; `prerequisiteGroups` is an optional array of atomic operator/member groups. Omission maps to `FieldValue.omitted()` and an empty array maps to `FieldValue.supplied(emptySet())`.

   - Create `dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenVulnerabilityMappingCatalogResolver.java` using the configured Maven session and `RepositorySystem` to resolve only explicitly adopted coordinates (`groupId:artifactId:version[:type[:classifier]]`). Fail missing required artifacts and malformed/missing/unsupported containers explicitly. Compute and persist the resolved artifact SHA-256 as observed provenance; do not claim it authenticates a publisher or compare it with an unspecified expected digest. Emit contributions with `MergePriority.CATALOG`, `EvidenceOrigin.CATALOG`, stable catalog/row identity, and advisory URI in catalog source provenance. Persist a separate typed catalog-adoption observation, including empty catalogs, for report replay. The artifact remains a build input, not an application dependency or executable provider.
   - No catalog-exclusion configuration or precedence policy is defined yet. Persist an empty exclusions list while none are configured; do not derive catalog exclusions from local POM overrides.

---

## 6. Slice 3: Baseline vs. Final Inventory Capture, `ALL_OF`/`ANY_OF` Prerequisites, Trimmed-Class Proof & Attribution

### Step 3.1: Write Failing Tests First (TDD)

- `elider-core/src/test/java/io/github/spockz/elider/model/ADR0008PreconditionProofTest.java`:
  - **Trimmed-class prerequisite proof**: Affected `logback-core` is retained and the `org.codehaus.janino:janino` coordinate remains, but the reviewed required class `org.codehaus.janino.ClassBodyEvaluator` is absent from the actual staged Janino archive and all other providers. Assert proof succeeds only after inspecting the staged bytes; coordinate retention alone does not block a class-specific prerequisite proof. Add the inverse case where `ScriptEvaluator` is absent but `ClassBodyEvaluator` remains; proof must fail.
  - **Atomic prerequisite groups**: Keep operator, complete member set, version scope, priority, review intent, and row provenance together through reconciliation. Use `PrerequisiteGroup(operator, members)` as one supplied field. POM supplied groups replace catalog/automatic groups in their matching scope, omitted groups permit enrichment, and explicit empty groups clear lower-priority groups. Deduplicate identical groups independent of order; retain distinct groups as separate proof obligations rather than flattening their members or operators. Incompatible same-priority overlapping groups are unresolved, never order-wins.
  - **Conjunctive (`ALL_OF`) vs. alternative (`ANY_OF`)**:
    - Preserve the current all-declarations-absent rule as the default `ANY_OF`: with members `[P1, P2]`, one present member prevents proof; both absent permits proof.
    - `ALL_OF` explicitly means all members are jointly required: one absent member disarms that group. Every effective group must be disarmed before VEX proof.
    - Test identical and reordered rows, overlapping and disjoint scopes, same-priority conflicting operators, a scoped POM override, an omitted POM group enriched from catalog, explicit empty POM group, and LOW manual review intent overriding catalog AUTO_VERIFY.
  - **Baseline vs. Actual Staged Final Attribution**:
    - Absent in baseline and absent in final -> `PrerequisiteAbsenceAttribution.ALREADY_ABSENT`.
    - Present in baseline and absent from actual final bytes because all providers' owning archives were dropped -> `PrerequisiteAbsenceAttribution.ELIDED_DEPENDENCY`.
    - Present in baseline and absent from actual final bytes because an owning archive remains but the exact class was removed from its staged contents -> `PrerequisiteAbsenceAttribution.TRIMMED_CLASS`.
    - If duplicate baseline providers disappear through different routes (for example, one archive is dropped and another is trimmed), report `MIXED` and retain provider-level outcomes.
    - If either baseline or actual final inventory is incomplete, attribution is `UNKNOWN`; coordinate-only predictions cannot establish a cause.
  - If baseline is incomplete but actual final inventory is complete and proves all required classes absent, permit the physical VEX proof while reporting `UNKNOWN` attribution and the baseline refusal reason. If actual final inventory is incomplete, suppress proof.
  - Add duplicate/shaded-provider cases: any provider retaining the exact class makes that member present. Evaluate the complete atomic group's operator afterward; a present member blocks `ANY_OF` but does not block `ALL_OF` proof if another jointly required member is absent. Include `ALL_OF(P1 present through a duplicate provider, P2 absent)` and assert proof succeeds, while `ANY_OF` over the same member states fails.
  - Add a test-only provider case: an exact class present only in isolated test sources/classes/resources does not affect the runtime inventory. Proof succeeds while normal `testCompile` and `testResources` can run. Test output overlapping production output suppresses proof.

### Step 3.2: Production Implementation for Slice 3

1. **Add `PrerequisiteOperator` (`ALL_OF`, `ANY_OF`), atomic `PrerequisiteGroup`, and `PrerequisiteAbsenceAttribution`**:
   - Create `elider-core/src/main/java/io/github/spockz/elider/model/PrerequisiteOperator.java` (`ALL_OF`, `ANY_OF`), with `ANY_OF` as the compatibility default.
   - Create `PrerequisiteGroup` containing the operator and complete immutable member set. Store atomic groups in a supplied `FieldValue<Set<PrerequisiteGroup>>`; a supplied empty set explicitly clears lower-priority groups. The contribution's version claims, merge priority, assessment intent, stable row/source provenance remain bound to its groups through scoped reconciliation.
   - Create `elider-core/src/main/java/io/github/spockz/elider/model/PrerequisiteAbsenceAttribution.java` (`ALREADY_ABSENT`, `ELIDED_DEPENDENCY`, `TRIMMED_CLASS`, `MIXED`, `PRESENT`, `UNKNOWN`). Keep each claim's provider-based outcome so `MIXED` can be explained.
   - Default legacy/single-field mappings to `ANY_OF`, preserving today's behavior that every effective prerequisite pair must be absent. An explicit `ALL_OF` mapping opts into a new conjunctive contract and must be documented in ADR-0008/ADR-0014.
2. **Fix `PreconditionProof.java` (`:107-136`) for Trimmed Classes, `ALL_OF`/`ANY_OF`, and Attribution**:
   - In [PreconditionProof.java](../../elider-core/src/main/java/io/github/spockz/elider/model/PreconditionProof.java):
     - A pair's class is present iff the exact class appears in any provider in the inspected physical inventory. The declared coordinate remains part of the atomic evidence and attribution, but a retained archive does not refute that pair's absence when the class is absent from its actual staged bytes and every other provider.
     - For `ALL_OF`, a group is disarmed when at least one member class is absent. For `ANY_OF`, it is disarmed only when every member class is absent. Every effective group must be disarmed; same-priority operator conflicts remain unresolved.
     - Compare exact provider identities from complete baseline and actual staged final inventories. Derive `ALREADY_ABSENT`, `ELIDED_DEPENDENCY`, `TRIMMED_CLASS`, or `MIXED` from all duplicate providers and per-claim causes. If either inventory is incomplete, report `UNKNOWN`. Never infer physical absence or attribution from predicted coordinates/classes alone.
3. **Preserve Incomplete Inventory Diagnostics in `MavenVulnerabilityAssessment.java`**:
   - At [MavenVulnerabilityAssessment.java](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenVulnerabilityAssessment.java) lines 273–278, when `preconditionInventory != null && !preconditionInventory.classProviders().complete()`, pass `preconditionInventory.classProviders().detail()` into `GenericFindingAssessment` so the user and report JSON see the exact reason why the inventory was incomplete.

---

## 7. Slice 4: Decoupled Report/SBOM/VEX Publication & `analyze`/`elide`/`report` Parity

### Step 4.1: Write Failing Tests First (TDD)

- Integration tests in `MavenElisionOutputPublisherTest` / `ElideMojoTest` / `AnalyzeMojoTest`:
  - `elide` with `trimJars = false` captures the actual effective runtime providers after whole-artifact decisions. It proves `CVE-2025-11226` against selected physical bytes, writes matching report/CycloneDX/OpenVEX outputs, and leaves retained original `.jar` bytes untouched. Analyze can also prove current physical absence when the complete current runtime inventory is opted in; only absence that depends on its planned elision remains a prediction. Analyze does not publish VEX files.
  - With trimming enabled, capture staged archive bytes and inspect their classes/resources/providers, retained originals, dropped archives, application outputs, shaded and duplicate providers, and effective MRJAR tiers before constructing a verified VEX attestation. Mutate a staged archive after predicted analysis so it retains the required class; assert proof is suppressed and no VEX/report generation presents predicted absence as physical proof.
  - Analyze reports current physical prerequisite proof only from its complete, opted-in runtime inventory. Planned final absence remains a labeled prediction and never becomes physical proof. An incomplete current inventory suppresses proof with its refusal reason; an incomplete baseline affects causal attribution only.
  - An incomplete baseline with a complete actual staged final inventory still allows final absence proof but reports `UNKNOWN` attribution; an incomplete final inventory suppresses VEX proof.
  - Groups with prerequisites absent for different baseline/elision/trimming reasons report `MIXED` plus provider-level outcomes. A provider makes its exact member present; apply the selected group operator to the full member-state set, including alternate, shaded, application, retained, duplicate, and MRJAR providers.

### Step 4.2: Production Implementation for Slice 4

1. [ElideMojo.java](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/ElideMojo.java):
   - At line 272, change `final boolean preconditionInventoryComplete = trimJars && preconditionClassPathComplete;` to `final boolean preconditionInventoryComplete = preconditionClassPathComplete;`.
   - Attempt the complete baseline inventory whenever `preconditionClassPathComplete` is enabled. Baseline incompleteness supplies `UNKNOWN` attribution but does not by itself block final absence proof. After all trim outputs are staged and the effective Maven view is known, inspect actual staged archive bytes plus retained originals/application providers and exclude dropped archives; an incomplete final inventory suppresses VEX. With `trimJars=false`, inspect the unchanged retained archive bytes and the effective view after whole-artifact elision. Physical archive replacement remains gated by `trimJars`.
2. [AnalyzeMojo.java](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/AnalyzeMojo.java):
   - At lines 327–333, capture baseline and predicted post-elision `MavenPreconditionInventory` from `effectiveAnalysis` instead of passing `null`. Reports mark these as predictions and do not create verified CycloneDX/OpenVEX attestations; only `elide` inspects actual staged bytes for that claim.
3. [MavenElisionOutputPublisher.java](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenElisionOutputPublisher.java):
   - At lines 106–288, remove the `if (request.files().trimJars())` guard around SBOM (`generateSbom` / `sbomOutput`), OpenVEX generation/stale cleanup, and report publication. Only physical JAR path replacement (`applyArtifactChanges` / trimmed JAR file swapping) depends on `trimJars`.
   - If no VEX attestations remain, clear only an unchanged plugin-owned VEX path using the digest registry specified in Slice 0. Preserve and warn about modified or unowned configured outputs; do not call `Files.deleteIfExists` on an arbitrary path.
   - Construct VEX only from the complete actual staged-final inventory and exact affected-component bytes. The ban check and prerequisite proof consume the same staged view before report/SBOM/VEX files, artifact views, or resolver plans are published.
4. **Update Report Payload, Validator, and Renderers (Schema v1)**:
   - Add `prerequisiteAttribution` (`ALREADY_ABSENT`, `ELIDED_DEPENDENCY`, `TRIMMED_CLASS`, `MIXED`, `PRESENT`, `UNKNOWN`) and per-claim outcomes to `GenericFindingAssessment`, `MavenElisionReportGenericPayload`, `MavenElisionReportPayloadValidator`, and `MavenElisionReportGenericRenderer` (keeping schema version `1` per `AGENTS.md`).
   - Ensure console summary and report distinguish baseline absence, elision, trimming, and mixed causes. Preserve the exact incomplete-inventory reason and proof boundary.
   - Remove ownership claims that depend only on a Maven coordinate; report providers and attribution from observed class identity in baseline/final inventories.

---

## 8. Slice 5: Default `process-classes` Lifecycle, Source-Free Modules, and Packaging Guard

### Step 5.1: Write Failing Tests First (TDD)

- Update/add tests in `EliderPluginConfigurationTest`, `MavenPreconditionGenerationGuardTest`, and `LifecycleIT`:
  - Default phase of `elide` is `process-classes` when `<phase>` is omitted.
  - `EliderLifecycleParticipant` orders `elide` at the tail of `process-classes` (`priority = Integer.MAX_VALUE`).
  - A module with `0` `.java` source files and an absent or empty `target/classes` directory succeeds at `process-classes`.
  - `MavenPreconditionGenerationGuard` allows builds stopping at `process-classes` even when `package` has untrusted plugins, accepts known `spring-boot-maven-plugin:repackage` packaging, and resolves omitted `<phase>` on `dependency-elider-maven-plugin` to `process-classes`. A direct `elide` goal can capture proof when `elide.productionClassesComplete=true` asserts complete compiled output; lifecycle origin alone does not authorize or block physical proof.
  - A prerequisite class present only in isolated test output does not suppress runtime proof, even when test compilation/resources remain active. Test output routed into production roots suppresses proof. `-DskipTests=true` remains required when test execution follows capture; `-Dmaven.test.skip=true` is unnecessary.
  - An explicit `elide.sourceRootsComplete=true` invocation fails with the supported migration guidance to use `process-classes` and compiled production output.
  - Add real Maven fixtures, not priority-only unit assertions: an event-recording execution proves `elide` runs after compiler/AOT work at the tail of `process-classes`; a small multi-module reactor includes a source-free module; a package-bound plugin after the requested `process-classes` boundary does not block; the default lifecycle and `dependency:tree` invocations exercise their actual plugin behavior; and an explicit user phase binding is preserved and ordered according to that binding.

### Step 5.2: Production Implementation for Slice 5

1. **Switch Default Phase to `process-classes`**:
   - [ElideMojo.java](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/ElideMojo.java) line 25: Change `defaultPhase = LifecyclePhase.INITIALIZE` to `defaultPhase = LifecyclePhase.PROCESS_CLASSES`.
   - [EliderPluginConfiguration.java](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/EliderPluginConfiguration.java) line 74: Change default `phase` when `configuredPhase` is null/blank from `INITIALIZE_PHASE` to `PROCESS_CLASSES_PHASE`.
   - [EliderLifecycleParticipant.java](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/EliderLifecycleParticipant.java) line 63: When `PROCESS_CLASSES_PHASE.equals(phase)`, set `execution.setPriority(Integer.MAX_VALUE)` so `elide` runs at the tail of `process-classes` after compilers and AOT processors.
   - [EliderGoalOrder.java](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/EliderGoalOrder.java) lines 37–43, [EliderTreePreparation.java](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/EliderTreePreparation.java) line 66, and [BanishedDependencyLifecycleActivation.java](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/BanishedDependencyLifecycleActivation.java) line 74: Default implicit phase to `process-classes`.
2. **Support Source-Free Modules at `process-classes`**:
   - In [ProductionBytecodeAnalysis.java](../../elider-core/src/main/java/io/github/spockz/elider/scanner/ProductionBytecodeAnalysis.java) lines 92–94: When `Files.notExists(normalizedOutput)`, return a complete empty snapshot (`new BytecodeReferenceScan(normalizedOutput, 0, Set.of(), true)`) instead of `incomplete`.
   - In [ProductionAnalysisInputs.java](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/ProductionAnalysisInputs.java) lines 228–233: Only throw when `classFilesScanned() == 0` if the project actually has existing `.java` files under `project.getCompileSourceRoots()`; if the module has no `.java` source files, `0` scanned class files is valid and complete.
3. **Fix `MavenPreconditionGenerationGuard.java`**:
   - At lines 1212–1245: Move `if (phaseIndex > requestedPhaseIndex) { return; }` **above** the `if (trustedProcessClasses && phaseIndex > PROCESS_CLASSES_PHASE_INDEX)` block so plugins bound to later phases (`package`) do not fail a build that stops at `process-classes`.
   - At lines 1308–1343: When `execution.getPhase()` on `dependency-elider-maven-plugin` is null/blank, default it to `process-classes` (`PROCESS_CLASSES_PHASE`).
   - Remove `isSkippedTestCompiler` and the requirement to skip `testCompile`. Exclude the separate test output root from runtime inventory, reject output overlap/custom test compiler settings that can redirect into production, and retain `skipTests=true` for tests that would execute after capture.
   - Recognize `org.springframework.boot:spring-boot-maven-plugin` goal `repackage` at `package` as a known packager boundary.

---

## 9. Slice 6: Examples, Real-Snapshot Verification, ADRs/RQs & Transcripts

1. **Install/Configure Shared Vulnerability Mapping Catalog for Examples**:
   - Create a shared schema-v1 catalog fixture with stable row IDs and the reviewed `org.codehaus.janino.ClassBodyEvaluator` prerequisite for the inspected Logback Core versions 1.5.11 and 1.5.18 only. Do not claim the class is necessary for all versions below 1.6.0 without new advisory and bytecode evidence. Configure both [examples/example-spring-boot-app/pom.xml](../../examples/example-spring-boot-app/pom.xml) and [examples/example-cve-safe-class-app/pom.xml](../../examples/example-cve-safe-class-app/pom.xml) to consume it. Keep scope-only catalog rows from asserting affectedness; verify fixed versions 1.3.16 and 1.5.19 are not reported affected merely because they fall inside a supplemental scope. Add the negative case where `ScriptEvaluator` is absent but `ClassBodyEvaluator` remains.
   - Remove redundant `<phase>process-classes</phase>` and `<productionClassesComplete>true</productionClassesComplete>` boilerplate from example POMs where `process-classes` is now the default.
2. **Verify Real-Snapshot Behavior on `example-spring-boot-app`**:
   - Build/install the current plugin, then prepare the pinned cache with `bash ./scripts/prepare-example-vulnerability-cache.sh "$PWD/.scratch/wp-wholesale/vulnerability-cache" ./mvnw`. The helper requires a cache-directory argument and a Maven executable; pass any additional Maven arguments after those two values. Run `elide` and `analyze` on `example-spring-boot-app` with `-Delide.cveCacheDirectory="$PWD/.scratch/wp-wholesale/vulnerability-cache"`.
   - Confirm `CVE-2025-11226` is reported as `NOT_AFFECTED` (`requires_dependency`) with attribution `ALREADY_ABSENT` only after actual staged-final inventory inspection (Janino is absent from the baseline dependency tree), emitted in `bom.json` and `vex.openvex.json`. Record baseline/final retained and elided archive counts plus retained/pruned class and resource counts. Assert selected known-dead archives/classes are removed and required live classes, resources, explicit-retention inputs, and MRJAR providers remain; do not claim a global or theoretical maximum.
3. **Update ADRs, RQs, and Generated Transcripts**:
   - Update [ADR-0001](../adr/0001-runtime-telemetry-driven-dependency-elision-at-maven-initialize-phase.md), [ADR-0003](../adr/0003-proguard-core-intra-jar-trimming-and-cyclonedx-pedigree.md), [ADR-0004](../adr/0004-assume-resolved-inputs-stable-during-build.md), [ADR-0008](../adr/0008-precondition-gated-vex-attestations.md), [ADR-0010](../adr/0010-process-classes-lifecycle-and-bytecode-completeness.md), [ADR-0012](../adr/0012-dual-layer-ban-policy-and-retention-naming.md), [ADR-0013](../adr/0013-compiler-decoupling-multi-jdk-portability-and-report-driven-liveness.md), [ADR-0014](../adr/0014-source-independent-vulnerability-findings.md), [RQ-0017](../research/RQ-0017-source-generation-lifecycle-integration-and-deferred-source-root-completeness.md), [RQ-0020](../research/RQ-0020-advisory-source-coverage-and-scanner-finding-projections.md), and [RQ-0021](../research/RQ-0021-centrally-distributed-vulnerability-mapping-dependencies.md), each only where the implementation changes or adds evidence to its decision.
   - Run:

     ```bash
     make update-transcripts
     make test-examples
     make check
     ```

   - Use focused `make test-core` / `make test-plugin` during the corresponding development slices. The final gate runs `make check` once for the repository's combined tests, static checks, Markdown lint, SBOM comparison, and transcript drift; run `make test-examples` once because it is an additional end-to-end gate.

## Delivery Closeout (2026-11-09)

Implementation is complete on `.scratch/worktrees/track-wholesale`, branch `track/wholesale`; the authorized fast-forward to local `main` and its post-merge gate remain pending. No remote push is planned.

The final audit follow-ups are complete. A transformed-archive test loads only the trimmed application JAR in an isolated classloader, invokes the traced method successfully, confirms that an untraced method fails because `closure/b/Middle` is absent, and checks that uncalled frame and catch types remain. Provider-read `SecurityException` during Analyze baseline capture is reported as incomplete evidence and an UNKNOWN forecast. Production bytecode analysis now reuses the captured snapshot fingerprint instead of rescanning all output class files.

Verification completed:

- JDK 21 `make check` passed: 517 core tests, 895 plugin executions with one configured skip, 33 lifecycle tests, coverage, Checkstyle, PMD, SpotBugs, Markdown lint, fixture scheduler, format checks, SBOM comparison, and transcript drift. Log: `.scratch/check-final-20261109.log`.
- JDK 25 runs of `MavenPreconditionPredictionTest` and `RuntimeEvidenceOutputPropagationTest` passed 13 tests. Earlier JDK 21 and JDK 25 `make test-examples` runs passed all five standalone fixtures and the multi-module reactor; logs: `.scratch/test-examples-jdk21-final.log` and `.scratch/test-examples-jdk25-final.log`.
- Final formatting and Java static checks passed; log: `.scratch/fmt-lint-final.log`. `make update-transcripts` and the final transcript drift check passed.
- Architect review found no remaining acceptance gaps. The independent final review approved the package; receipt: `.scratch/reviews/wp-wholesale-final.md`.

The first post-fix full-gate attempt reported two Failsafe `NoClassDefFoundError` errors for `PluginCacheProducerIdentityResolver`. The isolated lifecycle rerun passed after repackaging the plugin, and the subsequent full `make check` passed without source changes. The failed attempt is retained as `.scratch/check-postfix-20261109.log` and is not final verification evidence.

The liveness claim is bounded by the declared closed-world workload. Prerequisite proof covers the enumerated Maven provider inventory and does not cover external runtime injection. Catalog digests bind bytes but do not authenticate the publisher. The optional `gemini_review_diff` bridge was unavailable and remains a recorded fail-open review step.

## Dated Boundary Clarification (2026-11-09)

The initial test-provider acceptance above is superseded: precondition proof covers production
class/resource outputs and effective dependency archives. Isolated test source, class, and resource
outputs are excluded; standard `testCompile` and `testResources` may run. Output overlap and custom
compiler settings that can redirect providers into production remain blocked. `skipTests=true`
remains required when tests would execute after capture because test code can mutate production
output.

Lifecycle origin alone is not proof authority. Direct `elide` may capture physical runtime inputs
when `elide.productionClassesComplete=true` asserts complete compiled production output. Analyze
does not apply the trim, so its planned removals remain predictions. The proof claim is bounded to
the captured declared Maven runtime inventory and does not assert inspection of a later assembled
package.
