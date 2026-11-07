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
| **Advisory Discovery & Cache** | **Partially Implemented** | [OsvVulnerabilityFindingAdapter](../../elider-core/src/main/java/io/github/spockz/elider/scanner/OsvVulnerabilityFindingAdapter.java), [CveVulnerabilityFindingAdapter](../../elider-core/src/main/java/io/github/spockz/elider/scanner/CveVulnerabilityFindingAdapter.java), [CveListFindingIndexer](../../elider-core/src/main/java/io/github/spockz/elider/scanner/CveListFindingIndexer.java), [GenericFindingCacheManager](../../elider-core/src/main/java/io/github/spockz/elider/scanner/GenericFindingCacheManager.java) | Record isolation, `PARTIAL`/`STALE`/`ERROR` source health, and unsupported Maven identity diagnostics are implemented. Automatic adapters omit `prerequisiteGroup` because upstream prose is unstructured. | Preserve source facts, unbound/review-only text leads, and source health through the common pipeline without inventing Maven coordinates or prerequisites from prose. |
| **Reconciliation & Shared Mapping Catalog** | **Partially Implemented (Catalog & Supplemental Scope Missing)** | [GenericFindingReconciler](../../elider-core/src/main/java/io/github/spockz/elider/model/GenericFindingReconciler.java), [ManualVulnerabilityMappingContributionAdapter](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/ManualVulnerabilityMappingContributionAdapter.java), [GenericVulnerabilityFinding](../../elider-core/src/main/java/io/github/spockz/elider/model/GenericVulnerabilityFinding.java) | 1. `ManualVulnerabilityMappingContributionAdapter` (`:51`) turns every mapping's `versionRangeSpec` into an explicit `VersionCoverageClaim.affected(...)`, causing `example-cve-safe-class-app`'s `(,1.6.0)` scope to falsely mark fixed Logback `1.3.16` and `1.5.19` as `AFFECTED`. 2. No shared data-only Maven vulnerability mapping catalog exists. | Separate **evidence scope** (version range where supplemental code/prerequisite claims apply) from **affected-version assertions**. Implement the versioned (schema v1) data-only Maven mapping catalog resolved via Maven `RepositorySystem` with `POM > CATALOG > AUTOMATIC` priority. |
| **Inventory, Applicability & Attribution** | **Partially Implemented (Gated on `trimJars` & Missing Baseline Attribution)** | [ElideMojo](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/ElideMojo.java), [AnalyzeMojo](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/AnalyzeMojo.java), [MavenVulnerabilityAssessment](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenVulnerabilityAssessment.java), [PreconditionProof](../../elider-core/src/main/java/io/github/spockz/elider/model/PreconditionProof.java) | 1. `ElideMojo:272` gates precondition inventory on `trimJars && preconditionClassPathComplete`. 2. `AnalyzeMojo:329` passes `null` for `preconditionInventory`. 3. `MavenVulnerabilityAssessment:274-278` discards incomplete inventory `.detail()`, replacing guard diagnostics with generic `NO_PROOF`. 4. `PreconditionProof:108-118` fails if the `requiresDependency` coordinate is retained even when `requiresClass` was trimmed out, lacks conjunctive/alternative semantics, and does not compare baseline vs. final inventory to distinguish **already absent** from **removed by elision**. | Capture and evaluate baseline and final (or predicted) inventories in both `elide` and `analyze` regardless of `trimJars`. Support conjunctive/alternative prerequisites, class absence in trimmed owners, concrete incompleteness reasons, and explicit baseline-absent vs. elision-removed attribution. |
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

When the user provides a runtime trace (`-Xlog:class+load`, CDS class list, JFR `jdk.ClassLoad`, or JaCoCo probe hits) and enables `closedWorld = true`, the analysis data is treated as the **closed world of executed classes**:

1. **Default Conservative Mode (`closedWorld = false`)**:
   - Treats `target/classes`, runtime traces, explicit `trimRoots`, and active dynamic metadata (`META-INF/services/*`, `spring.factories`, `AutoConfiguration.imports`, conditional `META-INF/native-image/**`) as **seed roots**.
   - Feeds those seed roots into `proguard-core`'s `CompleteReferencedClassVisitor` to retain the full transitive static constant-pool closure across all methods and branches.
2. **Closed-World Mode (`closedWorld = true`)**:
   - Every class loaded by the JVM during the traced workload is already present in the runtime trace.
   - **No `proguard-core` method-body constant-pool search (`CompleteReferencedClassVisitor`) is performed to pull in untraced classes**: if class `A` was loaded in the trace and references class `B` inside an unexecuted method/branch, and `B` was **not** in the trace (nor an explicit/active dynamic root), `B` is **not** added to `retainedClasses`, and its owning JAR `jar-b` is elided if no other class in `jar-b` is live.
   - **Only Structural Linkage Edges (`structuralEdges`) are traversed unconditionally**: For any root (including JaCoCo instruction-level traces or explicit `trimRoots` that may omit pure interfaces/superclasses without executable code), `proguard-core` visits class-header/declaration structures required to load and link the class (`ClassHierarchyTraveler` for superclasses/interfaces, `MemberDescriptorReferencedClassVisitor` for field/method descriptors, `SignatureAttributeReferencedClassVisitor` for generic signatures, and `ExceptionHandlerConstantVisitor` for `try`/`catch` exception handler types in `CodeAttribute.exceptions`), plus code-body edges (`CompleteReferencedClassVisitor`) **only when the target class is itself in the closed-world allowed set** (`tracedClasses ∪ explicitRoots ∪ activeDynamicRoots`).
   - **No `UnresolvedReferenceException` on untraced dead-method references**: In `closedWorld = true`, `PreparedAnalysisState.ClosureTraversal` does not throw `UnresolvedReferenceException` for missing classes or members that are outside the closed-world set.
   - **Application bytecode (`target/classes`) scoping in `closedWorld = true`**: When a non-empty runtime trace is supplied and `closedWorld = true`, `target/classes` only roots dependency classes that were either observed in the runtime trace, structurally linked by a traced application class, or explicitly rooted — unexecuted application methods in `target/classes` do not pull in untraced dependency JARs.

---

## 3. Slice 0: Wholesale `git rm` of 91 Obsolete/Over-Engineered Files & Exact Caller Edits

Execute this slice first to remove **91 files (~15,000+ lines)** before adding new features.

### Step 0.1: Run `git rm` on All 91 Files

Run the following `git rm` commands from the repository root:

```bash
# Cluster A: Entire elider.cache package (10 files) + 12 zero-caller dead files/resources
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
  elider-core/src/test/resources/osv-fixtures/cve-2025-12345.json \
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

### Step 0.2: Exact Caller Cleanups in `elider-core`

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
   - Remove the `List<CnaAffectedEntry> cnaAffectedEntries` record component (or keep a delegating overloaded constructor without `cnaAffectedEntries` and remove `validateStructuredEntryLink` / `validateCorroboratedEntryLink`).
4. [AdvisoryEvidenceReader.java](../../elider-core/src/main/java/io/github/spockz/elider/scanner/AdvisoryEvidenceReader.java) & [AdvisoryEvidenceWriter.java](../../elider-core/src/main/java/io/github/spockz/elider/scanner/AdvisoryEvidenceWriter.java):
   - Remove `CnaAffectedEntryReader` / `CnaAffectedEntryCodec` calls and `STRUCTURED_SOURCE_CLASS` / `CORROBORATED_SOURCE_CLASS_CANDIDATE` branches.
5. Clean up test references in:
   - `elider-core/src/test/java/io/github/spockz/elider/model/OmittedCodeProofTest.java` (remove `explicitClassEvidenceRetainsPomOrigin` at lines 47–58).
   - `elider-core/src/test/java/io/github/spockz/elider/model/ADR0008PreconditionProofTest.java` (remove `explicitPrerequisiteEvidenceRetainsPomOrigin` at lines 84–91).
   - `elider-core/src/test/java/io/github/spockz/elider/scanner/AdvisoryEvidenceCodecTest.java`, `OsvSnapshotFixtures.java`, `OsvSnapshotIndexerTest.java`, `VulnerabilityCacheRecordFixture.java`, and `dependency-elider-maven-plugin/src/test/java/io/github/spockz/elider/plugin/MavenAssessmentFixtures.java`: remove test cases/arguments for deleted `StructuredSourceClassEvidence`, `CorroboratedSourceClassCandidate`, `ExplicitClassMappingEvidence`, `ExplicitPrerequisiteEvidence`, and `cnaAffectedEntries`.

### Step 0.3: Exact Caller Cleanups in `dependency-elider-maven-plugin`

1. [ProductionAnalysisInputs.java](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/ProductionAnalysisInputs.java):
   - At lines 77–97, replace the `if (sourceRootsComplete)` branch with throwing `new IOException("elide.sourceRootsComplete is no longer supported; bind elide to process-classes")`.
   - Remove `ProductionOutputFingerprint.fingerprint` double-check at lines 236–239.
2. [MavenPreconditionProviderRoots.java](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenPreconditionProviderRoots.java):
   - Remove `SourceRootCompleteness.hasUnknownSourceGeneration` (lines 74–77).
   - Remove `addSourceRoots` (lines 105–117) and `addSourceProviders` / `MavenSourceDeclarationScanner` (lines 269–288) — at `process-classes`, only compiled output directories (`production-output`, `test-output`, `configured-production-output`) and resource directories (`production-resource`, `test-resource`) are scanned as runtime class/resource providers.
   - Remove `LinkOption.NOFOLLOW_LINKS`, `Files.isSymbolicLink`, and `verifyCapturedRootDigests` double-hashing (lines 80–93, 208–220, 329–388).
3. [AnalyzeMojo.java](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/AnalyzeMojo.java) & [MavenElisionOutputPublisher.java](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenElisionOutputPublisher.java):
   - Replace `MavenOutputTransaction` / `MavenGeneratedOutputManifest` with direct file writing (`Files.createDirectories(target.getParent())`, `MavenElisionReportWriter.write(...)`, `Files.writeString(...)`, and `Files.deleteIfExists(vexPath)` when no VEX attestations exist).
   - Remove `MavenPreconditionInventory.verifyFresh(...)`, `MavenBanPublicationVerifier.verify(...)`, and `banPlan.verifyAuditFresh(...)`.
4. [MavenPreconditionInventory.java](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenPreconditionInventory.java):
   - Remove `MavenPreconditionOutputState`, `MavenPreconditionStages`, and `verifyFresh(...)`.
5. [TrimGenerationPublisher.java](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/TrimGenerationPublisher.java), [EffectiveOutputStaging.java](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/EffectiveOutputStaging.java), [TrimResult.java](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/TrimResult.java):
   - Remove `TrimOutputGenerationPublisher`, `TrimOutputGenerationCommitHandle`, `PreparedOutputPublisher`, and `verifyEffectiveInputs(...)`; publish staged outputs directly into the `generation` directory and call `JarTrimCache.storeCache(...)`.
6. [ElisionReachabilityEngine.java](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/ElisionReachabilityEngine.java), [MavenBanPlan.java](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenBanPlan.java), [MavenElideExecution.java](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenElideExecution.java):
   - Remove `banPlan.verifyAuditBytesFresh()`, `MavenArtifactInventory.verifyPreparedInventory(prepared)` inside the loop, `MavenBanRetainedProviderClosure.verify(...)`, and `requiresTierAwareMrjarTrim(...)`.
7. [MavenDependencyTrimmer.java](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenDependencyTrimmer.java) & [MavenElisionService.java](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenElisionService.java):
   - Remove `MavenDependencyTrimmer.trim(TrimRequest)` and route `MavenElisionService.finish(PreparedAnalysis)` directly to `finishEffectiveOutputs(finishAnalysis(prepared))`.
   - Call `EffectiveTrimOutput.trimEffectivePrepared(...)` directly instead of `TrimOutputCoordinator.trimPrepared(...)`.
8. Run `make test-core` and `make test-plugin` to confirm clean compilation and green baseline tests before Slice 1.

---

## 4. Slice 1: Unified Liveness, `closedWorld` Mode vs. ProGuard, and Maximum Sound Trimming

### Step 1.1: Write Failing Tests First (TDD)

Create/update tests in:

- `elider-core/src/test/java/io/github/spockz/elider/trace/JaCoCoTraceReaderTest.java`:
  - Assert that an XML/CSV `<class>` or `<method>` row with `ci="0"` / `mi > 0` (`!record.hasHits()`) is **excluded** from `TraceData.loadedClasses()`.
- `elider-core/src/test/java/io/github/spockz/elider/trimmer/DependencyJarTrimmerTest.java`:
  - Assert that calling `analyze(...)` with `retainedRoots = Set.of()` returns `retainedClasses = Set.of()` (`0` retained classes), **not** all classes in the JAR.
  - Assert that `SingleReleaseArchiveWriter` filters `META-INF/services/<S>` so pruned provider classes from the JAR are removed while retained or external providers remain, and if all providers in `META-INF/services/<S>` are pruned, the descriptor entry is omitted.
  - Assert **Conservative (`closedWorld = false`) vs. Closed-World (`closedWorld = true`)**:
    - Build a fixture with `jar-a` containing `com.example.LiveA` (which `extends com.example.BaseA` in `jar-a`, has a method `used()` and an unexecuted method `unused()` that calls `com.other.UnusedB.run()` in `jar-b`) and `com.example.DeadA`.
    - When `closedWorld = false` and `LiveA` is in the trace: `LiveA` and `BaseA` are retained in `jar-a`, `DeadA` is trimmed, and `com.other.UnusedB` is in `reachableLibraryClasses()`.
    - When `closedWorld = true` and `LiveA` + `BaseA` are in the closed-world trace (while `UnusedB` is **not** in the trace): `LiveA` and `BaseA` are retained in `jar-a`, `DeadA` is trimmed, `reachableLibraryClasses()` does **not** contain `com.other.UnusedB`, no `UnresolvedReferenceException` is thrown, and loading `LiveA` + invoking `LiveA.used()` in a `URLClassLoader` on JDK 21+ succeeds without `jar-b` on the classpath.
- `dependency-elider-maven-plugin/src/test/java/io/github/spockz/elider/plugin/SpringMetadataRootsTest.java` & `DependencyDynamicRootsTest.java`:
  - Assert that `META-INF/spring-autoconfigure-metadata.properties` inside a JAR is **ignored** and does not add any owner or `.ConditionalOnClass` classes to dynamic roots.
  - Assert that an unowned class in `META-INF/spring.factories` or `META-INF/services/java.sql.Driver` does **not** cause `DynamicRootOrchestrator.dynamicRootArtifactOwners` or `SingleReleaseTrimInventory` to retain unrelated JARs in the inventory.
- `dependency-elider-maven-plugin/src/test/java/io/github/spockz/elider/plugin/MavenElisionServiceEffectiveReportTest.java`:
  - **Cross-JAR reached JAR trimming**: `target/classes` -> `jar-a:LiveA` -> `jar-b:LiveB` (where `jar-b` also has `DeadB` and `DeadB` references `jar-c:DeadC`). Assert `jar-a` and `jar-b` are retained and trimmed to only `LiveA` and `LiveB` (`DeadB` is trimmed out), and `jar-c` is **elided** (because `jar-b` is no longer marked `forcedUnchanged`).
  - **Ancestor-promoted 0-live-class JAR**: `project -> jar-a -> jar-b` (where `jar-a` has `0` live classes and `DeadA -> jar-d:DeadD`, while `jar-b` has `LiveB`). Assert `jar-a` is `ANCESTOR_PROMOTED`, `jar-d` is **elided**, and when `trimJars = true`, `jar-a` is trimmed to `0` `.class` entries while keeping its `META-INF/MANIFEST.MF` and resources.
  - **`closedWorld = true` end-to-end**: With `closedWorld = true`, `jar-b` referenced only from an unexecuted method in `jar-a` (and absent from the trace) is **elided** by `elide` and predicted as elided by `analyze`.

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
4. **Fix `JaCoCoTraceReader` & `SingleReleaseArchiveWriter` Service Filtering**:
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

   - In [SingleReleaseArchiveWriter.java](../../elider-core/src/main/java/io/github/spockz/elider/trimmer/SingleReleaseArchiveWriter.java) at lines 166–186:
     - Accept `Set<String> serviceRetainedClasses` (defaulting to `retainedClasses` when not supplied, and passed from `EffectiveOutputStaging` using `globallyRetainedClasses` just like `MultiReleaseArchivePlan`).
     - When `ServiceDescriptorFilter.isServiceDescriptor(entry.getName())` is true, call `ServiceDescriptorFilter.filterServices(input, entry, inputClasses, serviceRetainedClasses)`. If `Optional.empty()`, omit the entry; if present, write the filtered bytes.
5. **Implement `closedWorld` Mode in `elider-core` and `dependency-elider-maven-plugin`**:
   - In [ProGuardReferenceVisitors.java](../../elider-core/src/main/java/io/github/spockz/elider/trimmer/ProGuardReferenceVisitors.java):
     - Add `static ClassVisitor structural(final ClassVisitor classVisitor, final Function<String, Clazz> classLookup)` that visits:
       - Superclass and interfaces (`new ClassHierarchyTraveler(false, true, true, false, classVisitor)`),
       - Field and method descriptors (`new AllMemberVisitor(new MemberDescriptorReferencedClassVisitor(classVisitor))`),
       - Class and member `Signature` attributes (`new AllAttributeVisitor(true, new SignatureAttributeReferencedClassVisitor(classVisitor))`),
       - Exception handler `catch_type` constants (`new AllMethodVisitor(new AllAttributeVisitor(new AllExceptionInfoVisitor(new ExceptionHandlerConstantVisitor(new ReferencedClassVisitor(classVisitor)))))`).
   - In [ReferenceGraph.java](../../elider-core/src/main/java/io/github/spockz/elider/trimmer/ReferenceGraph.java) & [ReferenceGraphIndexer.java](../../elider-core/src/main/java/io/github/spockz/elider/trimmer/ReferenceGraphIndexer.java):
     - Store `Map<String, Set<String>> structuralEdges` alongside `Map<String, Set<String>> edges` (code + structural edges).
   - In [PreparedAnalysisState.java](../../elider-core/src/main/java/io/github/spockz/elider/trimmer/PreparedAnalysisState.java):
     - Support `analyze(Collection<String> requestedRoots, Set<String> closedWorldAllowedClasses)` (when `closedWorldAllowedClasses` is empty/null, run normal conservative traversal over `graph.edges()` with unresolved-reference checks; when `closedWorldAllowedClasses` is non-null, traverse `graph.structuralEdges()` unconditionally and only traverse `graph.edges()` to targets in `closedWorldAllowedClasses`, and skip `UnresolvedReferenceException` for targets outside `closedWorldAllowedClasses`).
   - Expose `<closedWorld>` (`@Parameter(property = "elide.closedWorld", defaultValue = "false") boolean closedWorld`) on `ElideMojo` and `AnalyzeMojo`, thread it through `ElisionAnalysisModel`, `MavenElisionPolicyIdentity` (so cache fingerprints include `closedWorld`), `MavenAnalysisPreparation`, and `SingleReleaseClosureAnalyzer` / `TierClosureAnalyzer`.

---

## 5. Slice 2: Supplemental Evidence Scope vs. Affected Assertions & Shared Maven Mapping Catalog

### Step 2.1: Write Failing Tests First (TDD)

- `elider-core/src/test/java/io/github/spockz/elider/model/GenericVulnerabilityFindingTest.java`:
  - Test that a contribution with `VersionCoverageClaim.evidenceScope("(,1.6.0)")` and `PrerequisiteClaim("org.codehaus.janino:janino", "org.codehaus.janino.ScriptEvaluator")` merged with an OSV/CVE contribution affecting `[1.4.0, 1.5.19)` and `[1.3.0, 1.3.15)`:
    - Reports `applicability("1.5.18") == AFFECTED` and `effectivePrerequisitesFor("1.5.18")` contains Janino.
    - Reports `applicability("1.5.19") == NOT_AFFECTED` and `applicability("1.3.16") == NOT_AFFECTED`.
  - Test priority ordering: `MergePriority.MANUAL` (POM) > `MergePriority.CATALOG` > `MergePriority.AUTOMATIC` independently for `codeGroup` and `prerequisiteGroup`, regardless of contribution list order.
- `elider-core/src/test/java/io/github/spockz/elider/scanner/VulnerabilityMappingCatalogCodecTest.java`:
  - Test reading, writing, and validating `META-INF/elider/vulnerability-mappings.json` (`schemaVersion: 1`), rejecting unsupported `schemaVersion`, isolating malformed mapping rows as `PARTIAL` source health with diagnostics while keeping valid rows.
- `dependency-elider-maven-plugin/src/test/java/io/github/spockz/elider/plugin/MavenVulnerabilityMappingCatalogTest.java`:
  - Test resolving a data-only mapping catalog JAR via Maven `RepositorySystem` from `<vulnerabilityMappingCatalogs><coordinate>...</coordinate></vulnerabilityMappingCatalogs>`, verifying POM override precedence (`POM > CATALOG > AUTOMATIC`), offline replay via `report`, and that the catalog artifact never appears in project dependencies, `PreconditionClassInventory`, or CycloneDX SBOM components.

### Step 2.2: Production Implementation for Slice 2

1. **Supplemental Evidence Scope (`VersionCoverageClaim` & `GenericVulnerabilityFinding`)**:
   - In [VersionCoverageClaim.java](../../elider-core/src/main/java/io/github/spockz/elider/model/VersionCoverageClaim.java):
     - Add `public static VersionCoverageClaim evidenceScope(final String mavenRange)` using `VersionApplicability.EVIDENCE_SCOPE` (add `EVIDENCE_SCOPE` to [VersionApplicability.java](../../elider-core/src/main/java/io/github/spockz/elider/model/VersionApplicability.java)).
   - In [GenericVulnerabilityFinding.java](../../elider-core/src/main/java/io/github/spockz/elider/model/GenericVulnerabilityFinding.java):
     - `applicability(final String version)` (lines 107–121) only checks `claim.status() == VersionApplicability.AFFECTED` and `claim.status() == VersionApplicability.UNRESOLVED` (ignoring `EVIDENCE_SCOPE` so an evidence scope never marks a fixed version as `AFFECTED`).
     - `positivelyApplicable(final VulnerabilityFindingContribution contribution, final String version)` (lines 304–311) matches when `claim.status() == VersionApplicability.AFFECTED || claim.status() == VersionApplicability.EVIDENCE_SCOPE`.
   - In [ManualVulnerabilityMappingContributionAdapter.java](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/ManualVulnerabilityMappingContributionAdapter.java):
     - Add `boolean assertsAffected` (default `false`) to `VulnerabilityMappingConfig`. When `assertsAffected == false` (the default for supplemental code/prerequisite mappings), emit `VersionCoverageClaim.evidenceScope(spec)`; when `assertsAffected == true`, emit `VersionCoverageClaim.affected(spec)`.
2. **Add `CATALOG` Priority & Origin**:
   - In [MergePriority.java](../../elider-core/src/main/java/io/github/spockz/elider/model/MergePriority.java): Add `CATALOG` between `AUTOMATIC` and `MANUAL`.
   - In [EvidenceOrigin.java](../../elider-core/src/main/java/io/github/spockz/elider/model/EvidenceOrigin.java): Add `CATALOG`.
   - In [GenericVulnerabilityFinding.java](../../elider-core/src/main/java/io/github/spockz/elider/model/GenericVulnerabilityFinding.java): In `effectiveGroupSuppliers`, check `MANUAL` first, then `CATALOG`, then `AUTOMATIC`.
3. **Implement `VulnerabilityMappingCatalog` in `elider-core` & Resolver in Plugin**:
   - Create `elider-core/src/main/java/io/github/spockz/elider/scanner/VulnerabilityMappingCatalog.java` reading/writing `META-INF/elider/vulnerability-mappings.json`:

     ```json
     {
       "schemaVersion": 1,
       "catalogId": "io.github.spockz:elider-vulnerability-mappings",
       "mappings": [
         {
           "cveId": "CVE-2025-11226",
           "groupId": "ch.qos.logback",
           "artifactId": "logback-core",
           "versionRangeSpec": "(,1.6.0)",
           "assertsAffected": false,
           "prerequisiteOperator": "ALL_OF",
           "prerequisites": [
             {
               "requiresDependency": "org.codehaus.janino:janino",
               "requiresClass": "org.codehaus.janino.ScriptEvaluator"
             }
           ]
         }
       ]
     }
     ```

   - Create `dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenVulnerabilityMappingCatalogResolver.java` using `@Component RepositorySystem` to resolve each `<vulnerabilityMappingCatalogs>` coordinate (`groupId:artifactId:version[:type[:classifier]]`), verify its file digest, parse `META-INF/elider/vulnerability-mappings.json`, and emit `VulnerabilityFindingContribution`s with `MergePriority.CATALOG` and `EvidenceOrigin.CATALOG` + `FindingSourceObservation` for the catalog source.

---

## 6. Slice 3: Baseline vs. Final Inventory Capture, `ALL_OF`/`ANY_OF` Prerequisites, Trimmed-Class Proof & Attribution

### Step 3.1: Write Failing Tests First (TDD)

- `elider-core/src/test/java/io/github/spockz/elider/model/ADR0008PreconditionProofTest.java`:
  - **Trimmed-class prerequisite proof**: Affected `logback-core` is retained AND `org.codehaus.janino:janino` JAR is retained on the classpath, **but** `org.codehaus.janino.ScriptEvaluator` was trimmed out of `janino.jar` (and is absent from all other providers). Assert `PreconditionProof.prove(...)` **succeeds** (`NOT_AFFECTED`, `requires_dependency`).
  - **Conjunctive (`ALL_OF`) vs. Alternative (`ANY_OF`)**:
    - Under `ALL_OF` with prerequisites `[P1, P2]`, if `P1` is present and `P2` is absent, `PreconditionProof.prove(...)` **succeeds** (`NOT_AFFECTED`).
    - Under `ANY_OF` with prerequisites `[P1, P2]`, if `P1` is present and `P2` is absent, `PreconditionProof.prove(...)` **fails** (still exploitable via `P1`); if both `P1` and `P2` are absent, it **succeeds**.
  - **Baseline vs. Final Attribution**:
    - Absent in baseline and absent in final -> `PrerequisiteAbsenceAttribution.ALREADY_ABSENT`.
    - Present in baseline and absent in final because owning JAR was dropped -> `PrerequisiteAbsenceAttribution.ELIDED_DEPENDENCY`.
    - Present in baseline and absent in final because `requiresClass` was trimmed from retained owning JAR -> `PrerequisiteAbsenceAttribution.TRIMMED_CLASS`.

### Step 3.2: Production Implementation for Slice 3

1. **Add `PrerequisiteOperator` (`ALL_OF`, `ANY_OF`) & `PrerequisiteAbsenceAttribution`**:
   - Create `elider-core/src/main/java/io/github/spockz/elider/model/PrerequisiteOperator.java` (`ALL_OF`, `ANY_OF`, defaulting to `ALL_OF`).
   - Create `elider-core/src/main/java/io/github/spockz/elider/model/PrerequisiteAbsenceAttribution.java` (`ALREADY_ABSENT`, `ELIDED_DEPENDENCY`, `TRIMMED_CLASS`, `PRESENT`, `UNKNOWN`).
   - Include `PrerequisiteOperator prerequisiteOperator` on `VulnerabilityFindingContribution` / `GenericVulnerabilityFinding` (defaulting to `ALL_OF`).
2. **Fix `PreconditionProof.java` (`:107-136`) for Trimmed Classes, `ALL_OF`/`ANY_OF`, and Attribution**:
   - In [PreconditionProof.java](../../elider-core/src/main/java/io/github/spockz/elider/model/PreconditionProof.java):
     - A single `PrerequisiteClaim(requiresDependency, requiresClass)` is **present** in an `InventoryInspection` iff `inspection.availableClasses.contains(prerequisite.requiresClass())` (when `requiresClass` is specified; if `requiresClass` is absent from every provider in the complete inventory, the prerequisite is **absent** even if a trimmed `requiresDependency` archive remains).
     - For `PrerequisiteOperator.ALL_OF`: the vulnerability's prerequisite condition is disarmed if **at least one** declared `PrerequisiteClaim` is absent from `finalInspection`.
     - For `PrerequisiteOperator.ANY_OF`: the vulnerability's prerequisite condition is disarmed iff **every** declared `PrerequisiteClaim` is absent from `finalInspection`.
     - When `baselineInspection` is also provided:
       - If the disarming prerequisite(s) were already absent in `baselineInspection` -> `PrerequisiteAbsenceAttribution.ALREADY_ABSENT`.
       - Else if the prerequisite's `requiresDependency` archive was present in `baselineInspection` and absent in `finalInspection` -> `PrerequisiteAbsenceAttribution.ELIDED_DEPENDENCY`.
       - Else (`requiresDependency` archive is still in `finalInspection`, but `requiresClass` was removed by trimming) -> `PrerequisiteAbsenceAttribution.TRIMMED_CLASS`.
3. **Preserve Incomplete Inventory Diagnostics in `MavenVulnerabilityAssessment.java`**:
   - At [MavenVulnerabilityAssessment.java](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenVulnerabilityAssessment.java) lines 273–278, when `preconditionInventory != null && !preconditionInventory.classProviders().complete()`, pass `preconditionInventory.classProviders().detail()` into `GenericFindingAssessment` so the user and report JSON see the exact reason why the inventory was incomplete.

---

## 7. Slice 4: Decoupled Report/SBOM/VEX Publication & `analyze`/`elide`/`report` Parity

### Step 4.1: Write Failing Tests First (TDD)

- Integration tests in `MavenElisionOutputPublisherTest` / `ElideMojoTest` / `AnalyzeMojoTest`:
  - `elide` with `trimJars = false` captures `PreconditionClassInventory` (both baseline and final), proves `CVE-2025-11226` `NOT_AFFECTED` (`requires_dependency`, `ALREADY_ABSENT`), writes `dependency-elider-report.json`, writes `bom.json` with CycloneDX `vulnerabilities[].analysis` (`state: not_affected`, `justification: requires_dependency`), and writes `vex.openvex.json` — while leaving original `.jar` files untouched.
  - `analyze` computes baseline and predicted final `PreconditionClassInventory` and outputs matching assessment and attribution (`ALREADY_ABSENT` vs. `ELIDED_DEPENDENCY` / `TRIMMED_CLASS`) in console and JSON report.

### Step 4.2: Production Implementation for Slice 4

1. [ElideMojo.java](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/ElideMojo.java):
   - At line 272, change `final boolean preconditionInventoryComplete = trimJars && preconditionClassPathComplete;` to `final boolean preconditionInventoryComplete = preconditionClassPathComplete;`.
2. [AnalyzeMojo.java](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/AnalyzeMojo.java):
   - At lines 327–333, capture baseline and predicted post-elision `MavenPreconditionInventory` from `effectiveAnalysis` instead of passing `null`.
3. [MavenElisionOutputPublisher.java](../../dependency-elider-maven-plugin/src/main/java/io/github/spockz/elider/plugin/MavenElisionOutputPublisher.java):
   - At lines 106–288, remove the `if (request.files().trimJars())` guard around SBOM (`generateSbom` / `sbomOutput`), OpenVEX (`vex` generation and `Files.deleteIfExists`), and report publication. Only physical JAR path replacement (`applyArtifactChanges` / trimmed JAR file swapping) depends on `trimJars`.
4. **Update Report Payload, Validator, and Renderers (Schema v1)**:
   - Add `prerequisiteAttribution` (`ALREADY_ABSENT`, `ELIDED_DEPENDENCY`, `TRIMMED_CLASS`, `PRESENT`, `UNKNOWN`) to `GenericFindingAssessment`, `MavenElisionReportGenericPayload`, `MavenElisionReportPayloadValidator`, and `MavenElisionReportGenericRenderer` (keeping schema version `1` per `AGENTS.md`).
   - Ensure console summary and report clearly distinguish vulnerabilities mitigated by elision/trimming (`ELIDED_DEPENDENCY` / `TRIMMED_CLASS`) from vulnerabilities already non-exploitable in the baseline build (`ALREADY_ABSENT`).

---

## 8. Slice 5: Default `process-classes` Lifecycle, Source-Free Modules, and Packaging Guard

### Step 5.1: Write Failing Tests First (TDD)

- Update/add tests in `EliderPluginConfigurationTest`, `MavenPreconditionGenerationGuardTest`, and `LifecycleIT`:
  - Default phase of `elide` is `process-classes` when `<phase>` is omitted.
  - `EliderLifecycleParticipant` orders `elide` at the tail of `process-classes` (`priority = Integer.MAX_VALUE`).
  - A module with `0` `.java` source files and an absent or empty `target/classes` directory succeeds at `process-classes`.
  - `MavenPreconditionGenerationGuard` allows builds stopping at `process-classes` even when `package` has untrusted plugins, accepts `spring-boot-maven-plugin:repackage` at `package`, accepts `-Dmaven.test.skip=true` for `testCompile`, and resolves omitted `<phase>` on `dependency-elider-maven-plugin` to `process-classes`.

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
   - At lines 597–615: In `isSkippedTestCompiler`, also return `true` when `<skip>true</skip>` or property `maven.test.skip=true` is set.
   - Recognize `org.springframework.boot:spring-boot-maven-plugin` goal `repackage` at `package` as a known packager boundary.

---

## 9. Slice 6: Examples, Real-Snapshot Verification, ADRs/RQs & Transcripts

1. **Install/Configure Shared Vulnerability Mapping Catalog for Examples**:
   - Create a shared mapping catalog fixture/artifact (containing the schema-v1 `CVE-2025-11226` Logback `< 1.6.0` -> Janino `org.codehaus.janino:janino` / `org.codehaus.janino.ScriptEvaluator` mapping) and configure both [examples/example-spring-boot-app/pom.xml](../../examples/example-spring-boot-app/pom.xml) and [examples/example-cve-safe-class-app/pom.xml](../../examples/example-cve-safe-class-app/pom.xml) to consume it (with `example-cve-safe-class-app` also testing POM override / scope behavior on fixed `1.3.16` and `1.5.19`).
   - Remove redundant `<phase>process-classes</phase>` and `<productionClassesComplete>true</productionClassesComplete>` boilerplate from example POMs where `process-classes` is now the default.
2. **Verify Real-Snapshot Behavior on `example-spring-boot-app`**:
   - Build/install the current plugin, then prepare the pinned cache with `bash ./scripts/prepare-example-vulnerability-cache.sh "$PWD/.scratch/wp-wholesale/vulnerability-cache" ./mvnw`. The helper requires a cache-directory argument and a Maven executable; pass any additional Maven arguments after those two values. Run `elide` and `analyze` on `example-spring-boot-app` with `-Delide.cveCacheDirectory="$PWD/.scratch/wp-wholesale/vulnerability-cache"`.
   - Confirm `CVE-2025-11226` is reported as `NOT_AFFECTED` (`requires_dependency`) with attribution `ALREADY_ABSENT` (since Janino is not in `example-spring-boot-app`'s baseline dependency tree), emitted in `bom.json` and `vex.openvex.json`, and that whole-JAR elision and intra-JAR trimming drop the maximum number of unused JARs and classes (now that `SpringMetadataRoots.readMetadata` and the unresolved-root keep-all poison pill are gone).
3. **Update ADRs, RQs, and Generated Transcripts**:
   - Update [ADR-0001](../adr/0001-runtime-telemetry-driven-dependency-elision-at-maven-initialize-phase.md), [ADR-0003](../adr/0003-proguard-core-intra-jar-trimming-and-cyclonedx-pedigree.md), [ADR-0008](../adr/0008-precondition-gated-vex-attestations.md), [ADR-0010](../adr/0010-process-classes-lifecycle-and-bytecode-completeness.md), [RQ-0020](../research/RQ-0020-advisory-source-coverage-and-scanner-finding-projections.md), and [RQ-0021](../research/RQ-0021-centrally-distributed-vulnerability-mapping-dependencies.md).
   - Run:

     ```bash
     make update-transcripts
     make check-transcripts
     make test-core
     make test-plugin
     make test-examples
     make check
     ```
