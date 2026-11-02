// WHY: Verifies assessment reports precondition inactivity only after exact complete-inventory
// proof.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.applicability.MavenVersionRangeMatcher;
import io.github.spockz.elider.engine.ClassUsageReport;
import io.github.spockz.elider.model.AdvisoryProvenance;
import io.github.spockz.elider.model.AdvisoryScope;
import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ArtifactFileRef;
import io.github.spockz.elider.model.ConfidenceLevel;
import io.github.spockz.elider.model.ElisionDecision;
import io.github.spockz.elider.model.EvidenceOrigin;
import io.github.spockz.elider.model.OsvAdvisoryRecord;
import io.github.spockz.elider.model.OsvAffectedPackage;
import io.github.spockz.elider.model.PackageAdvisoryEvidence;
import io.github.spockz.elider.model.PreconditionClassInventory;
import io.github.spockz.elider.model.PreconditionClassInventory.Provider;
import io.github.spockz.elider.model.PreconditionProof;
import io.github.spockz.elider.model.VulnerabilitySymbolMapping;
import io.github.spockz.elider.scanner.AdvisoryEvidenceWriter;
import io.github.spockz.elider.scanner.VulnerabilityCacheManager;
import io.github.spockz.elider.scanner.VulnerabilityCacheManager.CacheConfig;
import io.github.spockz.elider.trimmer.ArtifactDigests;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import org.apache.maven.project.MavenProject;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;

/** Verifies assessment and report handling for precondition evidence. */
@DisplayName("ADR-0008: Maven precondition assessment and report classification")
@SuppressWarnings({
  "PMD.AtLeastOneConstructor",
  "PMD.CommentDefaultAccessModifier",
  "PMD.CouplingBetweenObjects",
  "PMD.ExcessiveImports",
  "PMD.TooManyMethods",
  "PMD.UnitTestContainsTooManyAsserts",
  "checkstyle:AbbreviationAsWordInName"
})
final class ADR0008MavenPreconditionAssessmentTest {
  /** Stable test mapping range selecting one affected component version. */
  private static final String EXACT_VERSION_RANGE = "[1.0,1.0]";

  /** Shared Maven group ID for assessment fixtures. */
  private static final String GROUP_ID = "org.example";

  /** Shared affected artifact ID for assessment fixtures. */
  private static final String AFFECTED_ARTIFACT_ID = "affected";

  /** Shared affected version for assessment fixtures. */
  private static final String AFFECTED_VERSION = "1.0";

  /** Other affected version used by assessment fixtures. */
  private static final String SECOND_VERSION = "2.0";

  /** Later mapping version used by overlapping-range fixtures. */
  private static final String OVERLAP_MAPPING_VERSION = SECOND_VERSION;

  /** Candidate version covered by overlapping-range fixtures. */
  private static final String OVERLAP_CANDIDATE_VERSION = "2.5";

  /** First range used by overlapping-range fixtures. */
  private static final String FIRST_OVERLAP_RANGE = "[1.0,3.0)";

  /** Second range used by overlapping-range fixtures. */
  private static final String SECOND_OVERLAP_RANGE = "[2.0,4.0)";

  /** Stable prerequisite Maven coordinate used by the positive evidence fixture. */
  private static final String REQUIRED_DEPENDENCY = "org.example:prerequisite";

  /** Stable prerequisite class used by the positive evidence fixture. */
  private static final String REQUIRED_CLASS = "org.example.prerequisite.EntryPoint";

  /** Stable CVE used by all focused mappings. */
  private static final String CVE_ID = "CVE-2026-12345";

  /** Temporary files for affected archives and cache seeds. */
  @TempDir Path temporaryDirectory;

  @Test
  void reportsExactAffectedVersionWithoutTrimRecordAndKeepsReportCategoryDistinct()
      throws IOException {
    final ArtifactCoordinate affectedOne =
        ArtifactCoordinate.of(GROUP_ID, AFFECTED_ARTIFACT_ID, AFFECTED_VERSION);
    final ArtifactCoordinate affectedTwo =
        ArtifactCoordinate.of(GROUP_ID, AFFECTED_ARTIFACT_ID, SECOND_VERSION);
    final Path affectedOneJar = writeJar("affected-1.0.jar");
    final Path affectedTwoJar = writeJar("affected-2.0.jar");
    final VulnerabilitySymbolMapping mapping =
        mapping(affectedOne, EXACT_VERSION_RANGE, Set.of(), ConfidenceLevel.HIGH);
    final ElisionAnalysisModel.Analysis analysis = analysis(List.of(affectedOne, affectedTwo));
    final MavenPreconditionInventory.Snapshot inventory =
        completeInventory(
            Provider.dependencyArchive(affectedOne, affectedOneJar),
            Provider.dependencyArchive(affectedTwo, affectedTwoJar));
    assertThat(MavenVersionRangeMatcher.includes(mapping.versionRangeSpec(), affectedOne.version()))
        .isTrue();
    assertThat(
            PreconditionProof.prove(
                ExplicitEvidenceTestSupport.prerequisiteEvidence(mapping),
                inventory.classProviders()))
        .isNotNull();

    final MavenVulnerabilityAssessment.Result result =
        new MavenVulnerabilityAssessment(new RecordingMavenLog())
            .assess(
                emptyCache("positive-cache"), configured(List.of(mapping)), analysis, inventory);

    final RecordingMavenLog summaryLog = new RecordingMavenLog();
    ElisionSummaryCveReporter.report(summaryLog, result, false);

    assertThat(result.attestations()).hasSize(1);
    assertThat(result.attestations().getFirst().coordinate()).isEqualTo(affectedOne);
    assertThat(result.attestations().getFirst().justification()).isEqualTo("requires_dependency");
    assertThat(result.attestations().getFirst().requiredDependency())
        .isEqualTo(REQUIRED_DEPENDENCY);
    assertThat(result.attestations().getFirst().requiredClass()).isEqualTo(REQUIRED_CLASS);
    assertThat(result.attestations().getFirst().evidenceSymbols()).isEmpty();
    assertThat(result.inactiveDueToMissingPrerequisites())
        .containsExactly(new MavenVulnerabilityAssessment.Finding(CVE_ID, affectedOne));
    assertThat(mapping.vulnerableClasses()).isEmpty();
    assertThat(summaryLog.messages())
        .contains(
            "    "
                + CVE_ID
                + " "
                + affectedOne.toId()
                + "; inactive because missing prerequisite dependencies: "
                + REQUIRED_DEPENDENCY
                + " (class "
                + REQUIRED_CLASS
                + ")");
    assertThat(result.provenVulnerableCodeAbsent()).isEmpty();
    assertThat(result.removedComponents()).isEmpty();

    final MavenElisionReportSnapshot report = reportSnapshot(analysis, result);
    assertThat(report.schemaVersion()).isEqualTo(MavenElisionReportSnapshot.SCHEMA_VERSION);
    assertThat(report.inactivePreconditionCves())
        .containsExactly(
            new MavenElisionReportSnapshot.CveFinding(
                CVE_ID,
                affectedOne.toId(),
                List.of(new MavenMissingPrerequisite(REQUIRED_DEPENDENCY, REQUIRED_CLASS))));
    assertThat(report.provenAbsentCves()).isEmpty();
    assertThat(report.removedCveComponents()).isEmpty();
  }

  @Test
  void doesNotReportInactiveWhenPrerequisiteCoordinateIsRetainedAtAnotherVersion()
      throws IOException {
    final ArtifactCoordinate affected =
        ArtifactCoordinate.of(GROUP_ID, AFFECTED_ARTIFACT_ID, AFFECTED_VERSION);
    final ArtifactCoordinate prerequisite =
        ArtifactCoordinate.of("org.example", "prerequisite", "9.7");
    final Path affectedJar = writeJar("affected.jar");
    final Path prerequisiteJar = writeJar("prerequisite-9.7.jar");
    final ElisionAnalysisModel.Analysis analysis = analysis(List.of(affected, prerequisite));
    final MavenPreconditionInventory.Snapshot inventory =
        completeInventory(
            Provider.dependencyArchive(affected, affectedJar),
            Provider.dependencyArchive(prerequisite, prerequisiteJar));

    final MavenVulnerabilityAssessment.Result result =
        assess(
            analysis,
            inventory,
            List.of(mapping(affected, EXACT_VERSION_RANGE, Set.of(), ConfidenceLevel.HIGH)));

    assertThat(result.attestations()).isEmpty();
    assertThat(result.inactiveDueToMissingPrerequisites()).isEmpty();
  }

  @Test
  void doesNotReportInactiveWhenAnApplicationResourceProvidesThePrerequisiteClass()
      throws IOException {
    final ArtifactCoordinate affected =
        ArtifactCoordinate.of(GROUP_ID, AFFECTED_ARTIFACT_ID, AFFECTED_VERSION);
    final Path affectedJar = writeJar("affected-resource-case.jar");
    final Path classResource = temporaryDirectory.resolve("renamed-resource.bin");
    Files.write(classResource, classBytes(REQUIRED_CLASS.replace('.', '/')));
    final MavenPreconditionInventory.Snapshot inventory =
        completeInventory(
            Provider.dependencyArchive(affected, affectedJar),
            Provider.applicationResourceFile(classResource));

    final MavenVulnerabilityAssessment.Result result =
        assess(
            analysis(List.of(affected)),
            inventory,
            List.of(mapping(affected, EXACT_VERSION_RANGE, Set.of(), ConfidenceLevel.HIGH)));

    assertThat(result.attestations()).isEmpty();
    assertThat(result.inactiveDueToMissingPrerequisites()).isEmpty();
  }

  @Test
  void incompleteInventoryAndOptOutProduceTheSameNonProofAssessment() throws IOException {
    final ArtifactCoordinate affected =
        ArtifactCoordinate.of(GROUP_ID, AFFECTED_ARTIFACT_ID, AFFECTED_VERSION);
    final Path affectedJar = writeJar("affected-incomplete.jar");
    final Provider affectedProvider = Provider.dependencyArchive(affected, affectedJar);
    final PreconditionClassInventory incompleteClassProviders =
        PreconditionClassInventory.incomplete(
            List.of(affectedProvider), "application provider inventory is incomplete");
    final MavenPreconditionInventory.Snapshot complete = completeInventory(affectedProvider);
    final MavenPreconditionInventory.Snapshot incomplete =
        inventory(incompleteClassProviders, affectedProvider);
    final MavenPreconditionInventory.Snapshot disabled =
        inventory(complete.classProviders(), false, affectedProvider);
    final ElisionAnalysisModel.Analysis analysis = analysis(List.of(affected));
    final List<VulnerabilitySymbolMapping> mappings =
        List.of(mapping(affected, EXACT_VERSION_RANGE, Set.of(), ConfidenceLevel.HIGH));
    final ConfiguredVulnerabilityMappings configured = configured(mappings);
    final RecordingMavenLog log = new RecordingMavenLog();
    final MavenVulnerabilityAssessment assessment = new MavenVulnerabilityAssessment(log);
    final CacheConfig cache = emptyCache("incomplete-cache");

    assertAll(
        "independent precondition inventory proof gates",
        () -> {
          final MavenVulnerabilityAssessment.Result result =
              assessment.assess(cache, configured, analysis, complete);
          assertAll(
              "complete inventory admits the configured HIGH assertion",
              () -> assertThat(result.attestations()).hasSize(1),
              () -> assertThat(result.inactiveDueToMissingPrerequisites()).hasSize(1));
        },
        () -> {
          final MavenVulnerabilityAssessment.Result result =
              assessment.assess(cache, configured, analysis, null);
          assertAll(
              "missing inventory",
              () -> assertThat(result.attestations()).isEmpty(),
              () -> assertThat(result.inactiveDueToMissingPrerequisites()).isEmpty());
        },
        () -> {
          final MavenVulnerabilityAssessment.Result result =
              assessment.assess(cache, configured, analysis, incomplete);
          assertAll(
              "incomplete opted-in inventory",
              () -> assertThat(result.attestations()).isEmpty(),
              () -> assertThat(result.inactiveDueToMissingPrerequisites()).isEmpty());
        },
        () -> {
          final MavenVulnerabilityAssessment.Result result =
              assessment.assess(cache, configured, analysis, disabled);
          assertAll(
              "explicit opt-out",
              () -> assertThat(result.attestations()).isEmpty(),
              () -> assertThat(result.inactiveDueToMissingPrerequisites()).isEmpty());
        },
        () ->
            assertThat(
                    log.messages().stream()
                        .filter(message -> message.contains("Precondition proof suppressed"))
                        .count())
                .isEqualTo(1L));
  }

  @Test
  void lowAndMediumConfidenceMappingsCannotCreateInactiveFindings() throws IOException {
    final ArtifactCoordinate affected =
        ArtifactCoordinate.of(GROUP_ID, AFFECTED_ARTIFACT_ID, AFFECTED_VERSION);
    final Path affectedJar = writeJar("affected-confidence.jar");
    final MavenPreconditionInventory.Snapshot inventory =
        completeInventory(Provider.dependencyArchive(affected, affectedJar));
    final ElisionAnalysisModel.Analysis analysis = analysis(List.of(affected));

    for (final ConfidenceLevel confidence : List.of(ConfidenceLevel.LOW, ConfidenceLevel.MEDIUM)) {
      final MavenVulnerabilityAssessment.Result result =
          assess(
              analysis,
              inventory,
              List.of(mapping(affected, EXACT_VERSION_RANGE, Set.of(), confidence)));

      assertThat(result.attestations()).isEmpty();
      assertThat(result.inactiveDueToMissingPrerequisites()).isEmpty();
    }
  }

  @Test
  void lowerConfidencePomOverrideAndCachedHighMappingCannotProducePreconditionVex()
      throws IOException {
    final ArtifactCoordinate affected =
        ArtifactCoordinate.of(GROUP_ID, AFFECTED_ARTIFACT_ID, AFFECTED_VERSION);
    final Path affectedJar = writeJar("affected-override.jar");
    final MavenPreconditionInventory.Snapshot inventory =
        completeInventory(Provider.dependencyArchive(affected, affectedJar));
    final ElisionAnalysisModel.Analysis analysis = analysis(List.of(affected));
    final VulnerabilitySymbolMapping cachedHigh =
        mapping(affected, EXACT_VERSION_RANGE, Set.of(), ConfidenceLevel.HIGH);
    final VulnerabilitySymbolMapping pomOverride =
        mapping(affected, EXACT_VERSION_RANGE, Set.of(), ConfidenceLevel.MEDIUM);
    final CacheConfig cache = seededCache("override-cache", cachedHigh);
    final MavenVulnerabilityAssessment assessment =
        new MavenVulnerabilityAssessment(new RecordingMavenLog());

    assertAll(
        "cache and lower-confidence POM evidence remain ineligible",
        () -> {
          final MavenVulnerabilityAssessment.Result result =
              assessment.assess(
                  cache, ConfiguredVulnerabilityMappings.empty(), analysis, inventory);
          assertAll(
              "cached package evidence has no owner assertion",
              () -> assertThat(result.attestations()).isEmpty(),
              () -> assertThat(result.inactiveDueToMissingPrerequisites()).isEmpty(),
              () -> assertThat(result.potentiallyConservativeCves()).isEmpty(),
              () -> assertThat(result.matchedAdvisoryEvidence()).hasSize(1));
        },
        () -> {
          final MavenVulnerabilityAssessment.Result result =
              assessment.assess(cache, configured(List.of(pomOverride)), analysis, inventory);
          assertAll(
              "POM MEDIUM remains review-only",
              () -> assertThat(result.attestations()).isEmpty(),
              () -> assertThat(result.inactiveDueToMissingPrerequisites()).isEmpty());
        });
  }

  @Test
  void omittedCodeEvidenceKeepsPrecedenceOverPreconditionEvidence() throws IOException {
    final ArtifactCoordinate affected =
        new ArtifactCoordinate(
            GROUP_ID, AFFECTED_ARTIFACT_ID, AFFECTED_VERSION, "jar", "", "compile");
    final ArtifactCoordinate trimCoordinate =
        new ArtifactCoordinate(
            GROUP_ID, AFFECTED_ARTIFACT_ID, AFFECTED_VERSION, "jar", "", "runtime");
    final Path originalJar = writeJar("affected-original.jar", "org/example/Vulnerable.class");
    final Path trimmedJar = writeJar("affected-trimmed.jar");
    final ArtifactTrimRecord trimRecord = trimRecord(trimCoordinate, originalJar, trimmedJar);
    final ElisionAnalysisModel.Analysis analysis = analysis(List.of(affected), List.of(trimRecord));
    final MavenPreconditionInventory.Snapshot inventory =
        completeInventory(Provider.dependencyArchive(affected, trimmedJar));
    final VulnerabilitySymbolMapping mapping =
        mapping(
            affected, EXACT_VERSION_RANGE, Set.of("org.example.Vulnerable"), ConfidenceLevel.HIGH);

    final MavenVulnerabilityAssessment.Result result =
        assess(analysis, inventory, List.of(mapping));

    assertThat(result.attestations()).hasSize(1);
    assertThat(result.attestations().getFirst().justification())
        .isEqualTo("vulnerable_code_not_present");
    assertThat(result.provenVulnerableCodeAbsent())
        .containsExactly(new MavenVulnerabilityAssessment.Finding(CVE_ID, affected));
    assertThat(result.inactiveDueToMissingPrerequisites()).isEmpty();
  }

  @Test
  void equivalentOverlappingMappingsProduceOneOrderIndependentStatement() throws IOException {
    final ArtifactCoordinate candidate =
        ArtifactCoordinate.of(GROUP_ID, AFFECTED_ARTIFACT_ID, OVERLAP_CANDIDATE_VERSION);
    final ArtifactCoordinate firstMappingCoordinate =
        ArtifactCoordinate.of(GROUP_ID, AFFECTED_ARTIFACT_ID, AFFECTED_VERSION);
    final ArtifactCoordinate secondMappingCoordinate =
        ArtifactCoordinate.of(GROUP_ID, AFFECTED_ARTIFACT_ID, OVERLAP_MAPPING_VERSION);
    final MavenPreconditionInventory.Snapshot inventory =
        completeInventory(Provider.dependencyArchive(candidate, writeJar("overlap-candidate.jar")));
    final ElisionAnalysisModel.Analysis analysis = analysis(List.of(candidate));
    final VulnerabilitySymbolMapping first =
        mapping(firstMappingCoordinate, FIRST_OVERLAP_RANGE, Set.of(), ConfidenceLevel.HIGH);
    final VulnerabilitySymbolMapping second =
        mapping(secondMappingCoordinate, SECOND_OVERLAP_RANGE, Set.of(), ConfidenceLevel.HIGH);

    final MavenVulnerabilityAssessment.Result forward =
        assess(analysis, inventory, List.of(first, second));
    final MavenVulnerabilityAssessment.Result reverse =
        assess(analysis, inventory, List.of(second, first));

    assertThat(forward.attestations()).hasSize(1);
    assertThat(reverse.attestations()).hasSize(1);
    assertThat(forward.attestations().getFirst().coordinate()).isEqualTo(candidate);
    assertThat(reverse.attestations().getFirst().coordinate()).isEqualTo(candidate);
    assertThat(forward.inactiveDueToMissingPrerequisites())
        .containsExactly(new MavenVulnerabilityAssessment.Finding(CVE_ID, candidate));
    assertThat(reverse.inactiveDueToMissingPrerequisites())
        .containsExactly(new MavenVulnerabilityAssessment.Finding(CVE_ID, candidate));
  }

  @Test
  void conflictingPrerequisiteClassesSuppressPreconditionAndSuccessfulOmittedProofsInEitherOrder()
      throws IOException {
    final ArtifactCoordinate candidate =
        ArtifactCoordinate.of(GROUP_ID, AFFECTED_ARTIFACT_ID, OVERLAP_CANDIDATE_VERSION);
    final ArtifactCoordinate firstMappingCoordinate =
        ArtifactCoordinate.of(GROUP_ID, AFFECTED_ARTIFACT_ID, AFFECTED_VERSION);
    final ArtifactCoordinate secondMappingCoordinate =
        ArtifactCoordinate.of(GROUP_ID, AFFECTED_ARTIFACT_ID, OVERLAP_MAPPING_VERSION);
    final Path originalJar = writeJar("conflict-original.jar", "org/example/Vulnerable.class");
    final Path trimmedJar = writeJar("conflict-trimmed.jar");
    final ArtifactTrimRecord trimRecord = trimRecord(candidate, originalJar, trimmedJar);
    final ElisionAnalysisModel.Analysis analysis =
        analysis(List.of(candidate), List.of(trimRecord));
    final MavenPreconditionInventory.Snapshot inventory =
        completeInventory(Provider.dependencyArchive(candidate, trimmedJar));
    final VulnerabilitySymbolMapping first =
        mappingWithPrerequisites(
            firstMappingCoordinate,
            FIRST_OVERLAP_RANGE,
            Set.of("org.example.Vulnerable"),
            ConfidenceLevel.HIGH,
            REQUIRED_DEPENDENCY,
            REQUIRED_CLASS);
    final VulnerabilitySymbolMapping second =
        mappingWithPrerequisites(
            secondMappingCoordinate,
            SECOND_OVERLAP_RANGE,
            Set.of("org.example.Vulnerable"),
            ConfidenceLevel.HIGH,
            REQUIRED_DEPENDENCY,
            "org.example.alternate.EntryPoint");

    for (final List<VulnerabilitySymbolMapping> mappings :
        List.of(List.of(first, second), List.of(second, first))) {
      final MavenVulnerabilityAssessment.Result result = assess(analysis, inventory, mappings);

      assertThat(result.attestations()).isEmpty();
      assertThat(result.provenVulnerableCodeAbsent()).isEmpty();
      assertThat(result.inactiveDueToMissingPrerequisites()).isEmpty();
      assertThat(result.potentiallyConservativeCves()).isEmpty();
      final MavenElisionReportSnapshot report = reportSnapshot(analysis, result);
      assertThat(report.provenAbsentCves()).isEmpty();
      assertThat(report.inactivePreconditionCves()).isEmpty();
      assertThat(report.potentiallyConservativeCves()).isEmpty();
    }
  }

  @Test
  void conflictingConfidenceAndIncompleteMappingsSuppressOtherwiseValidPreconditionProof()
      throws IOException {
    final ArtifactCoordinate candidate =
        ArtifactCoordinate.of(GROUP_ID, AFFECTED_ARTIFACT_ID, OVERLAP_CANDIDATE_VERSION);
    final ArtifactCoordinate firstMappingCoordinate =
        ArtifactCoordinate.of(GROUP_ID, AFFECTED_ARTIFACT_ID, AFFECTED_VERSION);
    final ArtifactCoordinate secondMappingCoordinate =
        ArtifactCoordinate.of(GROUP_ID, AFFECTED_ARTIFACT_ID, OVERLAP_MAPPING_VERSION);
    final MavenPreconditionInventory.Snapshot inventory =
        completeInventory(
            Provider.dependencyArchive(candidate, writeJar("conflicting-variant.jar")));
    final ElisionAnalysisModel.Analysis analysis = analysis(List.of(candidate));
    final VulnerabilitySymbolMapping high =
        mapping(firstMappingCoordinate, FIRST_OVERLAP_RANGE, Set.of(), ConfidenceLevel.HIGH);
    final VulnerabilitySymbolMapping low =
        mapping(secondMappingCoordinate, SECOND_OVERLAP_RANGE, Set.of(), ConfidenceLevel.LOW);
    final VulnerabilitySymbolMapping incomplete =
        new VulnerabilitySymbolMapping(
            CVE_ID,
            secondMappingCoordinate,
            SECOND_OVERLAP_RANGE,
            Set.of(),
            URI.create("https://example.com/advisories/" + CVE_ID),
            ConfidenceLevel.HIGH,
            REQUIRED_DEPENDENCY);

    final MavenVulnerabilityAssessment.Result confidenceConflict =
        assess(analysis, inventory, List.of(high, low));
    final MavenVulnerabilityAssessment.Result incompleteConflict =
        assess(analysis, inventory, List.of(high, incomplete));

    assertThat(confidenceConflict.attestations()).isEmpty();
    assertThat(confidenceConflict.inactiveDueToMissingPrerequisites()).isEmpty();
    assertThat(incompleteConflict.attestations()).isEmpty();
    assertThat(incompleteConflict.inactiveDueToMissingPrerequisites()).isEmpty();
  }

  @Test
  void sameKeyPomMappingsRemainVisibleToConflictReconciliation() throws IOException {
    final ArtifactCoordinate candidate =
        ArtifactCoordinate.of(GROUP_ID, AFFECTED_ARTIFACT_ID, OVERLAP_CANDIDATE_VERSION);
    final ArtifactCoordinate mappingCoordinate =
        ArtifactCoordinate.of(GROUP_ID, AFFECTED_ARTIFACT_ID, OVERLAP_MAPPING_VERSION);
    final MavenPreconditionInventory.Snapshot inventory =
        completeInventory(
            Provider.dependencyArchive(candidate, writeJar("same-key-candidate.jar")));
    final ElisionAnalysisModel.Analysis analysis = analysis(List.of(candidate));
    final VulnerabilitySymbolMapping first =
        mappingWithPrerequisites(
            mappingCoordinate,
            FIRST_OVERLAP_RANGE,
            Set.of(),
            ConfidenceLevel.HIGH,
            REQUIRED_DEPENDENCY,
            REQUIRED_CLASS);
    final VulnerabilitySymbolMapping second =
        mappingWithPrerequisites(
            mappingCoordinate,
            SECOND_OVERLAP_RANGE,
            Set.of(),
            ConfidenceLevel.HIGH,
            REQUIRED_DEPENDENCY,
            "org.example.alternate.EntryPoint");

    for (final List<VulnerabilitySymbolMapping> mappings :
        List.of(List.of(first, second), List.of(second, first))) {
      final MavenVulnerabilityAssessment.Result result = assess(analysis, inventory, mappings);

      assertThat(result.attestations()).isEmpty();
      assertThat(result.inactiveDueToMissingPrerequisites()).isEmpty();
    }
  }

  @Test
  void conflictingMappingsSuppressRemovedComponentClassification() throws IOException {
    final ArtifactCoordinate removed =
        ArtifactCoordinate.of(GROUP_ID, AFFECTED_ARTIFACT_ID, OVERLAP_CANDIDATE_VERSION);
    final ArtifactCoordinate firstMappingCoordinate =
        ArtifactCoordinate.of(GROUP_ID, AFFECTED_ARTIFACT_ID, AFFECTED_VERSION);
    final ArtifactCoordinate secondMappingCoordinate =
        ArtifactCoordinate.of(GROUP_ID, AFFECTED_ARTIFACT_ID, OVERLAP_MAPPING_VERSION);
    final ElisionAnalysisModel.Analysis analysis = analysis(List.of(), List.of(removed), List.of());
    final VulnerabilitySymbolMapping first =
        mappingWithPrerequisites(
            firstMappingCoordinate,
            FIRST_OVERLAP_RANGE,
            Set.of(),
            ConfidenceLevel.HIGH,
            REQUIRED_DEPENDENCY,
            REQUIRED_CLASS);
    final VulnerabilitySymbolMapping second =
        mappingWithPrerequisites(
            secondMappingCoordinate,
            SECOND_OVERLAP_RANGE,
            Set.of(),
            ConfidenceLevel.HIGH,
            REQUIRED_DEPENDENCY,
            "org.example.alternate.EntryPoint");

    final MavenVulnerabilityAssessment.Result result =
        new MavenVulnerabilityAssessment(new RecordingMavenLog())
            .assess(emptyCache("removed-conflict-cache"), List.of(first, second), analysis);

    assertThat(result.removedComponents()).isEmpty();
  }

  @Test
  void identicalDuplicateMappingsProduceAtMostOneStatementAndInactiveFinding() throws IOException {
    final ArtifactCoordinate affected =
        ArtifactCoordinate.of(GROUP_ID, AFFECTED_ARTIFACT_ID, AFFECTED_VERSION);
    final MavenPreconditionInventory.Snapshot inventory =
        completeInventory(Provider.dependencyArchive(affected, writeJar("duplicate-map.jar")));
    final ElisionAnalysisModel.Analysis analysis = analysis(List.of(affected));
    final VulnerabilitySymbolMapping duplicate =
        mapping(affected, EXACT_VERSION_RANGE, Set.of(), ConfidenceLevel.HIGH);

    final MavenVulnerabilityAssessment.Result result =
        assess(analysis, inventory, List.of(duplicate, duplicate));

    assertThat(result.attestations()).hasSize(1);
    assertThat(result.inactiveDueToMissingPrerequisites())
        .containsExactly(new MavenVulnerabilityAssessment.Finding(CVE_ID, affected));
  }

  @Test
  void successfulPreconditionProofSuppressesConservativeOmissionClassification()
      throws IOException {
    final ArtifactCoordinate affected =
        ArtifactCoordinate.of(GROUP_ID, AFFECTED_ARTIFACT_ID, AFFECTED_VERSION);
    final Path originalJar = writeJar("conservative-original.jar", "org/example/Present.class");
    final Path trimmedJar = writeJar("conservative-trimmed.jar");
    final ArtifactTrimRecord trimRecord = trimRecord(affected, originalJar, trimmedJar);
    final ElisionAnalysisModel.Analysis analysis = analysis(List.of(affected), List.of(trimRecord));
    final MavenPreconditionInventory.Snapshot inventory =
        completeInventory(Provider.dependencyArchive(affected, trimmedJar));
    final VulnerabilitySymbolMapping mapping =
        mapping(
            affected,
            EXACT_VERSION_RANGE,
            Set.of("org.example.Present", "org.example.AbsentInOriginal"),
            ConfidenceLevel.HIGH);

    final MavenVulnerabilityAssessment.Result result =
        assess(analysis, inventory, List.of(mapping));

    assertThat(result.attestations()).hasSize(1);
    assertThat(result.attestations().getFirst().justification()).isEqualTo("requires_dependency");
    assertThat(result.inactiveDueToMissingPrerequisites()).hasSize(1);
    assertThat(result.provenVulnerableCodeAbsent()).isEmpty();
    assertThat(result.potentiallyConservativeCves()).isEmpty();
    final MavenElisionReportSnapshot report = reportSnapshot(analysis, result);
    assertThat(report.inactivePreconditionCves()).hasSize(1);
    assertThat(report.potentiallyConservativeCves()).isEmpty();
  }

  private MavenVulnerabilityAssessment.Result assess(
      final ElisionAnalysisModel.Analysis analysis,
      final MavenPreconditionInventory.Snapshot inventory,
      final List<VulnerabilitySymbolMapping> mappings)
      throws IOException {
    return new MavenVulnerabilityAssessment(new RecordingMavenLog())
        .assess(emptyCache("assessment-cache"), configured(mappings), analysis, inventory);
  }

  private static ConfiguredVulnerabilityMappings configured(
      final List<VulnerabilitySymbolMapping> mappings) {
    final List<VulnerabilityMappingConfig> configs =
        mappings.stream()
            .map(
                mapping -> {
                  final VulnerabilityMappingConfig config = new VulnerabilityMappingConfig();
                  config.setCveId(mapping.cveId());
                  config.setGroupId(mapping.affectedCoordinate().groupId());
                  config.setArtifactId(mapping.affectedCoordinate().artifactId());
                  config.setVersion(mapping.affectedCoordinate().version());
                  config.setType(mapping.affectedCoordinate().type());
                  config.setClassifier(mapping.affectedCoordinate().classifier());
                  config.setScope(mapping.affectedCoordinate().scope());
                  config.setVersionRangeSpec(mapping.versionRangeSpec());
                  config.setVulnerableClasses(List.copyOf(mapping.vulnerableClasses()));
                  config.setSourceAdvisoryUrl(
                      mapping.sourceAdvisoryUrl() == null
                          ? null
                          : mapping.sourceAdvisoryUrl().toString());
                  config.setConfidenceLevel(mapping.confidenceLevel().name());
                  config.setRequiresDependency(mapping.requiresDependency());
                  config.setRequiresClass(mapping.requiresClass());
                  return config;
                })
            .toList();
    return ConfiguredVulnerabilityMappings.fromPom(configs);
  }

  private CacheConfig emptyCache(final String directory) {
    return new CacheConfig(
        temporaryDirectory.resolve(directory),
        null,
        null,
        Duration.ofHours(24),
        false,
        true,
        VulnerabilityCacheManager.bundledEmptySeed());
  }

  private CacheConfig seededCache(final String directory, final VulnerabilitySymbolMapping mapping)
      throws IOException {
    final byte[] seed = mappingDocument(mapping);
    return new CacheConfig(
        temporaryDirectory.resolve(directory),
        null,
        null,
        Duration.ofHours(24),
        false,
        true,
        () -> new ByteArrayInputStream(seed));
  }

  private static byte[] mappingDocument(final VulnerabilitySymbolMapping mapping)
      throws IOException {
    final ArtifactCoordinate coordinate =
        ArtifactCoordinate.of(
            mapping.affectedCoordinate().groupId(),
            mapping.affectedCoordinate().artifactId(),
            null);
    final AdvisoryScope scope =
        new AdvisoryScope(
            mapping.cveId(),
            coordinate,
            mapping.versionRangeSpec(),
            "Maven",
            coordinate.groupId() + ":" + coordinate.artifactId());
    final OsvAdvisoryRecord record =
        new OsvAdvisoryRecord(
            "GHSA-cache-fixture",
            "2026-10-31T00:00:00Z",
            Set.of(mapping.cveId()),
            List.of(
                new OsvAffectedPackage(
                    "Maven", scope.packageName(), coordinate, List.of(), List.of())),
            List.of(),
            List.of(
                new PackageAdvisoryEvidence(
                    scope,
                    new AdvisoryProvenance(EvidenceOrigin.OSV, "GHSA-cache-fixture", null, null))));
    return new AdvisoryEvidenceWriter().encode(List.of(record));
  }

  private static VulnerabilitySymbolMapping mapping(
      final ArtifactCoordinate affected,
      final String versionRange,
      final Set<String> vulnerableClasses,
      final ConfidenceLevel confidence) {
    return mappingWithPrerequisites(
        affected, versionRange, vulnerableClasses, confidence, REQUIRED_DEPENDENCY, REQUIRED_CLASS);
  }

  private static VulnerabilitySymbolMapping mappingWithPrerequisites(
      final ArtifactCoordinate affected,
      final String versionRange,
      final Set<String> vulnerableClasses,
      final ConfidenceLevel confidence,
      final String requiredDependency,
      final String requiredClass) {
    return new VulnerabilitySymbolMapping(
        CVE_ID,
        affected,
        versionRange,
        vulnerableClasses,
        URI.create("https://example.com/advisories/" + CVE_ID),
        confidence,
        requiredDependency,
        requiredClass);
  }

  private static ElisionAnalysisModel.Analysis analysis(
      final List<ArtifactCoordinate> retainedCoordinates) {
    return analysis(retainedCoordinates, List.of());
  }

  private static ElisionAnalysisModel.Analysis analysis(
      final List<ArtifactCoordinate> retainedCoordinates,
      final List<ArtifactTrimRecord> trimRecords) {
    return analysis(retainedCoordinates, List.of(), trimRecords);
  }

  private static ElisionAnalysisModel.Analysis analysis(
      final List<ArtifactCoordinate> retainedCoordinates,
      final List<ArtifactCoordinate> removedCoordinates,
      final List<ArtifactTrimRecord> trimRecords) {
    final ElisionDecision decision =
        new ElisionDecision(
            Set.copyOf(retainedCoordinates),
            Set.copyOf(removedCoordinates),
            Map.of(),
            Map.of(),
            0L);
    return new ElisionAnalysisModel.Analysis(
        new ElisionAnalysisModel.ArtifactViews(List.of(), false, List.of()),
        decision,
        decision,
        new ElisionAnalysisModel.AnalysisEvidence(
            new ClassUsageReport(List.of()), Optional.empty(), Map.of(), false, false, null),
        new TrimResult(trimRecords, List.of(), List.of(), List.of(), 0, 0L, 0, null),
        null,
        null,
        MavenElisionPolicyIdentityTestSupport.emptyPolicy());
  }

  private static MavenPreconditionInventory.Snapshot completeInventory(final Provider... providers)
      throws IOException {
    return inventory(PreconditionClassInventory.complete(List.of(providers)), providers);
  }

  private static MavenPreconditionInventory.Snapshot inventory(
      final PreconditionClassInventory classProviders, final Provider... providers)
      throws IOException {
    return inventory(classProviders, true, providers);
  }

  private static MavenPreconditionInventory.Snapshot inventory(
      final PreconditionClassInventory classProviders,
      final boolean optInEnabled,
      final Provider... providers)
      throws IOException {
    final List<ArtifactFileRef> artifactFiles = new ArrayList<>();
    for (final Provider provider : providers) {
      if (provider.coordinate() != null) {
        artifactFiles.add(ArtifactFileRef.fromPath(provider.coordinate(), provider.path()));
      }
    }
    return new MavenPreconditionInventory.Snapshot(
        artifactFiles,
        classProviders,
        "assessment-test-root-fingerprint",
        List.of(),
        List.of(),
        optInEnabled);
  }

  @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
  private Path writeJar(final String name, final String... classes) throws IOException {
    final Path path = temporaryDirectory.resolve(name);
    try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(path))) {
      for (final String className : classes) {
        output.putNextEntry(new JarEntry(className));
        output.write(classBytes(className.substring(0, className.length() - ".class".length())));
        output.closeEntry();
      }
    }
    return path;
  }

  private static byte[] classBytes(final String internalName) {
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, internalName, null, "java/lang/Object", null);
    writer.visitEnd();
    return writer.toByteArray();
  }

  private static ArtifactTrimRecord trimRecord(
      final ArtifactCoordinate coordinate, final Path original, final Path trimmed)
      throws IOException {
    final ArtifactDigests originalDigests = ArtifactDigests.read(original);
    final ArtifactDigests trimmedDigests = ArtifactDigests.read(trimmed);
    return new ArtifactTrimRecord(
        coordinate,
        original,
        originalDigests.sha256(),
        originalDigests.sha1(),
        trimmed,
        trimmedDigests.sha256(),
        trimmedDigests.sha1(),
        1,
        0,
        0L);
  }

  private MavenElisionReportSnapshot reportSnapshot(
      final ElisionAnalysisModel.Analysis analysis,
      final MavenVulnerabilityAssessment.Result result)
      throws IOException {
    final MavenProject project = new MavenProject();
    project.setGroupId(GROUP_ID);
    project.setArtifactId("assessment-project");
    project.setVersion(AFFECTED_VERSION);
    project.setFile(temporaryDirectory.resolve("pom.xml").toFile());
    return MavenElisionReportSnapshot.from(project, analysis, result);
  }
}
