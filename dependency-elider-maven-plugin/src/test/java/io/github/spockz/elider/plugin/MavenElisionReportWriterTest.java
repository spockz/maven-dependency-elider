// WHY: Verifies persisted report metric derivation, serialization, and formatting.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.engine.ClassUsageReport;
import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ElisionDecision;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;
import org.apache.maven.model.Build;
import org.apache.maven.project.MavenProject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Tests report snapshots independently from Maven dependency analysis. */
@SuppressWarnings({
  "PMD.UnitTestContainsTooManyAsserts",
  "PMD.TooManyMethods",
  "PMD.AvoidDuplicateLiterals"
})
final class MavenElisionReportWriterTest {
  /** Maven group used in synthetic test coordinates. */
  private static final String GROUP_ID = "org.example";

  /** Version used for synthetic whole-artifact removal records. */
  private static final String REMOVED_VERSION = "1.0";

  /** Stable version used by the synthetic report project. */
  private static final String PROJECT_VERSION = REMOVED_VERSION;

  /** Owners shared by persisted tolerated duplicate assertions. */
  private static final List<String> DUPLICATE_OWNERS =
      List.of("org.example:a:jar:1.0", "org.example:b:jar:1.0");

  /** Artifact identifier used for synthetic whole-artifact removal records. */
  private static final String REMOVED_ARTIFACT = "removed";

  /** Stable timestamp for deterministic snapshot serialization assertions. */
  private static final String GENERATED_AT = "2026-10-26T16:00:00Z";

  /** Temporary root for synthetic project and archive inputs. */
  @TempDir private Path temporaryDirectory;

  /** Creates the report writer test fixture. */
  @SuppressWarnings({"PMD.UncommentedEmptyConstructor", "PMD.CommentDefaultAccessModifier"})
  MavenElisionReportWriterTest() {}

  @Test
  void analysisSnapshotReplaysPlannedTrimWithUnknownBytes() throws IOException {
    final ArtifactCoordinate coordinate = ArtifactCoordinate.of("org.example", "trimmed", "1.0");
    final AnalyzePrediction prediction =
        new AnalyzePrediction(
            MavenAnalysisResolutionContext.Provenance.DETACHED_CURRENT_MODEL,
            List.of(new ElisionAnalysisModel.ArtifactSnapshot(null, coordinate, null)),
            List.of(coordinate),
            List.of(),
            List.of(new AnalyzePrediction.PlannedTrim(coordinate, Set.of("p.Removed"))),
            new ElisionAnalysisModel.AnalysisEvidence(
                new ClassUsageReport(List.of()),
                Optional.empty(),
                Map.of(),
                false,
                false,
                "source attribution unavailable"),
            "a".repeat(64),
            "b".repeat(64),
            "c".repeat(64));
    final MavenElisionReportSnapshot original =
        MavenElisionReportSnapshot.from(
            project(),
            prediction,
            new MavenVulnerabilityAssessment.Result(List.of(), List.of(), List.of(), false),
            ExclusionReview.unavailable("unavailable"));
    final Path report = temporaryDirectory.resolve("analysis-report.json");
    MavenElisionReportWriter.write(report, original);
    final MavenElisionReportSnapshot replay = MavenElisionReportWriter.read(report);
    final com.fasterxml.jackson.databind.ObjectMapper mapper =
        new com.fasterxml.jackson.databind.ObjectMapper();
    final com.fasterxml.jackson.databind.node.ObjectNode saved =
        (com.fasterxml.jackson.databind.node.ObjectNode) mapper.readTree(report.toFile());
    final com.fasterxml.jackson.databind.node.ObjectNode badMode = saved.deepCopy();
    badMode.put("mode", "INVENTED");
    final com.fasterxml.jackson.databind.node.ObjectNode falseMeasurement = saved.deepCopy();
    falseMeasurement.put("uncompressedProgramClassBytesPruned", 0);
    final com.fasterxml.jackson.databind.node.ObjectNode absentClasses = saved.deepCopy();
    ((com.fasterxml.jackson.databind.node.ObjectNode)
            absentClasses.withArray("trimmedArtifacts").get(0))
        .putNull("plannedClasses");
    assertAll(
        () -> assertThat(replay.mode()).isEqualTo(MavenElisionReportSnapshot.Mode.ANALYSIS),
        () -> assertThat(replay.inputArtifactCount()).isEqualTo(1),
        () ->
            assertThat(replay.sourceAttributionFallback())
                .isEqualTo("source attribution unavailable"),
        () ->
            assertThat(MavenElisionReportWriter.render(replay))
                .anyMatch(line -> line.contains("source attribution unavailable")),
        () -> assertBadPayloadRejected(mapper, badMode, "bad-mode"),
        () -> assertBadPayloadRejected(mapper, falseMeasurement, "false-measurement"),
        () -> assertBadPayloadRejected(mapper, absentClasses, "absent-classes"),
        () ->
            assertThat(replay.trimmedArtifacts())
                .singleElement()
                .satisfies(
                    trim -> {
                      assertThat(trim.programClassesPruned()).isEqualTo(1);
                      assertThat(trim.uncompressedProgramClassBytesPruned()).isNull();
                      assertThat(trim.plannedClasses()).containsExactly("p.Removed");
                    }),
        () -> assertThat(replay.uncompressedProgramClassBytesPruned()).isNull(),
        () ->
            assertThat(MavenElisionReportWriter.render(replay))
                .anyMatch(line -> line.contains("would") && line.contains("unknown")));
  }

  @Test
  void validatesForecastAgainstMatchingPlannedClassesAcrossScopes() throws IOException {
    final ArtifactCoordinate coordinate = ArtifactCoordinate.of("org.example", "trimmed", "1.0");
    final io.github.spockz.elider.model.CodeClaim code =
        io.github.spockz.elider.model.CodeClaim.declared(
            io.github.spockz.elider.model.CodeReference.className("p.Missing"));
    final GenericFindingAssessment finding =
        new GenericFindingAssessment(
            "GHSA-test",
            Set.of(),
            new ArtifactCoordinate("org.example", "trimmed", "1.0", "jar", "", "runtime"),
            io.github.spockz.elider.model.VersionApplicability.AFFECTED,
            Optional.of(io.github.spockz.elider.model.AssessmentIntent.AUTO_VERIFY),
            io.github.spockz.elider.model.ClaimGroupStatus.DECLARED,
            List.of(
                new io.github.spockz.elider.model.CodeAttributionResolver.DeclarationResult(
                    code,
                    io.github.spockz.elider.model.CodeAttributionResolver.Status.RESOLVED,
                    Set.of("p.Missing"),
                    List.of())),
            List.of(),
            io.github.spockz.elider.model.ClaimGroupStatus.OMITTED,
            List.of(),
            List.of(),
            Set.of(),
            Set.of(),
            GenericFindingAssessment.Outcome.PLANNED_CODE_ABSENT,
            "planned",
            MavenVulnerabilityAssessment.InventoryDisposition.PLANNED_TRIM,
            List.of());
    final AnalyzePrediction prediction =
        new AnalyzePrediction(
            MavenAnalysisResolutionContext.Provenance.DETACHED_CURRENT_MODEL,
            List.of(new ElisionAnalysisModel.ArtifactSnapshot(null, coordinate, null)),
            List.of(coordinate),
            List.of(),
            List.of(new AnalyzePrediction.PlannedTrim(coordinate, Set.of("p.Missing"))),
            new ElisionAnalysisModel.AnalysisEvidence(
                new ClassUsageReport(List.of()), Optional.empty(), Map.of(), false, false, null),
            "a".repeat(64),
            "b".repeat(64),
            "c".repeat(64));
    final MavenElisionReportSnapshot snapshot =
        MavenElisionReportSnapshot.from(
            project(),
            prediction,
            new MavenVulnerabilityAssessment.Result(List.of(), List.of(finding), List.of(), false),
            ExclusionReview.unavailable("unavailable"));
    final Path path = temporaryDirectory.resolve("forecast.json");
    MavenElisionReportWriter.write(path, snapshot);
    final com.fasterxml.jackson.databind.ObjectMapper mapper =
        new com.fasterxml.jackson.databind.ObjectMapper();
    final com.fasterxml.jackson.databind.node.ObjectNode saved =
        (com.fasterxml.jackson.databind.node.ObjectNode) mapper.readTree(path.toFile());
    final com.fasterxml.jackson.databind.node.ObjectNode badClass = saved.deepCopy();
    ((com.fasterxml.jackson.databind.node.ObjectNode) badClass.withArray("trimmedArtifacts").get(0))
        .putArray("plannedClasses")
        .add("p.Other");
    final com.fasterxml.jackson.databind.node.ObjectNode wrongVersion = saved.deepCopy();
    ((com.fasterxml.jackson.databind.node.ObjectNode)
            wrongVersion.withArray("trimmedArtifacts").get(0))
        .put("coordinate", "org.example:trimmed:jar:2.0 (compile)");
    final com.fasterxml.jackson.databind.node.ObjectNode wrongClassifier = saved.deepCopy();
    ((com.fasterxml.jackson.databind.node.ObjectNode)
            wrongClassifier.withArray("trimmedArtifacts").get(0))
        .put("coordinate", "org.example:trimmed:jar:tests:1.0 (compile)");
    final com.fasterxml.jackson.databind.node.ObjectNode duplicate = saved.deepCopy();
    final com.fasterxml.jackson.databind.node.ObjectNode duplicateTrim =
        ((com.fasterxml.jackson.databind.node.ObjectNode)
                duplicate.withArray("trimmedArtifacts").get(0))
            .deepCopy();
    duplicateTrim.put("coordinate", "org.example:trimmed:jar:1.0 (runtime)");
    duplicate.withArray("trimmedArtifacts").add(duplicateTrim);
    duplicate.put("programClassesPruned", 2);
    final com.fasterxml.jackson.databind.node.ObjectNode emptyFamily = saved.deepCopy();
    ((com.fasterxml.jackson.databind.node.ObjectNode)
            emptyFamily.withArray("genericFindings").get(0).path("codeAttribution").get(0))
        .putArray("classFamily");
    final com.fasterxml.jackson.databind.node.ObjectNode fakeProof = saved.deepCopy();
    ((com.fasterxml.jackson.databind.node.ObjectNode) fakeProof.withArray("genericFindings").get(0))
        .put("outcome", "DECLARED_CODE_ABSENT");
    final com.fasterxml.jackson.databind.node.ObjectNode appliedForecast = saved.deepCopy();
    appliedForecast.put("mode", "APPLIED");
    appliedForecast.put("uncompressedProgramClassBytesPruned", 1);
    final com.fasterxml.jackson.databind.node.ObjectNode appliedTrim =
        (com.fasterxml.jackson.databind.node.ObjectNode)
            appliedForecast.withArray("trimmedArtifacts").get(0);
    appliedTrim.put("uncompressedProgramClassBytesPruned", 1);
    appliedTrim.putNull("plannedClasses");
    assertAll(
        () -> assertThat(MavenElisionReportWriter.read(path).genericFindings()).hasSize(1),
        () -> assertBadPayloadRejected(mapper, badClass, "forged-class"),
        () -> assertBadPayloadRejected(mapper, wrongVersion, "wrong-version"),
        () -> assertBadPayloadRejected(mapper, wrongClassifier, "wrong-classifier"),
        () -> assertBadPayloadRejected(mapper, duplicate, "duplicate-component-plan"),
        () -> assertBadPayloadRejected(mapper, emptyFamily, "empty-family"),
        () -> assertBadPayloadRejected(mapper, fakeProof, "analysis-proof"),
        () -> assertBadPayloadRejected(mapper, appliedForecast, "applied-forecast"));
  }

  private void assertBadPayloadRejected(
      final com.fasterxml.jackson.databind.ObjectMapper mapper,
      final com.fasterxml.jackson.databind.node.ObjectNode payload,
      final String name)
      throws IOException {
    final Path path = temporaryDirectory.resolve(name + ".json");
    mapper.writeValue(path.toFile(), payload);
    assertThatThrownBy(() -> MavenElisionReportWriter.read(path)).isInstanceOf(IOException.class);
  }

  @Test
  void capturesOriginalArtifactAndUncompressedPrunedProgramClassBytes() throws IOException {
    final ArtifactCoordinate removedCoordinate =
        ArtifactCoordinate.of(GROUP_ID, REMOVED_ARTIFACT, REMOVED_VERSION);
    final ArtifactCoordinate trimmedCoordinate = ArtifactCoordinate.of(GROUP_ID, "trimmed", "2.0");
    final Path removedJar = temporaryDirectory.resolve(REMOVED_ARTIFACT + ".jar");
    final long originalDroppedJarBytes = writeDroppedJar(removedJar);
    final Path originalTrimmedJar = temporaryDirectory.resolve("trimmed.jar");
    Files.write(originalTrimmedJar, new byte[4096]);
    final Artifact removedArtifact = artifact(removedCoordinate, removedJar);
    final Artifact trimmedArtifact = artifact(trimmedCoordinate, originalTrimmedJar);
    final ElisionAnalysisModel.ArtifactSnapshot removedSnapshot =
        new ElisionAnalysisModel.ArtifactSnapshot(removedArtifact, removedCoordinate, removedJar);
    final ElisionAnalysisModel.ArtifactSnapshot trimmedSnapshot =
        new ElisionAnalysisModel.ArtifactSnapshot(
            trimmedArtifact, trimmedCoordinate, originalTrimmedJar);
    final ArtifactTrimRecord trimRecord =
        new ArtifactTrimRecord(
            trimmedCoordinate,
            originalTrimmedJar,
            "a".repeat(64),
            "b".repeat(40),
            temporaryDirectory.resolve("trimmed-output.jar"),
            "c".repeat(64),
            "d".repeat(40),
            7,
            3,
            3096);
    final ElisionDecision decision =
        new ElisionDecision(
            Set.of(trimmedCoordinate), Set.of(removedCoordinate), Map.of(), Map.of(), 0L);
    final MavenProject project = project();
    final ElisionAnalysisModel.Analysis analysis =
        new ElisionAnalysisModel.Analysis(
            new ElisionAnalysisModel.ArtifactViews(
                List.of(removedSnapshot, trimmedSnapshot), false, List.of()),
            decision,
            decision,
            new ElisionAnalysisModel.AnalysisEvidence(
                new ClassUsageReport(List.of()), Optional.empty(), Map.of(), false, false, null),
            new TrimResult(
                List.of(trimRecord),
                List.of(),
                List.of(),
                List.of(),
                0,
                0L,
                0,
                new TrimExecutionEnvironment(21, Runtime.version().feature()),
                List.of()),
            null,
            MediatedGraphReportTestSupport.reportForOutputs(
                removedCoordinate, trimmedCoordinate, GROUP_ID + ":consumer:" + PROJECT_VERSION),
            MavenElisionPolicyIdentityTestSupport.emptyPolicy());

    final MavenElisionReportSnapshot snapshot = MavenElisionReportSnapshot.from(project, analysis);
    final MavenElisionReportSnapshot.DroppedArtifactSummary droppedArtifacts =
        MavenElisionReportSnapshot.droppedArtifactSummary(analysis);

    assertThat(snapshot.inputArtifactCount()).isEqualTo(2);
    assertThat(snapshot.wholeArtifactsDropped()).isOne();
    assertThat(snapshot.originalJarBytesDropped()).isEqualTo(originalDroppedJarBytes);
    assertThat(snapshot.droppedProgramClassEntries()).isEqualTo(2);
    assertThat(snapshot.droppedProgramClassBytes()).isEqualTo(18);
    assertThat(droppedArtifacts.artifacts()).isEqualTo(snapshot.droppedArtifacts());
    assertThat(droppedArtifacts.originalJarBytes()).isEqualTo(snapshot.originalJarBytesDropped());
    assertThat(snapshot.programClassesPruned()).isEqualTo(4);
    assertThat(snapshot.uncompressedProgramClassBytesPruned()).isEqualTo(3096);
    assertThat(snapshot.droppedProgramClassEntries()).isNotEqualTo(snapshot.programClassesPruned());
    assertThat(snapshot.droppedArtifacts())
        .singleElement()
        .satisfies(row -> assertThat(row.coordinate()).contains(REMOVED_ARTIFACT));
    assertThat(snapshot.trimmedArtifacts())
        .singleElement()
        .satisfies(
            row -> {
              assertThat(row.programClassesPruned()).isEqualTo(4);
              assertThat(row.uncompressedProgramClassBytesPruned()).isEqualTo(3096);
            });
    assertThat(snapshot.droppedArtifacts())
        .singleElement()
        .satisfies(
            row -> {
              assertThat(row.programClassesRemoved()).isEqualTo(2);
              assertThat(row.uncompressedProgramClassBytesRemoved()).isEqualTo(18);
            });
  }

  @Test
  void writesReadsAndRendersDeterministicBinaryByteUnits() throws IOException {
    final MavenElisionReportSnapshot snapshot = snapshot();
    final Path output = temporaryDirectory.resolve("target/dependency-elider-report.json");

    MavenElisionReportWriter.write(output, snapshot);
    final MavenElisionReportSnapshot reread = MavenElisionReportWriter.read(output);

    assertAll(
        "policy identity survives report round-trip and renders stable canonical values",
        () -> assertThat(reread).isEqualTo(snapshot),
        () -> {
          final List<String> rendered = MavenElisionReportWriter.render(reread);
          assertAll(
              "rendered report contains saved graph and policy values without its opaque digest",
              () ->
                  assertThat(rendered)
                      .contains(
                          "Project: org.example:consumer:1.0",
                          "Snapshot: last successful elide run at " + GENERATED_AT,
                          "The snapshot does not revalidate changed inputs when this goal runs.",
                          "Whole artifacts dropped: 1 / 2 (original JAR file bytes: 2.00 KiB)",
                          "Program classes removed with dropped JARs: 2 (uncompressed .class entry"
                              + " payload bytes: 18 B; excludes module descriptors and "
                              + "archive sanitation metadata)",
                          "  - org.example:removed:jar:1.0 (compile): "
                              + "2.00 KiB original JAR, 2 class entries, 18 B",
                          "Program classes pruned from retained JARs: 4 (uncompressed omitted"
                              + " .class payload bytes: "
                              + "3.02 KiB; excludes module descriptors and archive metadata)",
                          "Vulnerability findings: none",
                          "CVE Sources: none",
                          "Mediated TEST dependency graph (captured and saved by the elide goal):"),
              () ->
                  assertThat(rendered)
                      .anySatisfy(message -> assertThat(message).contains("[EFFECTIVE_DROP]")),
              () ->
                  assertThat(rendered)
                      .anySatisfy(
                          message -> assertThat(message).contains("[RETAINED, CLASS_TRIMMED]")),
              () ->
                  assertThat(rendered)
                      .anySatisfy(
                          message ->
                              assertThat(message)
                                  .contains(
                                      "Policy: retained=[org.example:kept::jar:], "
                                          + "banished=[org.example:banned]")
                                  .doesNotContain(reread.policy().operationFingerprint())));
        },
        () ->
            assertThat(reread.policy())
                .isEqualTo(
                    new MavenElisionPolicyIdentity(
                        List.of("org.example:kept::jar:"),
                        List.of("org.example:banned"),
                        MavenElisionGraphBinding.sha256(List.of("report-policy-test")))),
        () ->
            assertThat(reread.policy().operationFingerprint())
                .isEqualTo(MavenElisionGraphBinding.sha256(List.of("report-policy-test"))),
        () -> assertThat(MavenElisionReportWriter.formatBytes(0)).isEqualTo("0 B"),
        () -> assertThat(MavenElisionReportWriter.formatBytes(1023)).isEqualTo("1023 B"),
        () -> assertThat(MavenElisionReportWriter.formatBytes(1024)).isEqualTo("1.00 KiB"),
        () -> assertThat(MavenElisionReportWriter.formatBytes(1_048_576)).isEqualTo("1.00 MiB"));
  }

  @Test
  void groupsDroppedJarsBeforeTheBanSummary() throws IOException {
    final List<String> rendered =
        MavenElisionReportWriter.render(snapshot().withAppliedBans(List.of()));
    assertThat(rendered)
        .containsSubsequence(
            "Whole artifacts dropped: 1 / 2 (original JAR file bytes: 2.00 KiB)",
            "  - org.example:removed:jar:1.0 (compile): 2.00 KiB original JAR, 2 class entries, 18"
                + " B",
            "Applied bans: none",
            "Program classes pruned from retained JARs: 4 (uncompressed omitted .class payload"
                + " bytes: 3.02 KiB; excludes module descriptors and archive metadata)");
  }

  @Test
  void rendersExplicitZeroTotals() throws IOException {
    final MavenElisionReportSnapshot populated = snapshot();
    final MavenElisionReportSnapshot empty =
        new MavenElisionReportSnapshot(
            populated.schemaVersion(),
            populated.projectGroupId(),
            populated.projectArtifactId(),
            populated.projectVersion(),
            populated.projectBaseDirectory(),
            populated.generatedAt(),
            populated.executionEnvironment(),
            0,
            0,
            List.of(),
            List.of(),
            0,
            0,
            List.of(),
            MediatedGraphReportTestSupport.emptyGraph(populated.projectGav()),
            populated.policy());

    assertThat(MavenElisionReportWriter.render(empty))
        .contains(
            "Whole artifacts dropped: 0 / 0 (original JAR file bytes: 0 B)",
            "Program classes removed with dropped JARs: 0 (uncompressed .class entry"
                + " payload bytes: 0 B; excludes module descriptors and "
                + "archive sanitation metadata)",
            "Program classes pruned from retained JARs: 0 (uncompressed omitted"
                + " .class payload bytes: "
                + "0 B; excludes module descriptors and archive metadata)",
            "Vulnerability findings: none",
            "CVE Sources: none");
  }

  @Test
  void writesReadsAndRendersToleratedDuplicatesAndRejectsMalformedRows() throws IOException {
    final MavenElisionReportSnapshot.ToleratedDuplicateClass retained =
        new MavenElisionReportSnapshot.ToleratedDuplicateClass(
            "dup.Retained",
            "RETAIN_JARS",
            List.of(DUPLICATE_OWNERS.get(1), DUPLICATE_OWNERS.get(0)));
    final MavenElisionReportSnapshot.ToleratedDuplicateClass trimmed =
        new MavenElisionReportSnapshot.ToleratedDuplicateClass(
            "dup.Trimmed", "TRIM_OTHER_CLASSES", DUPLICATE_OWNERS);
    final MavenElisionReportSnapshot populated =
        snapshot().withToleratedDuplicates(List.of(trimmed, retained));
    final Path output = temporaryDirectory.resolve("target/duplicates-report.json");

    MavenElisionReportWriter.write(output, populated);
    final MavenElisionReportSnapshot reread = MavenElisionReportWriter.read(output);

    assertAll(
        () -> assertThat(reread).isEqualTo(populated),
        () ->
            assertThat(populated.toleratedDuplicates())
                .extracting(MavenElisionReportSnapshot.ToleratedDuplicateClass::className)
                .containsExactly("dup.Retained", "dup.Trimmed"),
        () ->
            assertThat(retained.owners())
                .as("owners are stored sorted")
                .containsExactlyElementsOf(DUPLICATE_OWNERS),
        () ->
            assertThat(MavenElisionReportWriter.render(reread))
                .contains(
                    "Tolerated duplicate classes (accepted by configuration):",
                    "  - dup.Retained: owning JARs retained whole" + " " + DUPLICATE_OWNERS,
                    "  - dup.Trimmed: duplicate kept in every owner, other classes may be trimmed"
                        + " "
                        + DUPLICATE_OWNERS),
        () ->
            assertThat(MavenElisionReportWriter.render(snapshot()))
                .as("the section is omitted when nothing was tolerated")
                .noneMatch(line -> line.contains("Tolerated duplicate")),
        () ->
            assertThatThrownBy(
                    () ->
                        new MavenElisionReportSnapshot.ToleratedDuplicateClass(
                            "dup.One", "RETAIN_JARS", List.of(DUPLICATE_OWNERS.get(0))))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("two owners"),
        () ->
            assertThatThrownBy(
                    () ->
                        new MavenElisionReportSnapshot.ToleratedDuplicateClass(
                            "dup.One", "KEEP_EVERYTHING", DUPLICATE_OWNERS))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("action"));
  }

  @Test
  void persistsCatalogAdoptionWithoutMatchingFindings() throws IOException {
    final MavenVulnerabilityMappingCatalogResolver.Adoption adoption =
        new MavenVulnerabilityMappingCatalogResolver.Adoption(
            new MavenVulnerabilityMappingCatalogResolver.Coordinate(
                "org.example", "catalog", "1.2.3", "jar", ""),
            "a".repeat(64),
            "empty-catalog",
            1,
            List.of(),
            List.of(),
            List.of(),
            List.of(),
            "explicit-maven-catalog-coordinate",
            List.of());
    final MavenElisionReportSnapshot report = snapshot().withCatalogAdoptions(List.of(adoption));
    final Path output = temporaryDirectory.resolve("target/catalog-report.json");

    MavenElisionReportWriter.write(output, report);
    final MavenElisionReportSnapshot reread = MavenElisionReportWriter.read(output);

    assertAll(
        () -> assertThat(reread.catalogAdoptions()).containsExactly(adoption),
        () -> assertThat(reread.genericFindings()).isEmpty(),
        () -> assertThat(Files.readString(output)).contains("\"catalogAdoptions\""),
        () ->
            assertThat(MavenElisionReportWriter.render(reread))
                .anyMatch(line -> line.contains("org.example:catalog:1.2.3:jar:")));
  }

  @Test
  void failsClearlyWhenNoSuccessfulSnapshotExists() {
    final Path missing = temporaryDirectory.resolve("missing-report.json");

    assertThatThrownBy(() -> MavenElisionReportWriter.read(missing))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("No successful elision report snapshot")
        .hasMessageContaining("run a Maven lifecycle build")
        .hasMessageContaining("dependency-elider:analyze");
  }

  private MavenElisionReportSnapshot snapshot() throws IOException {
    return new MavenElisionReportSnapshot(
            MavenElisionReportSnapshot.SCHEMA_VERSION,
            GROUP_ID,
            "consumer",
            PROJECT_VERSION,
            temporaryDirectory.toRealPath().toString(),
            GENERATED_AT,
            new TrimExecutionEnvironment(21, Runtime.version().feature()),
            1,
            2048,
            List.of(
                new MavenElisionReportSnapshot.DroppedArtifact(
                    ArtifactCoordinate.of(GROUP_ID, REMOVED_ARTIFACT, REMOVED_VERSION).toString(),
                    2048,
                    2,
                    18)),
            List.of(ArtifactCoordinate.of(GROUP_ID, REMOVED_ARTIFACT, REMOVED_VERSION).toString()),
            4,
            3096,
            List.of(
                new MavenElisionReportSnapshot.TrimmedArtifact(
                    ArtifactCoordinate.of(GROUP_ID, "trimmed", "2.0").toString(), 4, 3096)),
            MediatedGraphReportTestSupport.reportForOutputs(
                ArtifactCoordinate.of(GROUP_ID, REMOVED_ARTIFACT, REMOVED_VERSION),
                ArtifactCoordinate.of(GROUP_ID, "trimmed", "2.0"),
                GROUP_ID + ":consumer:1.0"),
            new MavenElisionPolicyIdentity(
                List.of("org.example:kept::jar:"),
                List.of("org.example:banned"),
                MavenElisionGraphBinding.sha256(List.of("report-policy-test"))))
        .withAppliedBans(
            List.of(
                new MavenElisionReportSnapshot.AppliedBan(
                    "org.example:banned", "UNMATCHED", List.of(), List.of(), false)));
  }

  private static long writeDroppedJar(final Path path) throws IOException {
    try (JarOutputStream archive = new JarOutputStream(Files.newOutputStream(path))) {
      writeEntry(archive, "sample/First.class", 7);
      writeEntry(archive, "sample/Second.class", 11);
      writeEntry(archive, "module-info.class", 13);
      writeEntry(archive, "META-INF/versions/11/module-info.class", 17);
      writeEntry(archive, "META-INF/example.txt", 19);
    }
    return Files.size(path);
  }

  private static void writeEntry(
      final JarOutputStream archive, final String name, final int payloadBytes) throws IOException {
    archive.putNextEntry(new JarEntry(name));
    archive.write(new byte[payloadBytes]);
    archive.closeEntry();
  }

  private MavenProject project() {
    final MavenProject project = new MavenProject();
    project.setGroupId(GROUP_ID);
    project.setArtifactId("consumer");
    project.setVersion(PROJECT_VERSION);
    final Build build = new Build();
    build.setDirectory(temporaryDirectory.resolve("target").toString());
    project.setBuild(build);
    project.setFile(temporaryDirectory.resolve("pom.xml").toFile());
    return project;
  }

  private static Artifact artifact(final ArtifactCoordinate coordinate, final Path file) {
    final Artifact artifact =
        new DefaultArtifact(
            coordinate.groupId(),
            coordinate.artifactId(),
            coordinate.version(),
            coordinate.scope(),
            coordinate.type(),
            coordinate.classifier().isBlank() ? null : coordinate.classifier(),
            new DefaultArtifactHandler(coordinate.type()));
    artifact.setFile(file.toFile());
    return artifact;
  }
}
