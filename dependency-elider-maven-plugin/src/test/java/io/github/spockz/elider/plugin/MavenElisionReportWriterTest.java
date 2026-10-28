// WHY: Verifies persisted report metric derivation, serialization, and formatting.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

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
import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;
import org.apache.maven.model.Build;
import org.apache.maven.project.MavenProject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Tests report snapshots independently from Maven dependency analysis. */
@SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
final class MavenElisionReportWriterTest {
  /** Maven group used in synthetic test coordinates. */
  private static final String GROUP_ID = "org.example";

  /** Version used for synthetic whole-artifact removal records. */
  private static final String REMOVED_VERSION = "1.0";

  /** Stable version used by the synthetic report project. */
  private static final String PROJECT_VERSION = REMOVED_VERSION;

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
  void capturesOriginalArtifactAndUncompressedPrunedProgramClassBytes() throws IOException {
    final ArtifactCoordinate removedCoordinate =
        ArtifactCoordinate.of(GROUP_ID, REMOVED_ARTIFACT, REMOVED_VERSION);
    final ArtifactCoordinate trimmedCoordinate = ArtifactCoordinate.of(GROUP_ID, "trimmed", "2.0");
    final Path removedJar = temporaryDirectory.resolve(REMOVED_ARTIFACT + ".jar");
    Files.write(removedJar, new byte[2048]);
    final Path originalTrimmedJar = temporaryDirectory.resolve("trimmed.jar");
    Files.write(originalTrimmedJar, new byte[4096]);
    final Artifact removedArtifact = artifact(removedCoordinate, removedJar);
    final Artifact trimmedArtifact = artifact(trimmedCoordinate, originalTrimmedJar);
    final MavenElisionService.ArtifactSnapshot removedSnapshot =
        new MavenElisionService.ArtifactSnapshot(removedArtifact, removedCoordinate, removedJar);
    final MavenElisionService.ArtifactSnapshot trimmedSnapshot =
        new MavenElisionService.ArtifactSnapshot(
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
    final MavenElisionService.Analysis analysis =
        new MavenElisionService.Analysis(
            List.of(removedSnapshot, trimmedSnapshot),
            false,
            List.of(),
            decision,
            decision,
            new ClassUsageReport(List.of()),
            Optional.empty(),
            List.of(trimRecord),
            List.of(),
            List.of(),
            List.of(),
            0,
            0L,
            0,
            null,
            null,
            MediatedGraphReportTestSupport.reportForOutputs(
                removedCoordinate, trimmedCoordinate, GROUP_ID + ":consumer:" + PROJECT_VERSION));

    final MavenElisionReportSnapshot snapshot = MavenElisionReportSnapshot.from(project, analysis);
    final MavenElisionReportSnapshot.DroppedArtifactSummary droppedArtifacts =
        MavenElisionReportSnapshot.droppedArtifactSummary(analysis);

    assertThat(snapshot.wholeArtifactsDropped()).isOne();
    assertThat(snapshot.originalJarBytesDropped()).isEqualTo(2048);
    assertThat(droppedArtifacts.artifacts()).isEqualTo(snapshot.droppedArtifacts());
    assertThat(droppedArtifacts.originalJarBytes()).isEqualTo(snapshot.originalJarBytesDropped());
    assertThat(snapshot.programClassesPruned()).isEqualTo(4);
    assertThat(snapshot.uncompressedProgramClassBytesPruned()).isEqualTo(3096);
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
  }

  @Test
  void writesReadsAndRendersDeterministicBinaryByteUnits() throws IOException {
    final MavenElisionReportSnapshot snapshot = snapshot();
    final Path output = temporaryDirectory.resolve("target/dependency-elider-report.json");

    MavenElisionReportWriter.write(output, snapshot);
    final MavenElisionReportSnapshot reread = MavenElisionReportWriter.read(output);

    assertThat(reread).isEqualTo(snapshot);
    assertThat(MavenElisionReportWriter.render(reread))
        .contains(
            "Project: org.example:consumer:1.0",
            "Snapshot: last successful elide run at " + GENERATED_AT,
            "The snapshot does not revalidate changed inputs when this goal runs.",
            "Whole artifacts dropped: 1 (original JAR file bytes: 2.00 KiB)",
            "Program classes pruned from retained JARs: 4 (uncompressed omitted"
                + " .class payload bytes: "
                + "3.02 KiB; excludes module descriptors and archive metadata)",
            "Mediated TEST dependency graph (captured and saved by the elide goal):");
    assertThat(MavenElisionReportWriter.render(reread))
        .anySatisfy(message -> assertThat(message).contains("[EFFECTIVE_DROP]"));
    assertThat(MavenElisionReportWriter.render(reread))
        .anySatisfy(message -> assertThat(message).contains("[RETAINED, CLASS_TRIMMED]"));
    assertThat(MavenElisionReportWriter.formatBytes(0)).isEqualTo("0 B");
    assertThat(MavenElisionReportWriter.formatBytes(1023)).isEqualTo("1023 B");
    assertThat(MavenElisionReportWriter.formatBytes(1024)).isEqualTo("1.00 KiB");
    assertThat(MavenElisionReportWriter.formatBytes(1_048_576)).isEqualTo("1.00 MiB");
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
            0,
            0,
            List.of(),
            List.of(),
            0,
            0,
            List.of(),
            MediatedGraphReportTestSupport.emptyGraph(populated.projectGav()));

    assertThat(MavenElisionReportWriter.render(empty))
        .contains(
            "Whole artifacts dropped: 0 (original JAR file bytes: 0 B)",
            "Program classes pruned from retained JARs: 0 (uncompressed omitted"
                + " .class payload bytes: "
                + "0 B; excludes module descriptors and archive metadata)");
  }

  @Test
  void failsClearlyWhenNoSuccessfulSnapshotExists() {
    final Path missing = temporaryDirectory.resolve("missing-report.json");

    assertThatThrownBy(() -> MavenElisionReportWriter.read(missing))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("No successful elision report snapshot")
        .hasMessageContaining("run a Maven lifecycle build");
  }

  @Test
  void rejectsVersionTwoSnapshotsWithRerunGuidance() throws IOException {
    final Path legacy = temporaryDirectory.resolve("legacy-report.json");
    Files.writeString(legacy, "{\"schemaVersion\":2}");

    assertThatThrownBy(() -> MavenElisionReportWriter.read(legacy))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Unsupported elision report schema version 2")
        .hasMessageContaining("run dependency-elider:elide");
  }

  private MavenElisionReportSnapshot snapshot() throws IOException {
    return new MavenElisionReportSnapshot(
        MavenElisionReportSnapshot.SCHEMA_VERSION,
        GROUP_ID,
        "consumer",
        PROJECT_VERSION,
        temporaryDirectory.toRealPath().toString(),
        GENERATED_AT,
        1,
        2048,
        List.of(
            new MavenElisionReportSnapshot.DroppedArtifact(
                ArtifactCoordinate.of(GROUP_ID, REMOVED_ARTIFACT, REMOVED_VERSION).toString(),
                2048)),
        List.of(ArtifactCoordinate.of(GROUP_ID, REMOVED_ARTIFACT, REMOVED_VERSION).toString()),
        4,
        3096,
        List.of(
            new MavenElisionReportSnapshot.TrimmedArtifact(
                ArtifactCoordinate.of(GROUP_ID, "trimmed", "2.0").toString(), 4, 3096)),
        MediatedGraphReportTestSupport.reportForOutputs(
            ArtifactCoordinate.of(GROUP_ID, REMOVED_ARTIFACT, REMOVED_VERSION),
            ArtifactCoordinate.of(GROUP_ID, "trimmed", "2.0"),
            GROUP_ID + ":consumer:1.0"));
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
