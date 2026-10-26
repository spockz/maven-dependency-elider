// WHY: Preserves the last successful elision totals for a separate Maven report invocation.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;

/** Immutable result snapshot used by the Maven {@code report} goal. */
@SuppressWarnings({"PMD.CommentDefaultAccessModifier"})
record MavenElisionReportSnapshot(
    int schemaVersion,
    String projectGroupId,
    String projectArtifactId,
    String projectVersion,
    String projectBaseDirectory,
    String generatedAt,
    int wholeArtifactsDropped,
    long originalJarBytesDropped,
    List<DroppedArtifact> droppedArtifacts,
    int programClassesPruned,
    long uncompressedProgramClassBytesPruned,
    List<TrimmedArtifact> trimmedArtifacts) {
  /** Current persisted JSON format version. */
  static final int SCHEMA_VERSION = 1;

  MavenElisionReportSnapshot {
    require(schemaVersion == SCHEMA_VERSION, "Unsupported report snapshot schema version");
    requireNonBlank(projectGroupId, "projectGroupId");
    requireNonBlank(projectArtifactId, "projectArtifactId");
    requireNonBlank(projectVersion, "projectVersion");
    requireNonBlank(projectBaseDirectory, "projectBaseDirectory");
    try {
      Instant.parse(Objects.requireNonNull(generatedAt, "generatedAt"));
    } catch (final java.time.DateTimeException exception) {
      throw new IllegalArgumentException("generatedAt must be an ISO-8601 instant", exception);
    }
    droppedArtifacts = List.copyOf(Objects.requireNonNull(droppedArtifacts, "droppedArtifacts"));
    trimmedArtifacts = List.copyOf(Objects.requireNonNull(trimmedArtifacts, "trimmedArtifacts"));
    require(wholeArtifactsDropped >= 0, "wholeArtifactsDropped must not be negative");
    require(originalJarBytesDropped >= 0, "originalJarBytesDropped must not be negative");
    require(programClassesPruned >= 0, "programClassesPruned must not be negative");
    require(
        uncompressedProgramClassBytesPruned >= 0,
        "uncompressedProgramClassBytesPruned must not be negative");
    require(
        wholeArtifactsDropped == droppedArtifacts.size(), "Dropped artifact count is inconsistent");
    require(
        originalJarBytesDropped == sumDroppedArtifactBytes(droppedArtifacts),
        "Dropped artifact byte total is inconsistent");
    require(
        programClassesPruned == sumPrunedClassCounts(trimmedArtifacts),
        "Class count is inconsistent");
    require(
        uncompressedProgramClassBytesPruned == sumPrunedClassBytes(trimmedArtifacts),
        "Pruned class byte total is inconsistent");
  }

  static MavenElisionReportSnapshot from(
      final org.apache.maven.project.MavenProject project,
      final MavenElisionService.Analysis analysis)
      throws IOException {
    final List<DroppedArtifact> dropped = new ArrayList<>();
    for (final ArtifactCoordinate coordinate : analysis.decision().elidedArtifacts()) {
      final MavenElisionService.ArtifactSnapshot artifact =
          snapshotForCoordinate(analysis, coordinate);
      final Path path = artifact.filePath();
      if (path == null || !Files.isRegularFile(path)) {
        throw new IOException("Elided artifact has no regular input JAR: " + coordinate);
      }
      dropped.add(new DroppedArtifact(coordinate.toString(), Files.size(path)));
    }
    dropped.sort(Comparator.comparing(DroppedArtifact::coordinate));

    final List<TrimmedArtifact> trimmed =
        analysis.trimRecords().stream()
            .map(
                record ->
                    new TrimmedArtifact(
                        record.coordinate().toString(),
                        record.totalClasses() - record.retainedClasses(),
                        record.prunedClassBytes()))
            .sorted(Comparator.comparing(TrimmedArtifact::coordinate))
            .toList();
    final long droppedBytes = sumDroppedArtifactBytes(dropped);
    final int prunedClasses = sumPrunedClassCounts(trimmed);
    final long prunedBytes = sumPrunedClassBytes(trimmed);
    final Path projectBaseDirectory = canonicalProjectDirectory(project);
    return new MavenElisionReportSnapshot(
        SCHEMA_VERSION,
        project.getGroupId(),
        project.getArtifactId(),
        project.getVersion(),
        projectBaseDirectory.toString(),
        Instant.now().toString(),
        dropped.size(),
        droppedBytes,
        dropped,
        prunedClasses,
        prunedBytes,
        trimmed);
  }

  @SuppressWarnings("PMD.LawOfDemeter")
  static Path canonicalProjectDirectory(final org.apache.maven.project.MavenProject project)
      throws IOException {
    final File projectDirectory = project.getBasedir();
    if (projectDirectory == null) {
      throw new IOException("Maven project has no existing base directory");
    }
    try {
      final Path directory = projectDirectory.toPath();
      return directory.toRealPath();
    } catch (final IOException exception) {
      throw new IOException("Maven project has no existing base directory", exception);
    }
  }

  private static MavenElisionService.ArtifactSnapshot snapshotForCoordinate(
      final MavenElisionService.Analysis analysis, final ArtifactCoordinate coordinate)
      throws IOException {
    return analysis.resolvedSnapshots().stream()
        .filter(snapshot -> snapshot.coordinate().equals(coordinate))
        .findFirst()
        .orElseThrow(
            () ->
                new IOException(
                    "Elided artifact is missing from its input snapshot: " + coordinate));
  }

  String projectGav() {
    return projectGroupId + ":" + projectArtifactId + ":" + projectVersion;
  }

  private static long sumDroppedArtifactBytes(final List<DroppedArtifact> artifacts) {
    long total = 0;
    try {
      for (final DroppedArtifact artifact : artifacts) {
        total = Math.addExact(total, artifact.originalJarBytes());
      }
    } catch (final ArithmeticException exception) {
      throw new IllegalArgumentException("Dropped artifact byte total overflowed", exception);
    }
    return total;
  }

  private static int sumPrunedClassCounts(final List<TrimmedArtifact> artifacts) {
    int total = 0;
    try {
      for (final TrimmedArtifact artifact : artifacts) {
        total = Math.addExact(total, artifact.programClassesPruned());
      }
    } catch (final ArithmeticException exception) {
      throw new IllegalArgumentException("Pruned class count overflowed", exception);
    }
    return total;
  }

  private static long sumPrunedClassBytes(final List<TrimmedArtifact> artifacts) {
    long total = 0;
    try {
      for (final TrimmedArtifact artifact : artifacts) {
        total = Math.addExact(total, artifact.uncompressedProgramClassBytesPruned());
      }
    } catch (final ArithmeticException exception) {
      throw new IllegalArgumentException("Pruned class byte total overflowed", exception);
    }
    return total;
  }

  private static void requireNonBlank(final String value, final String field) {
    require(value != null && !value.isBlank(), field + " must not be blank");
  }

  private static void require(final boolean condition, final String message) {
    if (!condition) {
      throw new IllegalArgumentException(message);
    }
  }

  /** One whole artifact removed from Maven's resolved input set. */
  record DroppedArtifact(String coordinate, long originalJarBytes) {
    DroppedArtifact {
      requireNonBlank(coordinate, "coordinate");
      require(originalJarBytes >= 0, "originalJarBytes must not be negative");
    }
  }

  /** Program classes removed from one retained JAR. */
  record TrimmedArtifact(
      String coordinate, int programClassesPruned, long uncompressedProgramClassBytesPruned) {
    TrimmedArtifact {
      requireNonBlank(coordinate, "coordinate");
      require(programClassesPruned > 0, "programClassesPruned must be positive");
      require(
          uncompressedProgramClassBytesPruned >= 0,
          "uncompressedProgramClassBytesPruned must not be negative");
    }
  }
}
