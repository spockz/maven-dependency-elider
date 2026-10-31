// WHY: Preserves the last successful elision totals for a separate Maven report invocation.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/** Immutable result snapshot used by the Maven {@code report} goal. */
@SuppressWarnings({
  "PMD.CommentDefaultAccessModifier",
  "PMD.ExcessiveParameterList",
  "PMD.AvoidDuplicateLiterals"
})
record MavenElisionReportSnapshot(
    int schemaVersion,
    String projectGroupId,
    String projectArtifactId,
    String projectVersion,
    String projectBaseDirectory,
    String generatedAt,
    int wholeArtifactsDropped,
    long originalJarBytesDropped,
    int droppedProgramClassEntries,
    long droppedProgramClassBytes,
    List<DroppedArtifact> droppedArtifacts,
    List<String> rawDroppedCoordinates,
    int programClassesPruned,
    long uncompressedProgramClassBytesPruned,
    List<TrimmedArtifact> trimmedArtifacts,
    List<CveFinding> removedCveComponents,
    List<CveFinding> provenAbsentCves,
    List<CveFinding> inactivePreconditionCves,
    List<ConservativeCveFinding> potentiallyConservativeCves,
    MediatedGraphReport mediatedGraph,
    boolean assumeConventionalJavaSourceLayout,
    List<SourceReviewFinding> sourceReviewFindings) {
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
    rawDroppedCoordinates =
        List.copyOf(Objects.requireNonNull(rawDroppedCoordinates, "rawDroppedCoordinates"));
    trimmedArtifacts = List.copyOf(Objects.requireNonNull(trimmedArtifacts, "trimmedArtifacts"));
    removedCveComponents =
        List.copyOf(Objects.requireNonNull(removedCveComponents, "removedCveComponents"));
    provenAbsentCves = List.copyOf(Objects.requireNonNull(provenAbsentCves, "provenAbsentCves"));
    inactivePreconditionCves =
        List.copyOf(Objects.requireNonNull(inactivePreconditionCves, "inactivePreconditionCves"));
    potentiallyConservativeCves =
        List.copyOf(
            Objects.requireNonNull(potentiallyConservativeCves, "potentiallyConservativeCves"));
    sourceReviewFindings =
        Objects.requireNonNull(sourceReviewFindings, "sourceReviewFindings").stream()
            .distinct()
            .sorted(
                Comparator.comparing(SourceReviewFinding::coordinate)
                    .thenComparing(SourceReviewFinding::cveId)
                    .thenComparing(SourceReviewFinding::cnaAffectedEntryIdentity)
                    .thenComparing(value -> String.join("\u0000", value.programFiles()))
                    .thenComparing(value -> String.join("\u0000", value.programRoutines())))
            .toList();
    MavenElisionReportSourceReviewValidator.validate(
        sourceReviewFindings, assumeConventionalJavaSourceLayout);
    Objects.requireNonNull(mediatedGraph, "mediatedGraph");
    require(wholeArtifactsDropped >= 0, "wholeArtifactsDropped must not be negative");
    require(originalJarBytesDropped >= 0, "originalJarBytesDropped must not be negative");
    require(droppedProgramClassEntries >= 0, "droppedProgramClassEntries must not be negative");
    require(droppedProgramClassBytes >= 0, "droppedProgramClassBytes must not be negative");
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
        droppedProgramClassEntries == sumDroppedArtifactClassCounts(droppedArtifacts),
        "Dropped artifact class count is inconsistent");
    require(
        droppedProgramClassBytes == sumDroppedArtifactClassBytes(droppedArtifacts),
        "Dropped artifact class byte total is inconsistent");
    require(
        programClassesPruned == sumPrunedClassCounts(trimmedArtifacts),
        "Class count is inconsistent");
    require(
        uncompressedProgramClassBytesPruned == sumPrunedClassBytes(trimmedArtifacts),
        "Pruned class byte total is inconsistent");
    require(
        droppedAndTrimmedArtifactsAreDisjoint(droppedArtifacts, trimmedArtifacts),
        "An artifact cannot be both dropped and class-trimmed");
    MediatedGraphReportCoverageValidator.validateSnapshotOutputs(
        mediatedGraph,
        droppedArtifacts,
        trimmedArtifacts,
        projectGroupId + ":" + projectArtifactId + ":" + projectVersion);
  }

  MavenElisionReportSnapshot(
      final int schemaVersion,
      final String projectGroupId,
      final String projectArtifactId,
      final String projectVersion,
      final String projectBaseDirectory,
      final String generatedAt,
      final int wholeArtifactsDropped,
      final long originalJarBytesDropped,
      final int droppedProgramClassEntries,
      final long droppedProgramClassBytes,
      final List<DroppedArtifact> droppedArtifacts,
      final List<String> rawDroppedCoordinates,
      final int programClassesPruned,
      final long uncompressedProgramClassBytesPruned,
      final List<TrimmedArtifact> trimmedArtifacts,
      final List<CveFinding> removedCveComponents,
      final List<CveFinding> provenAbsentCves,
      final List<CveFinding> inactivePreconditionCves,
      final List<ConservativeCveFinding> potentiallyConservativeCves,
      final MediatedGraphReport mediatedGraph) {
    this(
        schemaVersion,
        projectGroupId,
        projectArtifactId,
        projectVersion,
        projectBaseDirectory,
        generatedAt,
        wholeArtifactsDropped,
        originalJarBytesDropped,
        droppedProgramClassEntries,
        droppedProgramClassBytes,
        droppedArtifacts,
        rawDroppedCoordinates,
        programClassesPruned,
        uncompressedProgramClassBytesPruned,
        trimmedArtifacts,
        removedCveComponents,
        provenAbsentCves,
        inactivePreconditionCves,
        potentiallyConservativeCves,
        mediatedGraph,
        false,
        List.of());
  }

  MavenElisionReportSnapshot(
      final int schemaVersion,
      final String projectGroupId,
      final String projectArtifactId,
      final String projectVersion,
      final String projectBaseDirectory,
      final String generatedAt,
      final int wholeArtifactsDropped,
      final long originalJarBytesDropped,
      final List<DroppedArtifact> droppedArtifacts,
      final List<String> rawDroppedCoordinates,
      final int programClassesPruned,
      final long uncompressedProgramClassBytesPruned,
      final List<TrimmedArtifact> trimmedArtifacts) {
    this(
        schemaVersion,
        projectGroupId,
        projectArtifactId,
        projectVersion,
        projectBaseDirectory,
        generatedAt,
        wholeArtifactsDropped,
        originalJarBytesDropped,
        droppedArtifacts,
        rawDroppedCoordinates,
        programClassesPruned,
        uncompressedProgramClassBytesPruned,
        trimmedArtifacts,
        MediatedGraphReport.unavailable("No mediated graph data was provided to this report"));
  }

  MavenElisionReportSnapshot(
      final int schemaVersion,
      final String projectGroupId,
      final String projectArtifactId,
      final String projectVersion,
      final String projectBaseDirectory,
      final String generatedAt,
      final int wholeArtifactsDropped,
      final long originalJarBytesDropped,
      final List<DroppedArtifact> droppedArtifacts,
      final List<String> rawDroppedCoordinates,
      final int programClassesPruned,
      final long uncompressedProgramClassBytesPruned,
      final List<TrimmedArtifact> trimmedArtifacts,
      final MediatedGraphReport mediatedGraph) {
    this(
        schemaVersion,
        projectGroupId,
        projectArtifactId,
        projectVersion,
        projectBaseDirectory,
        generatedAt,
        wholeArtifactsDropped,
        originalJarBytesDropped,
        sumDroppedArtifactClassCounts(droppedArtifacts),
        sumDroppedArtifactClassBytes(droppedArtifacts),
        droppedArtifacts,
        rawDroppedCoordinates,
        programClassesPruned,
        uncompressedProgramClassBytesPruned,
        trimmedArtifacts,
        List.of(),
        List.of(),
        List.of(),
        List.of(),
        mediatedGraph);
  }

  MavenElisionReportSnapshot(
      final int schemaVersion,
      final String projectGroupId,
      final String projectArtifactId,
      final String projectVersion,
      final String projectBaseDirectory,
      final String generatedAt,
      final int wholeArtifactsDropped,
      final long originalJarBytesDropped,
      final List<DroppedArtifact> droppedArtifacts,
      final List<String> rawDroppedCoordinates,
      final int programClassesPruned,
      final long uncompressedProgramClassBytesPruned,
      final List<TrimmedArtifact> trimmedArtifacts,
      final List<CveFinding> removedCveComponents,
      final List<CveFinding> provenAbsentCves,
      final List<CveFinding> inactivePreconditionCves,
      final MediatedGraphReport mediatedGraph) {
    this(
        schemaVersion,
        projectGroupId,
        projectArtifactId,
        projectVersion,
        projectBaseDirectory,
        generatedAt,
        wholeArtifactsDropped,
        originalJarBytesDropped,
        sumDroppedArtifactClassCounts(droppedArtifacts),
        sumDroppedArtifactClassBytes(droppedArtifacts),
        droppedArtifacts,
        rawDroppedCoordinates,
        programClassesPruned,
        uncompressedProgramClassBytesPruned,
        trimmedArtifacts,
        removedCveComponents,
        provenAbsentCves,
        inactivePreconditionCves,
        List.of(),
        mediatedGraph);
  }

  static MavenElisionReportSnapshot from(
      final org.apache.maven.project.MavenProject project,
      final ElisionAnalysisModel.Analysis analysis)
      throws IOException {
    return from(project, analysis, null);
  }

  static MavenElisionReportSnapshot from(
      final org.apache.maven.project.MavenProject project,
      final ElisionAnalysisModel.Analysis analysis,
      final MavenVulnerabilityAssessment.Result vulnerabilityAssessment)
      throws IOException {
    final DroppedArtifactSummary droppedSummary =
        droppedArtifactSummary(analysis, analysis.effectiveDecision());
    final List<DroppedArtifact> dropped = droppedSummary.artifacts();

    final List<TrimmedArtifact> trimmed =
        analysis.trimResult().records().stream()
            .map(MavenElisionReportSnapshot::trimmedArtifact)
            .sorted(Comparator.comparing(TrimmedArtifact::coordinate))
            .toList();
    final int prunedClasses = sumPrunedClassCounts(trimmed);
    final long prunedBytes = sumPrunedClassBytes(trimmed);
    final Path projectBaseDirectory = canonicalProjectDirectory(project);
    final List<CveFinding> removedCveComponents =
        vulnerabilityAssessment == null
            ? List.of()
            : vulnerabilityAssessment.removedComponents().stream()
                .map(finding -> new CveFinding(finding.cveId(), finding.coordinate().toId()))
                .sorted(
                    Comparator.comparing(CveFinding::cveId).thenComparing(CveFinding::coordinate))
                .toList();
    final List<CveFinding> provenAbsentCves =
        vulnerabilityAssessment == null
            ? List.of()
            : vulnerabilityAssessment.provenVulnerableCodeAbsent().stream()
                .map(finding -> new CveFinding(finding.cveId(), finding.coordinate().toId()))
                .sorted(
                    Comparator.comparing(CveFinding::cveId).thenComparing(CveFinding::coordinate))
                .toList();
    final List<CveFinding> inactivePreconditionCves =
        vulnerabilityAssessment == null
            ? List.of()
            : vulnerabilityAssessment.inactiveDueToMissingPrerequisites().stream()
                .map(finding -> new CveFinding(finding.cveId(), finding.coordinate().toId()))
                .sorted(
                    Comparator.comparing(CveFinding::cveId).thenComparing(CveFinding::coordinate))
                .toList();
    final List<ConservativeCveFinding> potentiallyConservativeCves =
        vulnerabilityAssessment == null
            ? List.of()
            : vulnerabilityAssessment.potentiallyConservativeCves().stream()
                .map(
                    finding ->
                        new ConservativeCveFinding(
                            finding.cveId(),
                            finding.coordinate().toId(),
                            finding.reason(),
                            finding.pomOverrideSnippet()))
                .sorted(
                    Comparator.comparing(ConservativeCveFinding::cveId)
                        .thenComparing(ConservativeCveFinding::coordinate))
                .toList();
    return new MavenElisionReportSnapshot(
        SCHEMA_VERSION,
        project.getGroupId(),
        project.getArtifactId(),
        project.getVersion(),
        projectBaseDirectory.toString(),
        Instant.now().toString(),
        dropped.size(),
        droppedSummary.originalJarBytes(),
        droppedSummary.programClassesRemoved(),
        droppedSummary.uncompressedProgramClassBytesRemoved(),
        dropped,
        analysis.decision().elidedArtifacts().stream()
            .map(ArtifactCoordinate::toString)
            .sorted()
            .toList(),
        prunedClasses,
        prunedBytes,
        trimmed,
        removedCveComponents,
        provenAbsentCves,
        inactivePreconditionCves,
        potentiallyConservativeCves,
        analysis.mediatedGraph() == null
            ? MediatedGraphReport.unavailable(
                "Mediated graph data is unavailable for this analysis")
            : analysis.mediatedGraph(),
        vulnerabilityAssessment != null && vulnerabilityAssessment.conventionalLayoutAssumed(),
        vulnerabilityAssessment == null
            ? List.of()
            : sourceReviewFindings(vulnerabilityAssessment.matchedSourceClaims()));
  }

  private static List<SourceReviewFinding> sourceReviewFindings(
      final List<MavenVulnerabilityAssessment.MatchedSourceClaim> claims) {
    return claims.stream()
        .map(
            claim ->
                new SourceReviewFinding(
                    claim.cveId(),
                    claim.coordinate().toString(),
                    claim.sourceRecordSha256(),
                    claim.cnaAffectedEntryIdentity(),
                    claim.affectedProductIdentity(),
                    claim.programFiles(),
                    claim.programRoutines(),
                    claim.conventionalLayoutAssumed(),
                    claim.matches().stream().map(SourceReviewMatch::from).toList(),
                    claim.unresolvedRationale()))
        .distinct()
        .sorted(
            Comparator.comparing(SourceReviewFinding::coordinate)
                .thenComparing(SourceReviewFinding::cveId)
                .thenComparing(SourceReviewFinding::cnaAffectedEntryIdentity))
        .toList();
  }

  static TrimmedArtifact trimmedArtifact(final ArtifactTrimRecord record) {
    final int prunedClasses = record.totalClasses() - record.retainedClasses();
    if (prunedClasses == 0 && !"elevated_and_trimmed".equals(record.mrjarStatus())) {
      throw new IllegalArgumentException(
          "A single-release trim record must prune at least one class: " + record.coordinate());
    }
    return new TrimmedArtifact(
        record.coordinate().toString(), prunedClasses, record.prunedClassBytes());
  }

  static DroppedArtifactSummary droppedArtifactSummary(final ElisionAnalysisModel.Analysis analysis)
      throws IOException {
    return droppedArtifactSummary(analysis, analysis.effectiveDecision());
  }

  private static DroppedArtifactSummary droppedArtifactSummary(
      final ElisionAnalysisModel.Analysis analysis,
      final io.github.spockz.elider.model.ElisionDecision decision)
      throws IOException {
    final List<DroppedArtifact> dropped = new ArrayList<>();
    for (final ArtifactCoordinate coordinate : decision.elidedArtifacts()) {
      final ElisionAnalysisModel.ArtifactSnapshot artifact =
          snapshotForCoordinate(analysis, coordinate);
      final Path path = artifact.filePath();
      if (path == null || !Files.isRegularFile(path)) {
        throw new IOException("Elided artifact has no regular input JAR: " + coordinate);
      }
      final ProgramClassEntryMetrics classMetrics = ProgramClassEntryMetrics.scan(path);
      dropped.add(
          new DroppedArtifact(
              coordinate.toString(),
              Files.size(path),
              classMetrics.entries(),
              classMetrics.uncompressedBytes()));
    }
    dropped.sort(Comparator.comparing(DroppedArtifact::coordinate));
    return new DroppedArtifactSummary(
        dropped,
        sumDroppedArtifactBytes(dropped),
        sumDroppedArtifactClassCounts(dropped),
        sumDroppedArtifactClassBytes(dropped));
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

  private static ElisionAnalysisModel.ArtifactSnapshot snapshotForCoordinate(
      final ElisionAnalysisModel.Analysis analysis, final ArtifactCoordinate coordinate)
      throws IOException {
    return analysis.artifacts().resolvedSnapshots().stream()
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

  private static int sumDroppedArtifactClassCounts(final List<DroppedArtifact> artifacts) {
    int total = 0;
    try {
      for (final DroppedArtifact artifact : artifacts) {
        total = Math.addExact(total, artifact.programClassesRemoved());
      }
    } catch (final ArithmeticException exception) {
      throw new IllegalArgumentException("Dropped artifact class count overflowed", exception);
    }
    return total;
  }

  private static long sumDroppedArtifactClassBytes(final List<DroppedArtifact> artifacts) {
    long total = 0;
    try {
      for (final DroppedArtifact artifact : artifacts) {
        total = Math.addExact(total, artifact.uncompressedProgramClassBytesRemoved());
      }
    } catch (final ArithmeticException exception) {
      throw new IllegalArgumentException("Dropped artifact class byte total overflowed", exception);
    }
    return total;
  }

  private static boolean droppedAndTrimmedArtifactsAreDisjoint(
      final List<DroppedArtifact> droppedArtifacts, final List<TrimmedArtifact> trimmedArtifacts) {
    final Set<String> droppedCoordinates = new HashSet<>();
    for (final DroppedArtifact artifact : droppedArtifacts) {
      droppedCoordinates.add(artifact.coordinate());
    }
    return trimmedArtifacts.stream()
        .noneMatch(artifact -> droppedCoordinates.contains(artifact.coordinate()));
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
  record DroppedArtifact(
      String coordinate,
      long originalJarBytes,
      int programClassesRemoved,
      long uncompressedProgramClassBytesRemoved) {
    DroppedArtifact {
      requireNonBlank(coordinate, "coordinate");
      MavenElisionReportSourceCoordinateValidator.validate(coordinate);
      require(originalJarBytes >= 0, "originalJarBytes must not be negative");
      require(programClassesRemoved >= 0, "programClassesRemoved must not be negative");
      require(
          uncompressedProgramClassBytesRemoved >= 0,
          "uncompressedProgramClassBytesRemoved must not be negative");
    }

    DroppedArtifact(final String coordinate, final long originalJarBytes) {
      this(coordinate, originalJarBytes, 0, 0);
    }
  }

  record DroppedArtifactSummary(
      List<DroppedArtifact> artifacts,
      long originalJarBytes,
      int programClassesRemoved,
      long uncompressedProgramClassBytesRemoved) {
    DroppedArtifactSummary {
      artifacts = List.copyOf(Objects.requireNonNull(artifacts, "artifacts"));
      require(originalJarBytes >= 0, "originalJarBytes must not be negative");
      require(programClassesRemoved >= 0, "programClassesRemoved must not be negative");
      require(
          uncompressedProgramClassBytesRemoved >= 0,
          "uncompressedProgramClassBytesRemoved must not be negative");
    }
  }

  /** Program classes removed from one retained JAR. */
  record TrimmedArtifact(
      String coordinate, int programClassesPruned, long uncompressedProgramClassBytesPruned) {
    TrimmedArtifact {
      requireNonBlank(coordinate, "coordinate");
      require(programClassesPruned >= 0, "programClassesPruned must not be negative");
      require(
          uncompressedProgramClassBytesPruned >= 0,
          "uncompressedProgramClassBytesPruned must not be negative");
    }
  }

  /** Vulnerability finding associated with a dependency coordinate. */
  record CveFinding(String cveId, String coordinate) {
    CveFinding {
      requireNonBlank(cveId, "cveId");
      require(cveId.matches("CVE-[0-9]{4}-[0-9]{4,}"), "Invalid CVE format: " + cveId);
      requireNonBlank(coordinate, "coordinate");
    }
  }

  /** Conservative exclusion with actionable override guidance. */
  record ConservativeCveFinding(
      String cveId, String coordinate, String reason, String pomOverrideSnippet) {
    ConservativeCveFinding {
      requireNonBlank(cveId, "cveId");
      require(cveId.matches("CVE-[0-9]{4}-[0-9]{4,}"), "Invalid CVE format: " + cveId);
      requireNonBlank(coordinate, "coordinate");
      requireNonBlank(reason, "reason");
      requireNonBlank(pomOverrideSnippet, "pomOverrideSnippet");
    }
  }

  /** Structured source claim saved for historical review, never as a finding. */
  record SourceReviewFinding(
      String cveId,
      String coordinate,
      String sourceRecordSha256,
      String cnaAffectedEntryIdentity,
      String affectedProductIdentity,
      List<String> programFiles,
      List<String> programRoutines,
      boolean conventionalLayoutAssumed,
      List<SourceReviewMatch> matches,
      String unresolvedRationale) {
    SourceReviewFinding {
      requireNonBlank(cveId, "cveId");
      require(cveId.matches("CVE-[0-9]{4}-[0-9]{4,}"), "Invalid CVE format: " + cveId);
      requireNonBlank(coordinate, "coordinate");
      requireNonBlank(sourceRecordSha256, "sourceRecordSha256");
      require(
          sourceRecordSha256.matches("[0-9a-f]{64}"),
          "sourceRecordSha256 must be a lowercase SHA-256");
      requireNonBlank(cnaAffectedEntryIdentity, "cnaAffectedEntryIdentity");
      require(
          cnaAffectedEntryIdentity.matches("containers\\.cna\\.affected\\[[0-9]+\\]"),
          "cnaAffectedEntryIdentity must identify one CNA entry");
      requireNonBlank(affectedProductIdentity, "affectedProductIdentity");
      programFiles = sortedNonBlank(programFiles, "programFiles");
      programRoutines = sortedNonBlank(programRoutines, "programRoutines");
      require(!programFiles.isEmpty() || !programRoutines.isEmpty(), "Source claims are required");
      matches =
          Objects.requireNonNull(matches, "matches").stream()
              .distinct()
              .sorted(Comparator.comparing(SourceReviewMatch::physicalJarEntry))
              .toList();
      MavenElisionReportSourceReviewValidator.validateFinding(
          coordinate, programFiles, matches, conventionalLayoutAssumed, conventionalLayoutAssumed);
      requireNonBlank(unresolvedRationale, "unresolvedRationale");
    }

    private static List<String> sortedNonBlank(final List<String> values, final String field) {
      return Objects.requireNonNull(values, field).stream()
          .map(value -> Objects.requireNonNull(value, field + " item"))
          .peek(value -> requireNonBlank(value, field + " item"))
          .distinct()
          .sorted()
          .toList();
    }
  }

  /** One freshly recomputed SourceFile match bound to a physical archive entry. */
  record SourceReviewMatch(
      String programFile,
      String physicalJarEntry,
      int multiReleaseTier,
      String classEntry,
      String sourceFileAttribute,
      String packagePathComparison,
      String originalArchiveSha256) {
    SourceReviewMatch {
      requireNonBlank(programFile, "programFile");
      requireNonBlank(physicalJarEntry, "physicalJarEntry");
      require(multiReleaseTier == 0 || multiReleaseTier >= 9, "Invalid multi-release tier");
      requireNonBlank(classEntry, "classEntry");
      requireNonBlank(sourceFileAttribute, "sourceFileAttribute");
      requireNonBlank(packagePathComparison, "packagePathComparison");
      requireNonBlank(originalArchiveSha256, "originalArchiveSha256");
      require(
          originalArchiveSha256.matches("[0-9a-f]{64}"),
          "originalArchiveSha256 must be a lowercase SHA-256");
      MavenElisionReportSourceReviewValidator.validateMatch(
          programFile,
          physicalJarEntry,
          multiReleaseTier,
          classEntry,
          sourceFileAttribute,
          packagePathComparison);
    }

    static SourceReviewMatch from(
        final io.github.spockz.elider.model.CorroboratedSourceClassCandidate candidate) {
      return new SourceReviewMatch(
          candidate.programFile(),
          candidate.physicalJarEntry(),
          candidate.multiReleaseTier(),
          candidate.classEntry(),
          candidate.sourceFileAttribute(),
          candidate.packagePathComparison(),
          candidate.originalArchiveSha256());
    }
  }
}
