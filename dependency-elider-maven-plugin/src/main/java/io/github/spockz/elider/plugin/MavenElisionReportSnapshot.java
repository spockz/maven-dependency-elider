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
import java.util.TreeSet;

/** Immutable result snapshot used by the Maven {@code report} goal. */
@SuppressWarnings({"PMD.CommentDefaultAccessModifier", "PMD.ExcessiveParameterList"})
record MavenElisionReportSnapshot(
    int schemaVersion,
    String projectGroupId,
    String projectArtifactId,
    String projectVersion,
    String projectBaseDirectory,
    String generatedAt,
    TrimExecutionEnvironment executionEnvironment,
    int wholeArtifactsDropped,
    long originalJarBytesDropped,
    int droppedProgramClassEntries,
    long droppedProgramClassBytes,
    List<DroppedArtifact> droppedArtifacts,
    List<String> rawDroppedCoordinates,
    int programClassesPruned,
    long uncompressedProgramClassBytesPruned,
    List<TrimmedArtifact> trimmedArtifacts,
    MediatedGraphReport mediatedGraph,
    boolean assumeConventionalJavaSourceLayout,
    MavenElisionPolicyIdentity policy,
    ExclusionReview exclusionReview,
    List<AppliedBan> appliedBans,
    List<ToleratedDuplicateClass> toleratedDuplicates,
    @com.fasterxml.jackson.annotation.JsonIgnore List<GenericFindingAssessment> genericFindings,
    @com.fasterxml.jackson.annotation.JsonIgnore
        List<FindingSourceObservation> sourceObservations) {
  /** Current persisted JSON format version. */
  static final int SCHEMA_VERSION = 1;

  MavenElisionReportSnapshot {
    genericFindings =
        genericFindings == null
            ? List.of()
            : genericFindings.stream()
                .sorted(
                    Comparator.comparing(GenericFindingAssessment::vulnerabilityId)
                        .thenComparing(GenericFindingAssessment::candidate)
                        .thenComparing(GenericFindingAssessment::outcome)
                        .thenComparing(GenericFindingAssessment::detail))
                .toList();
    sourceObservations =
        sourceObservations == null
            ? List.of()
            : sourceObservations.stream()
                .sorted(
                    Comparator.comparing(
                            (FindingSourceObservation value) ->
                                value.source().map(Enum::name).orElse(""))
                        .thenComparing(FindingSourceObservation::status)
                        .thenComparing(value -> Objects.toString(value.revision(), ""))
                        .thenComparing(value -> Objects.toString(value.diagnostic(), "")))
                .toList();
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
    Objects.requireNonNull(executionEnvironment, "executionEnvironment");
    droppedArtifacts = List.copyOf(Objects.requireNonNull(droppedArtifacts, "droppedArtifacts"));
    rawDroppedCoordinates =
        List.copyOf(Objects.requireNonNull(rawDroppedCoordinates, "rawDroppedCoordinates"));
    trimmedArtifacts = List.copyOf(Objects.requireNonNull(trimmedArtifacts, "trimmedArtifacts"));
    Objects.requireNonNull(mediatedGraph, "mediatedGraph");
    Objects.requireNonNull(policy, "policy");
    Objects.requireNonNull(exclusionReview, "exclusionReview");
    appliedBans = List.copyOf(Objects.requireNonNull(appliedBans, "appliedBans"));
    toleratedDuplicates =
        Objects.requireNonNull(toleratedDuplicates, "toleratedDuplicates").stream()
            .sorted(Comparator.comparing(ToleratedDuplicateClass::className))
            .toList();
    for (int index = 1; index < toleratedDuplicates.size(); index++) {
      require(
          !toleratedDuplicates
              .get(index - 1)
              .className()
              .equals(toleratedDuplicates.get(index).className()),
          "Tolerated duplicate classes must be distinct");
    }
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
      final TrimExecutionEnvironment executionEnvironment,
      final int wholeArtifactsDropped,
      final long originalJarBytesDropped,
      final List<DroppedArtifact> droppedArtifacts,
      final List<String> rawDroppedCoordinates,
      final int programClassesPruned,
      final long uncompressedProgramClassBytesPruned,
      final List<TrimmedArtifact> trimmedArtifacts,
      final MavenElisionPolicyIdentity policy) {
    this(
        schemaVersion,
        projectGroupId,
        projectArtifactId,
        projectVersion,
        projectBaseDirectory,
        generatedAt,
        executionEnvironment,
        wholeArtifactsDropped,
        originalJarBytesDropped,
        droppedArtifacts,
        rawDroppedCoordinates,
        programClassesPruned,
        uncompressedProgramClassBytesPruned,
        trimmedArtifacts,
        MediatedGraphReport.unavailable("No mediated graph data was provided to this report"),
        policy);
  }

  MavenElisionReportSnapshot(
      final int schemaVersion,
      final String projectGroupId,
      final String projectArtifactId,
      final String projectVersion,
      final String projectBaseDirectory,
      final String generatedAt,
      final TrimExecutionEnvironment executionEnvironment,
      final int wholeArtifactsDropped,
      final long originalJarBytesDropped,
      final List<DroppedArtifact> droppedArtifacts,
      final List<String> rawDroppedCoordinates,
      final int programClassesPruned,
      final long uncompressedProgramClassBytesPruned,
      final List<TrimmedArtifact> trimmedArtifacts,
      final MediatedGraphReport mediatedGraph,
      final MavenElisionPolicyIdentity policy) {
    this(
        schemaVersion,
        projectGroupId,
        projectArtifactId,
        projectVersion,
        projectBaseDirectory,
        generatedAt,
        executionEnvironment,
        wholeArtifactsDropped,
        originalJarBytesDropped,
        sumDroppedArtifactClassCounts(droppedArtifacts),
        sumDroppedArtifactClassBytes(droppedArtifacts),
        droppedArtifacts,
        rawDroppedCoordinates,
        programClassesPruned,
        uncompressedProgramClassBytesPruned,
        trimmedArtifacts,
        mediatedGraph,
        false,
        policy,
        ExclusionReview.unavailable("No pre-injection declaration capture is available"),
        List.of(),
        List.of(),
        List.of(),
        List.of());
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
    final Set<ArtifactCoordinate> rawTraceDrops =
        new TreeSet<>(analysis.traceDecision().elidedArtifacts());
    rawTraceDrops.removeAll(analysis.banPlan().forcedAbsentAfterResolution());
    return new MavenElisionReportSnapshot(
        SCHEMA_VERSION,
        project.getGroupId(),
        project.getArtifactId(),
        project.getVersion(),
        projectBaseDirectory.toString(),
        Instant.now().toString(),
        analysis.trimResult().executionEnvironment(),
        dropped.size(),
        droppedSummary.originalJarBytes(),
        droppedSummary.programClassesRemoved(),
        droppedSummary.uncompressedProgramClassBytesRemoved(),
        dropped,
        rawTraceDrops.stream().map(ArtifactCoordinate::toString).sorted().toList(),
        prunedClasses,
        prunedBytes,
        trimmed,
        analysis.mediatedGraph() == null
            ? MediatedGraphReport.unavailable(
                "Mediated graph data is unavailable for this analysis")
            : analysis.mediatedGraph(),
        vulnerabilityAssessment != null && vulnerabilityAssessment.conventionalLayoutAssumed(),
        analysis.policyIdentity(),
        ExclusionReview.unavailable("No pre-injection declaration capture is available"),
        analysis.banPlan().entries().stream()
            .map(
                entry ->
                    new AppliedBan(
                        entry.dependency().toString(),
                        entry.status().name(),
                        entry.artifacts().stream().map(Object::toString).sorted().toList(),
                        entry.originalArtifacts().stream().map(Object::toString).sorted().toList(),
                        entry.status() != MavenBanPlan.Entry.Status.UNMATCHED))
            .toList(),
        analysis.trimResult().toleratedDuplicates().stream()
            .map(ToleratedDuplicateClass::from)
            .toList(),
        vulnerabilityAssessment == null ? List.of() : vulnerabilityAssessment.genericFindings(),
        vulnerabilityAssessment == null ? List.of() : vulnerabilityAssessment.sourceObservations());
  }

  MavenElisionReportSnapshot withGenericFindings(
      final List<GenericFindingAssessment> findings,
      final List<FindingSourceObservation> observations) {
    return copy(exclusionReview, appliedBans, toleratedDuplicates, findings, observations);
  }

  MavenElisionReportSnapshot withExclusionReview(final ExclusionReview review) {
    return copy(review, appliedBans, toleratedDuplicates, genericFindings, sourceObservations);
  }

  MavenElisionReportSnapshot withAppliedBans(final List<AppliedBan> bans) {
    return copy(exclusionReview, bans, toleratedDuplicates, genericFindings, sourceObservations);
  }

  MavenElisionReportSnapshot withToleratedDuplicates(final List<ToleratedDuplicateClass> rows) {
    return copy(exclusionReview, appliedBans, rows, genericFindings, sourceObservations);
  }

  private MavenElisionReportSnapshot copy(
      final ExclusionReview review,
      final List<AppliedBan> bans,
      final List<ToleratedDuplicateClass> duplicates,
      final List<GenericFindingAssessment> findings,
      final List<FindingSourceObservation> observations) {
    return new MavenElisionReportSnapshot(
        schemaVersion,
        projectGroupId,
        projectArtifactId,
        projectVersion,
        projectBaseDirectory,
        generatedAt,
        executionEnvironment,
        wholeArtifactsDropped,
        originalJarBytesDropped,
        droppedProgramClassEntries,
        droppedProgramClassBytes,
        droppedArtifacts,
        rawDroppedCoordinates,
        programClassesPruned,
        uncompressedProgramClassBytesPruned,
        trimmedArtifacts,
        mediatedGraph,
        assumeConventionalJavaSourceLayout,
        policy,
        review,
        bans,
        duplicates,
        findings,
        observations);
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

  static DroppedArtifactSummary droppedArtifactSummary(final AnalyzePrediction prediction)
      throws IOException {
    final List<DroppedArtifact> dropped = new ArrayList<>();
    for (final ArtifactCoordinate coordinate : prediction.wouldElideArtifacts()) {
      dropped.add(droppedArtifact(prediction, coordinate));
    }
    dropped.sort(Comparator.comparing(DroppedArtifact::coordinate));
    return new DroppedArtifactSummary(
        dropped,
        sumDroppedArtifactBytes(dropped),
        sumDroppedArtifactClassCounts(dropped),
        sumDroppedArtifactClassBytes(dropped));
  }

  private static DroppedArtifact droppedArtifact(
      final AnalyzePrediction prediction, final ArtifactCoordinate coordinate) throws IOException {
    final ElisionAnalysisModel.ArtifactSnapshot artifact =
        prediction.inputArtifacts().stream()
            .filter(snapshot -> snapshot.coordinate().equals(coordinate))
            .findFirst()
            .orElseThrow(
                () ->
                    new IOException(
                        "Predicted artifact is absent from its input inventory: " + coordinate));
    final Path path = artifact.filePath();
    if (path == null || !Files.isRegularFile(path)) {
      throw new IOException("Predicted artifact has no regular input JAR: " + coordinate);
    }
    final ProgramClassEntryMetrics classMetrics = ProgramClassEntryMetrics.scan(path);
    return new DroppedArtifact(
        coordinate.toString(),
        Files.size(path),
        classMetrics.entries(),
        classMetrics.uncompressedBytes());
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

  /** One tolerated duplicated class and its configured owner action. */
  record ToleratedDuplicateClass(String className, String action, List<String> owners) {
    ToleratedDuplicateClass {
      requireNonBlank(className, "className");
      Objects.requireNonNull(action, "action");
      try {
        DuplicateClassPolicy.Action.valueOf(action);
      } catch (final IllegalArgumentException exception) {
        throw new IllegalArgumentException("Tolerated duplicate action is invalid", exception);
      }
      owners = sortedDistinctNonBlank(owners, "owners");
      require(owners.size() > 1, "A tolerated duplicate must have at least two owners");
    }

    static ToleratedDuplicateClass from(final DuplicateClasses.ToleratedDuplicate duplicate) {
      return new ToleratedDuplicateClass(
          duplicate.className(),
          duplicate.action().name(),
          duplicate.owners().stream().map(Object::toString).toList());
    }
  }

  /** One requested ban and its applied Elide outcome. */
  record AppliedBan(
      String dependency,
      String status,
      List<String> matchedArtifacts,
      List<String> originalArtifacts,
      boolean applied) {
    AppliedBan {
      requireNonBlank(dependency, "dependency");
      try {
        final List<String> normalized =
            BanishedDependencyPolicy.normalize(List.of(dependency)).stream()
                .map(Object::toString)
                .toList();
        require(normalized.equals(List.of(dependency)), "Ban dependency is not canonical");
      } catch (final org.apache.maven.plugin.MojoFailureException exception) {
        throw new IllegalArgumentException("Ban dependency is invalid", exception);
      }
      final MavenBanPlan.Entry.Status parsedStatus = parseStatus(status);
      matchedArtifacts = sortedDistinctNonBlank(matchedArtifacts, "matchedArtifacts");
      originalArtifacts = sortedDistinctNonBlank(originalArtifacts, "originalArtifacts");
      require(
          applied == (parsedStatus != MavenBanPlan.Entry.Status.UNMATCHED),
          "Ban applied flag disagrees with its status");
      if (parsedStatus == MavenBanPlan.Entry.Status.FORCED_ABSENT_AFTER_RESOLUTION) {
        require(!matchedArtifacts.isEmpty(), "Forced-absent ban has no effective match");
      } else if (parsedStatus == MavenBanPlan.Entry.Status.EXCLUDED_BEFORE_RESOLUTION) {
        require(
            matchedArtifacts.isEmpty() && !originalArtifacts.isEmpty(),
            "Excluded-before-resolution ban has inconsistent artifact matches");
      } else {
        require(
            matchedArtifacts.isEmpty() && originalArtifacts.isEmpty(),
            "Unmatched ban carries artifact matches");
      }
      require(
          originalArtifacts.containsAll(matchedArtifacts),
          "Ban effective matches are absent from the original audit");
    }

    private static MavenBanPlan.Entry.Status parseStatus(final String status) {
      try {
        return MavenBanPlan.Entry.Status.valueOf(status);
      } catch (final IllegalArgumentException exception) {
        throw new IllegalArgumentException("Ban status is invalid", exception);
      }
    }
  }

  private static List<String> sortedDistinctNonBlank(
      final List<String> values, final String field) {
    return Objects.requireNonNull(values, field).stream()
        .map(value -> Objects.requireNonNull(value, field + " item"))
        .peek(value -> requireNonBlank(value, field + " item"))
        .distinct()
        .sorted()
        .toList();
  }
}
