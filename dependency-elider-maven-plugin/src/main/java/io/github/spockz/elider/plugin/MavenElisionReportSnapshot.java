// WHY: Preserves the last successful elision totals for a separate Maven report invocation.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ConfidenceLevel;
import io.github.spockz.elider.model.EvidenceOrigin;
import io.github.spockz.elider.model.OsvAffectedRange;
import io.github.spockz.elider.model.StructuredProofProvenance;
import io.github.spockz.elider.model.VexAttestation;
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
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;

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
    List<SourceReviewFinding> sourceReviewFindings,
    AdvisoryReview advisoryReview,
    List<VerifiedStructuredProofFinding> verifiedStructuredProofs,
    MavenElisionPolicyIdentity policy) {
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
    Objects.requireNonNull(advisoryReview, "advisoryReview");
    verifiedStructuredProofs = List.copyOf(verifiedStructuredProofs);
    final Set<VerifiedStructuredProofIdentity> proofIdentities = new HashSet<>();
    for (final VerifiedStructuredProofFinding proof : verifiedStructuredProofs) {
      require(
          proofIdentities.add(VerifiedStructuredProofIdentity.of(proof)),
          "Duplicate verified structured proof identities are not allowed");
    }
    verifiedStructuredProofs =
        verifiedStructuredProofs.stream()
            .sorted(
                Comparator.comparing(VerifiedStructuredProofFinding::coordinate)
                    .thenComparing(VerifiedStructuredProofFinding::cveId)
                    .thenComparing(finding -> finding.provenance().cnaAffectedEntryIdentity()))
            .toList();
    validateVerifiedStructuredProofs(
        verifiedStructuredProofs,
        provenAbsentCves,
        trimmedArtifacts,
        assumeConventionalJavaSourceLayout);
    validateSourceReviewProofSeparation(sourceReviewFindings, verifiedStructuredProofs);
    Objects.requireNonNull(mediatedGraph, "mediatedGraph");
    Objects.requireNonNull(policy, "policy");
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
      final MediatedGraphReport mediatedGraph,
      final boolean assumeConventionalJavaSourceLayout,
      final List<SourceReviewFinding> sourceReviewFindings,
      final MavenElisionPolicyIdentity policy) {
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
        assumeConventionalJavaSourceLayout,
        sourceReviewFindings,
        AdvisoryReview.empty(),
        List.of(),
        policy);
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
      final MediatedGraphReport mediatedGraph,
      final boolean assumeConventionalJavaSourceLayout,
      final List<SourceReviewFinding> sourceReviewFindings,
      final AdvisoryReview advisoryReview,
      final MavenElisionPolicyIdentity policy) {
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
        assumeConventionalJavaSourceLayout,
        sourceReviewFindings,
        advisoryReview,
        List.of(),
        policy);
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
      final MediatedGraphReport mediatedGraph,
      final MavenElisionPolicyIdentity policy) {
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
        List.of(),
        policy);
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
      final MavenElisionPolicyIdentity policy) {
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
        mediatedGraph,
        policy);
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
      final MediatedGraphReport mediatedGraph,
      final MavenElisionPolicyIdentity policy) {
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
        mediatedGraph,
        policy);
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
    final CveFindingGroups findingGroups = CveFindingGroups.from(vulnerabilityAssessment);
    final List<VerifiedStructuredProofFinding> verifiedProofs =
        verifiedStructuredProofs(vulnerabilityAssessment);
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
        findingGroups.removedComponents(),
        findingGroups.provenAbsent(),
        findingGroups.inactivePrerequisites(),
        findingGroups.potentiallyConservative(),
        analysis.mediatedGraph() == null
            ? MediatedGraphReport.unavailable(
                "Mediated graph data is unavailable for this analysis")
            : analysis.mediatedGraph(),
        vulnerabilityAssessment != null && vulnerabilityAssessment.conventionalLayoutAssumed(),
        sourceReviewFindings(vulnerabilityAssessment, verifiedProofs),
        advisoryReview(vulnerabilityAssessment),
        verifiedProofs,
        analysis.policyIdentity());
  }

  private static List<VerifiedStructuredProofFinding> verifiedStructuredProofs(
      final MavenVulnerabilityAssessment.Result assessment) {
    if (assessment == null) {
      return List.of();
    }
    return assessment.attestations().stream()
        .flatMap(
            attestation ->
                attestation
                    .structuredProofProvenance()
                    .map(provenance -> VerifiedStructuredProofFinding.from(attestation, provenance))
                    .stream())
        .toList();
  }

  private static void validateVerifiedStructuredProofs(
      final List<VerifiedStructuredProofFinding> proofs,
      final List<CveFinding> provenAbsent,
      final List<TrimmedArtifact> trimmed,
      final boolean snapshotLayoutAssumption) {
    for (final VerifiedStructuredProofFinding proof : proofs) {
      require(
          proof.provenance().conventionalLayoutAssumed() == snapshotLayoutAssumption,
          "Verified structured proof layout assumption must match the snapshot");
      require(
          provenAbsent.contains(
              new CveFinding(
                  proof.cveId(),
                  MavenElisionReportSourceCoordinateValidator.parseCanonical(proof.coordinate())
                      .toId())),
          "Verified structured proof must be present in provenAbsentCves");
      require(
          trimmed.stream()
              .map(
                  value ->
                      MavenElisionReportSourceCoordinateValidator.parseCanonical(value.coordinate())
                          .toId())
              .anyMatch(
                  coordinate ->
                      coordinate.equals(
                          MavenElisionReportSourceCoordinateValidator.parseCanonical(
                                  proof.coordinate())
                              .toId())),
          "Verified structured proof must identify a trimmed artifact");
    }
  }

  MavenElisionReportSnapshot withAdvisoryReview(final AdvisoryReview review) {
    return new MavenElisionReportSnapshot(
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
        assumeConventionalJavaSourceLayout,
        sourceReviewFindings,
        review,
        verifiedStructuredProofs,
        policy);
  }

  static AdvisoryReview advisoryReview(final MavenVulnerabilityAssessment.Result assessment) {
    if (assessment == null) {
      return AdvisoryReview.empty();
    }
    return new AdvisoryReview(
        assessment.packageAdvisoryFindings().stream().map(PackageAdvisoryFinding::from).toList(),
        assessment.heuristicAdvisoryFindings().stream()
            .map(HeuristicAdvisoryFinding::from)
            .toList());
  }

  private record CveFindingGroups(
      List<CveFinding> removedComponents,
      List<CveFinding> provenAbsent,
      List<CveFinding> inactivePrerequisites,
      List<ConservativeCveFinding> potentiallyConservative) {
    private static CveFindingGroups from(final MavenVulnerabilityAssessment.Result assessment) {
      if (assessment == null) {
        return new CveFindingGroups(List.of(), List.of(), List.of(), List.of());
      }
      return new CveFindingGroups(
          cveFindings(assessment.removedComponents()),
          cveFindings(assessment.provenVulnerableCodeAbsent()),
          cveFindings(assessment.inactiveDueToMissingPrerequisites()),
          assessment.potentiallyConservativeCves().stream()
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
              .toList());
    }

    private static List<CveFinding> cveFindings(
        final List<MavenVulnerabilityAssessment.Finding> findings) {
      return findings.stream()
          .map(finding -> new CveFinding(finding.cveId(), finding.coordinate().toId()))
          .sorted(Comparator.comparing(CveFinding::cveId).thenComparing(CveFinding::coordinate))
          .toList();
    }
  }

  private static List<SourceReviewFinding> sourceReviewFindings(
      final MavenVulnerabilityAssessment.Result assessment,
      final List<VerifiedStructuredProofFinding> verifiedProofs) {
    if (assessment == null) {
      return List.of();
    }
    final Set<VerifiedClaimIdentity> verifiedClaims =
        verifiedProofs.stream()
            .flatMap(
                proof ->
                    proof.provenance().claimAttributions().stream()
                        .map(
                            claim ->
                                new VerifiedClaimIdentity(
                                    proof.provenance().osvId(),
                                    proof.cveId(),
                                    proofCoordinateId(proof.coordinate()),
                                    proof.provenance().cveSourceSha256(),
                                    proof.provenance().cnaAffectedEntryIdentity(),
                                    proof.provenance().affectedProductIdentity(),
                                    proof.provenance().conventionalLayoutAssumed(),
                                    claim.type(),
                                    claim.claim())))
            .collect(java.util.stream.Collectors.toUnmodifiableSet());
    return assessment.matchedSourceClaims().stream()
        .filter(claim -> !isFullyVerified(claim, verifiedClaims))
        .map(MavenElisionReportSnapshot::sourceReviewFinding)
        .toList();
  }

  private static boolean isFullyVerified(
      final MavenVulnerabilityAssessment.MatchedSourceClaim claim,
      final Set<VerifiedClaimIdentity> verified) {
    if (claim.programFiles().isEmpty() && claim.programRoutines().isEmpty()) {
      return false;
    }
    return claim.programFiles().stream()
            .allMatch(
                file ->
                    verified.contains(
                        VerifiedClaimIdentity.of(
                            claim, StructuredProofProvenance.ClaimType.FILE, file)))
        && claim.programRoutines().stream()
            .allMatch(
                routine ->
                    verified.contains(
                        VerifiedClaimIdentity.of(
                            claim, StructuredProofProvenance.ClaimType.ROUTINE, routine)));
  }

  private static boolean isFullyVerified(
      final SourceReviewFinding finding, final Set<VerifiedClaimIdentity> verified) {
    return finding.programFiles().stream()
            .allMatch(
                file ->
                    verified.contains(
                        VerifiedClaimIdentity.of(
                            finding, StructuredProofProvenance.ClaimType.FILE, file)))
        && finding.programRoutines().stream()
            .allMatch(
                routine ->
                    verified.contains(
                        VerifiedClaimIdentity.of(
                            finding, StructuredProofProvenance.ClaimType.ROUTINE, routine)));
  }

  private static void validateSourceReviewProofSeparation(
      final List<SourceReviewFinding> reviewFindings,
      final List<VerifiedStructuredProofFinding> verifiedProofs) {
    final Set<VerifiedClaimIdentity> verifiedClaims =
        verifiedProofs.stream()
            .flatMap(
                proof ->
                    proof.provenance().claimAttributions().stream()
                        .map(
                            claim ->
                                new VerifiedClaimIdentity(
                                    proof.provenance().osvId(),
                                    proof.cveId(),
                                    proofCoordinateId(proof.coordinate()),
                                    proof.provenance().cveSourceSha256(),
                                    proof.provenance().cnaAffectedEntryIdentity(),
                                    proof.provenance().affectedProductIdentity(),
                                    proof.provenance().conventionalLayoutAssumed(),
                                    claim.type(),
                                    claim.claim())))
            .collect(java.util.stream.Collectors.toUnmodifiableSet());
    for (final SourceReviewFinding finding : reviewFindings) {
      if (isFullyVerified(finding, verifiedClaims)) {
        throw new IllegalArgumentException(
            "Elision report source review claim is already fully represented as verified");
      }
    }
  }

  private static SourceReviewFinding sourceReviewFinding(
      final MavenVulnerabilityAssessment.MatchedSourceClaim claim) {
    return new SourceReviewFinding(
        claim.osvId(),
        claim.cveId(),
        claim.coordinate().toString(),
        claim.sourceRecordSha256(),
        claim.cnaAffectedEntryIdentity(),
        claim.affectedProductIdentity(),
        claim.programFiles(),
        claim.programRoutines(),
        claim.conventionalLayoutAssumed(),
        claim.matches().stream().map(SourceReviewMatch::from).toList(),
        claim.applicability(),
        claim.applicabilityRationale(),
        claim.unresolvedRationale());
  }

  private record VerifiedClaimIdentity(
      String osvId,
      String cveId,
      String coordinate,
      String sourceDigest,
      String entryIdentity,
      String productIdentity,
      boolean conventionalLayoutAssumed,
      StructuredProofProvenance.ClaimType type,
      String claim) {
    private static VerifiedClaimIdentity of(
        final MavenVulnerabilityAssessment.MatchedSourceClaim sourceClaim,
        final StructuredProofProvenance.ClaimType type,
        final String claim) {
      return new VerifiedClaimIdentity(
          sourceClaim.osvId(),
          sourceClaim.cveId(),
          sourceClaim.coordinate().toId(),
          sourceClaim.sourceRecordSha256(),
          sourceClaim.cnaAffectedEntryIdentity(),
          sourceClaim.affectedProductIdentity(),
          sourceClaim.conventionalLayoutAssumed(),
          type,
          claim);
    }

    private static VerifiedClaimIdentity of(
        final SourceReviewFinding sourceClaim,
        final StructuredProofProvenance.ClaimType type,
        final String claim) {
      return new VerifiedClaimIdentity(
          sourceClaim.osvId(),
          sourceClaim.cveId(),
          proofCoordinateId(sourceClaim.coordinate()),
          sourceClaim.sourceRecordSha256(),
          sourceClaim.cnaAffectedEntryIdentity(),
          sourceClaim.affectedProductIdentity(),
          sourceClaim.conventionalLayoutAssumed(),
          type,
          claim);
    }
  }

  private static String proofCoordinateId(final String coordinate) {
    return MavenElisionReportSourceCoordinateValidator.parseCanonical(coordinate).toId();
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

  private static void requireSha256(final String value, final String field) {
    if (value == null || !value.matches("[0-9a-f]{64}")) {
      throw new IllegalArgumentException(field + " must be a lowercase SHA-256");
    }
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
      String osvId,
      String cveId,
      String coordinate,
      String sourceRecordSha256,
      String cnaAffectedEntryIdentity,
      String affectedProductIdentity,
      List<String> programFiles,
      List<String> programRoutines,
      boolean conventionalLayoutAssumed,
      List<SourceReviewMatch> matches,
      OsvPackageApplicability.Status applicability,
      String applicabilityRationale,
      String unresolvedRationale) {
    SourceReviewFinding {
      requireNonBlank(osvId, "osvId");
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
      Objects.requireNonNull(applicability, "applicability");
      requireNonBlank(applicabilityRationale, "applicabilityRationale");
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

  /** Historical rendering of a proof already verified during the saved elision run. */
  record VerifiedStructuredProofFinding(
      String cveId,
      String coordinate,
      String originalSha256,
      String trimmedSha256,
      StructuredProofProvenance provenance) {
    VerifiedStructuredProofFinding {
      requireNonBlank(cveId, "verified structured proof cveId");
      require(
          cveId.matches("CVE-[0-9]{4}-[0-9]{4,}"),
          "verified structured proof cveId must be a CVE identifier");
      requireNonBlank(coordinate, "verified structured proof coordinate");
      MavenElisionReportSourceCoordinateValidator.validate(coordinate);
      requireSha256(originalSha256, "verified structured proof originalSha256");
      requireSha256(trimmedSha256, "verified structured proof trimmedSha256");
      Objects.requireNonNull(provenance, "provenance");
      final ArtifactCoordinate candidate =
          MavenElisionReportSourceCoordinateValidator.parseCanonical(coordinate);
      final ArtifactCoordinate sources = provenance.sourcesCoordinate();
      MavenElisionReportAdvisoryInvariants.validateProofRawPackageIdentity(
          coordinate,
          provenance.rawScopeEvidence().osvEcosystem(),
          provenance.rawScopeEvidence().osvPackageName());
      require(
          candidate.groupId().equals(sources.groupId())
              && candidate.artifactId().equals(sources.artifactId())
              && candidate.version().equals(sources.version())
              && candidate.type().equals(sources.type())
              && "sources".equals(sources.classifier()),
          "Verified structured proof sources coordinate must match the exact sources classifier");
    }

    private static VerifiedStructuredProofFinding from(
        final VexAttestation attestation, final StructuredProofProvenance provenance) {
      return new VerifiedStructuredProofFinding(
          attestation.cveId(),
          attestation.coordinate().toString(),
          attestation.originalSha256(),
          attestation.trimmedSha256(),
          provenance);
    }
  }

  private record VerifiedStructuredProofIdentity(String cveId, String coordinate) {
    private static VerifiedStructuredProofIdentity of(final VerifiedStructuredProofFinding proof) {
      return new VerifiedStructuredProofIdentity(
          proof.cveId(),
          MavenElisionReportSourceCoordinateValidator.parseCanonical(proof.coordinate()).toId());
    }
  }

  /** Historical advisory rows separate from proof and classification fields. */
  record AdvisoryReview(
      List<PackageAdvisoryFinding> packageAdvisories,
      List<HeuristicAdvisoryFinding> heuristicAdvisories) {
    AdvisoryReview {
      packageAdvisories =
          Objects.requireNonNull(packageAdvisories, "packageAdvisories").stream()
              .distinct()
              .sorted(MavenElisionReportAdvisoryOrdering::comparePackageFindings)
              .toList();
      heuristicAdvisories =
          Objects.requireNonNull(heuristicAdvisories, "heuristicAdvisories").stream()
              .distinct()
              .sorted(MavenElisionReportAdvisoryOrdering::compareHeuristicFindings)
              .toList();
      MavenElisionReportAdvisoryInvariants.validateHeuristicPackageOwners(
          packageAdvisories.stream()
              .map(
                  value ->
                      new MavenElisionReportAdvisoryInvariants.PackageOwner(
                          value.osvId(),
                          value.coordinate(),
                          value.ecosystem(),
                          value.packageName(),
                          value.affectedVersions(),
                          value.ranges(),
                          value.applicability()))
              .toList(),
          heuristicAdvisories.stream()
              .map(
                  value ->
                      new MavenElisionReportAdvisoryInvariants.HeuristicOwner(
                          value.osvId(),
                          value.coordinate(),
                          value.ecosystem(),
                          value.packageName(),
                          value.applicability()))
              .toList());
    }

    static AdvisoryReview empty() {
      return new AdvisoryReview(List.of(), List.of());
    }
  }

  /** Package-level OSV claim with exact component and inventory facts. */
  record PackageAdvisoryFinding(
      String osvId,
      List<String> aliases,
      String coordinate,
      String ecosystem,
      String packageName,
      List<String> affectedVersions,
      List<AffectedRange> ranges,
      OsvPackageApplicability.Status applicability,
      String applicabilityRationale,
      MavenVulnerabilityAssessment.InventoryDisposition inventoryDisposition,
      String sourceRecordSha256) {
    PackageAdvisoryFinding {
      requireNonBlank(osvId, "osvId");
      aliases = sortedDistinctNonBlank(aliases, "aliases");
      MavenElisionReportSourceCoordinateValidator.validate(coordinate);
      requireNonBlank(ecosystem, "ecosystem");
      requireNonBlank(packageName, "packageName");
      affectedVersions = sortedDistinctNonBlank(affectedVersions, "affectedVersions");
      ranges = List.copyOf(Objects.requireNonNull(ranges, "ranges"));
      Objects.requireNonNull(applicability, "applicability");
      requireNonBlank(applicabilityRationale, "applicabilityRationale");
      Objects.requireNonNull(inventoryDisposition, "inventoryDisposition");
      if (sourceRecordSha256 != null) {
        require(
            sourceRecordSha256.matches("[0-9a-f]{64}"),
            "sourceRecordSha256 must be a lowercase SHA-256 when present");
      }
      MavenElisionReportAdvisoryInvariants.validatePackageIdentity(
          coordinate, ecosystem, packageName);
      MavenElisionReportAdvisoryInvariants.validatePackageApplicability(
          coordinate, affectedVersions, ranges, applicability);
    }

    private static PackageAdvisoryFinding from(
        final MavenVulnerabilityAssessment.PackageAdvisoryFinding finding) {
      return new PackageAdvisoryFinding(
          finding.osvId(),
          finding.aliases().stream().sorted().toList(),
          finding.coordinate().toString(),
          finding.ecosystem(),
          finding.packageName(),
          finding.affectedVersions(),
          finding.ranges().stream().map(AffectedRange::from).toList(),
          finding.applicability(),
          finding.applicabilityRationale(),
          finding.inventoryDisposition(),
          finding.sourceRecordSha256());
    }
  }

  /** One unflattened OSV range and its ordered events. */
  record AffectedRange(String type, String repo, List<Map<String, String>> events) {
    AffectedRange {
      requireNonBlank(type, "type");
      events =
          Objects.requireNonNull(events, "events").stream()
              .map(event -> java.util.Collections.unmodifiableMap(new TreeMap<>(event)))
              .toList();
    }

    private static AffectedRange from(final OsvAffectedRange range) {
      return new AffectedRange(range.type(), range.repo(), range.events());
    }
  }

  /** Review-only heuristic candidates retain their source and assessed component. */
  record HeuristicAdvisoryFinding(
      String osvId,
      List<String> aliases,
      String cveId,
      String coordinate,
      String ecosystem,
      String packageName,
      String versionRangeSpec,
      OsvPackageApplicability.Status applicability,
      String applicabilityRationale,
      MavenVulnerabilityAssessment.InventoryDisposition inventoryDisposition,
      EvidenceOrigin origin,
      String sourceRecordId,
      String sourceUrl,
      String sourceRecordSha256,
      ConfidenceLevel confidence,
      List<String> candidateClasses,
      List<String> candidateDependencies) {
    HeuristicAdvisoryFinding {
      requireNonBlank(osvId, "osvId");
      aliases = sortedDistinctNonBlank(aliases, "aliases");
      if (cveId != null) {
        require(cveId.matches("CVE-[0-9]{4}-[0-9]{4,}"), "Invalid heuristic CVE identifier");
      }
      MavenElisionReportSourceCoordinateValidator.validate(coordinate);
      requireNonBlank(ecosystem, "ecosystem");
      requireNonBlank(packageName, "packageName");
      requireNonBlank(versionRangeSpec, "versionRangeSpec");
      Objects.requireNonNull(applicability, "applicability");
      requireNonBlank(applicabilityRationale, "applicabilityRationale");
      Objects.requireNonNull(inventoryDisposition, "inventoryDisposition");
      Objects.requireNonNull(origin, "origin");
      require(
          origin == EvidenceOrigin.DESCRIPTION || origin == EvidenceOrigin.REFERENCE_URL,
          "Heuristic report origin must be DESCRIPTION or REFERENCE_URL");
      requireNonBlank(sourceRecordId, "sourceRecordId");
      if (sourceUrl != null) {
        try {
          final java.net.URI uri = java.net.URI.create(sourceUrl);
          require(
              uri.isAbsolute()
                  && ("http".equalsIgnoreCase(uri.getScheme())
                      || "https".equalsIgnoreCase(uri.getScheme())),
              "sourceUrl must be an absolute HTTP(S) URL");
        } catch (final IllegalArgumentException exception) {
          throw new IllegalArgumentException(
              "sourceUrl must be an absolute HTTP(S) URL", exception);
        }
      }
      if (sourceRecordSha256 != null) {
        require(
            sourceRecordSha256.matches("[0-9a-f]{64}"),
            "sourceRecordSha256 must be a lowercase SHA-256 when present");
      }
      require(confidence == ConfidenceLevel.MEDIUM, "Heuristic report confidence must be MEDIUM");
      candidateClasses = sortedDistinctNonBlank(candidateClasses, "candidateClasses");
      candidateDependencies =
          sortedDistinctNonBlank(candidateDependencies, "candidateDependencies");
      require(
          !candidateClasses.isEmpty() || !candidateDependencies.isEmpty(),
          "Heuristic report requires at least one candidate");
      MavenElisionReportAdvisoryInvariants.validateHeuristicIdentity(
          osvId,
          aliases,
          cveId,
          coordinate,
          ecosystem,
          packageName,
          sourceRecordId,
          candidateClasses,
          candidateDependencies);
    }

    private static HeuristicAdvisoryFinding from(
        final MavenVulnerabilityAssessment.HeuristicAdvisoryFinding finding) {
      return new HeuristicAdvisoryFinding(
          finding.osvId(),
          finding.aliases().stream().sorted().toList(),
          finding.cveId(),
          finding.coordinate().toString(),
          finding.ecosystem(),
          finding.packageName(),
          finding.versionRangeSpec(),
          finding.applicability(),
          finding.applicabilityRationale(),
          finding.inventoryDisposition(),
          finding.origin(),
          finding.sourceRecordId(),
          finding.sourceUrl(),
          finding.sourceRecordSha256(),
          finding.confidence(),
          finding.candidateClasses().stream().sorted().toList(),
          finding.candidateDependencies().stream().sorted().toList());
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
