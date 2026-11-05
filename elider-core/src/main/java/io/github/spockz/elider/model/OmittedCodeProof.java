/* WHY: This package controls creation of immutable VEX proof evidence. */

package io.github.spockz.elider.model;

import io.github.spockz.elider.scanner.JarSourceFileIndex;
import io.github.spockz.elider.trimmer.ArtifactDigests;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.IOException;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

/** Proves mapped classes are absent from physical archives. */
@SuppressWarnings("PMD.LawOfDemeter")
public final class OmittedCodeProof {
  /** Minimum number of mapped classes to require multi-symbol evaluation. */
  private static final int MULTI_SYMBOL_MINIMUM = 2;

  private OmittedCodeProof() {}

  /** Captures exact archive observations once for all findings on a trimmed artifact. */
  public static ArchiveInspection inspect(final ArtifactTrimRecord record) throws IOException {
    Objects.requireNonNull(record, "record");
    final JarSourceFileIndex original = JarSourceFileIndex.read(record.originalPath());
    final ArtifactDigests trimmed = ArtifactDigests.read(record.trimmedPath());
    if (!original.archiveSha256().equals(record.originalSha256())
        || !trimmed.sha256().equals(record.trimmedSha256())) {
      throw new IllegalArgumentException("Artifact digest no longer matches trim record");
    }
    return new ArchiveInspection(
        record, original, OmittedArchiveClassInventory.read(record.trimmedPath()));
  }

  /** Inspects archives and verifies every effective declared code locator. */
  public static VexAttestation prove(
      final GenericVulnerabilityFinding finding,
      final ArtifactTrimRecord record,
      final boolean assumeConventionalJavaSourceLayout)
      throws IOException {
    return prove(finding, inspect(record), assumeConventionalJavaSourceLayout);
  }

  /** Uses controlled artifact observations for attribution. */
  public static VexAttestation prove(
      final GenericVulnerabilityFinding finding,
      final ArchiveInspection inspection,
      final boolean assumeConventionalJavaSourceLayout) {
    Objects.requireNonNull(inspection, "inspection");
    final ArtifactTrimRecord record = inspection.record;
    FindingVerification.requireEligible(finding, record.coordinate());
    if (finding.codeGroupStatusFor(record.coordinate().version()) != ClaimGroupStatus.DECLARED) {
      throw new IllegalArgumentException("Physical omission requires effective declared code");
    }
    final CodeAttributionResolver.Result attribution =
        CodeAttributionResolver.resolve(
            finding.effectiveCodeClaimsFor(record.coordinate().version()),
            inspection.originalIndex,
            assumeConventionalJavaSourceLayout);
    if (attribution.declarations().isEmpty()
        || attribution.declarations().stream()
            .anyMatch(
                declaration -> declaration.status() != CodeAttributionResolver.Status.RESOLVED)) {
      throw new IllegalArgumentException("Declared code attribution is incomplete: " + attribution);
    }
    final Set<String> declaredClasses = new TreeSet<>();
    attribution
        .declarations()
        .forEach(declaration -> declaredClasses.addAll(declaration.classFamily()));
    final Set<String> originalClasses =
        inspection.originalIndex.classFiles().stream()
            .map(value -> value.classEntry().replace('.', '/'))
            .collect(java.util.stream.Collectors.toSet());
    final Set<String> absent =
        PhysicalOmissionChecks.verifySymbols(
            declaredClasses, originalClasses, inspection.trimmedClasses);
    return VexAttestation.genericOmittedCode(
        finding,
        record.coordinate(),
        "All effective declared code and its nested classes are absent from the trimmed artifact. "
            + "This observation is limited to the declared code and does not establish "
            + "declaration completeness.",
        absent,
        record.originalSha256(),
        record.trimmedSha256());
  }

  /** Returns proof evidence or throws when checks fail. */
  public static VexAttestation prove(
      final ExplicitClassMappingEvidence evidence, final ArtifactTrimRecord trimRecord)
      throws IOException {
    final VulnerabilitySymbolMapping mapping = requireEvidence(evidence);
    requireMatchingIdentity(mapping, trimRecord);
    final String impactDetail =
        mapping.sourceAdvisoryUrl() != null
            ? "Mapped vulnerable classes and their original nested classes are absent "
                + "from the trimmed artifact (verified against fix commit/advisory: "
                + mapping.sourceAdvisoryUrl()
                + ")."
            : "Mapped vulnerable classes and their original nested classes are absent "
                + "from the trimmed artifact.";
    final ArtifactDigests originalDigests =
        PhysicalOmissionChecks.verifyDigest(
            trimRecord.originalPath(), trimRecord.originalSha256(), trimRecord.originalSha1());
    final ArtifactDigests trimmedDigests =
        PhysicalOmissionChecks.verifyDigest(
            trimRecord.trimmedPath(), trimRecord.trimmedSha256(), trimRecord.trimmedSha1());
    final Set<String> originalClasses =
        OmittedArchiveClassInventory.read(trimRecord.originalPath());
    final Set<String> trimmedClasses = OmittedArchiveClassInventory.read(trimRecord.trimmedPath());
    final Set<String> absent =
        PhysicalOmissionChecks.verifySymbols(
            mapping.vulnerableClasses(), originalClasses, trimmedClasses);
    PhysicalOmissionChecks.verifyUnchanged(trimRecord, originalDigests, trimmedDigests);
    return new VexAttestation(
        mapping.cveId(),
        trimRecord.coordinate(),
        "vulnerable_code_not_present",
        impactDetail,
        absent,
        originalDigests.sha256(),
        trimmedDigests.sha256());
  }

  /** Revalidates current source claims and then proves omission. */
  public static VexAttestation proveStructured(
      final StructuredSourceProofRequest request, final ArtifactTrimRecord trimRecord)
      throws IOException {
    return StructuredOmittedCodeProof.prove(request, trimRecord);
  }

  /** Observations bound to original and resulting archive digests. */
  @SuppressWarnings({"PMD.CommentRequired", "PMD.AvoidFieldNameMatchingMethodName"})
  public static final class ArchiveInspection {
    private final ArtifactTrimRecord record;
    private final JarSourceFileIndex originalIndex;
    private final Set<String> trimmedClasses;

    private ArchiveInspection(
        final ArtifactTrimRecord record,
        final JarSourceFileIndex originalIndex,
        final Set<String> trimmedClasses) {
      this.record = record;
      this.originalIndex = originalIndex;
      this.trimmedClasses = Set.copyOf(trimmedClasses);
    }

    /** Returns attribution data without granting proof authority. */
    public JarSourceFileIndex originalIndex() {
      return originalIndex;
    }
  }

  private static void requireMatchingIdentity(
      final VulnerabilitySymbolMapping mapping, final ArtifactTrimRecord record) {
    if (mapping == null || record == null) {
      throw new IllegalArgumentException("mapping and trimRecord are required");
    }
    if (!PhysicalOmissionChecks.sameArtifactIdentity(
        mapping.affectedCoordinate(), record.coordinate())) {
      throw new IllegalArgumentException("Mapping coordinate does not match trim record");
    }
  }

  private static VulnerabilitySymbolMapping requireEvidence(
      final ExplicitClassMappingEvidence evidence) {
    if (evidence == null) {
      throw new IllegalArgumentException("Explicit class evidence is required");
    }
    return evidence.mapping();
  }

  /** Evaluates whether a multi-symbol mapping had missing symbols. */
  public record ConservativeOmission(
      String cveId,
      ArtifactCoordinate coordinate,
      Set<String> absentFromOriginal,
      Set<String> presentAndPruned) {
    /** Validates non-null collections and wraps them immutably. */
    public ConservativeOmission {
      Objects.requireNonNull(cveId, "cveId");
      Objects.requireNonNull(coordinate, "coordinate");
      absentFromOriginal = Set.copyOf(absentFromOriginal);
      presentAndPruned = Set.copyOf(presentAndPruned);
    }
  }

  /** Evaluates multi-symbol mapping drops due to missing archive symbols. */
  @SuppressWarnings("PMD.CyclomaticComplexity")
  public static Optional<ConservativeOmission> evaluateConservativeOmission(
      final VulnerabilitySymbolMapping mapping, final ArtifactTrimRecord trimRecord)
      throws IOException {
    if (mapping == null || trimRecord == null) {
      return Optional.empty();
    }
    if (!PhysicalOmissionChecks.sameArtifactIdentity(
        mapping.affectedCoordinate(), trimRecord.coordinate())) {
      return Optional.empty();
    }
    if (mapping.vulnerableClasses().size() < MULTI_SYMBOL_MINIMUM) {
      return Optional.empty();
    }
    final Set<String> originalClasses =
        OmittedArchiveClassInventory.read(trimRecord.originalPath());
    final Set<String> trimmedClasses = OmittedArchiveClassInventory.read(trimRecord.trimmedPath());
    final Set<String> absentFromOriginal = new TreeSet<>();
    final Set<String> presentAndPruned = new TreeSet<>();
    for (final String mapped : mapping.vulnerableClasses()) {
      final String binaryName = mapped.replace('.', '/');
      if (originalClasses.contains(binaryName)) {
        if (classSurvives(binaryName, originalClasses, trimmedClasses)) {
          return Optional.empty();
        }
        presentAndPruned.add(mapped);
      } else {
        absentFromOriginal.add(mapped);
      }
    }
    if (!absentFromOriginal.isEmpty() && !presentAndPruned.isEmpty()) {
      return Optional.of(
          new ConservativeOmission(
              mapping.cveId(), trimRecord.coordinate(), absentFromOriginal, presentAndPruned));
    }
    return Optional.empty();
  }

  private static boolean classSurvives(
      final String binaryName,
      final Set<String> originalClasses,
      final Set<String> trimmedClasses) {
    if (trimmedClasses.contains(binaryName)) {
      return true;
    }
    for (final String symbol : PhysicalOmissionChecks.nestedSymbols(binaryName, originalClasses)) {
      if (trimmedClasses.contains(symbol)) {
        return true;
      }
    }
    final String nestedPrefix = binaryName + "$";
    for (final String trimmed : trimmedClasses) {
      if (trimmed.startsWith(nestedPrefix)) {
        return true;
      }
    }
    return false;
  }
}
