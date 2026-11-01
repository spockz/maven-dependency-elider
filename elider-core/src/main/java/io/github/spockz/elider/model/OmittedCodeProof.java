/* WHY: This package controls creation of immutable VEX proof evidence. */

package io.github.spockz.elider.model;

import io.github.spockz.elider.correspondence.SourceReproductionEngine;
import io.github.spockz.elider.trimmer.ArtifactDigests;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.IOException;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

/** Proves mapped classes are absent from physical archives. */
public final class OmittedCodeProof {
  /** Minimum number of mapped classes to require multi-symbol evaluation. */
  private static final int MULTI_SYMBOL_MINIMUM = 2;

  private OmittedCodeProof() {}

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
    return proveStructured(request, trimRecord, SourceReproductionEngine.forCurrentJdk());
  }

  /** Reuses a claim-independent engine scoped to the enclosing assessment invocation. */
  public static VexAttestation proveStructured(
      final StructuredSourceProofRequest request,
      final ArtifactTrimRecord trimRecord,
      final SourceReproductionEngine reproductionEngine)
      throws IOException {
    return StructuredOmittedCodeProof.prove(request, trimRecord, reproductionEngine);
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
