/* WHY: Keeps source matches
 * review-only until attribution is complete. */

package io.github.spockz.elider.model;

import io.github.spockz.elider.model.VulnerabilitySymbolMapping.ConfidenceLevel;
import java.util.Objects;

/** Review-only candidate corroborated by structured source metadata. */
public record CorroboratedSourceClassCandidate(
    AdvisoryScope scope,
    AdvisoryProvenance provenance,
    String cnaAffectedEntryIdentity,
    ArtifactCoordinate artifactCoordinate,
    String originalArchiveSha256,
    String physicalJarEntry,
    int multiReleaseTier,
    String affectedProductIdentity,
    String programFile,
    String classEntry,
    String sourceFileAttribute,
    String packagePathComparison,
    boolean conventionalLayoutAssumed,
    MappingStatus mappingStatus)
    implements AdvisoryEvidence {
  /** Review-only state until the source-unit output set is complete. */
  public enum MappingStatus {
    INCOMPLETE_REVIEW_ONLY
  }

  /** Validates and freezes the review-only attribution details. */
  public CorroboratedSourceClassCandidate {
    Objects.requireNonNull(scope, "scope");
    Objects.requireNonNull(provenance, "provenance");
    Objects.requireNonNull(cnaAffectedEntryIdentity, "cnaAffectedEntryIdentity");
    Objects.requireNonNull(mappingStatus, "mappingStatus");
    Objects.requireNonNull(artifactCoordinate, "artifactCoordinate");
    if (provenance.origin() != EvidenceOrigin.CVE_LIST
        || provenance.sourceRecordSha256() == null
        || !provenance.sourceRecordId().equals(scope.cveId())) {
      throw new IllegalArgumentException("Corroboration requires CVE record provenance");
    }
    if (!scope.affectedCoordinate().groupId().equals(artifactCoordinate.groupId())
        || !scope.affectedCoordinate().artifactId().equals(artifactCoordinate.artifactId())
        || !scope.affectedCoordinate().type().equals(artifactCoordinate.type())
        || !scope.affectedCoordinate().classifier().equals(artifactCoordinate.classifier())
        || artifactCoordinate.version() == null
        || (scope.affectedCoordinate().version() != null
            && !scope.affectedCoordinate().version().equals(artifactCoordinate.version()))) {
      throw new IllegalArgumentException(
          "artifactCoordinate must bind a concrete version in the advisory scope");
    }
    if (!cnaAffectedEntryIdentity.matches("containers\\.cna\\.affected\\[[0-9]+\\]")) {
      throw new IllegalArgumentException("cnaAffectedEntryIdentity must identify one CNA entry");
    }
    requireText(affectedProductIdentity, "affectedProductIdentity");
    requireText(cnaAffectedEntryIdentity, "cnaAffectedEntryIdentity");
    requireText(originalArchiveSha256, "originalArchiveSha256");
    requireText(physicalJarEntry, "physicalJarEntry");
    requireText(programFile, "programFile");
    requireText(classEntry, "classEntry");
    requireText(packagePathComparison, "packagePathComparison");
    if (!originalArchiveSha256.matches("[0-9a-f]{64}")) {
      throw new IllegalArgumentException("originalArchiveSha256 must be a lowercase SHA-256");
    }
    if (multiReleaseTier != 0 && multiReleaseTier < 9) {
      throw new IllegalArgumentException("multiReleaseTier must be zero or at least 9");
    }
    if (!physicalJarEntry.endsWith(".class")) {
      throw new IllegalArgumentException("physicalJarEntry must identify a class file");
    }
    final String expectedTierPrefix =
        multiReleaseTier == 0 ? "" : "META-INF/versions/" + multiReleaseTier + "/";
    if (!physicalJarEntry.startsWith(expectedTierPrefix)) {
      throw new IllegalArgumentException("physicalJarEntry must agree with multiReleaseTier");
    }
    final String logicalEntry =
        multiReleaseTier == 0
            ? physicalJarEntry
            : physicalJarEntry.substring(expectedTierPrefix.length());
    if (!logicalEntry
        .substring(0, logicalEntry.length() - ".class".length())
        .replace('/', '.')
        .equals(classEntry)) {
      throw new IllegalArgumentException("physicalJarEntry must identify classEntry");
    }
    if (!classEntry.matches("[A-Za-z_$][A-Za-z0-9_$]*(\\.[A-Za-z_$][A-Za-z0-9_$]*)+")
        || classEntry.indexOf('$') >= 0) {
      throw new IllegalArgumentException("classEntry must be a top-level fully qualified class");
    }
    if (sourceFileAttribute == null || sourceFileAttribute.isBlank()) {
      throw new IllegalArgumentException("sourceFileAttribute must be present and non-blank");
    }
    final String normalizedProgramFile = programFile.replace('\\', '/');
    final int basenameSeparator = normalizedProgramFile.lastIndexOf('/');
    final String programBasename = normalizedProgramFile.substring(basenameSeparator + 1);
    if (!programBasename.endsWith(".java") || !programBasename.equals(sourceFileAttribute)) {
      throw new IllegalArgumentException(
          "sourceFileAttribute must match the Java source claim basename");
    }
  }

  @Override
  public ConfidenceLevel confidenceLabel() {
    return ConfidenceLevel.MEDIUM;
  }

  private static void requireText(final String value, final String field) {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException(field + " must not be blank");
    }
  }
}
