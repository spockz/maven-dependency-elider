/* WHY: Keeps source matches
 * review-only until attribution is complete. */

package io.github.spockz.elider.model;

import io.github.spockz.elider.model.VulnerabilitySymbolMapping.ConfidenceLevel;
import java.util.Objects;

/** Review-only candidate corroborated by structured source metadata. */
public record CorroboratedSourceClassCandidate(
    AdvisoryScope scope,
    AdvisoryProvenance provenance,
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
    Objects.requireNonNull(mappingStatus, "mappingStatus");
    if (provenance.origin() != EvidenceOrigin.CVE_LIST
        || provenance.sourceRecordSha256() == null
        || !provenance.sourceRecordId().equals(scope.cveId())) {
      throw new IllegalArgumentException("Corroboration requires CVE record provenance");
    }
    requireText(affectedProductIdentity, "affectedProductIdentity");
    requireText(programFile, "programFile");
    requireText(classEntry, "classEntry");
    requireText(packagePathComparison, "packagePathComparison");
    if (!classEntry.matches("[A-Za-z_$][A-Za-z0-9_$]*(\\.[A-Za-z_$][A-Za-z0-9_$]*)+")
        || classEntry.indexOf('$') >= 0) {
      throw new IllegalArgumentException("classEntry must be a top-level fully qualified class");
    }
    if (sourceFileAttribute != null && sourceFileAttribute.isBlank()) {
      throw new IllegalArgumentException("sourceFileAttribute must not be blank when present");
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
