/* WHY: Restricts VEX evidence creation to the adjacent proof engine. */

package io.github.spockz.elider.model;

import java.util.Collections;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;

/** Immutable evidence that mapped vulnerable classes are absent. */
@SuppressWarnings({
  "PMD.DataClass",
  "PMD.AvoidFieldNameMatchingMethodName",
  "PMD.CommentDefaultAccessModifier"
})
public final class VexAttestation {
  /** The CVE identifier proven by archive inspection. */
  private final String cveId;

  /** Exact Maven artifact identity inspected by the proof. */
  private final ArtifactCoordinate coordinate;

  /** Supported VEX justification. */
  private final String justification;

  /** Human-readable summary of the physical archive proof. */
  private final String impactDetail;

  /** Mapped classes and original nested classes proven absent. */
  private final Set<String> evidenceSymbols;

  /** Verified original archive digest. */
  private final String originalSha256;

  /** Verified trimmed archive digest. */
  private final String trimmedSha256;

  /** Only the model-package proof engine can construct a verified attestation. */
  VexAttestation(
      final String cveId,
      final ArtifactCoordinate coordinate,
      final String justification,
      final String impactDetail,
      final Set<String> evidenceSymbols,
      final String originalSha256,
      final String trimmedSha256) {
    this.cveId = Objects.requireNonNull(cveId, "cveId");
    this.coordinate = Objects.requireNonNull(coordinate, "coordinate");
    if (!"vulnerable_code_not_present".equals(justification)) {
      throw new IllegalArgumentException("Unsupported VEX justification");
    }
    this.justification = justification;
    if (impactDetail == null || impactDetail.isBlank()) {
      throw new IllegalArgumentException("impactDetail must not be blank");
    }
    this.impactDetail = impactDetail;
    Objects.requireNonNull(evidenceSymbols, "evidenceSymbols");
    if (evidenceSymbols.isEmpty()) {
      throw new IllegalArgumentException("evidenceSymbols must not be empty");
    }
    this.evidenceSymbols = Collections.unmodifiableSet(new TreeSet<>(evidenceSymbols));
    requireSha256(originalSha256, "originalSha256");
    requireSha256(trimmedSha256, "trimmedSha256");
    this.originalSha256 = originalSha256;
    this.trimmedSha256 = trimmedSha256;
  }

  /** Returns the CVE identifier proven by this attestation. */
  public String cveId() {
    return cveId;
  }

  /** Returns the exact artifact coordinate whose archive was inspected. */
  public ArtifactCoordinate coordinate() {
    return coordinate;
  }

  /** Returns the supported VEX justification. */
  public String justification() {
    return justification;
  }

  /** Returns the human-readable summary of the proof result. */
  public String impactDetail() {
    return impactDetail;
  }

  /** Returns the mapped and nested symbols proven absent. */
  public Set<String> evidenceSymbols() {
    return evidenceSymbols;
  }

  /** Returns the original archive digest verified by the proof. */
  public String originalSha256() {
    return originalSha256;
  }

  /** Returns the trimmed archive digest verified by the proof. */
  public String trimmedSha256() {
    return trimmedSha256;
  }

  private static void requireSha256(final String value, final String name) {
    if (value == null || !value.matches("[0-9a-f]{64}")) {
      throw new IllegalArgumentException(name + " must be a lowercase SHA-256 digest");
    }
  }
}
