/* WHY: Restricts VEX evidence creation to the adjacent proof engine. */

package io.github.spockz.elider.model;

import java.nio.file.Path;
import java.util.Collections;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;

/** Immutable evidence for omitted-code or prerequisite-class VEX justifications. */
@SuppressWarnings({
  "PMD.DataClass",
  "PMD.AvoidFieldNameMatchingMethodName",
  "PMD.CommentDefaultAccessModifier",
  "PMD.TooManyMethods"
})
public final class VexAttestation {
  /** Stable VEX justification for omitted vulnerable code. */
  private static final String OMITTED_CODE_JUSTIFICATION = "vulnerable_code_not_present";

  /** VEX justification for proof of a missing dependency. */
  private static final String PRECONDITION_JUSTIFICATION = "requires_dependency";

  /** The CVE identifier proven by archive inspection. */
  private final String cveId;

  /** Exact Maven artifact identity inspected by the proof. */
  private final ArtifactCoordinate coordinate;

  /** Supported VEX justification. */
  private final String justification;

  /** Human-readable summary of the archive or class-inventory proof. */
  private final String impactDetail;

  /** Mapped symbols proven absent; empty for precondition evidence. */
  private final Set<String> evidenceSymbols;

  /** Verified original archive digest. */
  private final String originalSha256;

  /** Verified trimmed archive digest. */
  private final String trimmedSha256;

  /** Exact required group and artifact for precondition evidence. */
  private final String requiredDependency;

  /** Exact prerequisite class whose absence was inspected. */
  private final String requiredClass;

  /** Retained affected artifact path bound by precondition evidence. */
  private final Path affectedArtifactPath;

  /** Verified retained affected artifact digest. */
  private final String postElisionSha256;

  /** Fingerprint of the complete declared class inventory. */
  private final String inventorySha256;

  /** Only the model-package proof engine can construct a verified attestation. */
  VexAttestation(
      final String cveId,
      final ArtifactCoordinate coordinate,
      final String justification,
      final String impactDetail,
      final Set<String> evidenceSymbols,
      final String originalSha256,
      final String trimmedSha256) {
    this(
        cveId,
        coordinate,
        justification,
        impactDetail,
        evidenceSymbols,
        originalSha256,
        trimmedSha256,
        null,
        null,
        null,
        null,
        null);
  }

  private VexAttestation(
      final String cveId,
      final ArtifactCoordinate coordinate,
      final String justification,
      final String impactDetail,
      final Set<String> evidenceSymbols,
      final String originalSha256,
      final String trimmedSha256,
      final String requiredDependency,
      final String requiredClass,
      final Path affectedArtifactPath,
      final String postElisionSha256,
      final String inventorySha256) {
    this.cveId = Objects.requireNonNull(cveId, "cveId");
    this.coordinate = Objects.requireNonNull(coordinate, "coordinate");
    if (!OMITTED_CODE_JUSTIFICATION.equals(justification)
        && !PRECONDITION_JUSTIFICATION.equals(justification)) {
      throw new IllegalArgumentException("Unsupported VEX justification");
    }
    this.justification = justification;
    if (impactDetail == null || impactDetail.isBlank()) {
      throw new IllegalArgumentException("impactDetail must not be blank");
    }
    this.impactDetail = impactDetail;
    Objects.requireNonNull(evidenceSymbols, "evidenceSymbols");
    this.evidenceSymbols = Collections.unmodifiableSet(new TreeSet<>(evidenceSymbols));
    Path boundArtifactPath = null;
    if (OMITTED_CODE_JUSTIFICATION.equals(justification)) {
      validateOmittedCodeEvidence(
          evidenceSymbols,
          originalSha256,
          trimmedSha256,
          requiredDependency,
          requiredClass,
          affectedArtifactPath,
          postElisionSha256,
          inventorySha256);
    } else {
      boundArtifactPath =
          validatePreconditionEvidence(
              evidenceSymbols,
              originalSha256,
              trimmedSha256,
              requiredDependency,
              requiredClass,
              affectedArtifactPath,
              postElisionSha256,
              inventorySha256);
    }
    this.originalSha256 = originalSha256;
    this.trimmedSha256 = trimmedSha256;
    this.requiredDependency = requiredDependency;
    this.requiredClass = requiredClass;
    this.affectedArtifactPath = boundArtifactPath;
    this.postElisionSha256 = postElisionSha256;
    this.inventorySha256 = inventorySha256;
  }

  /** Creates precondition evidence after the inventory proof succeeds. */
  static VexAttestation precondition(
      final String cveId,
      final ArtifactCoordinate coordinate,
      final String impactDetail,
      final String requiredDependency,
      final String requiredClass,
      final Path affectedArtifactPath,
      final String postElisionSha256,
      final String inventorySha256) {
    return new VexAttestation(
        cveId,
        coordinate,
        PRECONDITION_JUSTIFICATION,
        impactDetail,
        Set.of(),
        null,
        null,
        requiredDependency,
        requiredClass,
        affectedArtifactPath,
        postElisionSha256,
        inventorySha256);
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

  /** Returns the required Maven group and artifact for precondition evidence. */
  public String requiredDependency() {
    return requiredDependency;
  }

  /** Returns the exact prerequisite class for precondition evidence. */
  public String requiredClass() {
    return requiredClass;
  }

  /** Returns the retained affected artifact path for precondition evidence. */
  public Path affectedArtifactPath() {
    return affectedArtifactPath;
  }

  /** Returns the retained affected artifact digest for precondition evidence. */
  public String postElisionSha256() {
    return postElisionSha256;
  }

  /** Returns the complete class inventory fingerprint for precondition evidence. */
  public String inventorySha256() {
    return inventorySha256;
  }

  private static void requireSha256(final String value, final String name) {
    if (value == null || !value.matches("[0-9a-f]{64}")) {
      throw new IllegalArgumentException(name + " must be a lowercase SHA-256 digest");
    }
  }

  private static void validateOmittedCodeEvidence(
      final Set<String> evidenceSymbols,
      final String originalSha256,
      final String trimmedSha256,
      final String requiredDependency,
      final String requiredClass,
      final Path affectedArtifactPath,
      final String postElisionSha256,
      final String inventorySha256) {
    if (evidenceSymbols.isEmpty()) {
      throw new IllegalArgumentException("evidenceSymbols must not be empty");
    }
    requireSha256(originalSha256, "originalSha256");
    requireSha256(trimmedSha256, "trimmedSha256");
    if (requiredDependency != null
        || requiredClass != null
        || affectedArtifactPath != null
        || postElisionSha256 != null
        || inventorySha256 != null) {
      throw new IllegalArgumentException(
          "Omitted-code evidence must not contain precondition data");
    }
  }

  private static Path validatePreconditionEvidence(
      final Set<String> evidenceSymbols,
      final String originalSha256,
      final String trimmedSha256,
      final String requiredDependency,
      final String requiredClass,
      final Path affectedArtifactPath,
      final String postElisionSha256,
      final String inventorySha256) {
    if (!evidenceSymbols.isEmpty() || originalSha256 != null || trimmedSha256 != null) {
      throw new IllegalArgumentException(
          "Precondition evidence must not contain omitted-code symbols or digests");
    }
    requireDependency(requiredDependency);
    requireClass(requiredClass);
    final Path normalizedPath =
        Objects.requireNonNull(affectedArtifactPath, "affectedArtifactPath")
            .toAbsolutePath()
            .normalize();
    requireSha256(postElisionSha256, "postElisionSha256");
    requireSha256(inventorySha256, "inventorySha256");
    return normalizedPath;
  }

  private static void requireDependency(final String value) {
    if (!VulnerabilitySymbolMapping.isValidRequiredDependency(value)) {
      throw new IllegalArgumentException("requiredDependency must be group:artifact");
    }
  }

  private static void requireClass(final String value) {
    if (!VulnerabilitySymbolMapping.isValidFullyQualifiedClassName(value)) {
      throw new IllegalArgumentException("requiredClass must be a fully qualified class name");
    }
  }
}
