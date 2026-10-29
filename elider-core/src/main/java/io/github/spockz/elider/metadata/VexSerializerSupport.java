// WHY: Keeps both VEX serializers aligned on proof validation and evidence precedence.

package io.github.spockz.elider.metadata;

import io.github.spockz.elider.model.ArtifactFileRef;
import io.github.spockz.elider.model.VexAttestation;
import java.io.IOException;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

/** Shared validation for proof-backed VEX statements emitted by either format. */
@SuppressWarnings({
  "PMD.CommentDefaultAccessModifier",
  "PMD.CommentRequired",
  "PMD.UseConcurrentHashMap"
})
final class VexSerializerSupport {
  private static final String OMITTED_CODE = "vulnerable_code_not_present";
  private static final String PRECONDITION = "requires_dependency";

  private VexSerializerSupport() {}

  static boolean isPrecondition(final VexAttestation attestation) {
    return PRECONDITION.equals(attestation.justification());
  }

  static String verifyAttestation(final VexAttestation attestation, final ArtifactFileRef component)
      throws IOException {
    requireText(attestation.cveId(), "VEX vulnerability id");
    requireText(attestation.impactDetail(), "VEX impact detail");
    final String expectedSha256 = expectedSha256(attestation, component);
    final String actualSha256 = CycloneDxSbomGenerator.sha256(component.filePath());
    requireMatchingDigest(attestation, expectedSha256, actualSha256);
    return actualSha256;
  }

  static boolean sameEvidence(final VexAttestation left, final VexAttestation right) {
    return left.coordinate().equals(right.coordinate())
        && left.justification().equals(right.justification())
        && left.impactDetail().equals(right.impactDetail())
        && left.evidenceSymbols().equals(right.evidenceSymbols())
        && Objects.equals(left.originalSha256(), right.originalSha256())
        && Objects.equals(left.trimmedSha256(), right.trimmedSha256())
        && Objects.equals(left.requiredDependency(), right.requiredDependency())
        && Objects.equals(left.requiredClass(), right.requiredClass())
        && Objects.equals(left.affectedArtifactPath(), right.affectedArtifactPath())
        && Objects.equals(left.postElisionSha256(), right.postElisionSha256())
        && Objects.equals(left.inventorySha256(), right.inventorySha256());
  }

  /** Keeps proof types separate until each type's conflicts have been checked. */
  static void addAttestation(
      final Map<String, VexAttestation> omittedCode,
      final Map<String, VexAttestation> preconditions,
      final String key,
      final VexAttestation candidate) {
    final Map<String, VexAttestation> sameType =
        isPrecondition(candidate) ? preconditions : omittedCode;
    final VexAttestation prior = sameType.putIfAbsent(key, candidate);
    if (prior != null && !sameEvidence(prior, candidate)) {
      final String evidenceType = isPrecondition(candidate) ? "precondition" : "omitted-code";
      throw new IllegalArgumentException(
          "Conflicting duplicate " + evidenceType + " VEX attestation for " + key);
    }
  }

  /** Selects omitted-code only after same-type conflicts have been checked. */
  static Map<String, VexAttestation> preferredAttestations(
      final Map<String, VexAttestation> omittedCode,
      final Map<String, VexAttestation> preconditions) {
    final Map<String, VexAttestation> selected = new TreeMap<>(preconditions);
    selected.putAll(omittedCode);
    return selected;
  }

  private static String expectedSha256(
      final VexAttestation attestation, final ArtifactFileRef component) {
    return isPrecondition(attestation)
        ? preconditionSha256(attestation, component)
        : omittedCodeSha256(attestation);
  }

  private static String preconditionSha256(
      final VexAttestation attestation, final ArtifactFileRef component) {
    requireText(attestation.requiredDependency(), "required dependency");
    requireText(attestation.requiredClass(), "required class");
    if (attestation.evidenceSymbols() == null || !attestation.evidenceSymbols().isEmpty()) {
      throw new IllegalArgumentException(
          "Precondition attestation must not contain symbol evidence");
    }
    final String expectedSha256 = attestation.postElisionSha256();
    if (!isSha256(expectedSha256)) {
      throw new IllegalArgumentException(
          "Precondition attestation must contain an exact post-elision SHA-256 digest");
    }
    if (!component
        .filePath()
        .toAbsolutePath()
        .normalize()
        .equals(attestation.affectedArtifactPath())) {
      throw new IllegalArgumentException(
          "Precondition attestation path does not match post-elision component: "
              + CycloneDxSbomGenerator.componentPurl(attestation.coordinate()));
    }
    return expectedSha256;
  }

  private static String omittedCodeSha256(final VexAttestation attestation) {
    if (!OMITTED_CODE.equals(attestation.justification())) {
      throw new IllegalArgumentException("Unsupported VEX attestation justification");
    }
    if (attestation.evidenceSymbols() == null || attestation.evidenceSymbols().isEmpty()) {
      throw new IllegalArgumentException("VEX attestation has no purged symbol evidence");
    }
    if (!isSha256(attestation.originalSha256()) || !isSha256(attestation.trimmedSha256())) {
      throw new IllegalArgumentException("VEX attestation must contain exact SHA-256 digests");
    }
    return attestation.trimmedSha256();
  }

  private static void requireMatchingDigest(
      final VexAttestation attestation, final String expectedSha256, final String actualSha256) {
    if (!actualSha256.equals(expectedSha256)) {
      final String evidenceKind = isPrecondition(attestation) ? "precondition" : "trimmed";
      throw new IllegalArgumentException(
          "VEX attestation "
              + evidenceKind
              + " digest does not match post-elision component: "
              + CycloneDxSbomGenerator.componentPurl(attestation.coordinate()));
    }
  }

  private static boolean isSha256(final String value) {
    return value != null && value.matches("[0-9a-f]{64}");
  }

  private static void requireText(final String value, final String name) {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException(name + " must not be blank");
    }
  }
}
