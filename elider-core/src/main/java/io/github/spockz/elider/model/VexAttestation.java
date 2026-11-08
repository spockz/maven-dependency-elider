/* WHY: Restricts VEX evidence creation to the adjacent proof engine. */

package io.github.spockz.elider.model;

import java.nio.file.Path;
import java.util.Collections;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;

/** Immutable evidence for omitted-code or prerequisite-class VEX justifications. */
// PMD DataClass is intentional: this type is an immutable verified evidence value.
@SuppressWarnings({
  "PMD.DataClass",
  "PMD.AvoidFieldNameMatchingMethodName",
  "PMD.CommentDefaultAccessModifier",
  "PMD.TooManyMethods"
})
public final class VexAttestation {
  /** Stable VEX justification for omitted vulnerable code. */
  private static final String OMITTED_CODE_JUSTIFICATION = "vulnerable_code_not_present";

  /** Number of pairs supported by the legacy singular getters. */
  private static final int SINGLE_PREREQUISITE = 1;

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

  /** Complete atomic prerequisite set checked against one inventory. */
  private final Set<PrerequisiteClaim> requiredPrerequisites;

  /** Complete operator groups retained from the selected source evidence. */
  private final Set<PrerequisiteGroup> requiredPrerequisiteGroups;

  /** Final-inventory presence state for every checked prerequisite member. */
  private final Set<PrerequisiteMemberObservation> requiredPrerequisiteObservations;

  /** Retained affected artifact path bound by precondition evidence. */
  private final Path affectedArtifactPath;

  /** Verified retained affected artifact digest. */
  private final String postElisionSha256;

  /** Fingerprint of the complete declared class inventory. */
  private final String inventorySha256;

  /** Display-only source labels. */
  private final Set<String> sourceLabels;

  /** Display-only source records. */
  private final Set<AdvisoryProvenance> sourceProvenance;

  private VexAttestation(
      final String cveId,
      final ArtifactCoordinate coordinate,
      final String justification,
      final String impactDetail,
      final Set<String> evidenceSymbols,
      final String originalSha256,
      final String trimmedSha256,
      final Set<PrerequisiteClaim> requiredPrerequisites,
      final Set<PrerequisiteGroup> requiredPrerequisiteGroups,
      final Set<PrerequisiteMemberObservation> requiredPrerequisiteObservations,
      final Path affectedArtifactPath,
      final String postElisionSha256,
      final String inventorySha256,
      final Set<String> sourceLabels,
      final Set<AdvisoryProvenance> sourceProvenance) {
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
    this.requiredPrerequisites = Collections.unmodifiableSet(new TreeSet<>(requiredPrerequisites));
    this.requiredPrerequisiteGroups =
        Collections.unmodifiableSet(new TreeSet<>(requiredPrerequisiteGroups));
    this.requiredPrerequisiteObservations =
        Collections.unmodifiableSet(new TreeSet<>(requiredPrerequisiteObservations));
    Path boundArtifactPath = null;
    if (OMITTED_CODE_JUSTIFICATION.equals(justification)) {
      PrerequisiteEvidenceValidator.validateOmittedCode(
          evidenceSymbols,
          originalSha256,
          trimmedSha256,
          this.requiredPrerequisites,
          this.requiredPrerequisiteGroups,
          this.requiredPrerequisiteObservations,
          affectedArtifactPath,
          postElisionSha256,
          inventorySha256);
    } else {
      boundArtifactPath =
          PrerequisiteEvidenceValidator.validatePrecondition(
              evidenceSymbols,
              originalSha256,
              trimmedSha256,
              this.requiredPrerequisites,
              this.requiredPrerequisiteGroups,
              this.requiredPrerequisiteObservations,
              affectedArtifactPath,
              postElisionSha256,
              inventorySha256);
    }
    this.originalSha256 = originalSha256;
    this.trimmedSha256 = trimmedSha256;
    this.affectedArtifactPath = boundArtifactPath;
    this.postElisionSha256 = postElisionSha256;
    this.inventorySha256 = inventorySha256;
    this.sourceLabels = Collections.unmodifiableSet(new TreeSet<>(sourceLabels));
    this.sourceProvenance = Set.copyOf(sourceProvenance);
  }

  /** Creates verified omission evidence with source metadata. */
  static VexAttestation genericOmittedCode(
      final GenericVulnerabilityFinding finding,
      final ArtifactCoordinate coordinate,
      final String detail,
      final Set<String> symbols,
      final String original,
      final String trimmed) {
    return new VexAttestation(
        finding.vulnerabilityId(),
        coordinate,
        OMITTED_CODE_JUSTIFICATION,
        detail,
        symbols,
        original,
        trimmed,
        Set.of(),
        Set.of(),
        Set.of(),
        null,
        null,
        null,
        finding.provenance(),
        sources(finding));
  }

  /** Creates verified prerequisite evidence with source metadata. */
  static VexAttestation genericPrecondition(
      final GenericVulnerabilityFinding finding,
      final ArtifactCoordinate coordinate,
      final String detail,
      final Set<PrerequisiteGroup> groups,
      final Set<PrerequisiteMemberObservation> observations,
      final Path path,
      final String digest,
      final String inventoryDigest) {
    final Set<PrerequisiteClaim> pairs =
        groups.stream()
            .flatMap(group -> group.members().stream())
            .collect(java.util.stream.Collectors.toUnmodifiableSet());
    return new VexAttestation(
        finding.vulnerabilityId(),
        coordinate,
        PRECONDITION_JUSTIFICATION,
        detail,
        Set.of(),
        null,
        null,
        pairs,
        groups,
        observations,
        path,
        digest,
        inventoryDigest,
        finding.provenance(),
        sources(finding));
  }

  private static Set<AdvisoryProvenance> sources(final GenericVulnerabilityFinding finding) {
    return finding.contributions().stream()
        .flatMap(value -> value.sourceProvenance().stream())
        .collect(java.util.stream.Collectors.toUnmodifiableSet());
  }

  /** Returns source labels retained for display only. */
  public Set<String> sourceLabels() {
    return sourceLabels;
  }

  /** Returns display-only source records. */
  public Set<AdvisoryProvenance> sourceProvenance() {
    return sourceProvenance;
  }

  /** Combines display metadata without changing this verified evidence. */
  public VexAttestation withSourceMetadataFrom(final VexAttestation other) {
    Objects.requireNonNull(other, "other");
    final Set<String> labels = new TreeSet<>(sourceLabels);
    labels.addAll(other.sourceLabels);
    final Set<AdvisoryProvenance> sources = new java.util.HashSet<>(sourceProvenance);
    sources.addAll(other.sourceProvenance);
    return new VexAttestation(
        cveId,
        coordinate,
        justification,
        impactDetail,
        evidenceSymbols,
        originalSha256,
        trimmedSha256,
        requiredPrerequisites,
        requiredPrerequisiteGroups,
        requiredPrerequisiteObservations,
        affectedArtifactPath,
        postElisionSha256,
        inventorySha256,
        labels,
        sources);
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
    return singlePrerequisite().map(PrerequisiteClaim::requiresDependency).orElse(null);
  }

  /** Returns the exact prerequisite class for precondition evidence. */
  public String requiredClass() {
    return singlePrerequisite().map(PrerequisiteClaim::requiresClass).orElse(null);
  }

  /** Returns checked members; their operators determine the proof state. */
  public Set<PrerequisiteClaim> requiredPrerequisites() {
    return requiredPrerequisites;
  }

  /** Returns the operator groups evaluated by prerequisite proof. */
  public Set<PrerequisiteGroup> requiredPrerequisiteGroups() {
    return requiredPrerequisiteGroups;
  }

  /** Returns final-inventory presence for every checked prerequisite member. */
  public Set<PrerequisiteMemberObservation> requiredPrerequisiteObservations() {
    return requiredPrerequisiteObservations;
  }

  private java.util.Optional<PrerequisiteClaim> singlePrerequisite() {
    if (requiredPrerequisites.size() > SINGLE_PREREQUISITE) {
      throw new IllegalStateException(
          "Plural prerequisite evidence requires requiredPrerequisites");
    }
    return requiredPrerequisites.stream().findFirst();
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
}
