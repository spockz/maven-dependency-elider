/* WHY: Represents an exact owner-supplied prerequisite mapping for ADR-0008 proof. */

package io.github.spockz.elider.model;

import java.util.Objects;
import java.util.Set;

/** Owner-declared prerequisite dependency and class for an affected component. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
public final class ExplicitPrerequisiteEvidence {
  /** Source row retaining the explicit owner assertion. */
  private final VulnerabilitySymbolMapping sourceMapping;

  /** Effective project POM row identifier. */
  private final String originIdentifier;

  /** Whether exact candidate scope is bound. */
  private final boolean bound;

  private ExplicitPrerequisiteEvidence(
      final VulnerabilitySymbolMapping mapping, final String origin, final boolean isBound) {
    this.sourceMapping = Objects.requireNonNull(mapping, "mapping");
    this.bound = isBound;
    if (origin == null || origin.isBlank()) {
      throw new IllegalArgumentException("Configuration origin is required");
    }
    this.originIdentifier = origin;
    if (mapping.requiresDependency() == null || mapping.requiresClass() == null) {
      throw new IllegalArgumentException(
          "Explicit prerequisite evidence requires requiresDependency and requiresClass");
    }
    if (mapping.confidenceLevel() != VulnerabilitySymbolMapping.ConfidenceLevel.HIGH) {
      throw new IllegalArgumentException("Explicit prerequisite evidence requires HIGH confidence");
    }
  }

  /** Creates an owner assertion from configured fields. */
  public static ExplicitPrerequisiteEvidence declare(
      final String cveId,
      final ArtifactCoordinate coordinate,
      final String versionRange,
      final String requiresDependency,
      final String requiresClass,
      final java.net.URI advisoryUrl,
      final VulnerabilitySymbolMapping.ConfidenceLevel confidence,
      final String origin) {
    return new ExplicitPrerequisiteEvidence(
        new VulnerabilitySymbolMapping(
            cveId,
            coordinate,
            versionRange,
            Set.of(),
            advisoryUrl,
            confidence,
            requiresDependency,
            requiresClass),
        origin,
        false);
  }

  /** Binds after exact component and version-scope matching. */
  public ExplicitPrerequisiteEvidence bindTo(
      final ArtifactCoordinate candidate, final VersionScopeMatcher matcher) {
    Objects.requireNonNull(candidate, "candidate");
    Objects.requireNonNull(matcher, "matcher");
    if (!sameComponent(sourceMapping.affectedCoordinate(), candidate)
        || !hasExactVersion(candidate)) {
      throw new IllegalArgumentException("Owner assertion does not match an exact candidate");
    }
    if (!matcher.includes(sourceMapping.versionRangeSpec(), candidate.version())) {
      throw new IllegalArgumentException("Owner assertion version scope does not match candidate");
    }
    return new ExplicitPrerequisiteEvidence(
        new VulnerabilitySymbolMapping(
            sourceMapping.cveId(),
            candidate,
            sourceMapping.versionRangeSpec(),
            Set.of(),
            sourceMapping.sourceAdvisoryUrl(),
            sourceMapping.confidenceLevel(),
            sourceMapping.requiresDependency(),
            sourceMapping.requiresClass()),
        originIdentifier,
        true);
  }

  VulnerabilitySymbolMapping mapping() {
    if (!bound) {
      throw new IllegalArgumentException(
          "Prerequisite evidence must be bound to a matched candidate");
    }
    return sourceMapping;
  }

  /** Checks whether reconciliation selected this configured row. */
  public boolean matches(final VulnerabilitySymbolMapping mapping) {
    return mapping != null
        && sourceMapping.cveId().equals(mapping.cveId())
        && sourceMapping.affectedCoordinate().equals(mapping.affectedCoordinate())
        && sourceMapping.versionRangeSpec().equals(mapping.versionRangeSpec())
        && Objects.equals(sourceMapping.requiresDependency(), mapping.requiresDependency())
        && Objects.equals(sourceMapping.requiresClass(), mapping.requiresClass())
        && Objects.equals(sourceMapping.sourceAdvisoryUrl(), mapping.sourceAdvisoryUrl())
        && sourceMapping.confidenceLevel() == mapping.confidenceLevel();
  }

  /** Returns the fixed provenance carried by this evidence variant. */
  public EvidenceOrigin origin() {
    return EvidenceOrigin.POM;
  }

  /** Identifies the effective configured POM row. */
  public String configurationOrigin() {
    return originIdentifier;
  }

  /** Returns the CVE identifier asserted by the project owner. */
  public String cveId() {
    return sourceMapping.cveId();
  }

  private static boolean sameComponent(
      final ArtifactCoordinate configured, final ArtifactCoordinate candidate) {
    return configured.groupId().equals(candidate.groupId())
        && configured.artifactId().equals(candidate.artifactId())
        && configured.type().equals(candidate.type())
        && configured.classifier().equals(candidate.classifier());
  }

  private static boolean hasExactVersion(final ArtifactCoordinate candidate) {
    return candidate.version() != null && !candidate.version().isBlank();
  }
}
