/* WHY: Represents a project owner's explicit class mapping as proof-specific evidence. */

package io.github.spockz.elider.model;

import java.util.Objects;
import java.util.Set;

/** Owner-declared classes relevant to an advisory. */
@SuppressWarnings({"PMD.CommentDefaultAccessModifier", "PMD.TooManyMethods"})
public final class ExplicitClassMappingEvidence implements AdvisoryEvidence {
  /** Source row retaining the explicit owner assertion. */
  private final VulnerabilitySymbolMapping sourceMapping;

  /** Effective project POM row identifier. */
  private final String originIdentifier;

  /** Whether exact candidate scope is bound. */
  private final boolean bound;

  private ExplicitClassMappingEvidence(
      final VulnerabilitySymbolMapping mapping, final String origin, final boolean isBound) {
    this.sourceMapping = Objects.requireNonNull(mapping, "mapping");
    this.originIdentifier = requireOrigin(origin);
    this.bound = isBound;
    if (mapping.vulnerableClasses().isEmpty()) {
      throw new IllegalArgumentException("Explicit class evidence requires vulnerableClasses");
    }
    if (mapping.confidenceLevel() != VulnerabilitySymbolMapping.ConfidenceLevel.HIGH) {
      throw new IllegalArgumentException("Explicit class evidence requires HIGH confidence");
    }
  }

  /** Creates an owner assertion from configured fields. */
  public static ExplicitClassMappingEvidence declare(
      final String cveId,
      final ArtifactCoordinate coordinate,
      final String versionRange,
      final Set<String> classes,
      final java.net.URI advisoryUrl,
      final VulnerabilitySymbolMapping.ConfidenceLevel confidence,
      final String origin) {
    return new ExplicitClassMappingEvidence(
        new VulnerabilitySymbolMapping(
            cveId, coordinate, versionRange, classes, advisoryUrl, confidence),
        origin,
        false);
  }

  /** Binds after exact component and version-scope matching. */
  public ExplicitClassMappingEvidence bindTo(
      final ArtifactCoordinate candidate, final VersionScopeMatcher matcher) {
    Objects.requireNonNull(candidate, "candidate");
    Objects.requireNonNull(matcher, "matcher");
    if (!sameComponent(sourceMapping.affectedCoordinate(), candidate)
        || candidate.version() == null
        || candidate.version().isBlank()) {
      throw new IllegalArgumentException("Owner assertion does not match an exact candidate");
    }
    if (!matcher.includes(sourceMapping.versionRangeSpec(), candidate.version())) {
      throw new IllegalArgumentException("Owner assertion version scope does not match candidate");
    }
    return new ExplicitClassMappingEvidence(
        new VulnerabilitySymbolMapping(
            sourceMapping.cveId(),
            candidate,
            sourceMapping.versionRangeSpec(),
            sourceMapping.vulnerableClasses(),
            sourceMapping.sourceAdvisoryUrl(),
            sourceMapping.confidenceLevel()),
        originIdentifier,
        true);
  }

  VulnerabilitySymbolMapping mapping() {
    if (!bound) {
      throw new IllegalArgumentException("Class evidence must be bound to a matched candidate");
    }
    return sourceMapping;
  }

  /** Checks whether reconciliation selected this configured row. */
  public boolean matches(final VulnerabilitySymbolMapping mapping) {
    return mapping != null
        && sourceMapping.cveId().equals(mapping.cveId())
        && sourceMapping.affectedCoordinate().equals(mapping.affectedCoordinate())
        && sourceMapping.versionRangeSpec().equals(mapping.versionRangeSpec())
        && sourceMapping.vulnerableClasses().equals(mapping.vulnerableClasses())
        && Objects.equals(sourceMapping.sourceAdvisoryUrl(), mapping.sourceAdvisoryUrl())
        && sourceMapping.confidenceLevel() == mapping.confidenceLevel();
  }

  /** Returns the fixed provenance carried by this evidence variant. */
  public EvidenceOrigin origin() {
    return EvidenceOrigin.POM;
  }

  @Override
  public AdvisoryScope scope() {
    return new AdvisoryScope(
        sourceMapping.cveId(),
        sourceMapping.affectedCoordinate(),
        sourceMapping.versionRangeSpec());
  }

  @Override
  public AdvisoryProvenance provenance() {
    return new AdvisoryProvenance(
        EvidenceOrigin.POM, originIdentifier, sourceMapping.sourceAdvisoryUrl(), null);
  }

  @Override
  public VulnerabilitySymbolMapping.ConfidenceLevel confidenceLabel() {
    return sourceMapping.confidenceLevel();
  }

  /** Identifies the effective configured POM row. */
  public String configurationOrigin() {
    return originIdentifier;
  }

  /** Returns the CVE identifier asserted by the project owner. */
  public String cveId() {
    return sourceMapping.cveId();
  }

  private static String requireOrigin(final String origin) {
    if (origin == null || origin.isBlank()) {
      throw new IllegalArgumentException("Configuration origin is required");
    }
    return origin;
  }

  private static boolean sameComponent(
      final ArtifactCoordinate configured, final ArtifactCoordinate candidate) {
    return configured.groupId().equals(candidate.groupId())
        && configured.artifactId().equals(candidate.artifactId())
        && configured.type().equals(candidate.type())
        && configured.classifier().equals(candidate.classifier());
  }
}
