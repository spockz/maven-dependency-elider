// WHY: Builds bound owner assertions for proof tests without exposing generic production
// conversion.

package io.github.spockz.elider.model;

/** Test-only helpers for owner-declared proof evidence. */
public final class ExplicitEvidenceTestSupport {
  private ExplicitEvidenceTestSupport() {}

  /** Makes test class evidence. */
  public static ExplicitClassMappingEvidence classEvidence(
      final VulnerabilitySymbolMapping mapping) {
    return ExplicitClassMappingEvidence.declare(
            mapping.cveId(),
            mapping.affectedCoordinate(),
            mapping.versionRangeSpec(),
            mapping.vulnerableClasses(),
            mapping.sourceAdvisoryUrl(),
            mapping.confidenceLevel(),
            "test-project-pom")
        .bindTo(mapping.affectedCoordinate(), (range, version) -> true);
  }

  /** Makes test prerequisite evidence. */
  public static ExplicitPrerequisiteEvidence prerequisiteEvidence(
      final VulnerabilitySymbolMapping mapping) {
    return ExplicitPrerequisiteEvidence.declare(
            mapping.cveId(),
            mapping.affectedCoordinate(),
            mapping.versionRangeSpec(),
            mapping.requiresDependency(),
            mapping.requiresClass(),
            mapping.sourceAdvisoryUrl(),
            mapping.confidenceLevel(),
            "test-project-pom")
        .bindTo(mapping.affectedCoordinate(), (range, version) -> true);
  }
}
