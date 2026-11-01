// WHY: Creates bound owner assertions in plugin tests without admitting generic cache mappings.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ExplicitPrerequisiteEvidence;
import io.github.spockz.elider.model.VulnerabilitySymbolMapping;

/** Test-only construction helper for explicit POM prerequisite assertions. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class ExplicitEvidenceTestSupport {
  private ExplicitEvidenceTestSupport() {}

  static ExplicitPrerequisiteEvidence prerequisiteEvidence(
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
        .bindTo(mapping.affectedCoordinate(), MavenVersionRangeMatcher::includes);
  }
}
