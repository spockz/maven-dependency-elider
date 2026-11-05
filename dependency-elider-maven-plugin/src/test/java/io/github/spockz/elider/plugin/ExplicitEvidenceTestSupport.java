// WHY: Creates generic prerequisite findings for plugin proof and assessment tests.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.AssessmentIntent;
import io.github.spockz.elider.model.FieldValue;
import io.github.spockz.elider.model.GenericVulnerabilityFinding;
import io.github.spockz.elider.model.MergePriority;
import io.github.spockz.elider.model.PrerequisiteClaim;
import io.github.spockz.elider.model.VersionCoverageClaim;
import io.github.spockz.elider.model.VulnerabilityFindingContribution;
import io.github.spockz.elider.model.VulnerabilitySymbolMapping;
import java.util.List;
import java.util.Set;

/** Test-only construction helper for generic prerequisite findings. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class ExplicitEvidenceTestSupport {
  private ExplicitEvidenceTestSupport() {}

  static GenericVulnerabilityFinding genericPrerequisiteFinding(
      final VulnerabilitySymbolMapping mapping) {
    return GenericVulnerabilityFinding.merge(
        List.of(
            new VulnerabilityFindingContribution(
                mapping.cveId(),
                Set.of(),
                mapping.affectedCoordinate().groupId(),
                mapping.affectedCoordinate().artifactId(),
                mapping.affectedCoordinate().type(),
                mapping.affectedCoordinate().classifier(),
                List.of(VersionCoverageClaim.affected(mapping.versionRangeSpec())),
                FieldValue.omitted(),
                FieldValue.supplied(
                    Set.of(
                        new PrerequisiteClaim(
                            mapping.requiresDependency(), mapping.requiresClass()))),
                MergePriority.AUTOMATIC,
                AssessmentIntent.AUTO_VERIFY,
                "plugin-test",
                Set.of())));
  }
}
