/* WHY: Keeps heuristic version leads scoped to supported OSV package coverage. */

package io.github.spockz.elider.scanner;

import io.github.spockz.elider.model.VersionApplicability;
import io.github.spockz.elider.model.VersionCoverageClaim;
import java.util.ArrayList;
import java.util.List;
import org.apache.maven.artifact.versioning.ArtifactVersion;
import org.apache.maven.artifact.versioning.InvalidVersionSpecificationException;
import org.apache.maven.artifact.versioning.Restriction;
import org.apache.maven.artifact.versioning.VersionRange;

/** Intersects a heuristic Maven range with affected package intervals. */
final class OsvHeuristicRangeIntersector {
  private OsvHeuristicRangeIntersector() {}

  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  static List<VersionCoverageClaim> intersect(
      final List<VersionCoverageClaim> coverage, final String leadRange) {
    try {
      final VersionRange lead = parseRange(leadRange);
      final List<VersionCoverageClaim> intersections = new ArrayList<>();
      for (final VersionCoverageClaim claim : coverage) {
        if (isAffectedRange(claim)) {
          intersections.addAll(intersectClaim(claim, lead));
        }
      }
      if (intersections.isEmpty() && hasUnresolvedRange(coverage)) {
        return List.of(
            VersionCoverageClaim.unresolvedAffected(
                "heuristic-scope:" + leadRange,
                "OSV package scope is unresolved for heuristic lead intersection"));
      }
      return List.copyOf(intersections);
    } catch (final InvalidVersionSpecificationException | IllegalArgumentException exception) {
      return unresolved(leadRange);
    }
  }

  private static List<VersionCoverageClaim> intersectClaim(
      final VersionCoverageClaim claim, final VersionRange lead)
      throws InvalidVersionSpecificationException {
    final VersionRange intersection = parseRange(claim.normalizedMavenRange()).restrict(lead);
    if (!intersection.hasRestrictions()) {
      final ArtifactVersion recommended = intersection.getRecommendedVersion();
      return recommended == null ? List.of() : List.of(exactVersionClaim(recommended));
    }
    return intersection.getRestrictions().stream()
        .map(restriction -> VersionCoverageClaim.affected(rangeText(restriction)))
        .toList();
  }

  private static boolean isAffectedRange(final VersionCoverageClaim claim) {
    return claim.status() == VersionApplicability.AFFECTED && claim.normalizedMavenRange() != null;
  }

  private static boolean hasUnresolvedRange(final List<VersionCoverageClaim> coverage) {
    return coverage.stream().anyMatch(claim -> claim.status() == VersionApplicability.UNRESOLVED);
  }

  private static VersionCoverageClaim exactVersionClaim(final ArtifactVersion version) {
    return VersionCoverageClaim.affected("[" + version + "]");
  }

  private static VersionRange parseRange(final String specification)
      throws InvalidVersionSpecificationException {
    if (isExactVersion(specification)) {
      final String version = specification.substring(1, specification.length() - 1);
      return VersionRange.createFromVersionSpec("[" + version + "," + version + "]");
    }
    return VersionRange.createFromVersionSpec(specification);
  }

  private static boolean isExactVersion(final String specification) {
    return specification.startsWith("[")
        && specification.endsWith("]")
        && specification.indexOf(',') < 0;
  }

  @SuppressWarnings("PMD.LawOfDemeter")
  // Maven Restriction exposes bounds directly as its public value API.
  private static String rangeText(final Restriction restriction) {
    final ArtifactVersion lowerBound = restriction.getLowerBound();
    final ArtifactVersion upperBound = restriction.getUpperBound();
    final String lower = lowerBound == null ? "" : lowerBound.toString();
    final String upper = upperBound == null ? "" : upperBound.toString();
    return (restriction.isLowerBoundInclusive() ? "[" : "(")
        + lower
        + ","
        + upper
        + (restriction.isUpperBoundInclusive() ? "]" : ")");
  }

  private static List<VersionCoverageClaim> unresolved(final String leadRange) {
    return List.of(
        VersionCoverageClaim.unresolvedAffected(
            "heuristic-scope:" + leadRange,
            "OSV heuristic scope could not be intersected with package coverage"));
  }
}
