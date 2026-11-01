// WHY: Keeps package/range selection separate from assessment publication and proof ownership.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.applicability.MavenVersionRangeMatcher;
import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.VulnerabilitySymbolMapping;
import java.util.Comparator;
import java.util.List;

/** Selects configured mappings by exact Maven artifact identity and version scope. */
final class MavenMappingApplicability {
  private MavenMappingApplicability() {
    throw new AssertionError("No instances");
  }

  /* default */ static List<VulnerabilitySymbolMapping> applicableMappings(
      final List<VulnerabilitySymbolMapping> configured,
      final ArtifactCoordinate candidate,
      final Comparator<VulnerabilitySymbolMapping> mappingOrder) {
    return configured.stream()
        .filter(mapping -> appliesTo(mapping, candidate))
        .sorted(mappingOrder)
        .toList();
  }

  /* default */ static VulnerabilitySymbolMapping applicableMapping(
      final VulnerabilitySymbolMapping mapping, final ArtifactCoordinate coordinate) {
    return new VulnerabilitySymbolMapping(
        mapping.cveId(),
        coordinate,
        mapping.versionRangeSpec(),
        mapping.vulnerableClasses(),
        mapping.sourceAdvisoryUrl(),
        mapping.confidenceLevel(),
        mapping.requiresDependency(),
        mapping.requiresClass());
  }

  private static boolean appliesTo(
      final VulnerabilitySymbolMapping mapping, final ArtifactCoordinate candidate) {
    return sameArtifact(mapping.affectedCoordinate(), candidate)
        && MavenVersionRangeMatcher.includes(mapping.versionRangeSpec(), candidate.version());
  }

  private static boolean sameArtifact(
      final ArtifactCoordinate left, final ArtifactCoordinate right) {
    return left.groupId().equals(right.groupId())
        && left.artifactId().equals(right.artifactId())
        && left.type().equals(right.type())
        && left.classifier().equals(right.classifier());
  }
}
