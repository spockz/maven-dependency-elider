// WHY: Preserves explicit policy intent independently of merged advisory claims and proof
// authority.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.advisory.ForbiddenSymbol;
import io.github.spockz.elider.model.AdvisoryProvenance;
import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.VersionCoverageClaim;
import io.github.spockz.elider.plugin.ForbiddenCodeAssessment.ComponentKind;
import java.util.List;

@SuppressWarnings("PMD.CommentDefaultAccessModifier")
record ForbiddenCodeRule(
    String cveId,
    ComponentKind componentKind,
    MavenIdentity mavenIdentity,
    VersionCoverageClaim version,
    ForbiddenSymbol symbol,
    AdvisoryProvenance provenance) {
  record MavenIdentity(String groupId, String artifactId, String type, String classifier) {
    static MavenIdentity of(final ArtifactCoordinate coordinate) {
      return new MavenIdentity(
          coordinate.groupId(),
          coordinate.artifactId(),
          coordinate.type(),
          coordinate.classifier());
    }

    String display() {
      final String unclassified = groupId + ":" + artifactId + ":" + type;
      return classifier.isEmpty() ? unclassified : unclassified + ":" + classifier;
    }
  }

  record Key(
      String cveId,
      ComponentKind componentKind,
      MavenIdentity mavenIdentity,
      String version,
      String owner,
      String method,
      List<String> parameters) {}

  Key key() {
    return new Key(
        cveId,
        componentKind,
        mavenIdentity,
        version.normalizedMavenRange(),
        symbol.owner(),
        symbol.method(),
        symbol.parameters());
  }
}
