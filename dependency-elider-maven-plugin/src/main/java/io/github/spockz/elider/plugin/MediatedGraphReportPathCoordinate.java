/* WHY: Converts detached artifact payloads to report coordinates without leaking Aether objects. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import java.util.Map;

/** Reads a display coordinate from one frozen graph node. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier") // Package-internal coordinate extraction API.
final class MediatedGraphReportPathCoordinate {
  private MediatedGraphReportPathCoordinate() {
    throw new AssertionError("No instances");
  }

  static String display(final Map<String, Object> node, final String projectGav) {
    final ArtifactCoordinate coordinate = coordinate(node);
    return coordinate == null ? projectGav : coordinate.toString();
  }

  static ArtifactCoordinate coordinate(final Map<String, Object> node) {
    final Object rawArtifact = node.get(ResolverArtifactGraphSnapshotSchema.ARTIFACT);
    if (!(rawArtifact instanceof Map<?, ?> artifact)) {
      return null;
    }
    final String groupId = stringValue(artifact.get(ResolverArtifactGraphSnapshotSchema.GROUP_ID));
    final String artifactId =
        stringValue(artifact.get(ResolverArtifactGraphSnapshotSchema.ARTIFACT_ID));
    final String version = stringValue(artifact.get(ResolverArtifactGraphSnapshotSchema.VERSION));
    final String extension =
        stringValue(artifact.get(ResolverArtifactGraphSnapshotSchema.EXTENSION));
    final String scope = stringValue(node.get(ResolverArtifactGraphSnapshotSchema.EFFECTIVE_SCOPE));
    if (groupId == null
        || artifactId == null
        || version == null
        || extension == null
        || scope == null) {
      return null;
    }
    final String classifier =
        stringValue(artifact.get(ResolverArtifactGraphSnapshotSchema.CLASSIFIER));
    return new ArtifactCoordinate(groupId, artifactId, version, extension, classifier, scope);
  }

  private static String stringValue(final Object value) {
    return value instanceof String text ? text : null;
  }
}
