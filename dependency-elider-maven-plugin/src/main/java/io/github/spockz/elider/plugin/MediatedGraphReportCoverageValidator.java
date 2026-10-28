/* WHY: Prevents reports from publishing outputs without an occurrence-specific graph path. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Validates that every effective output has a persisted dependency path. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier") // Package-internal coverage validation.
final class MediatedGraphReportCoverageValidator {
  /** Path kinds that correspond to output records. */
  private static final String DROPPED_KIND = "WHOLE_ARTIFACT_DROPPED";

  /** Class trimming also requires a persisted graph occurrence path. */
  private static final String TRIMMED_KIND = "CLASS_TRIMMED";

  /** A path row is tied to one exact output kind and graph occurrence. */
  private record PathKey(String kind, String nodeId, String coordinate) {}

  private MediatedGraphReportCoverageValidator() {
    throw new AssertionError("No instances");
  }

  static void validate(
      final List<MediatedGraphReport.ArtifactPath> paths,
      final Set<ArtifactCoordinate> drops,
      final List<ArtifactTrimRecord> trims)
      throws IOException {
    final Set<EffectiveGraphDecisionIndex.DecisionKey> coveredDrops = new HashSet<>();
    final Set<EffectiveGraphDecisionIndex.DecisionKey> coveredTrims = new HashSet<>();
    paths.forEach(path -> addCoverage(path, coveredDrops, coveredTrims));
    if (!coveredDrops.containsAll(decisionKeys(drops))
        || !coveredTrims.containsAll(trimKeys(trims))) {
      throw new IOException("Bound graph has no dependency path for every effective output");
    }
  }

  static void validateSnapshotOutputs(
      final MediatedGraphReport graph,
      final List<MavenElisionReportSnapshot.DroppedArtifact> drops,
      final List<MavenElisionReportSnapshot.TrimmedArtifact> trims,
      final String projectGav) {
    if (!graph.available()) {
      if (!drops.isEmpty()) {
        throw new IllegalArgumentException(
            "Unavailable mediated graph cannot substantiate effective whole-artifact drops");
      }
      return;
    }
    MediatedGraphReportPathValidator.validate(
        graph.snapshot(), graph.nodeStatuses(), graph.artifactPaths(), projectGav);
    final Set<String> droppedCoordinates =
        drops.stream()
            .map(MavenElisionReportSnapshot.DroppedArtifact::coordinate)
            .collect(java.util.stream.Collectors.toSet());
    final Set<String> trimmedCoordinates =
        trims.stream()
            .map(MavenElisionReportSnapshot.TrimmedArtifact::coordinate)
            .collect(java.util.stream.Collectors.toSet());
    if (!java.util.Collections.disjoint(droppedCoordinates, trimmedCoordinates)) {
      throw new IllegalArgumentException("One artifact cannot be both dropped and class-trimmed");
    }
    final Set<PathKey> expected = expectedPaths(graph, droppedCoordinates, trimmedCoordinates);
    final Set<PathKey> actual = actualPaths(graph.artifactPaths());
    if (actual.size() != graph.artifactPaths().size() || !actual.equals(expected)) {
      throw new IllegalArgumentException(
          "Persisted graph paths do not exactly cover dropped and trimmed outputs");
    }
  }

  @SuppressWarnings("PMD.UseConcurrentHashMap") // This index is local to one validation call.
  private static Set<PathKey> expectedPaths(
      final MediatedGraphReport graph,
      final Set<String> droppedCoordinates,
      final Set<String> trimmedCoordinates) {
    final Map<String, String> dispositions = new HashMap<>();
    graph.nodeStatuses().forEach(status -> dispositions.put(status.nodeId(), status.disposition()));
    final Set<PathKey> expected = new HashSet<>();
    for (final Map<String, Object> node : graph.snapshot().nodes()) {
      final String nodeId = (String) node.get(ResolverArtifactGraphSnapshotSchema.NODE_ID);
      final String disposition = dispositions.get(nodeId);
      final PathKey outputPath =
          expectedPath(node, nodeId, disposition, droppedCoordinates, trimmedCoordinates);
      if (outputPath != null) {
        expected.add(outputPath);
      }
    }
    final Set<String> coveredDrops = new HashSet<>();
    final Set<String> coveredTrims = new HashSet<>();
    expected.forEach(
        path -> {
          if (DROPPED_KIND.equals(path.kind())) {
            coveredDrops.add(path.coordinate());
          } else {
            coveredTrims.add(path.coordinate());
          }
        });
    if (!coveredDrops.equals(droppedCoordinates) || !coveredTrims.equals(trimmedCoordinates)) {
      throw new IllegalArgumentException(
          "Persisted graph has no policy-compatible path for every output coordinate");
    }
    return expected;
  }

  private static PathKey expectedPath(
      final Map<String, Object> node,
      final String nodeId,
      final String disposition,
      final Set<String> droppedCoordinates,
      final Set<String> trimmedCoordinates) {
    if (!Boolean.TRUE.equals(node.get(ResolverArtifactGraphSnapshotSchema.REACHABLE))) {
      return null;
    }
    final ArtifactCoordinate coordinate = MediatedGraphReportPathCoordinate.coordinate(node);
    final PathKey droppedPath =
        expectedDroppedPath(nodeId, disposition, coordinate, droppedCoordinates);
    if (droppedPath != null) {
      return droppedPath;
    }
    return expectedTrimmedPath(nodeId, disposition, coordinate, trimmedCoordinates);
  }

  private static PathKey expectedDroppedPath(
      final String nodeId,
      final String disposition,
      final ArtifactCoordinate coordinate,
      final Set<String> droppedCoordinates) {
    if (!isSafeDrop(disposition)) {
      return null;
    }
    if (coordinate == null) {
      throw new IllegalArgumentException("SAFE_ELIDED node has no dependency coordinate");
    }
    final String text = coordinate.toString();
    if (!droppedCoordinates.contains(text)) {
      throw new IllegalArgumentException(
          "Persisted SAFE_ELIDED graph occurrence is missing from effective drop outputs");
    }
    return new PathKey(DROPPED_KIND, nodeId, text);
  }

  private static PathKey expectedTrimmedPath(
      final String nodeId,
      final String disposition,
      final ArtifactCoordinate coordinate,
      final Set<String> trimmedCoordinates) {
    if (coordinate != null
        && trimmedCoordinates.contains(coordinate.toString())
        && isOutputRetained(disposition)) {
      return new PathKey(TRIMMED_KIND, nodeId, coordinate.toString());
    }
    return null;
  }

  private static boolean isSafeDrop(final String disposition) {
    return "SAFE_ELIDED".equals(disposition);
  }

  private static boolean isOutputRetained(final String disposition) {
    return !"METADATA_ONLY".equals(disposition);
  }

  private static Set<PathKey> actualPaths(final List<MediatedGraphReport.ArtifactPath> paths) {
    final Set<PathKey> actual = new HashSet<>();
    paths.forEach(
        path -> actual.add(new PathKey(path.kind(), path.nodeId(), path.coordinate().toString())));
    return actual;
  }

  private static void addCoverage(
      final MediatedGraphReport.ArtifactPath path,
      final Set<EffectiveGraphDecisionIndex.DecisionKey> coveredDrops,
      final Set<EffectiveGraphDecisionIndex.DecisionKey> coveredTrims) {
    final EffectiveGraphDecisionIndex.DecisionKey key =
        EffectiveGraphDecisionIndex.DecisionKey.of(path.coordinate());
    if (DROPPED_KIND.equals(path.kind())) {
      coveredDrops.add(key);
    } else if (TRIMMED_KIND.equals(path.kind())) {
      coveredTrims.add(key);
    }
  }

  private static Set<EffectiveGraphDecisionIndex.DecisionKey> decisionKeys(
      final Set<ArtifactCoordinate> coordinates) {
    final Set<EffectiveGraphDecisionIndex.DecisionKey> result = new HashSet<>();
    coordinates.stream().map(EffectiveGraphDecisionIndex.DecisionKey::of).forEach(result::add);
    return result;
  }

  private static Set<EffectiveGraphDecisionIndex.DecisionKey> trimKeys(
      final List<ArtifactTrimRecord> records) {
    final Set<EffectiveGraphDecisionIndex.DecisionKey> result = new HashSet<>();
    records.stream()
        .map(ArtifactTrimRecord::coordinate)
        .map(EffectiveGraphDecisionIndex.DecisionKey::of)
        .forEach(result::add);
    return result;
  }
}
