// WHY: Validates completeness and graph identity for an isolated Maven resolution.

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.util.List;
import org.apache.maven.project.DependencyResolutionResult;
import org.eclipse.aether.graph.DependencyNode;

/** Holds graph and dependency entries proven by one complete resolution. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class MavenOriginalInputResolution {
  private MavenOriginalInputResolution() {}

  static Validated validate(
      final String projectKey,
      final DependencyResolutionResult result,
      final ResolverArtifactGraphCapturePair graphPair)
      throws IOException {
    validateCollections(result);
    validateResolutionErrors(result, result.getResolvedDependencies());
    final DependencyNode graph = validateGraph(projectKey, result, graphPair);
    return new Validated(graph, result.getResolvedDependencies(), graphPair);
  }

  private static void validateCollections(final DependencyResolutionResult result)
      throws IOException {
    final List<Exception> collectionErrors = result.getCollectionErrors();
    final List<org.eclipse.aether.graph.Dependency> unresolved = result.getUnresolvedDependencies();
    final List<org.eclipse.aether.graph.Dependency> resolved = result.getResolvedDependencies();
    if (collectionErrors == null || unresolved == null || resolved == null) {
      throw new IOException("Original-input resolver returned incomplete result state");
    }
    if (!collectionErrors.isEmpty() || !unresolved.isEmpty()) {
      throw new IOException("Original-input resolver returned a partial dependency result");
    }
  }

  private static void validateResolutionErrors(
      final DependencyResolutionResult result,
      final List<org.eclipse.aether.graph.Dependency> dependencies)
      throws IOException {
    for (final org.eclipse.aether.graph.Dependency dependency : dependencies) {
      if (dependency == null) {
        throw new IOException("Original-input resolver returned a null dependency");
      }
      final List<Exception> errors = result.getResolutionErrors(dependency);
      if (errors == null || !errors.isEmpty()) {
        throw new IOException("Original-input resolver returned a partial dependency result");
      }
    }
  }

  private static DependencyNode validateGraph(
      final String projectKey,
      final DependencyResolutionResult result,
      final ResolverArtifactGraphCapturePair graphPair)
      throws IOException {
    final DependencyNode graph = result.getDependencyGraph();
    if (graph == null) {
      throw new IOException("Original-input resolver returned no dependency graph");
    }
    if (graphPair == null) {
      throw new IOException("Original-input resolver did not invoke the audit graph transformer");
    }
    final ResolverArtifactGraphSnapshot resultGraph =
        ResolverArtifactGraphSnapshot.capture(graph, projectKey, false, null, 0L, 0L);
    if (!graphPair.after().graphFingerprint().equals(resultGraph.graphFingerprint())) {
      throw new IOException(
          "Original-input resolver result does not match the captured audit graph");
    }
    return graph;
  }

  record Validated(
      DependencyNode graph,
      List<org.eclipse.aether.graph.Dependency> dependencies,
      ResolverArtifactGraphCapturePair graphPair) {}
}
