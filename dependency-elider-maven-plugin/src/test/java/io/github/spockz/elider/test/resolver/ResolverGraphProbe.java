/*
 * WHY: Proves whether dependency:tree receives resolver graph edits.
 */

package io.github.spockz.elider.test.resolver;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;
import org.apache.maven.project.DependencyResolutionException;
import org.apache.maven.project.DependencyResolutionRequest;
import org.apache.maven.project.DependencyResolutionResult;
import org.apache.maven.project.ProjectDependenciesResolver;
import org.eclipse.aether.artifact.Artifact;
import org.eclipse.aether.graph.Dependency;
import org.eclipse.aether.graph.DependencyFilter;
import org.eclipse.aether.graph.DependencyNode;
import org.eclipse.sisu.Priority;

/** Test resolver that edits one synthetic leaf. */
@SuppressWarnings({
  "PMD.AtLeastOneConstructor",
  "PMD.CommentRequired",
  "PMD.CompareObjectsWithEquals",
  "PMD.LawOfDemeter",
  "PMD.SystemPrintln"
})
@Named("default")
@Priority(10)
@Singleton
public final class ResolverGraphProbe implements ProjectDependenciesResolver {
  private static final String DROP_GROUP = "io.github.spockz.elider.test";

  private static final String DROP_ARTIFACT = "drop-library";

  private static final String DROP_VERSION = "1.0.0";

  private static final int EXPECTED_DROP_COUNT = 1;

  private static final String ACTIVE_MODE_PROPERTY = "resolver.probe.mode";

  private static final AtomicInteger CALL_SEQUENCE = new AtomicInteger();

  @Inject
  @Named("resolver-probe-delegate")
  private ProjectDependenciesResolver delegate;

  @Override
  public DependencyResolutionResult resolve(final DependencyResolutionRequest request)
      throws DependencyResolutionException {
    if (delegate == null || delegate == this) {
      throw new IllegalStateException("Resolver probe has no distinct concrete delegate");
    }
    final DependencyResolutionResult result = delegate.resolve(request);
    final DependencyNode graph = result.getDependencyGraph();
    final List<DependencyNode> inputChildren = children(graph);
    final List<String> graphInput = nodeInventory(inputChildren);
    final List<String> dependenciesInput = dependencyInventory(result.getDependencies());
    final List<String> filterInput =
        filterInventory(request.getResolutionFilter(), graph, inputChildren);
    final boolean transform = "active".equals(System.getProperty(ACTIVE_MODE_PROPERTY));
    if (transform) {
      transformDirectLeaf(graph, inputChildren);
    }
    final List<String> graphOutput = nodeInventory(children(graph));
    final List<String> dependenciesOutput = dependencyInventory(result.getDependencies());
    final int call = CALL_SEQUENCE.incrementAndGet();
    System.out.println(
        "RESOLVER_PROBE call="
            + call
            + " requestToken="
            + ResolverRequestTokens.tokenFor(request)
            + " project="
            + request.getMavenProject().getArtifact().getArtifactId()
            + " mode="
            + (transform ? "active" : "baseline")
            + " filter="
            + filterInput
            + " delegate="
            + delegate.getClass().getName()
            + " delegateDistinct="
            + (delegate != this)
            + " graphIn="
            + graphInput
            + " graphOut="
            + graphOutput
            + " dependenciesIn="
            + dependenciesInput
            + " dependenciesOut="
            + dependenciesOutput);
    return result;
  }

  private static List<DependencyNode> children(final DependencyNode graph) {
    return graph == null || graph.getChildren() == null ? List.of() : graph.getChildren();
  }

  private static List<String> nodeInventory(final List<DependencyNode> nodes) {
    return nodes.stream().map(node -> coordinate(node.getArtifact())).toList();
  }

  private static List<String> dependencyInventory(final List<Dependency> dependencies) {
    return dependencies.stream().map(dependency -> coordinate(dependency.getArtifact())).toList();
  }

  private static List<String> filterInventory(
      final DependencyFilter filter,
      final DependencyNode graph,
      final List<DependencyNode> inputChildren) {
    if (filter == null) {
      return List.of("none");
    }
    final List<DependencyNode> parents = graph == null ? List.of() : List.of(graph);
    return inputChildren.stream()
        .map(node -> coordinate(node.getArtifact()) + "=" + filter.accept(node, parents))
        .toList();
  }

  private static void transformDirectLeaf(
      final DependencyNode graph, final List<DependencyNode> inputChildren) {
    if (graph == null) {
      throw new IllegalStateException("Resolver returned no dependency graph");
    }
    final List<DependencyNode> retained = new ArrayList<>();
    int dropped = 0;
    for (final DependencyNode node : inputChildren) {
      if (isDropArtifact(node.getArtifact())) {
        verifyLeaf(node);
        dropped++;
        continue;
      }
      retained.add(node);
    }
    if (dropped != EXPECTED_DROP_COUNT) {
      throw new IllegalStateException(
          "Expected exactly one direct synthetic drop leaf, found " + dropped);
    }
    graph.setChildren(retained);
  }

  private static void verifyLeaf(final DependencyNode node) {
    if (!children(node).isEmpty()) {
      throw new IllegalStateException("Probe refuses to remove a graph node with descendants");
    }
  }

  private static boolean isDropArtifact(final Artifact artifact) {
    return DROP_GROUP.equals(artifact.getGroupId())
        && DROP_ARTIFACT.equals(artifact.getArtifactId())
        && DROP_VERSION.equals(artifact.getVersion());
  }

  private static String coordinate(final Artifact artifact) {
    return artifact.getGroupId()
        + ":"
        + artifact.getArtifactId()
        + ":"
        + artifact.getExtension()
        + ":"
        + artifact.getVersion();
  }
}
