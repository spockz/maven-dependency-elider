// WHY: Shares synthetic mediated-graph builders across effective policy tests.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ElisionDecision;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.eclipse.aether.artifact.DefaultArtifact;
import org.eclipse.aether.graph.DefaultDependencyNode;
import org.eclipse.aether.graph.Dependency;
import org.eclipse.aether.graph.DependencyNode;
import org.eclipse.aether.graph.Exclusion;

/** Shared synthetic Maven graphs for policy tests. */
public final class EffectiveGraphPolicyTestSupport {
  /** Project identity stored in all synthetic graph pairs. */
  public static final String PROJECT_KEY = "policy-project";

  /** Standard version for non-conflict fixture artifacts. */
  public static final String TEST_VERSION = "1.0";

  /** Root artifact identifier. */
  public static final String ROOT_ID = "root";

  /** Compile scope used for eligible fixture paths. */
  public static final String COMPILE_SCOPE = "compile";

  /** Extension used by fixture artifacts. */
  public static final String JAR_EXTENSION = "jar";

  /** Candidate drop artifact identifier. */
  public static final String DROP_ID = "drop";

  /** Retained artifact identifier. */
  public static final String KEEP_ID = "keep";

  /** Candidate ancestor identifier. */
  public static final String ANCESTOR_ID = "ancestor";

  /** Retained child identifier. */
  public static final String RETAINED_ID = "retained";

  /** Candidate parent identifier. */
  public static final String PARENT_ID = "parent";

  /** First diamond branch identifier. */
  public static final String LEFT_ID = "left";

  /** Second diamond branch identifier. */
  public static final String RIGHT_ID = "right";

  /** Shared diamond child identifier. */
  public static final String SHARED_ID = "shared";

  /** Unrelated unused leaf identifier. */
  public static final String UNUSED_ID = "unused";

  /** Repeated identity identifier. */
  public static final String SAME_ID = "same";

  /** Conflict family candidate identifier. */
  public static final String CANDIDATE_ID = "candidate";

  private EffectiveGraphPolicyTestSupport() {
    throw new AssertionError("No instances");
  }

  /** Runs the pure policy against one synthetic before/after capture pair. */
  public static EffectiveGraphPolicy.Evaluation evaluate(
      final DependencyNode before, final DependencyNode after, final ElisionDecision decision) {
    return EffectiveGraphPolicy.evaluate(
        List.of(pair(before, after, "capture")), PROJECT_KEY, decision);
  }

  /** Creates one plan-absent pair for the supplied graph roots. */
  public static ResolverArtifactGraphCapturePair pair(
      final DependencyNode before, final DependencyNode after, final String token) {
    final ResolverArtifactGraphSnapshot beforeSnapshot =
        ResolverArtifactGraphSnapshot.capture(before, PROJECT_KEY, false, null, 0L, 1L);
    final ResolverArtifactGraphSnapshot afterSnapshot =
        ResolverArtifactGraphSnapshot.capture(after, PROJECT_KEY, false, null, 0L, 1L);
    return new ResolverArtifactGraphCapturePair(
        PROJECT_KEY, token, 1L, false, null, 0L, beforeSnapshot, afterSnapshot);
  }

  /** Creates a raw decision without class-level reporting metadata. */
  public static ElisionDecision decision(
      final Set<ArtifactCoordinate> retained, final Set<ArtifactCoordinate> elided) {
    return new ElisionDecision(retained, elided, Map.of(), Map.of(), 0L);
  }

  /** Creates a fixture coordinate with the standard version and JAR extension. */
  public static ArtifactCoordinate coordinate(final String artifactId, final String scope) {
    return new ArtifactCoordinate("fixture", artifactId, TEST_VERSION, JAR_EXTENSION, "", scope);
  }

  /** Creates an ordinary compile-scoped fixture node. */
  public static DependencyNode node(final String artifactId) {
    return node(artifactId, COMPILE_SCOPE, null, List.of());
  }

  /** Creates a compile-scoped node at an explicit version. */
  public static DependencyNode node(final String artifactId, final String version) {
    return completeNode(
        new DefaultDependencyNode(
            new Dependency(
                new DefaultArtifact("fixture", artifactId, "", JAR_EXTENSION, version),
                COMPILE_SCOPE,
                null)));
  }

  /** Creates a node with explicit scope and optionality. */
  public static DependencyNode node(
      final String artifactId, final String scope, final Boolean optional) {
    return node(artifactId, scope, optional, List.of());
  }

  /** Creates a node with path-specific dependency exclusions. */
  public static DependencyNode node(
      final String artifactId,
      final String scope,
      final Boolean optional,
      final List<Exclusion> exclusions) {
    return completeNode(
        new DefaultDependencyNode(
            new Dependency(
                new DefaultArtifact("fixture", artifactId, "", JAR_EXTENSION, TEST_VERSION),
                scope,
                optional,
                exclusions)));
  }

  private static DependencyNode completeNode(final DependencyNode node) {
    node.setChildren(List.of());
    return node;
  }
}
