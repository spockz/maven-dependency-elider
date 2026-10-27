/* WHY: Guards the immutable graph snapshot's topology and conflict metadata contract. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.eclipse.aether.artifact.DefaultArtifact;
import org.eclipse.aether.graph.DefaultDependencyNode;
import org.eclipse.aether.graph.Dependency;
import org.eclipse.aether.graph.DependencyNode;
import org.eclipse.aether.util.graph.transformer.ConflictResolver;
import org.junit.jupiter.api.Test;

/** Verifies detached graph capture without changing the graph. */
@SuppressWarnings({"PMD.CommentRequired", "PMD.UnitTestContainsTooManyAsserts"})
final class ResolverArtifactGraphSnapshotTest {
  private static final String ARTIFACT_KEY = "artifact";

  private static final String ROOT_ARTIFACT = "root";

  /** Distinguishes a project-scoped graph capture in direct model tests. */
  private static final String PROJECT_KEY = "project-A";

  /** Creates the graph snapshot test fixture. */
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  ResolverArtifactGraphSnapshotTest() {
    super();
  }

  @Test
  void preservesDiamondRepeatedReferencesAndCycles() {
    final DependencyNode root = node(ROOT_ARTIFACT);
    final DependencyNode left = node("left");
    final DependencyNode right = node("right");
    final DependencyNode shared = node("shared");
    root.setChildren(List.of(left, right));
    left.setChildren(List.of(shared));
    right.setChildren(List.of(shared, node("shared")));
    shared.setChildren(List.of(root));

    final ResolverArtifactGraphSnapshot snapshot =
        ResolverArtifactGraphSnapshot.capture(root, PROJECT_KEY, false, null, 0, 1);

    assertThat(snapshot.nodes()).hasSize(5);
    assertThat(snapshot.edges()).hasSize(6);
    assertThat(snapshot.nodes().stream().map(value -> value.get("id")))
        .containsExactly("n0", "n1", "n2", "n3", "n4");
    assertThat(snapshot.edges())
        .contains(
            Map.of("parentNodeId", "n1", "childNodeId", "n3"),
            Map.of("parentNodeId", "n2", "childNodeId", "n3"),
            Map.of("parentNodeId", "n3", "childNodeId", "n0"));
    assertThat(snapshot.nodes().get(3).get(ARTIFACT_KEY))
        .isEqualTo(snapshot.nodes().get(4).get(ARTIFACT_KEY));
    final Map<?, ?> dependency = (Map<?, ?>) snapshot.nodes().get(3).get("dependency");
    final Map<?, ?> dependencyArtifact = (Map<?, ?>) dependency.get(ARTIFACT_KEY);
    assertThat(dependencyArtifact.get("artifactId")).isEqualTo("shared");
    assertThat(snapshot.nodes().get(3).get("id")).isNotEqualTo(snapshot.nodes().get(4).get("id"));
  }

  @Test
  void recordsWinnerOutsideReachableGraphAsMetadataOnlyNode() {
    final DependencyNode root = node(ROOT_ARTIFACT);
    final DependencyNode winner = node("winner");
    root.setData(ConflictResolver.NODE_DATA_WINNER, winner);

    final ResolverArtifactGraphSnapshot snapshot =
        ResolverArtifactGraphSnapshot.capture(root, PROJECT_KEY, false, null, 0, 1);

    assertThat(snapshot.nodes()).hasSize(2);
    assertThat(snapshot.nodes().get(1))
        .containsEntry("reachable", false)
        .extractingByKey(ARTIFACT_KEY)
        .asInstanceOf(org.assertj.core.api.InstanceOfAssertFactories.MAP)
        .containsEntry("artifactId", "winner");
    assertThat(snapshot.nodes().getFirst())
        .containsEntry("conflictWinnerNodeId", "n1")
        .containsEntry("conflictWinnerExternalArtifact", null);
    assertThat(root.getChildren()).isEmpty();
  }

  @Test
  @SuppressWarnings("PMD.UseConcurrentHashMap")
  void preservesMissingNullAndFalseConflictOptionalitySeparately() {
    final DependencyNode missing = node("missing");
    final DependencyNode nullValue = node("null-value");
    final DependencyNode falseValue = node("false-value");
    final Map<Object, Object> nullValueData = new LinkedHashMap<>();
    nullValueData.put(ConflictResolver.NODE_DATA_ORIGINAL_OPTIONALITY, null);
    nullValue.setData(nullValueData);
    falseValue.setData(ConflictResolver.NODE_DATA_ORIGINAL_OPTIONALITY, false);
    final DependencyNode root = node(ROOT_ARTIFACT);
    root.setChildren(List.of(missing, nullValue, falseValue));

    final ResolverArtifactGraphSnapshot snapshot =
        ResolverArtifactGraphSnapshot.capture(root, PROJECT_KEY, false, null, 0, 1);

    assertThat(snapshot.nodes().get(1))
        .containsEntry("originalOptionalityPresent", false)
        .containsEntry("originalOptionality", null);
    assertThat(snapshot.nodes().get(2))
        .containsEntry("originalOptionalityPresent", true)
        .containsEntry("originalOptionality", null);
    assertThat(snapshot.nodes().get(3))
        .containsEntry("originalOptionalityPresent", true)
        .containsEntry("originalOptionality", false);
  }

  @Test
  void rejectsUnsupportedOriginalMetadataAndDeeplyFreezesNestedPayloads() {
    final DependencyNode unsupported = node("unsupported");
    unsupported.setData(ConflictResolver.NODE_DATA_ORIGINAL_SCOPE, new Object());
    assertThatThrownBy(
            () ->
                ResolverArtifactGraphSnapshot.capture(unsupported, PROJECT_KEY, false, null, 0, 1))
        .isInstanceOf(IllegalArgumentException.class);
    final DependencyNode unsupportedOptionality = node("unsupported-optionality");
    unsupportedOptionality.setData(ConflictResolver.NODE_DATA_ORIGINAL_OPTIONALITY, new Object());
    assertThatThrownBy(
            () ->
                ResolverArtifactGraphSnapshot.capture(
                    unsupportedOptionality, PROJECT_KEY, false, null, 0, 1))
        .isInstanceOf(IllegalArgumentException.class);

    final ResolverArtifactGraphSnapshot snapshot =
        ResolverArtifactGraphSnapshot.capture(node("immutable"), PROJECT_KEY, false, null, 0, 1);
    final Map<?, ?> artifact = (Map<?, ?>) snapshot.nodes().getFirst().get(ARTIFACT_KEY);
    assertThatThrownBy(artifact::clear).isInstanceOf(UnsupportedOperationException.class);
  }

  @Test
  void structuralFingerprintExcludesPlanProvenance() {
    final DependencyNode root = node(ROOT_ARTIFACT);

    final ResolverArtifactGraphSnapshot absent =
        ResolverArtifactGraphSnapshot.capture(root, PROJECT_KEY, false, null, 0, 1);
    final ResolverArtifactGraphSnapshot presentEmpty =
        ResolverArtifactGraphSnapshot.capture(root, PROJECT_KEY, true, "empty-plan", 1, 2);

    assertThat(absent.graphFingerprint()).isEqualTo(presentEmpty.graphFingerprint());
    assertThat(absent.planPresent()).isFalse();
    assertThat(presentEmpty.planPresent()).isTrue();
    assertThat(presentEmpty.planFingerprint()).isEqualTo("empty-plan");
  }

  @Test
  void preservesRelocationSequenceInStructuralFingerprint() {
    final DefaultDependencyNode forward = (DefaultDependencyNode) node(ROOT_ARTIFACT);
    forward.setRelocations(List.of(artifact("first"), artifact("second")));
    final DefaultDependencyNode reverse = (DefaultDependencyNode) node(ROOT_ARTIFACT);
    reverse.setRelocations(List.of(artifact("second"), artifact("first")));

    final ResolverArtifactGraphSnapshot forwardSnapshot =
        ResolverArtifactGraphSnapshot.capture(forward, PROJECT_KEY, false, null, 0, 1);
    final ResolverArtifactGraphSnapshot reverseSnapshot =
        ResolverArtifactGraphSnapshot.capture(reverse, PROJECT_KEY, false, null, 0, 1);

    assertThat(forwardSnapshot.graphFingerprint()).isNotEqualTo(reverseSnapshot.graphFingerprint());
    final List<?> relocations = (List<?>) forwardSnapshot.nodes().getFirst().get("relocations");
    final List<String> artifactIds =
        relocations.stream().map(value -> (String) ((Map<?, ?>) value).get("artifactId")).toList();
    assertThat(artifactIds).containsExactly("first", "second");
  }

  private static DependencyNode node(final String artifactId) {
    final DefaultArtifact artifact = artifact(artifactId);
    return new DefaultDependencyNode(new Dependency(artifact, "compile", (Boolean) null));
  }

  private static DefaultArtifact artifact(final String artifactId) {
    return new DefaultArtifact("fixture", artifactId, "", "jar", "1.0");
  }
}
