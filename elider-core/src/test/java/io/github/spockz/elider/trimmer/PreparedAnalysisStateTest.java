/* WHY: Verifies supplier lifecycle and retry behavior at graph materialization boundaries. */

package io.github.spockz.elider.trimmer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Tests graph supplier release and failed-build retry behavior. */
@SuppressWarnings({"PMD.AtLeastOneConstructor"})
class PreparedAnalysisStateTest {
  /** Names the candidate class shared by the graph and query fixtures. */
  private static final String ROOT_CLASS = "fixture/Root";

  /** Names the same fixture class in the public dotted form accepted by analysis. */
  private static final String ROOT_NAME = "fixture.Root";

  /** Names the class reached from the graph root. */
  private static final String LINKED_CLASS = "fixture/Linked";

  /** Names a node excluded by the query root. */
  private static final String DEAD_CLASS = "fixture/Dead";

  /** A class exposed by an over-approximated edge and by typed structural closure. */
  private static final String TRANSITIVE_CLASS = "fixture/Transitive";

  /** Fails exactly the initial graph build before allowing deterministic retry. */
  private static final int FIRST_BUILD = 1;

  @Test
  @DisplayName("ADR-0003: successful graph materialization releases its supplier")
  void successfulBuildReleasesSupplier() throws Exception {
    final AtomicInteger buildCount = new AtomicInteger();
    final PreparedAnalysisState state =
        state(
            () -> {
              buildCount.incrementAndGet();
              return graph();
            });

    final DependencyJarTrimmer.TrimAnalysis analysis = state.analyze(List.of(ROOT_NAME));

    assertThat(analysis.retainedClasses()).containsExactly(ROOT_CLASS);
    assertThat(state.graphSupplierRetained()).isFalse();
    assertThat(buildCount).hasValue(1);
  }

  @Test
  @DisplayName("ADR-0003: failed graph materialization retains the supplier for retry")
  void failedBuildRetainsSupplierAndRetries() throws Exception {
    final AtomicInteger buildCount = new AtomicInteger();
    final PreparedAnalysisState state =
        state(
            () -> {
              if (buildCount.incrementAndGet() == FIRST_BUILD) {
                throw new IOException("temporary graph build failure");
              }
              return graph();
            });

    assertThatThrownBy(() -> state.analyze(List.of(ROOT_NAME)))
        .isInstanceOf(IOException.class)
        .hasMessage("temporary graph build failure");
    assertThat(state.graphBuilt()).isFalse();
    assertThat(state.graphSupplierRetained()).isTrue();

    assertThat(state.analyze(List.of(ROOT_NAME)).retainedClasses()).containsExactly(ROOT_CLASS);
    assertThat(state.graphSupplierRetained()).isFalse();
    assertThat(buildCount).hasValue(2);
  }

  @Test
  void conservativeQueryFollowsProguardEdgeWithoutTypedClassification() throws Exception {
    final ReferenceGraph graph =
        new ReferenceGraph(
            Set.of(ROOT_CLASS, LINKED_CLASS),
            Set.of(),
            Map.of(ROOT_CLASS, Set.of(LINKED_CLASS)),
            Map.of(ROOT_CLASS, Map.of()),
            Map.of(ROOT_CLASS, Set.of(LINKED_CLASS)),
            Map.of(),
            Map.of(),
            Map.of(),
            Map.of(),
            Map.of(),
            2);

    final DependencyJarTrimmer.TrimAnalysis analysis =
        state(() -> graph, Set.of(ROOT_CLASS))
            .analyze(List.of(ROOT_NAME), ClosureQueryPolicy.conservative());

    assertThat(analysis.retainedClasses()).containsExactlyInAnyOrder(ROOT_CLASS, LINKED_CLASS);
  }

  @Test
  void closedWorldQueryRejectsUnclassifiedEdgeFromReachedSource() throws Exception {
    final ReferenceGraph graph =
        new ReferenceGraph(
            Set.of(ROOT_CLASS, LINKED_CLASS),
            Set.of(),
            Map.of(ROOT_CLASS, Set.of(LINKED_CLASS)),
            Map.of(ROOT_CLASS, Map.of()),
            Map.of(ROOT_CLASS, Set.of(LINKED_CLASS)),
            Map.of(),
            Map.of(),
            Map.of(),
            Map.of(),
            Map.of(),
            2);

    assertThatThrownBy(
            () ->
                state(() -> graph, Set.of(ROOT_CLASS))
                    .analyze(List.of(ROOT_NAME), ClosureQueryPolicy.closedWorld(Set.of(ROOT_NAME))))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Unclassified reference target");
  }

  @Test
  void closedWorldAcceptsUnclassifiedEdgeWhenTypedClosureRetainsItsTarget() throws Exception {
    final ReferenceGraph graph =
        new ReferenceGraph(
            Set.of(ROOT_CLASS, LINKED_CLASS, TRANSITIVE_CLASS),
            Set.of(),
            Map.of(
                ROOT_CLASS, Set.of(LINKED_CLASS, TRANSITIVE_CLASS),
                LINKED_CLASS, Set.of(TRANSITIVE_CLASS)),
            Map.of(
                ROOT_CLASS,
                Map.of(LINKED_CLASS, Set.of(ReferenceGraph.EdgeKind.STRUCTURAL)),
                LINKED_CLASS,
                Map.of(TRANSITIVE_CLASS, Set.of(ReferenceGraph.EdgeKind.STRUCTURAL))),
            Map.of(ROOT_CLASS, Set.of(TRANSITIVE_CLASS)),
            Map.of(),
            Map.of(),
            Map.of(),
            Map.of(),
            Map.of(),
            3);

    final DependencyJarTrimmer.TrimAnalysis analysis =
        state(() -> graph, Set.of(ROOT_CLASS, LINKED_CLASS, TRANSITIVE_CLASS))
            .analyze(List.of(ROOT_NAME), ClosureQueryPolicy.closedWorld(Set.of(ROOT_NAME)));

    assertThat(analysis.retainedClasses())
        .containsExactlyInAnyOrder(ROOT_CLASS, LINKED_CLASS, TRANSITIVE_CLASS);
  }

  @Test
  void unusedClassConstantDoesNotSuppressMissingMemberEvidence() {
    final String missingMember = ROOT_CLASS + " -> member " + LINKED_CLASS + ".call()V";
    final ReferenceGraph graph =
        new ReferenceGraph(
            Set.of(ROOT_CLASS),
            Set.of(),
            Map.of(),
            Map.of(),
            Map.of(),
            Map.of(ROOT_CLASS, Set.of(LINKED_CLASS)),
            Map.of(),
            Map.of(
                ROOT_CLASS,
                Set.of(
                    new ReferenceGraph.UnresolvedLink(
                        LINKED_CLASS,
                        ReferenceGraph.UnresolvedKind.MISSING_MEMBER,
                        missingMember))),
            Map.of(),
            Map.of(),
            1);

    assertThatThrownBy(
            () ->
                state(() -> graph)
                    .analyze(List.of(ROOT_NAME), ClosureQueryPolicy.closedWorld(Set.of(ROOT_NAME))))
        .isInstanceOf(DependencyJarTrimmer.UnresolvedReferenceException.class)
        .hasMessageContaining(missingMember);
  }

  @Test
  void closedWorldQueryDoesNotFailForUnclassifiedEdgeFromDeadSource() throws Exception {
    final ReferenceGraph graph =
        new ReferenceGraph(
            Set.of(ROOT_CLASS, DEAD_CLASS, LINKED_CLASS),
            Set.of(),
            Map.of(DEAD_CLASS, Set.of(LINKED_CLASS)),
            Map.of(DEAD_CLASS, Map.of()),
            Map.of(DEAD_CLASS, Set.of(LINKED_CLASS)),
            Map.of(),
            Map.of(),
            Map.of(),
            Map.of(),
            Map.of(),
            3);

    final DependencyJarTrimmer.TrimAnalysis analysis =
        state(() -> graph, Set.of(ROOT_CLASS, DEAD_CLASS, LINKED_CLASS))
            .analyze(List.of(ROOT_NAME), ClosureQueryPolicy.closedWorld(Set.of(ROOT_NAME)));

    assertThat(analysis.retainedClasses()).containsExactly(ROOT_CLASS);
  }

  private static PreparedAnalysisState state(final PreparedAnalysisState.GraphSupplier supplier) {
    return state(supplier, Set.of(ROOT_CLASS));
  }

  private static PreparedAnalysisState state(
      final PreparedAnalysisState.GraphSupplier supplier, final Set<String> candidateClasses) {
    return new PreparedAnalysisState(
        Path.of("candidate.jar"), supplier, candidateClasses, false, Set.of());
  }

  private static ReferenceGraph graph() {
    return new ReferenceGraph(
        Set.of(ROOT_CLASS),
        Set.of(),
        Map.of(),
        Map.of(),
        Map.of(),
        Map.of(),
        Map.of(),
        Map.of(),
        Map.of(),
        Map.of(),
        FIRST_BUILD);
  }
}
