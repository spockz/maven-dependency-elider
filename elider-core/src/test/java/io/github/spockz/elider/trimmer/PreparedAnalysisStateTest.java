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
@SuppressWarnings({"PMD.AtLeastOneConstructor", "PMD.UnitTestContainsTooManyAsserts"})
class PreparedAnalysisStateTest {
  /** Names the candidate class shared by the graph and query fixtures. */
  private static final String ROOT_CLASS = "fixture/Root";

  /** Names the same fixture class in the public dotted form accepted by analysis. */
  private static final String ROOT_NAME = "fixture.Root";

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

  private static PreparedAnalysisState state(final PreparedAnalysisState.GraphSupplier supplier) {
    return new PreparedAnalysisState(
        Path.of("candidate.jar"), supplier, Set.of(ROOT_CLASS), false, Set.of());
  }

  private static ReferenceGraph graph() {
    return new ReferenceGraph(
        Set.of(ROOT_CLASS), Set.of(), Map.of(), Map.of(), Map.of(), Map.of(), FIRST_BUILD);
  }
}
