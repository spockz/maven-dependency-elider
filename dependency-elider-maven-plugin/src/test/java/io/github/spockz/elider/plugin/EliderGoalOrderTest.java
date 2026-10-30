/* WHY: Protects phase-relative tree preparation when bytecode capture moves after compile. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Proves a pre-compile request cannot stand in for process-classes preparation. */
final class EliderGoalOrderTest {
  /** Creates the test instance. */
  @SuppressWarnings({"PMD.CommentDefaultAccessModifier", "PMD.UncommentedEmptyConstructor"})
  EliderGoalOrderTest() {}

  @Test
  @DisplayName("ADR-0010/process-classes requires a lifecycle goal at or after its phase")
  void compileDoesNotSatisfyProcessClassesTreePreparation() {
    assertThat(
            EliderGoalOrder.hasPreparedLifecycleAfter(
                List.of("compile", "dependency:tree"), -1, 1, "process-classes"))
        .isFalse();
  }

  @Test
  @DisplayName("ADR-0010/initialize preparation accepts a compile goal")
  void compileSatisfiesInitializeTreePreparation() {
    assertThat(
            EliderGoalOrder.hasPreparedLifecycleAfter(
                List.of("compile", "dependency:tree"), -1, 1, "initialize"))
        .isTrue();
  }

  @Test
  @DisplayName("ADR-0010/process-classes preparation accepts verify")
  void verifySatisfiesProcessClassesTreePreparation() {
    assertThat(
            EliderGoalOrder.hasPreparedLifecycleAfter(
                List.of("compile", "verify", "dependency:tree"), -1, 2, "process-classes"))
        .isTrue();
  }
}
