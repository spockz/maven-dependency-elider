/* WHY: Proves duplicate-class owner patterns select one explicit action per class. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.plugin.DuplicateClassPolicy.Action;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

/** Verifies glob matching, precedence, and conflicting configuration rejection. */
final class DuplicateClassPolicyTest {
  /** A class intentionally matched by overlapping policies. */
  private static final String OVERLAPPING_CLASS = "org.example.Foo";

  /** Creates the focused policy test. */
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  DuplicateClassPolicyTest() {
    super();
  }

  @Test
  void matchesExactNamesAndGlobsInDottedAndSlashedForm() {
    final DuplicateClassPolicy policy =
        new DuplicateClassPolicy(
            List.of("org.example.Exact", "org.example.single.*"),
            List.of("org.example.deep.**", " com.other.Trim "));

    assertAll(
        () ->
            assertThat(policy.actionFor("org.example.Exact"))
                .isEqualTo(Optional.of(Action.RETAIN_JARS)),
        () ->
            assertThat(policy.actionFor("org/example/Exact"))
                .isEqualTo(Optional.of(Action.RETAIN_JARS)),
        () ->
            assertThat(policy.actionFor("org.example.single.Leaf"))
                .isEqualTo(Optional.of(Action.RETAIN_JARS)),
        () ->
            assertThat(policy.actionFor("org.example.single.nested.Leaf"))
                .as("single star must not cross package separators")
                .isEmpty(),
        () ->
            assertThat(policy.actionFor("org.example.deep.a.b.Leaf"))
                .isEqualTo(Optional.of(Action.TRIM_OTHER_CLASSES)),
        () ->
            assertThat(policy.actionFor("com.other.Trim"))
                .isEqualTo(Optional.of(Action.TRIM_OTHER_CLASSES)),
        () -> assertThat(policy.actionFor("org.example.ExactSuffix")).isEmpty(),
        () -> assertThat(DuplicateClassPolicy.NONE.actionFor("org.example.Exact")).isEmpty());
  }

  @Test
  void retainWinsWhenBothListsMatchDifferentPatterns() {
    final DuplicateClassPolicy policy =
        new DuplicateClassPolicy(List.of(OVERLAPPING_CLASS), List.of("org.example.**"));

    assertThat(policy.actionFor(OVERLAPPING_CLASS)).contains(Action.RETAIN_JARS);
  }

  @Test
  void rejectsIdenticalPatternInBothListsAndBlankPatterns() {
    assertAll(
        () ->
            assertThatThrownBy(
                    () ->
                        new DuplicateClassPolicy(
                            List.of(OVERLAPPING_CLASS), List.of(OVERLAPPING_CLASS)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining(OVERLAPPING_CLASS),
        () ->
            assertThatThrownBy(() -> new DuplicateClassPolicy(List.of(" "), List.of()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("blank"));
  }
}
