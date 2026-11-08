/* WHY: Pins prerequisite operator semantics before they enter persisted finding data. */

package io.github.spockz.elider.model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.util.LinkedHashSet;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** JUnit uses the implicit package constructor for this test class. */
@SuppressWarnings("PMD.AtLeastOneConstructor")
final class PrerequisiteGroupTest {

  @Test
  void operatorsAndMembersAreTypedAndImmutable() {
    final PrerequisiteClaim first = new PrerequisiteClaim("org.example:one", "org.example.One");
    final PrerequisiteClaim second = new PrerequisiteClaim("org.example:two", "org.example.Two");
    final Set<PrerequisiteClaim> members = new LinkedHashSet<>(Set.of(first, second));
    final PrerequisiteGroup anyOf = new PrerequisiteGroup(PrerequisiteOperator.ANY_OF, members);
    final PrerequisiteGroup allOf =
        new PrerequisiteGroup(PrerequisiteOperator.ALL_OF, Set.of(first, second));

    members.clear();

    assertAll(
        "operator types and member snapshots survive source mutation",
        () -> assertOperator(anyOf, PrerequisiteOperator.ANY_OF),
        () -> assertMembers(anyOf, first, second),
        () -> assertOperator(allOf, PrerequisiteOperator.ALL_OF),
        () -> assertMembers(allOf, first, second),
        PrerequisiteGroupTest::assertEmptyRejected);
  }

  private static void assertOperator(
      final PrerequisiteGroup group, final PrerequisiteOperator expected) {
    assertThat(group.operator()).isEqualTo(expected);
  }

  private static void assertMembers(
      final PrerequisiteGroup group,
      final PrerequisiteClaim first,
      final PrerequisiteClaim second) {
    assertThat(group.members()).containsExactlyInAnyOrder(first, second);
  }

  private static void assertEmptyRejected() {
    assertThatIllegalArgumentException()
        .isThrownBy(() -> new PrerequisiteGroup(PrerequisiteOperator.ANY_OF, Set.of()));
  }
}
