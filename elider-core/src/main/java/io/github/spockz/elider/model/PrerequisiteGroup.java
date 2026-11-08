/* WHY: Keeps prerequisite operator semantics attached to their exact member pairs. */

package io.github.spockz.elider.model;

import java.util.Collections;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;

/** A nonempty set of exact prerequisite pairs with one applicability operator. */
public record PrerequisiteGroup(PrerequisiteOperator operator, Set<PrerequisiteClaim> members)
    implements Comparable<PrerequisiteGroup> {
  /** Validates and freezes the operator's exact member set. */
  public PrerequisiteGroup {
    Objects.requireNonNull(operator, "operator");
    Objects.requireNonNull(members, "members");
    final Set<PrerequisiteClaim> copy = new TreeSet<>();
    members.forEach(value -> copy.add(Objects.requireNonNull(value, "prerequisite member")));
    if (copy.isEmpty()) {
      throw new IllegalArgumentException("prerequisite groups must not be empty");
    }
    members = Collections.unmodifiableSet(copy);
  }

  @Override
  public int compareTo(final PrerequisiteGroup other) {
    final int operatorOrder = operator.compareTo(other.operator);
    if (operatorOrder != 0) {
      return operatorOrder;
    }
    final java.util.Iterator<PrerequisiteClaim> left = members.iterator();
    final java.util.Iterator<PrerequisiteClaim> right = other.members.iterator();
    while (left.hasNext() && right.hasNext()) {
      final int memberOrder = left.next().compareTo(right.next());
      if (memberOrder != 0) {
        return memberOrder;
      }
    }
    return Boolean.compare(left.hasNext(), right.hasNext());
  }
}
