/* WHY: Keeps each checked prerequisite class state explicit in final VEX evidence. */

package io.github.spockz.elider.model;

import java.util.Objects;

/** Final-inventory state of one checked prerequisite member. */
public record PrerequisiteMemberObservation(PrerequisiteClaim claim, State state)
    implements Comparable<PrerequisiteMemberObservation> {
  /** Whether the exact class appeared in the final inventory. */
  public enum State {
    PRESENT,
    ABSENT
  }

  /** Validates one immutable member observation. */
  public PrerequisiteMemberObservation {
    Objects.requireNonNull(claim, "claim");
    Objects.requireNonNull(state, "state");
  }

  @Override
  public int compareTo(final PrerequisiteMemberObservation other) {
    final int claimOrder = claim.compareTo(other.claim);
    return claimOrder == 0 ? state.compareTo(other.state) : claimOrder;
  }
}
