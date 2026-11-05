/* WHY: Distinguishes declared, omitted, empty, and unresolved effective claim groups. */

package io.github.spockz.elider.model;

/** Applicability state for one effective code or prerequisite group. */
public enum ClaimGroupStatus {
  NOT_APPLICABLE,
  UNRESOLVED,
  OMITTED,
  EXPLICITLY_EMPTY,
  DECLARED
}
