/* WHY: Distinguishes declared, omitted, empty, and unresolved code groups. */

package io.github.spockz.elider.model;

/** Applicability state for one declared-code group. */
public enum CodeGroupStatus {
  NOT_APPLICABLE,
  UNRESOLVED,
  OMITTED,
  EXPLICITLY_EMPTY,
  DECLARED
}
