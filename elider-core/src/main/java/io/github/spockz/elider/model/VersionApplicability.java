/* WHY: Keeps unresolved candidate applicability distinct from a negative match. */

package io.github.spockz.elider.model;

/** Result of evaluating the merged version coverage for one concrete candidate. */
public enum VersionApplicability {
  AFFECTED,
  NOT_AFFECTED,
  UNRESOLVED
}
