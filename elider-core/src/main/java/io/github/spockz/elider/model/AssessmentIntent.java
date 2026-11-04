/* WHY: Separates review policy from confidence and from the presence of code claims. */

package io.github.spockz.elider.model;

/** Requested downstream treatment of an applicable finding contribution. */
public enum AssessmentIntent {
  AUTO_VERIFY,
  REVIEW_ONLY
}
