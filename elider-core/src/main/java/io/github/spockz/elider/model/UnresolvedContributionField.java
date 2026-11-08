/* WHY: Identifies source fields whose malformed declarations must block lower-priority proof. */

package io.github.spockz.elider.model;

/** A contribution field that was present but could not be interpreted safely. */
public enum UnresolvedContributionField {
  CODE,
  PREREQUISITES
}
