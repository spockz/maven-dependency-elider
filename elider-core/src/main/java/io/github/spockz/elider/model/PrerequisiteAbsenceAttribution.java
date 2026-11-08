/* WHY: Names the observed cause, or limit, of each prerequisite-class absence. */

package io.github.spockz.elider.model;

/** Physical-provider outcome for a prerequisite class. */
public enum PrerequisiteAbsenceAttribution {
  /** The exact class was absent from both complete inventories. */
  ALREADY_ABSENT,

  /** Its dependency archive was present in baseline and absent from final. */
  ELIDED_DEPENDENCY,

  /** Its dependency archive remained but no longer contained the exact class. */
  TRIMMED_CLASS,

  /** Duplicate providers disappeared through different observed routes. */
  MIXED,

  /** The exact class is present in the actual final inventory. */
  PRESENT,

  /** The inventories do not establish a safe physical cause. */
  UNKNOWN
}
