/* WHY: Makes alternative and conjunctive prerequisite semantics explicit in catalog data. */

package io.github.spockz.elider.model;

/** Operator applied to prerequisite members in one group. */
public enum PrerequisiteOperator {
  ANY_OF,
  ALL_OF
}
