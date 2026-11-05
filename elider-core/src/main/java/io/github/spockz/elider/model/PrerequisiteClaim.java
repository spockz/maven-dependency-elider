/* WHY: Prevents merging a prerequisite dependency with a different declaration's class. */

package io.github.spockz.elider.model;

/** One exact dependency/class pair required for a vulnerability to apply. */
public record PrerequisiteClaim(String requiresDependency, String requiresClass)
    implements Comparable<PrerequisiteClaim> {
  /** Validates the complete atomic pair without granting verification authority. */
  public PrerequisiteClaim {
    if (!VulnerabilitySymbolMapping.isValidRequiredDependency(requiresDependency)) {
      throw new IllegalArgumentException(
          "requiresDependency must be an exact Maven group:artifact coordinate");
    }
    if (!VulnerabilitySymbolMapping.isValidFullyQualifiedClassName(requiresClass)) {
      throw new IllegalArgumentException(
          "requiresClass must be an exact fully qualified class name");
    }
  }

  @Override
  public int compareTo(final PrerequisiteClaim other) {
    final int dependencyOrder = requiresDependency.compareTo(other.requiresDependency);
    return dependencyOrder == 0 ? requiresClass.compareTo(other.requiresClass) : dependencyOrder;
  }
}
