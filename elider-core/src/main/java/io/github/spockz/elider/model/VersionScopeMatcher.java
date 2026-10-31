// WHY: Lets proof evidence bind only after the caller validates its configured version scope.

package io.github.spockz.elider.model;

/** Checks whether one exact artifact version satisfies a configured evidence range. */
@FunctionalInterface
public interface VersionScopeMatcher {
  /** Returns whether the concrete version is included by the configured range. */
  boolean includes(String range, String version);
}
