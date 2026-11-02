// WHY: Shares verified prerequisite details between the Maven summary and persisted report.

package io.github.spockz.elider.plugin;

/** A dependency and required class absent from the declared inventory. */
record MavenMissingPrerequisite(String dependency, String requiredClass) {
  MavenMissingPrerequisite {
    if (dependency == null
        || !dependency.matches("[A-Za-z0-9_][A-Za-z0-9_.-]*:[A-Za-z0-9_][A-Za-z0-9_.-]*")) {
      throw new IllegalArgumentException("dependency must be an exact Maven group:artifact value");
    }
    if (requiredClass == null
        || !requiredClass.matches("[A-Za-z_$][A-Za-z0-9_$]*(\\.[A-Za-z_$][A-Za-z0-9_$]*)+")) {
      throw new IllegalArgumentException("requiredClass must be a fully qualified class name");
    }
  }

  /* default */ String displayText() {
    return dependency + " (class " + requiredClass + ")";
  }
}
