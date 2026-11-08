/* WHY: Carries observable root service descriptor changes into report rows. */

package io.github.spockz.elider.plugin;

import java.util.Objects;

/** One root service descriptor changed while preparing an artifact output. */
record ServiceDescriptorChange(String path, Outcome outcome)
    implements Comparable<ServiceDescriptorChange> {
  ServiceDescriptorChange {
    Objects.requireNonNull(path, "path");
    Objects.requireNonNull(outcome, "outcome");
    if (!path.startsWith("META-INF/services/")
        || path.length() == "META-INF/services/".length()
        || !AsciiBinaryClassName.isValid(path.substring("META-INF/services/".length()))) {
      throw new IllegalArgumentException("Service descriptor path is not a canonical root path");
    }
  }

  @Override
  public int compareTo(final ServiceDescriptorChange other) {
    return path.compareTo(other.path);
  }

  /** Distinguishes replacement of descriptor content from descriptor removal. */
  /* default */ enum Outcome {
    REPLACED,
    OMIT
  }
}
