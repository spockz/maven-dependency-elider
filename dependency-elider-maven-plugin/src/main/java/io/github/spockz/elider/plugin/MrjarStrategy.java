// WHY: Defines typed multi-release JAR handling strategies for trimming and pass-through.

package io.github.spockz.elider.plugin;

/** Strategy governing multi-release and modular JAR transformation. */
enum MrjarStrategy {
  /** Elevates target release bytecode to the root and trims while preserving upper tiers. */
  VERTICAL_SHADING("vertical-shading"),

  /** Preserves multi-release archives unchanged while analyzing their dependencies. */
  PASS_THROUGH("pass-through"),

  /** Trims modular dependencies as classpath-only runtime derivatives by stripping module-info. */
  CLASSPATH_ONLY("classpath-only");

  private final String configurationValue;

  MrjarStrategy(final String configurationValue) {
    this.configurationValue = configurationValue;
  }

  /** Returns the configuration string representation. */
  String configurationValue() {
    return configurationValue;
  }

  /** Parses the configuration string value, defaulting to VERTICAL_SHADING if null. */
  static MrjarStrategy parse(final String value) {
    if (value == null) {
      return VERTICAL_SHADING;
    }
    for (final MrjarStrategy strategy : values()) {
      if (strategy.configurationValue.equalsIgnoreCase(value.trim())) {
        return strategy;
      }
    }
    throw new IllegalArgumentException(
        "elide.mrjarStrategy must be vertical-shading, pass-through, or classpath-only (found "
            + value
            + ")");
  }
}
