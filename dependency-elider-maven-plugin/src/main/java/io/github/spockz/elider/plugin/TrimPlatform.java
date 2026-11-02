/* WHY: Resolves the configured target release for archive analysis while the
 * JDK class table remains bound to the active runtime. */

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.util.List;

/** Resolves the target release used for multi-release archive analysis. */
final class TrimPlatform {
  /** Earliest platform release supported by standard JDK 21+ compilers. */
  private static final int MINIMUM_SUPPORTED_RELEASE = 8;

  /** Compiler option identifying the target release. */
  private static final String RELEASE_OPTION = "--release";

  private TrimPlatform() {}

  /* package */ static int targetReleaseFromOptions(final List<String> options) throws IOException {
    final String release = optionValue(options, List.of(RELEASE_OPTION));
    final String source = optionValue(options, List.of("-source", "--source"));
    final String target = optionValue(options, List.of("-target", "--target"));
    if (release != null && (source != null || target != null)) {
      throw new IOException("Cannot determine target release with both release and source/target");
    }
    if (release != null) {
      return parseRelease(release);
    }
    if (target == null) {
      if (source != null) {
        parseRelease(source);
      }
      return Runtime.version().feature();
    }
    if (source != null) {
      parseRelease(source);
    }
    return parseRelease(target);
  }

  private static int parseRelease(final String value) throws IOException {
    final String normalized = value.startsWith("1.") ? value.substring(2) : value;
    final int release;
    try {
      release = Integer.parseInt(normalized);
    } catch (final NumberFormatException exception) {
      throw new IOException("Unsupported Java compiler release: " + value, exception);
    }
    if (release < MINIMUM_SUPPORTED_RELEASE) {
      throw new IOException("Unsupported Java compiler release: " + value);
    }
    return release;
  }

  private static String optionValue(final List<String> options, final List<String> names)
      throws IOException {
    String value = null;
    int index = 0;
    while (index < options.size()) {
      if (!names.contains(options.get(index))) {
        index++;
        continue;
      }
      if (index + 1 >= options.size() || options.get(index + 1).startsWith("-")) {
        throw new IOException("Missing value for compiler option " + options.get(index));
      }
      if (value != null) {
        throw new IOException("Multiple values for compiler option " + options.get(index));
      }
      value = options.get(index + 1);
      index += 2;
    }
    return value;
  }
}
