/* WHY: Keeps Graal module/version selectors distinct from valid unrelated unknown flags. */

package io.github.spockz.elider.plugin;

import java.io.IOException;

/** Rejects the audited version and module selector grammar. */
final class NativeImageVersionIndirection {
  private NativeImageVersionIndirection() {}

  /* package */ static void validate(final String argument) throws IOException {
    validateVersion(argument);
    validateModule(argument);
  }

  private static void validateVersion(final String argument) throws IOException {
    if ("-V".equals(argument) || (argument.startsWith("-V") && argument.contains("="))) {
      final int equals = argument.indexOf('=');
      if (argument.length() < 4 || equals <= 2 || equals == argument.length() - 1) {
        NativeImageIndirectionGuard.reject(argument, "version selector must use -V<key>=<value>");
      }
      NativeImageIndirectionGuard.reject(argument, "version selection is unsupported");
    }
  }

  private static void validateModule(final String argument) throws IOException {
    if ("-H:Module".equals(argument) || argument.startsWith("-H:Module=")) {
      NativeImageIndirectionGuard.reject(argument, "module selection is unsupported");
    }
  }
}
