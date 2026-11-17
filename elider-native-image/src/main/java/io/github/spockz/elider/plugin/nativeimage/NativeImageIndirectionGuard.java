/* WHY: Blocks audited Native Image indirections before unknown flags can be accepted
 * without roots. */

package io.github.spockz.elider.plugin.nativeimage;

import java.io.IOException;

/** Enforces the bounded launcher inputs that otherwise hide unmodeled classes. */
public final class NativeImageIndirectionGuard {
  private NativeImageIndirectionGuard() {}

  /** Rejects launcher or external indirection flags in native-image arguments. */
  public static void validate(final String argument) throws IOException {
    NativeImageLauncherIndirection.validate(argument);
    validateVersion(argument);
    validateModule(argument);
  }

  /* package */ static void reject(final String argument, final String reason) throws IOException {
    throw new IOException("Unsupported native-image indirection '" + argument + "': " + reason);
  }

  private static void validateVersion(final String argument) throws IOException {
    if ("-V".equals(argument) || (argument.startsWith("-V") && argument.contains("="))) {
      final int equals = argument.indexOf('=');
      if (argument.length() < 4 || equals <= 2 || equals == argument.length() - 1) {
        reject(argument, "version selector must use -V<key>=<value>");
      }
      reject(argument, "version selection is unsupported");
    }
  }

  private static void validateModule(final String argument) throws IOException {
    if ("-H:Module".equals(argument) || argument.startsWith("-H:Module=")) {
      reject(argument, "module selection is unsupported");
    }
  }
}
