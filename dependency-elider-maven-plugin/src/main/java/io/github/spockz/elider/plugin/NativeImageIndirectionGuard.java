/* WHY: Blocks audited Native Image indirections before unknown flags can be accepted
 * without roots. */

package io.github.spockz.elider.plugin;

import java.io.IOException;

/** Enforces the bounded launcher inputs that otherwise hide unmodeled classes. */
final class NativeImageIndirectionGuard {
  private NativeImageIndirectionGuard() {}

  /* package */ static void validate(final String argument) throws IOException {
    NativeImageLauncherIndirection.validate(argument);
    NativeImageVersionIndirection.validate(argument);
  }

  /* package */ static void reject(final String argument, final String reason) throws IOException {
    throw new IOException("Unsupported native-image indirection '" + argument + "': " + reason);
  }
}
