/* WHY: Applies one compiled ASCII binary-name grammar to service and Spring metadata. */

package io.github.spockz.elider.plugin;

import java.util.regex.Pattern;

/** Validates the ASCII Java binary names used in service and Spring metadata. */
final class AsciiBinaryClassName {
  /** WHY: Service and Spring metadata use the project's ASCII binary-name policy. */
  private static final Pattern GRAMMAR =
      Pattern.compile("[A-Za-z_$][A-Za-z0-9_$]*(\\.[A-Za-z_$][A-Za-z0-9_$]*)*");

  private AsciiBinaryClassName() {
    throw new AssertionError("No instances");
  }

  /* package */ static boolean isValid(final String value) {
    return GRAMMAR.matcher(value).matches();
  }

  /* package */ static boolean isFullyQualified(final String value) {
    return isValid(value) && value.indexOf('.') >= 0;
  }
}
