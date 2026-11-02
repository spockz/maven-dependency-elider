/* WHY: Shares lowercase hexadecimal validation without compiling repeat hash patterns. */

package io.github.spockz.elider.plugin;

import java.util.regex.Pattern;

/** Validates lowercase hexadecimal digests with an explicit length. */
final class HexDigest {
  /** WHY: All serialized digest forms use lowercase hexadecimal text. */
  private static final Pattern LOWERCASE_HEX = Pattern.compile("[0-9a-f]+");

  private HexDigest() {
    throw new AssertionError("No instances");
  }

  /* package */ static boolean isLowercaseHex(final String value, final int length) {
    return value != null && value.length() == length && LOWERCASE_HEX.matcher(value).matches();
  }
}
