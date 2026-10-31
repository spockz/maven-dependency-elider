/* WHY: Shares strict primitive JSON validation across independent descriptor readers. */

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.util.Iterator;
import java.util.Set;

/** Provides common shape checks without coupling descriptor schemas together. */
final class NativeImageJsonSupport {
  private NativeImageJsonSupport() {}

  /* package */
  static void requireObject(final JsonNode node, final String what, final String name)
      throws IOException {
    // Package access keeps shape checks internal to descriptor parsing.
    if (node == null || !node.isObject()) {
      throw new IOException("Malformed " + what + ": " + name);
    }
  }

  /* package */
  static void requireText(final JsonNode node, final String what, final String name)
      throws IOException {
    if (node == null || !node.isTextual() || node.textValue().isBlank()) {
      throw new IOException("Malformed " + what + ": " + name);
    }
  }

  /* package */
  static void validateFields(
      final JsonNode object, final Set<String> supported, final String what, final String name)
      throws IOException {
    final Iterator<String> keys = object.fieldNames();
    while (keys.hasNext()) {
      final String key = keys.next();
      if (!supported.contains(key)) {
        throw new IOException("Unsupported native-image " + what + " field " + key + " in " + name);
      }
    }
  }
}
