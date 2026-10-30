/* WHY: Validates standalone foreign ABI descriptors without inventing Java class roots. */

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.util.Set;

/** Reads the audited standalone foreign ABI descriptor. */
final class NativeImageStandaloneSupplementalConfig {
  private NativeImageStandaloneSupplementalConfig() {}

  /** Reads ABI descriptors whose fields do not name Java classes. */
  /* package */
  static void readForeign(final JsonNode document, final String name) throws IOException {
    NativeImageJsonSupport.requireObject(document, "standalone foreign configuration", name);
    NativeImageJsonSupport.validateFields(
        document, Set.of("downcalls"), "standalone foreign configuration", name);
    final JsonNode downcalls = document.get("downcalls");
    if (downcalls == null) {
      return;
    }
    if (!downcalls.isArray()) {
      throw new IOException("Malformed standalone foreign downcalls: " + name);
    }
    for (final JsonNode descriptor : downcalls) {
      NativeImageJsonSupport.requireObject(descriptor, "standalone foreign downcall", name);
      NativeImageJsonSupport.validateFields(
          descriptor, Set.of("descriptor", "options"), "standalone foreign downcall", name);
      NativeImageJsonSupport.requireText(
          descriptor.get("descriptor"), "foreign ABI descriptor", name);
      if (descriptor.has("options")) {
        validateForeignOptions(descriptor.get("options"), name);
      }
    }
  }

  private static void validateForeignOptions(final JsonNode options, final String name)
      throws IOException {
    NativeImageJsonSupport.requireObject(options, "foreign options", name);
    NativeImageJsonSupport.validateFields(
        options,
        Set.of("firstVariadicArg", "captureCallState", "trivial"),
        "foreign options",
        name);
    if (options.has("firstVariadicArg") && !options.get("firstVariadicArg").isIntegralNumber()) {
      throw new IOException("Malformed foreign firstVariadicArg: " + name);
    }
    for (final String option : Set.of("captureCallState", "trivial")) {
      if (options.has(option) && !options.get(option).isBoolean()) {
        throw new IOException("Malformed foreign option " + option + ": " + name);
      }
    }
  }
}
