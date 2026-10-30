/* WHY: Resolves predefined class metadata and its required sibling bytecode resources. */

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.util.Set;

/** Validates predefined configuration entries and expands bytecode references. */
final class NativeImagePredefinedConfig {
  private NativeImagePredefinedConfig() {}

  /* package */
  static void read(final JsonNode document, final NativeImageInput input, final Set<String> roots)
      throws IOException {
    final String name = input.name();
    if (!document.isArray()) {
      throw new IOException("Malformed predefined classes configuration: " + name);
    }
    for (final JsonNode origin : document) {
      readOrigin(origin, input, roots);
    }
  }

  private static void readOrigin(
      final JsonNode origin, final NativeImageInput input, final Set<String> roots)
      throws IOException {
    final String name = input.name();
    NativeImageJsonSupport.requireObject(origin, "predefined origin", name);
    NativeImageJsonSupport.validateFields(
        origin, Set.of("type", "classes"), "predefined origin", name);
    final JsonNode originType = origin.get("type");
    if (originType == null
        || !originType.isTextual()
        || !"agent-extracted".equals(originType.textValue())) {
      throw new IOException("Unsupported predefined origin: " + name);
    }
    final JsonNode classes = origin.get("classes");
    if (classes == null || !classes.isArray()) {
      throw new IOException("Malformed predefined classes: " + name);
    }
    for (final JsonNode item : classes) {
      readClass(item, input, roots);
    }
  }

  private static void readClass(
      final JsonNode item, final NativeImageInput input, final Set<String> roots)
      throws IOException {
    final String name = input.name();
    NativeImageJsonSupport.requireObject(item, "predefined class", name);
    NativeImageJsonSupport.validateFields(
        item, Set.of("hash", "nameInfo"), "predefined class", name);
    final JsonNode hashNode = item.get("hash");
    if (hashNode == null
        || !hashNode.isTextual()
        || !hashNode.textValue().matches("[A-Fa-f0-9]{32,128}")) {
      throw new IOException("Malformed predefined class hash: " + name);
    }
    roots.addAll(NativeImagePredefinedBytecode.read(input, hashNode.textValue()));
    final JsonNode nameInfo = item.get("nameInfo");
    if (nameInfo != null && !nameInfo.isNull()) {
      NativeImageJsonSupport.requireText(nameInfo, "predefined nameInfo", name);
    }
  }
}
