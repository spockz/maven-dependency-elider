/* WHY: Reads standalone serialization references apart from deny and ABI descriptors. */

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.util.Set;

/** Parses the standalone serialization descriptor variants. */
final class NativeImageSerializationConfig {
  /** WHY: These keys must match across standalone serialization forms. */
  private static final String NAME = "name";

  /** WHY: Legacy entries and objects use the same condition field. */
  private static final String CONDITION = "condition";

  /** WHY: This optional type reference is shared by both supported forms. */
  private static final String CUSTOM_TARGET = "customTargetConstructorClass";

  /** WHY: Both standalone forms use the selected parser's exact field spelling. */
  private static final String LAMBDA_TYPES = "lambdaCapturingTypes";

  /** WHY: Standalone serialization proxies add their interfaces as roots. */
  private static final String PROXIES = "proxies";

  /** WHY: Error diagnostics retain one consistent type description. */
  private static final String SERIALIZATION_TYPE = "serialization type";

  private NativeImageSerializationConfig() {}

  /* package */
  static void readDocument(final JsonNode document, final String name, final Set<String> roots)
      throws IOException {
    NativeImageJsonSupport.requireObject(document, "serialization configuration", name);
    NativeImageJsonSupport.validateFields(
        document, Set.of("types", LAMBDA_TYPES, PROXIES), "serialization configuration", name);
    readTypes(document.get("types"), name, roots);
    readLambdaTypes(document.get(LAMBDA_TYPES), name, roots);
    readProxies(document.get(PROXIES), name, roots);
  }

  /* package */
  static void readLegacy(final JsonNode entry, final String name, final Set<String> roots)
      throws IOException {
    NativeImageJsonSupport.requireObject(entry, "legacy serialization entry", name);
    NativeImageJsonSupport.validateFields(
        entry,
        Set.of(NAME, CUSTOM_TARGET, LAMBDA_TYPES, PROXIES, CONDITION),
        "legacy serialization entry",
        name);
    NativeImageRootSupport.addRequiredClass(entry.get(NAME), SERIALIZATION_TYPE, name, roots);
    readOptionalClass(entry, CUSTOM_TARGET, name, roots);
    NativeImageRootSupport.readCondition(entry.get(CONDITION), name, roots, false);
    NativeImageRootSupport.readTypeArray(entry.get(LAMBDA_TYPES), name, roots, true);
    if (entry.has(PROXIES)) {
      readProxies(entry.get(PROXIES), name, roots);
    }
  }

  private static void readTypes(final JsonNode types, final String name, final Set<String> roots)
      throws IOException {
    if (types == null || !types.isArray()) {
      throw new IOException("Malformed serialization types: " + name);
    }
    for (final JsonNode entry : types) {
      NativeImageJsonSupport.requireObject(entry, SERIALIZATION_TYPE, name);
      NativeImageJsonSupport.validateFields(
          entry, Set.of(NAME, CONDITION, CUSTOM_TARGET), SERIALIZATION_TYPE, name);
      NativeImageRootSupport.addRequiredClass(entry.get(NAME), SERIALIZATION_TYPE, name, roots);
      readOptionalClass(entry, CUSTOM_TARGET, name, roots);
      NativeImageRootSupport.readCondition(entry.get(CONDITION), name, roots, false);
    }
  }

  private static void readLambdaTypes(
      final JsonNode types, final String name, final Set<String> roots) throws IOException {
    if (types == null || !types.isArray()) {
      throw new IOException("Malformed lambdaCapturingTypes: " + name);
    }
    for (final JsonNode entry : types) {
      NativeImageJsonSupport.requireObject(entry, "lambda capturing type", name);
      NativeImageJsonSupport.validateFields(
          entry, Set.of(NAME, CONDITION), "lambda capturing type", name);
      NativeImageRootSupport.addRequiredClass(
          entry.get(NAME), "lambda capturing type", name, roots);
      NativeImageRootSupport.readCondition(entry.get(CONDITION), name, roots, false);
    }
  }

  private static void readProxies(
      final JsonNode proxies, final String name, final Set<String> roots) throws IOException {
    if (proxies == null || !proxies.isArray()) {
      throw new IOException("Malformed serialization proxies: " + name);
    }
    for (final JsonNode proxy : proxies) {
      NativeImageJsonSupport.requireObject(proxy, "serialization proxy", name);
      NativeImageJsonSupport.validateFields(
          proxy, Set.of("interfaces", CONDITION), "serialization proxy", name);
      NativeImageRootSupport.readClassArray(proxy.get("interfaces"), name, roots, true);
      NativeImageRootSupport.readCondition(proxy.get(CONDITION), name, roots, false);
    }
  }

  private static void readOptionalClass(
      final JsonNode object, final String field, final String name, final Set<String> roots)
      throws IOException {
    if (object.has(field)) {
      NativeImageRootSupport.addRequiredClass(object.get(field), field, name, roots);
    }
  }
}
