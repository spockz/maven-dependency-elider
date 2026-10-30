/* WHY: Validates deny metadata while deliberately keeping all names out of positive roots. */

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

/** Reads serialization-deny standalone formats without producing roots. */
final class NativeImageSerializationDenyConfig {
  /** WHY: Deny object and legacy entries share the selected parser's name field. */
  private static final String NAME = "name";

  /** WHY: Conditions are validated while all deny references remain non-roots. */
  private static final String CONDITION = "condition";

  /** WHY: Validate this field while discarding all deny roots. */
  private static final String CUSTOM_TARGET = "customTargetConstructorClass";

  /** WHY: Both supported deny forms accept this optional type section. */
  private static final String LAMBDA_TYPES = "lambdaCapturingTypes";

  /** WHY: Proxy interfaces are validated but never promoted to positive roots. */
  private static final String PROXIES = "proxies";

  /** WHY: Deny validation uses one consistent type diagnostic. */
  private static final String DENY_TYPE = "serialization-deny type";

  private NativeImageSerializationDenyConfig() {}

  /* package */
  static void read(final JsonNode document, final String name) throws IOException {
    final Set<String> ignoredReferences = new HashSet<>();
    if (document.isArray()) {
      for (final JsonNode entry : document) {
        readLegacyEntry(entry, name, ignoredReferences);
      }
      return;
    }
    NativeImageJsonSupport.requireObject(document, "serialization-deny configuration", name);
    NativeImageJsonSupport.validateFields(
        document, Set.of("types", LAMBDA_TYPES, PROXIES), "serialization-deny configuration", name);
    if (document.has("types")) {
      readTypes(document.get("types"), name, ignoredReferences);
    }
    if (document.has(LAMBDA_TYPES)) {
      readLambdaTypes(document.get(LAMBDA_TYPES), name, ignoredReferences);
    }
    if (document.has(PROXIES)) {
      readProxies(document.get(PROXIES), name, ignoredReferences);
    }
  }

  private static void readLegacyEntry(
      final JsonNode entry, final String name, final Set<String> ignoredReferences)
      throws IOException {
    NativeImageJsonSupport.requireObject(entry, "serialization-deny entry", name);
    NativeImageJsonSupport.validateFields(
        entry,
        Set.of(NAME, CONDITION, PROXIES, LAMBDA_TYPES, CUSTOM_TARGET),
        "serialization-deny entry",
        name);
    NativeImageRootSupport.addRequiredClass(entry.get(NAME), DENY_TYPE, name, ignoredReferences);
    readOptionalClass(entry, CUSTOM_TARGET, name, ignoredReferences);
    NativeImageRootSupport.readCondition(entry.get(CONDITION), name, ignoredReferences, false);
    if (entry.has(PROXIES)) {
      readProxies(entry.get(PROXIES), name, ignoredReferences);
    }
    if (entry.has(LAMBDA_TYPES)) {
      readLambdaTypes(entry.get(LAMBDA_TYPES), name, ignoredReferences);
    }
  }

  private static void readTypes(
      final JsonNode types, final String name, final Set<String> ignoredReferences)
      throws IOException {
    if (types == null || !types.isArray()) {
      throw new IOException("Malformed serialization-deny types: " + name);
    }
    for (final JsonNode entry : types) {
      NativeImageJsonSupport.requireObject(entry, DENY_TYPE, name);
      NativeImageJsonSupport.validateFields(
          entry, Set.of(NAME, CONDITION, CUSTOM_TARGET), DENY_TYPE, name);
      NativeImageRootSupport.addRequiredClass(entry.get(NAME), DENY_TYPE, name, ignoredReferences);
      readOptionalClass(entry, CUSTOM_TARGET, name, ignoredReferences);
      NativeImageRootSupport.readCondition(entry.get(CONDITION), name, ignoredReferences, false);
    }
  }

  private static void readLambdaTypes(
      final JsonNode types, final String name, final Set<String> ignoredReferences)
      throws IOException {
    if (types == null || !types.isArray()) {
      throw new IOException("Malformed serialization-deny lambdaCapturingTypes: " + name);
    }
    for (final JsonNode entry : types) {
      NativeImageJsonSupport.requireObject(entry, "serialization-deny lambda type", name);
      NativeImageJsonSupport.validateFields(
          entry, Set.of(NAME, CONDITION), "serialization-deny lambda type", name);
      NativeImageRootSupport.addRequiredClass(
          entry.get(NAME), "serialization-deny lambda type", name, ignoredReferences);
      NativeImageRootSupport.readCondition(entry.get(CONDITION), name, ignoredReferences, false);
    }
  }

  private static void readOptionalClass(
      final JsonNode entry,
      final String field,
      final String name,
      final Set<String> ignoredReferences)
      throws IOException {
    if (entry.has(field)) {
      NativeImageRootSupport.addRequiredClass(
          entry.get(field), "serialization-deny constructor class", name, ignoredReferences);
    }
  }

  private static void readProxies(
      final JsonNode proxies, final String name, final Set<String> ignoredReferences)
      throws IOException {
    if (proxies == null || !proxies.isArray()) {
      throw new IOException("Malformed serialization-deny proxies: " + name);
    }
    for (final JsonNode proxy : proxies) {
      NativeImageJsonSupport.requireObject(proxy, "serialization-deny proxy", name);
      NativeImageJsonSupport.validateFields(
          proxy, Set.of("interfaces", CONDITION), "serialization-deny proxy", name);
      NativeImageRootSupport.readClassArray(proxy.get("interfaces"), name, ignoredReferences, true);
      NativeImageRootSupport.readCondition(proxy.get(CONDITION), name, ignoredReferences, false);
    }
  }
}
