/* WHY: Foreign call options vary by call direction. */

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.util.Set;

/** Reads unified foreign downcalls, upcalls, and direct-upcall classes. */
final class NativeImageUnifiedForeignConfig {
  /** WHY: Upcalls and downcalls share the same condition field. */
  private static final String CONDITION = "condition";

  /** WHY: Options are validated according to the call direction. */
  private static final String OPTIONS = "options";

  /** WHY: Reachability reason metadata has one schema key. */
  private static final String REASON = "reason";

  /** WHY: Foreign call descriptors use one return type key. */
  private static final String RETURN_TYPE = "returnType";

  private NativeImageUnifiedForeignConfig() {}

  /* package */
  static void readUnifiedForeign(final JsonNode foreign, final String name, final Set<String> roots)
      throws IOException {
    if (foreign == null) {
      return;
    }
    NativeImageJsonSupport.requireObject(foreign, "foreign section", name);
    NativeImageJsonSupport.validateFields(
        foreign, Set.of("downcalls", "upcalls", "directUpcalls"), "foreign section", name);
    for (final String key : Set.of("downcalls", "upcalls")) {
      readForeignFunctionArray(foreign.get(key), key, name, roots);
    }
    final JsonNode direct = foreign.get("directUpcalls");
    if (direct != null) {
      if (!direct.isArray()) {
        throw new IOException("Malformed foreign directUpcalls: " + name);
      }
      for (final JsonNode entry : direct) {
        NativeImageJsonSupport.requireObject(entry, "foreign direct-upcall", name);
        NativeImageJsonSupport.validateFields(
            entry,
            Set.of(REASON, CONDITION, "class", "method", RETURN_TYPE, "parameterTypes", OPTIONS),
            "foreign direct-upcall",
            name);
        NativeImageRootSupport.addRequiredClass(
            entry.get("class"), "foreign direct-upcall class", name, roots);
        NativeImageJsonSupport.requireText(
            entry.get("method"), "foreign direct-upcall method", name);
        NativeImageRootSupport.readCondition(entry.get("condition"), name, roots, true);
        validateForeignTypes(entry, name, false, true);
        validateReason(entry, name);
      }
    }
  }

  private static void readForeignFunctionArray(
      final JsonNode array, final String key, final String name, final Set<String> roots)
      throws IOException {
    if (array == null) {
      return;
    }
    if (!array.isArray()) {
      throw new IOException("Malformed foreign " + key + ": " + name);
    }
    for (final JsonNode entry : array) {
      NativeImageJsonSupport.requireObject(entry, "foreign function", name);
      NativeImageJsonSupport.validateFields(
          entry,
          Set.of(REASON, CONDITION, RETURN_TYPE, "parameterTypes", OPTIONS),
          "foreign function",
          name);
      NativeImageRootSupport.readCondition(entry.get("condition"), name, roots, true);
      final boolean downcall = "downcalls".equals(key);
      validateForeignTypes(entry, name, true, !downcall);
      validateReason(entry, name);
    }
  }

  private static void validateReason(final JsonNode entry, final String name) throws IOException {
    if (entry.has(REASON)) {
      NativeImageRootSupport.validateStringOrStrings(entry.get(REASON), name);
    }
  }

  private static void validateForeignTypes(
      final JsonNode entry, final String name, final boolean required, final boolean emptyOptions)
      throws IOException {
    validateReturnType(entry, name, required);
    validateParameterTypes(entry.get("parameterTypes"), name, required);
    if (entry.has(OPTIONS)) {
      validateForeignOptions(entry.get(OPTIONS), name, emptyOptions);
    }
  }

  private static void validateReturnType(
      final JsonNode entry, final String name, final boolean required) throws IOException {
    if (required || entry.has(RETURN_TYPE)) {
      NativeImageJsonSupport.requireText(entry.get(RETURN_TYPE), "foreign returnType", name);
    }
  }

  private static void validateParameterTypes(
      final JsonNode parameters, final String name, final boolean required) throws IOException {
    if (parameters == null) {
      if (required) {
        throw new IOException("Malformed foreign parameterTypes: " + name);
      }
      return;
    }
    if (!parameters.isArray()) {
      throw new IOException("Malformed foreign parameterTypes: " + name);
    }
    for (final JsonNode parameter : parameters) {
      NativeImageJsonSupport.requireText(parameter, "foreign parameter type", name);
    }
  }

  private static void validateForeignOptions(
      final JsonNode options, final String name, final boolean emptyOnly) throws IOException {
    NativeImageJsonSupport.requireObject(options, "foreign options", name);
    if (emptyOnly) {
      if (!options.isEmpty()) {
        throw new IOException("Unsupported foreign options: " + name);
      }
      return;
    }
    NativeImageJsonSupport.validateFields(
        options,
        Set.of("captureCallState", "critical", "firstVariadicArg"),
        "foreign options",
        name);
    validateOptionalBoolean(
        options, "captureCallState", "Malformed foreign captureCallState", name);
    validateOptionalInteger(options, "firstVariadicArg", name);
    readCriticalOption(options.get("critical"), name);
  }

  private static void validateOptionalBoolean(
      final JsonNode object, final String field, final String message, final String name)
      throws IOException {
    if (object.has(field) && !object.get(field).isBoolean()) {
      throw new IOException(message + ": " + name);
    }
  }

  private static void validateOptionalInteger(
      final JsonNode object, final String field, final String name) throws IOException {
    if (object.has(field) && !object.get(field).isIntegralNumber()) {
      throw new IOException("Malformed foreign " + field + ": " + name);
    }
  }

  private static void readCriticalOption(final JsonNode critical, final String name)
      throws IOException {
    if (critical == null) {
      return;
    }
    NativeImageJsonSupport.requireObject(critical, "foreign critical option", name);
    NativeImageJsonSupport.validateFields(
        critical, Set.of("allowHeapAccess"), "foreign critical option", name);
    validateOptionalBoolean(critical, "allowHeapAccess", "Malformed foreign allowHeapAccess", name);
  }
}
