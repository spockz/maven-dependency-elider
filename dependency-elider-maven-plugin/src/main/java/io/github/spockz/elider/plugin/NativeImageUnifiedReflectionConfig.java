/* WHY: Parses class-bearing reflection and lambda descriptors in unified metadata 1.2.0. */

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.util.Set;

/** Reads unified reflection entries and class type descriptors. */
final class NativeImageUnifiedReflectionConfig {
  /** WHY: Unified method descriptors share this property name. */
  private static final String METHOD_NAME = "name";

  /** WHY: Required parameter type roots use one schema key. */
  private static final String PARAMETER_TYPES = "parameterTypes";

  /** WHY: Proxy type descriptors use this section key. */
  private static final String PROXY_TYPE = "proxy";

  private NativeImageUnifiedReflectionConfig() {}

  /* package */
  static void readUnifiedReflection(
      final JsonNode section, final String name, final Set<String> roots) throws IOException {
    if (section == null) {
      return;
    }
    if (!section.isArray()) {
      throw new IOException("Malformed reachability reflection section: " + name);
    }
    for (final JsonNode item : section) {
      readReflectionEntry(item, name, roots);
    }
  }

  private static void readReflectionEntry(
      final JsonNode item, final String name, final Set<String> roots) throws IOException {
    NativeImageJsonSupport.requireObject(item, "reachability reflection entry", name);
    NativeImageJsonSupport.validateFields(
        item,
        Set.of(
            "reason",
            "condition",
            "type",
            "methods",
            "fields",
            "allDeclaredMethods",
            "allDeclaredFields",
            "allDeclaredConstructors",
            "allPublicMethods",
            "allPublicFields",
            "allPublicConstructors",
            "unsafeAllocated",
            "serializable",
            "jniAccessible"),
        "reachability reflection entry",
        name);
    addType(item.get("type"), name, roots);
    NativeImageRootSupport.readCondition(item.get("condition"), name, roots, true);
    readMethods(item.get("methods"), name, roots);
    if (item.has("fields")) {
      readUnifiedFields(item.get("fields"), name);
    }
    NativeImageRootSupport.validateBooleanFields(
        item,
        Set.of(
            "allDeclaredMethods",
            "allDeclaredFields",
            "allDeclaredConstructors",
            "allPublicMethods",
            "allPublicFields",
            "allPublicConstructors",
            "unsafeAllocated",
            "serializable",
            "jniAccessible"),
        name);
    if (item.has("reason")) {
      NativeImageRootSupport.validateStringOrStrings(item.get("reason"), name);
    }
  }

  private static void readMethods(
      final JsonNode methods, final String name, final Set<String> roots) throws IOException {
    if (methods == null) {
      return;
    }
    if (!methods.isArray()) {
      throw new IOException("Malformed reachability methods: " + name);
    }
    for (final JsonNode method : methods) {
      NativeImageJsonSupport.requireObject(method, "method descriptor", name);
      NativeImageJsonSupport.validateFields(
          method, Set.of(METHOD_NAME, PARAMETER_TYPES), "method descriptor", name);
      NativeImageJsonSupport.requireText(method.get(METHOD_NAME), "method name", name);
      readMethodParameters(method.get(PARAMETER_TYPES), name, roots);
    }
  }

  private static void readMethodParameters(
      final JsonNode parameters, final String name, final Set<String> roots) throws IOException {
    if (parameters == null || !parameters.isArray()) {
      throw new IOException("Malformed reachability method parameterTypes: " + name);
    }
    for (final JsonNode parameter : parameters) {
      NativeImageJsonSupport.requireText(parameter, "reachability method parameter type", name);
      final String value = parameter.textValue();
      if (!isTypeName(value)) {
        throw new IOException("Malformed reachability method parameter type: " + name);
      }
      final String component =
          NativeImageTypeDescriptor.requireComponentClass(
              value, "Malformed reachability method parameter type: " + name);
      if (!component.isEmpty()) {
        roots.add(component);
      }
    }
  }

  private static void readUnifiedFields(final JsonNode fields, final String name)
      throws IOException {
    if (!fields.isArray()) {
      throw new IOException("Malformed reachability fields: " + name);
    }
    for (final JsonNode field : fields) {
      NativeImageJsonSupport.requireObject(field, "reachability field descriptor", name);
      NativeImageJsonSupport.validateFields(
          field, Set.of(METHOD_NAME), "reachability field descriptor", name);
      NativeImageJsonSupport.requireText(field.get(METHOD_NAME), "reachability field name", name);
      if (field.get(METHOD_NAME).textValue().matches(".*[.;\\[/].*")) {
        throw new IOException("Malformed reachability field name: " + name);
      }
    }
  }

  private static boolean isTypeName(final String value) {
    return value.matches("[^.;\\[/]+(\\.[^.;\\[/]+)*(\\[\\])*");
  }

  /* package */
  static void addType(final JsonNode type, final String name, final Set<String> roots)
      throws IOException {
    if (type == null) {
      throw new IOException("Missing native-image type descriptor: " + name);
    }
    if (type.isTextual()) {
      addTextType(type.textValue(), name, roots);
      return;
    }
    NativeImageJsonSupport.requireObject(type, "type descriptor", name);
    NativeImageJsonSupport.validateFields(
        type, Set.of(PROXY_TYPE, "lambda"), "type descriptor", name);
    if (type.has(PROXY_TYPE) == type.has("lambda")) {
      throw new IOException("Malformed native-image type descriptor: " + name);
    }
    if (type.has(PROXY_TYPE)) {
      readProxyType(type.get(PROXY_TYPE), name, roots);
    } else {
      readLambdaType(type.get("lambda"), name, roots);
    }
  }

  private static void addTextType(final String value, final String name, final Set<String> roots)
      throws IOException {
    if (!isTypeName(value)) {
      throw new IOException("Malformed native-image type descriptor: " + name);
    }
    final String component = NativeImageTypeDescriptor.extractComponentClass(value);
    if (component == null) {
      throw new IOException("Malformed native-image type descriptor: " + name);
    }
    if (!component.isEmpty()) {
      roots.add(component);
    }
  }

  private static void readProxyType(
      final JsonNode proxy, final String name, final Set<String> roots) throws IOException {
    NativeImageRootSupport.readClassArray(proxy, name, roots, true);
  }

  private static void readLambdaType(
      final JsonNode lambda, final String name, final Set<String> roots) throws IOException {
    NativeImageJsonSupport.requireObject(lambda, "lambda descriptor", name);
    NativeImageJsonSupport.validateFields(
        lambda,
        Set.of("declaringClass", "declaringMethod", "interfaces"),
        "lambda descriptor",
        name);
    NativeImageRootSupport.addRequiredClass(
        lambda.get("declaringClass"), "lambda declaring class", name, roots);
    NativeImageRootSupport.readClassArray(lambda.get("interfaces"), name, roots, true);
    if (lambda.has("declaringMethod")) {
      final JsonNode method = lambda.get("declaringMethod");
      NativeImageJsonSupport.requireObject(method, "lambda method descriptor", name);
      NativeImageJsonSupport.validateFields(
          method, Set.of(METHOD_NAME, PARAMETER_TYPES), "lambda method descriptor", name);
      NativeImageJsonSupport.requireText(method.get(METHOD_NAME), "lambda method name", name);
      readMethodParameters(method.get(PARAMETER_TYPES), name, roots);
    }
  }
}
