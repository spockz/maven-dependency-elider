/* WHY: Centralizes the legacy class/array syntax used by native-image metadata. */

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.util.Set;

/** Extracts component classes while rejecting malformed descriptors. */
final class NativeImageTypeDescriptor {
  /** Java primitives contribute no class roots. */
  private static final Set<String> PRIMITIVES =
      Set.of("boolean", "byte", "char", "short", "int", "long", "float", "double", "void");

  /** JVM primitive descriptors contribute no class roots. */
  private static final Set<Character> PRIMITIVE_DESCRIPTORS =
      Set.of('Z', 'B', 'C', 'S', 'I', 'J', 'F', 'D', 'V');

  private NativeImageTypeDescriptor() {}

  /* package */
  static String extractComponentClass(final String value) {
    if (value == null || value.isBlank()) {
      return null;
    }
    final String trimmed = value.trim();
    if (trimmed.startsWith("[")) {
      return extractJvmArrayClass(trimmed);
    }
    if (trimmed.endsWith("[]")) {
      return extractJavaArrayClass(trimmed);
    }
    return extractScalarClass(trimmed);
  }

  /* package */
  static String requireComponentClass(final String value, final String errorMessage)
      throws IOException {
    final String component = extractComponentClass(value);
    if (component == null) {
      throw new IOException(errorMessage);
    }
    return component;
  }

  private static String extractJvmArrayClass(final String value) {
    int index = 0;
    while (index < value.length() && value.charAt(index) == '[') {
      index++;
    }
    final String element = value.substring(index);
    if (element.startsWith("L") && element.endsWith(";") && element.length() > 2) {
      return validateClassName(element.substring(1, element.length() - 1).replace('/', '.'));
    }
    if (element.length() == 1
        && PRIMITIVE_DESCRIPTORS.contains(element.charAt(0))
        && element.charAt(0) != 'V') {
      return "";
    }
    return null;
  }

  private static String extractJavaArrayClass(final String value) {
    String element = value;
    while (element.endsWith("[]")) {
      element = element.substring(0, element.length() - 2);
    }
    if (isPrimitive(element)) {
      return "void".equals(element) ? null : "";
    }
    return validateClassName(element);
  }

  private static String extractScalarClass(final String value) {
    if (isPrimitive(value)) {
      return "";
    }
    return validateClassName(value);
  }

  private static boolean isPrimitive(final String value) {
    return PRIMITIVES.contains(value);
  }

  private static String validateClassName(final String value) {
    return NativeImageDynamicRoots.isBinaryClassName(value) ? value : null;
  }
}
