/* WHY: Parses standalone reflection, JNI, and proxy descriptors into explicit class roots. */

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.util.Set;

/** Reads standalone reflection/JNI arrays and dynamic proxy entries. */
final class NativeImageReflectionConfig {
  /** WHY: Pinned standalone reflection schemas require the name field. */
  private static final String NAME_FIELD = "name";

  /** WHY: Conditions share one key across reflection and proxy entries. */
  private static final String CONDITION_FIELD = "condition";

  private NativeImageReflectionConfig() {}

  /* package */
  static void read(
      final JsonNode document,
      final String name,
      final NativeImageDescriptorKind kind,
      final Set<String> roots)
      throws IOException {
    if (!document.isArray()) {
      throw new IOException("Malformed native-image reflection configuration: " + name);
    }
    for (final JsonNode element : document) {
      if (kind == NativeImageDescriptorKind.PROXY) {
        readProxy(element, name, roots);
      } else if (kind == NativeImageDescriptorKind.REFLECTION) {
        readStandaloneReflection(element, name, roots);
      } else {
        throw new IOException("Unsupported native-image class configuration: " + name);
      }
    }
  }

  private static void readStandaloneReflection(
      final JsonNode element, final String name, final Set<String> roots) throws IOException {
    NativeImageJsonSupport.requireObject(element, "reflect entry", name);
    NativeImageJsonSupport.validateFields(
        element,
        Set.of(
            NAME_FIELD,
            CONDITION_FIELD,
            "methods",
            "queriedMethods",
            "fields",
            "allDeclaredMethods",
            "allDeclaredFields",
            "allDeclaredConstructors",
            "allPublicMethods",
            "allPublicFields",
            "allPublicConstructors",
            "allDeclaredClasses",
            "allRecordComponents",
            "allPermittedSubclasses",
            "allPublicClasses",
            "allNestMembers",
            "allSigners",
            "queryAllDeclaredConstructors",
            "queryAllPublicConstructors",
            "queryAllDeclaredMethods",
            "queryAllPublicMethods",
            "unsafeAllocated"),
        "reflect entry",
        name);
    final JsonNode type = element.get(NAME_FIELD);
    if (type == null) {
      throw new IOException("Reflect configuration lacks a valid class name: " + name);
    }
    NativeImageRootSupport.addStandaloneType(type, name, roots);
    NativeImageRootSupport.readCondition(element.get(CONDITION_FIELD), name, roots, false);
    readLegacyMethods(element.get("methods"), name, roots);
    readLegacyMethods(element.get("queriedMethods"), name, roots);
    readLegacyFields(element.get("fields"), name);
    NativeImageRootSupport.validateBooleanFields(
        element,
        Set.of(
            "allDeclaredMethods",
            "allDeclaredFields",
            "allDeclaredConstructors",
            "allPublicMethods",
            "allPublicFields",
            "allPublicConstructors",
            "allDeclaredClasses",
            "allRecordComponents",
            "allPermittedSubclasses",
            "allPublicClasses",
            "allNestMembers",
            "allSigners",
            "queryAllDeclaredConstructors",
            "queryAllPublicConstructors",
            "queryAllDeclaredMethods",
            "queryAllPublicMethods",
            "unsafeAllocated"),
        name);
  }

  private static void readLegacyMethods(
      final JsonNode methods, final String name, final Set<String> roots) throws IOException {
    if (methods == null) {
      return;
    }
    if (!methods.isArray()) {
      throw new IOException("Malformed reflection methods: " + name);
    }
    for (final JsonNode method : methods) {
      NativeImageJsonSupport.requireObject(method, "method descriptor", name);
      NativeImageJsonSupport.validateFields(
          method, Set.of(NAME_FIELD, "parameterTypes"), "method descriptor", name);
      NativeImageJsonSupport.requireText(method.get(NAME_FIELD), "method name", name);
      NativeImageRootSupport.readTypeArray(method.get("parameterTypes"), name, roots, true);
    }
  }

  private static void readLegacyFields(final JsonNode fields, final String name)
      throws IOException {
    if (fields == null) {
      return;
    }
    if (!fields.isArray()) {
      throw new IOException("Malformed reflection fields: " + name);
    }
    for (final JsonNode field : fields) {
      NativeImageJsonSupport.requireObject(field, "field descriptor", name);
      NativeImageJsonSupport.validateFields(
          field, Set.of(NAME_FIELD, "allowWrite", "allowUnsafeAccess"), "field descriptor", name);
      NativeImageJsonSupport.requireText(field.get(NAME_FIELD), "field name", name);
      NativeImageRootSupport.validateBooleanFields(
          field, Set.of("allowWrite", "allowUnsafeAccess"), name);
    }
  }

  private static void readProxy(final JsonNode element, final String name, final Set<String> roots)
      throws IOException {
    if (element.isArray()) {
      NativeImageRootSupport.readClassArray(element, name, roots, true);
      return;
    }
    NativeImageJsonSupport.requireObject(element, "proxy entry", name);
    NativeImageJsonSupport.validateFields(
        element, Set.of(CONDITION_FIELD, "interfaces"), "proxy entry", name);
    NativeImageRootSupport.readCondition(element.get(CONDITION_FIELD), name, roots, false);
    NativeImageRootSupport.readClassArray(element.get("interfaces"), name, roots, true);
  }
}
