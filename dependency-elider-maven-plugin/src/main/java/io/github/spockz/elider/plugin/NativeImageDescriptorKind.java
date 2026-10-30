/* WHY: Separates audited descriptor schemas from the filenames used to discover them. */

package io.github.spockz.elider.plugin;

/** Identifies the parser contract for a native-image descriptor input. */
enum NativeImageDescriptorKind {
  REFLECTION,
  PROXY,
  SERIALIZATION,
  PREDEFINED_CLASSES,
  REACHABILITY_METADATA,
  SERIALIZATION_DENY,
  OBJECT_INLINING,
  FOREIGN,
  RESOURCES;

  /* package */
  static NativeImageDescriptorKind classConfigFor(final String name) {
    if (NativeImageClassConfig.isReflectionConfig(name)) {
      return REFLECTION;
    }
    if (name.endsWith("proxy-config.json")) {
      return PROXY;
    }
    if (name.endsWith("serialization-config.json")) {
      return SERIALIZATION;
    }
    if (name.endsWith("predefined-classes-config.json")) {
      return PREDEFINED_CLASSES;
    }
    if (name.endsWith("reachability-metadata.json")) {
      return REACHABILITY_METADATA;
    }
    if (name.endsWith("serialization-deny-config.json")) {
      return SERIALIZATION_DENY;
    }
    if (name.endsWith("object-inlining-config.json")) {
      return OBJECT_INLINING;
    }
    if (name.endsWith("foreign-config.json")) {
      return FOREIGN;
    }
    return null;
  }

  /* package */
  static NativeImageDescriptorKind resourceConfigFor(final String name) {
    if (NativeImageResourceConfig.isNativeImageResourceConfig(name)) {
      return RESOURCES;
    }
    return null;
  }
}
