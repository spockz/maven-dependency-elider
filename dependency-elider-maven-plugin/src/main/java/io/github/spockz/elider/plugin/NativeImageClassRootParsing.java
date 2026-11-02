/* WHY: Centralizes strict class-name parsing and package expansion for modeled options. */

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;
import java.util.jar.JarEntry;

/** Parses direct class roots and expands package selectors from indexed classes. */
final class NativeImageClassRootParsing {
  private NativeImageClassRootParsing() {}

  /* package */
  static boolean readNamedList(
      final String values, final JarEntry propertiesEntry, final Set<String> roots)
      throws IOException {
    roots.addAll(parseClassNames(values, propertiesEntry));
    return true;
  }

  /* package */
  static boolean readSingleClass(
      final String value, final JarEntry propertiesEntry, final Set<String> roots)
      throws IOException {
    final Set<String> names = parseClassNames(value, propertiesEntry);
    if (names.size() != 1 || value.contains(",")) {
      throw malformedClassList(propertiesEntry, value);
    }
    roots.add(names.iterator().next());
    return true;
  }

  /* package */
  static boolean readResourceBundles(
      final String values,
      final JarEntry propertiesEntry,
      final Set<String> roots,
      final NativeImageScanContext scanContext,
      final Set<java.nio.file.Path> resourceProviders)
      throws IOException {
    if (values.isBlank()) {
      throw malformedClassList(propertiesEntry, values);
    }
    for (final String value : values.split(",", -1)) {
      final String bundle = value.trim();
      if (!NativeImageBundleResourceSupport.isBundleName(bundle)) {
        throw malformedClassList(propertiesEntry, bundle);
      }
      NativeImageBundleResourceSupport.include(
          scanContext.resourceIndex(), bundle, roots, resourceProviders);
    }
    return true;
  }

  /* package */
  static Set<String> parseClassNames(final String values, final JarEntry propertiesEntry)
      throws IOException {
    if (values.isBlank()) {
      throw malformedClassList(propertiesEntry, values);
    }
    final Set<String> classNames = new LinkedHashSet<>();
    for (final String value : values.split(",", -1)) {
      final String className = value.trim();
      if (className.isEmpty() || !NativeImageDynamicRoots.isBinaryClassName(className)) {
        throw malformedClassList(propertiesEntry, className);
      }
      classNames.add(className);
    }
    return classNames;
  }

  /* package */
  static boolean addTargets(
      final Set<String> targets, final Set<String> roots, final NativeImageScanContext scanContext)
      throws IOException {
    for (final String target : targets) {
      for (final String className : scanContext.logicalClasses(Optional.empty())) {
        if (className.equals(target) || className.startsWith(target + ".")) {
          roots.add(className);
        }
      }
    }
    return true;
  }

  /* package */
  static boolean addWholeInventory(
      final NativeImageScanContext scanContext, final Set<String> roots) throws IOException {
    final Set<String> logicalClasses = scanContext.logicalClasses(Optional.empty());
    roots.addAll(logicalClasses);
    return !logicalClasses.isEmpty();
  }

  private static IOException malformedClassList(
      final JarEntry propertiesEntry, final String value) {
    return new IOException(
        "Unsupported native-image class name in " + propertiesEntry.getName() + ": " + value);
  }
}
