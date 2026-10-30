/* WHY: Maps ResourceBundle names to locale resources while preserving MRJAR providers. */

package io.github.spockz.elider.plugin;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Adds existing bundle classes and all matching archive providers to scan results. */
final class NativeImageBundleResourceSupport {
  private NativeImageBundleResourceSupport() {}

  /* package */
  static void include(
      final Map<String, List<NativeImageArchiveInventory>> resources,
      final String requestedBundle,
      final Set<String> roots,
      final Set<Path> providers) {
    final String bundle = baseName(requestedBundle);
    final String resourceBase = bundle.replace('.', '/');
    for (final Map.Entry<String, List<NativeImageArchiveInventory>> entry : resources.entrySet()) {
      final String logicalResource = logicalResourceName(entry.getKey());
      if (isBundleResource(logicalResource, resourceBase)) {
        for (final NativeImageArchiveInventory archive : entry.getValue()) {
          providers.add(archive.path());
          addClassResourceRoot(logicalResource, archive, roots);
        }
      }
    }
  }

  private static String baseName(final String requestedBundle) {
    final int separator = requestedBundle.indexOf('_');
    if (separator <= 0 || !isLocale(requestedBundle.substring(separator + 1))) {
      return requestedBundle;
    }
    return requestedBundle.substring(0, separator);
  }

  private static boolean isLocale(final String suffix) {
    return suffix.matches("[A-Za-z]{2,3}(_[A-Za-z0-9]{2,8})*");
  }

  private static String logicalResourceName(final String resource) {
    return resource.replaceFirst("^META-INF/versions/[0-9]+/", "");
  }

  private static boolean isBundleResource(final String resource, final String base) {
    final boolean supportedSuffix = resource.endsWith(".properties") || resource.endsWith(".class");
    if (!supportedSuffix || !resource.startsWith(base)) {
      return false;
    }
    final String stem = resource.substring(0, resource.lastIndexOf('.'));
    return stem.equals(base)
        || (stem.startsWith(base + "_") && isLocale(stem.substring(base.length() + 1)));
  }

  private static void addClassResourceRoot(
      final String resource, final NativeImageArchiveInventory archive, final Set<String> roots) {
    if (!resource.endsWith(".class")) {
      return;
    }
    final String className = resource.substring(0, resource.length() - 6).replace('/', '.');
    if (archive.logicalClasses().contains(className)) {
      roots.add(className);
    }
  }
}
