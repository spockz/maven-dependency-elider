/* WHY: Maps ResourceBundle names to locale resources while preserving MRJAR providers. */

package io.github.spockz.elider.plugin;

import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/** Adds existing bundle classes and all matching archive providers to scan results. */
final class NativeImageBundleResourceSupport {
  /** WHY: Bundle names become resource paths and must not form path traversal. */
  private static final Pattern BUNDLE_NAME =
      Pattern.compile("[\\p{L}\\p{N}_$-]+(?:\\.[\\p{L}\\p{N}_$-]+)*");

  private NativeImageBundleResourceSupport() {}

  /* package */ static boolean isBundleName(final String name) {
    return name != null && BUNDLE_NAME.matcher(name).matches();
  }

  /* package */
  static void include(
      final Map<String, List<NativeImageArchiveInventory>> resources,
      final String requestedBundle,
      final Set<String> roots,
      final Set<Path> providers) {
    for (final String family : bundleFamilies(requestedBundle)) {
      final String resourceBase = family.replace('.', '/');
      for (final Map.Entry<String, List<NativeImageArchiveInventory>> entry :
          resources.entrySet()) {
        final String logicalResource = logicalResourceName(entry.getKey());
        if (isBundleResource(logicalResource, resourceBase)) {
          for (final NativeImageArchiveInventory archive : entry.getValue()) {
            providers.add(archive.path());
            addClassResourceRoot(logicalResource, archive, roots);
          }
        }
      }
    }
  }

  /* package */ static boolean matches(final String requestedBundle, final String resource) {
    final String logicalResource = logicalResourceName(resource);
    return bundleFamilies(requestedBundle).stream()
        .map(family -> family.replace('.', '/'))
        .anyMatch(base -> isBundleResource(logicalResource, base));
  }

  private static Set<String> bundleFamilies(final String requestedBundle) {
    final Set<String> families = new LinkedHashSet<>();
    families.add(lastComponentBaseName(requestedBundle));
    families.add(baseName(requestedBundle));
    return families;
  }

  private static String lastComponentBaseName(final String requestedBundle) {
    final int packageSeparator = requestedBundle.lastIndexOf('.');
    final int localeSeparator = requestedBundle.indexOf('_', packageSeparator + 1);
    return localeSeparator < 0 ? requestedBundle : requestedBundle.substring(0, localeSeparator);
  }

  private static String baseName(final String requestedBundle) {
    final int separator = requestedBundle.indexOf('_');
    if (separator < 0) {
      return requestedBundle;
    }
    return requestedBundle.substring(0, separator);
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
    if (stem.equals(base)) {
      return true;
    }
    if (!stem.startsWith(base + "_") || stem.length() <= base.length() + 1) {
      return false;
    }
    return stem.indexOf('/', base.length() + 1) < 0;
  }

  private static void addClassResourceRoot(
      final String resource, final NativeImageArchiveInventory archive, final Set<String> roots) {
    if (!resource.endsWith(".class")) {
      return;
    }
    final String className = resource.substring(0, resource.length() - 6).replace('/', '.');
    if (NativeImageDynamicRoots.isBinaryClassName(className)
        && archive.logicalClasses().contains(className)) {
      roots.add(className);
    }
  }
}
