/* WHY: Matches invocation resource patterns without mixing them with descriptor path lookup. */

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/** Applies whole-string Native Image resource selectors to indexed archive entries. */
final class NativeImageResourcePatternMatcher {
  private NativeImageResourcePatternMatcher() {
    throw new AssertionError("static resource pattern matcher");
  }

  /* package */
  static boolean apply(
      final List<Pattern> includes,
      final List<Pattern> excludes,
      final Map<String, List<NativeImageArchiveInventory>> resourceIndex,
      final Set<String> roots,
      final Set<Path> providers)
      throws IOException {
    boolean addedClassRoot = false;
    for (final Map.Entry<String, List<NativeImageArchiveInventory>> resource :
        resourceIndex.entrySet().stream().sorted(Map.Entry.comparingByKey()).toList()) {
      final String resourceName = resource.getKey();
      if (!matchesAny(includes, resourceName) || matchesAny(excludes, resourceName)) {
        continue;
      }
      for (final NativeImageArchiveInventory archive : resource.getValue()) {
        providers.add(archive.path());
        addedClassRoot |= addClassResourceRoot(resourceName, archive, roots);
      }
    }
    return addedClassRoot;
  }

  private static boolean matchesAny(final List<Pattern> patterns, final String resourceName) {
    final String entryName =
        resourceName.endsWith("/")
            ? resourceName.substring(0, resourceName.length() - 1)
            : resourceName;
    return patterns.stream()
        .anyMatch(
            pattern ->
                pattern.matcher(entryName).matches() || pattern.matcher(entryName + "/").matches());
  }

  private static boolean addClassResourceRoot(
      final String resourceName, final NativeImageArchiveInventory archive, final Set<String> roots)
      throws IOException {
    if (!resourceName.endsWith(".class")) {
      return false;
    }
    final String logicalName = MultiReleaseClassInventory.logicalClassName(resourceName);
    final String className =
        logicalName.substring(0, logicalName.length() - ".class".length()).replace('/', '.');
    if (!archive.logicalClasses().contains(className)
        || !NativeImageDynamicRoots.isBinaryClassName(className)) {
      return false;
    }
    roots.add(className);
    return true;
  }
}
