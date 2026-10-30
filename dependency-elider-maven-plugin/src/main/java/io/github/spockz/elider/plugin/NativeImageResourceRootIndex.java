/* WHY: Validates exact classpath root boundaries before selecting metadata entries. */

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.jar.JarEntry;

/** Finds recognized descriptors below an exact resource-root prefix. */
/* package */ final class NativeImageResourceRootIndex {
  private NativeImageResourceRootIndex() {}

  /* package */ static List<String> descriptorsUnder(
      final Map<String, List<NativeImageArchiveInventory>> resourcesByPath,
      final String root,
      final JarEntry propertiesEntry)
      throws IOException {
    final String resolvedRoot = expandDescriptorRelativeRoot(root, propertiesEntry);
    final String prefix = resourceRootPrefix(resolvedRoot, propertiesEntry);
    final List<String> resources =
        resourcesByPath.keySet().stream()
            .filter(resource -> resource.startsWith(prefix))
            .sorted()
            .toList();
    if (resources.isEmpty()) {
      if (prefix.isEmpty()) {
        return List.of();
      }
      throw new IOException("Native-image configuration resource root is missing: " + root);
    }
    return resources.stream()
        .filter(
            resource ->
                NativeImageDescriptorKind.classConfigFor(resource) != null
                    || NativeImageResourceConfig.isNativeImageResourceConfig(resource))
        .toList();
  }

  private static String expandDescriptorRelativeRoot(
      final String root, final JarEntry propertiesEntry) {
    if (!root.contains("${.}")) {
      return root;
    }
    final String name = propertiesEntry.getName();
    final int parentEnd = name.lastIndexOf('/');
    final String parent = parentEnd < 0 ? "" : name.substring(0, parentEnd);
    return root.replace("${.}", parent);
  }

  private static String resourceRootPrefix(final String root, final JarEntry propertiesEntry)
      throws IOException {
    if (root.contains("\\")) {
      throw new IOException(
          "Unsupported native-image configuration resource root in "
              + propertiesEntry.getName()
              + ": "
              + root);
    }
    final List<String> segments =
        java.util.Arrays.stream(root.split("/", -1))
            .filter(segment -> !segment.isEmpty() && !".".equals(segment))
            .toList();
    if (segments.stream().anyMatch(".."::equals)) {
      throw new IOException(
          "Unsupported native-image configuration resource root in "
              + propertiesEntry.getName()
              + ": "
              + root);
    }
    return segments.isEmpty() ? "" : String.join("/", segments) + "/";
  }
}
