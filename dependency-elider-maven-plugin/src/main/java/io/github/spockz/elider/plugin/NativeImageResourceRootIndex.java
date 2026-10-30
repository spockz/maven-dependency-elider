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
    final String prefix = resourceRootPrefix(root, propertiesEntry);
    final List<String> resources =
        resourcesByPath.keySet().stream()
            .filter(resource -> resource.startsWith(prefix))
            .sorted()
            .toList();
    if (resources.isEmpty()) {
      throw new IOException("Native-image configuration resource root is missing: " + root);
    }
    return resources.stream()
        .filter(
            resource ->
                NativeImageDescriptorKind.classConfigFor(resource) != null
                    || NativeImageResourceConfig.isNativeImageResourceConfig(resource))
        .toList();
  }

  private static String resourceRootPrefix(final String root, final JarEntry propertiesEntry)
      throws IOException {
    final String normalized = root.endsWith("/") ? root.substring(0, root.length() - 1) : root;
    if (normalized.isBlank()
        || normalized.startsWith("/")
        || normalized.contains("\\")
        || java.util.Arrays.stream(normalized.split("/", -1))
            .anyMatch(
                segment -> segment.isBlank() || ".".equals(segment) || "..".equals(segment))) {
      throw new IOException(
          "Unsupported native-image configuration resource root in "
              + propertiesEntry.getName()
              + ": "
              + root);
    }
    return normalized + "/";
  }
}
