/* WHY: Validates native-image resource and bundle configuration. */

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.io.InputStream;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/** Validates supported native-image metadata. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class NativeImageResourceConfig {
  private NativeImageResourceConfig() {}

  static boolean isNativeImageResourceConfig(final String name) {
    return name.endsWith("resource-config.json") || name.endsWith("-resource.json");
  }

  static void readNativeImageResourceConfig(
      final JarFile archive, final String name, final Set<String> roots) throws IOException {
    final JarEntry entry = archive.getJarEntry(name);
    if (entry == null || entry.isDirectory()) {
      throw new IOException("Native-image resource configuration is missing: " + name);
    }
    try (InputStream input = archive.getInputStream(entry)) {
      NativeImageResourceDocument.read(input, name, roots);
    }
  }
}
