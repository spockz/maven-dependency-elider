/* WHY: Detects JAR signature metadata and removes manifest digests invalidated by class pruning. */

package io.github.spockz.elider.trimmer;

import java.io.IOException;
import java.util.Locale;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;

/** Package-local helpers for signature and manifest sanitation. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class JarSignatureSanitizer {
  /** Prefix containing standard JAR signing metadata. */
  private static final String MANIFEST_PREFIX = "META-INF/";

  /** Standard manifest entry path. */
  private static final String MANIFEST_ENTRY = MANIFEST_PREFIX + "MANIFEST.MF";

  private JarSignatureSanitizer() {}

  /** Matches the JAR manifest entry case-insensitively. */
  static boolean isManifest(final String entryName) {
    return MANIFEST_ENTRY.equalsIgnoreCase(entryName);
  }

  /** Identifies top-level JAR signature files. */
  static boolean isSignatureFile(final String entryName) {
    final String normalized = entryName.toUpperCase(Locale.ROOT);
    if (!normalized.startsWith(MANIFEST_PREFIX)
        || normalized.substring(MANIFEST_PREFIX.length()).contains("/")) {
      return false;
    }
    return normalized.endsWith(".SF")
        || normalized.endsWith(".DSA")
        || normalized.endsWith(".RSA")
        || normalized.endsWith(".EC")
        || normalized.substring(MANIFEST_PREFIX.length()).startsWith("SIG-");
  }

  /** Removes digest attributes invalidated by rewritten class contents. */
  static void cleanse(final Manifest manifest) {
    removeDigestAttributes(manifest.getMainAttributes());
    manifest.getEntries().values().forEach(JarSignatureSanitizer::removeDigestAttributes);
    manifest.getEntries().entrySet().removeIf(entry -> entry.getValue().isEmpty());
  }

  /** Writes a sanitized manifest while preserving its source timestamp. */
  static void writeManifest(
      final JarOutputStream output, final JarEntry original, final Manifest manifest)
      throws IOException {
    final JarEntry copy = new JarEntry(original.getName());
    if (original.getTime() >= 0) {
      copy.setTime(original.getTime());
    }
    output.putNextEntry(copy);
    manifest.write(output);
    output.closeEntry();
  }

  private static void removeDigestAttributes(final Map<Object, Object> attributes) {
    attributes.keySet().removeIf(key -> isDigestAttribute(key.toString().toUpperCase(Locale.ROOT)));
  }

  private static boolean isDigestAttribute(final String attributeName) {
    return attributeName.contains("-DIGEST");
  }
}
