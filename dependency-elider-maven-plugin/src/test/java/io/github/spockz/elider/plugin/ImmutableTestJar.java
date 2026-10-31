// WHY: Reuses serialized fixture archive bytes while writing each test archive to its own path.

package io.github.spockz.elider.plugin;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

/** WHY: Reuses serialized fixture JAR bytes. */
final class ImmutableTestJar {
  /** WHY: Holds reusable archive bytes by content. */
  private static final ConcurrentMap<Map<String, String>, byte[]> ARCHIVES =
      new ConcurrentHashMap<>();

  private ImmutableTestJar() {}

  /** WHY: Writes a fresh file copy of cached archive bytes. */
  /* package */ static Path write(final Path path, final Map<String, byte[]> entries)
      throws IOException {
    final Map<String, String> key =
        entries.entrySet().stream()
            .collect(
                java.util.stream.Collectors.toUnmodifiableMap(
                    Map.Entry::getKey,
                    entry -> Base64.getEncoder().encodeToString(entry.getValue())));
    final byte[] archive = ARCHIVES.computeIfAbsent(key, ImmutableTestJar::serialize);
    Files.write(path, archive);
    return path;
  }

  private static byte[] serialize(final Map<String, String> entries) {
    try {
      final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
      try (JarOutputStream output = new JarOutputStream(bytes)) {
        for (final Map.Entry<String, String> entry : new TreeMap<>(entries).entrySet()) {
          writeEntry(output, entry);
        }
      }
      return bytes.toByteArray();
    } catch (final IOException exception) {
      throw new IllegalStateException("Could not serialize immutable test JAR fixture", exception);
    }
  }

  private static void writeEntry(
      final JarOutputStream output, final Map.Entry<String, String> entry) throws IOException {
    final JarEntry jarEntry = new JarEntry(entry.getKey());
    jarEntry.setTime(0L);
    output.putNextEntry(jarEntry);
    output.write(Base64.getDecoder().decode(entry.getValue()));
    output.closeEntry();
  }
}
