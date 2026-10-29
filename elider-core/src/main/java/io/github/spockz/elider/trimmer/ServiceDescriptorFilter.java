/* WHY: Filters only graph-pruned providers while preserving unknown service declarations
 * verbatim. */

package io.github.spockz.elider.trimmer;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/** Applies exact provider-name filtering to a root service descriptor. */
@SuppressWarnings({"PMD.CommentRequired", "PMD.CommentDefaultAccessModifier"})
final class ServiceDescriptorFilter {
  private static final String SERVICES_PREFIX = "META-INF/services/";

  private ServiceDescriptorFilter() {}

  static Optional<byte[]> filter(
      final JarFile input, final JarEntry entry, final Set<String> removedProviders)
      throws IOException {
    if (!entry.getName().startsWith(SERVICES_PREFIX) || removedProviders.isEmpty()) {
      return Optional.empty();
    }
    final byte[] original;
    try (InputStream contents = input.getInputStream(entry)) {
      original = contents.readAllBytes();
    }
    final String text;
    try {
      text =
          StandardCharsets.UTF_8
              .newDecoder()
              .onMalformedInput(CodingErrorAction.REPORT)
              .onUnmappableCharacter(CodingErrorAction.REPORT)
              .decode(ByteBuffer.wrap(original))
              .toString();
    } catch (final CharacterCodingException exception) {
      throw new IOException("Invalid UTF-8 service descriptor: " + entry.getName(), exception);
    }
    return filterLines(text, removedProviders);
  }

  private static Optional<byte[]> filterLines(
      final String text, final Set<String> removedProviders) {
    final String[] lines = text.split("\\n", -1);
    final StringBuilder filtered = new StringBuilder(text.length());
    boolean changed = false;
    for (int index = 0; index < lines.length; index++) {
      final String line = lines[index];
      final String comparable = line.endsWith("\r") ? line.substring(0, line.length() - 1) : line;
      final int comment = comparable.indexOf('#');
      final String provider = (comment < 0 ? comparable : comparable.substring(0, comment)).trim();
      final boolean removed = removedProviders.contains(provider);
      changed |= removed;
      if (!removed) {
        filtered.append(line);
        if (index < lines.length - 1) {
          filtered.append('\n');
        }
      }
    }
    return changed
        ? Optional.of(filtered.toString().getBytes(StandardCharsets.UTF_8))
        : Optional.empty();
  }
}
