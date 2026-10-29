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
    final StringBuilder filtered = new StringBuilder(text.length());
    boolean changed = false;
    int lineStart = 0;
    while (lineStart < text.length()) {
      int lineEnd = lineStart;
      while (lineEnd < text.length() && !isLineBreak(text.charAt(lineEnd))) {
        lineEnd++;
      }
      final int separatorEnd = lineSeparatorEnd(text, lineEnd);
      final boolean removed =
          removedProviders.contains(providerName(text.substring(lineStart, lineEnd)));
      changed |= removed;
      if (!removed) {
        filtered.append(text, lineStart, separatorEnd);
      }
      lineStart = separatorEnd;
    }
    return changed
        ? Optional.of(filtered.toString().getBytes(StandardCharsets.UTF_8))
        : Optional.empty();
  }

  private static boolean isLineBreak(final char value) {
    return value == '\r' || value == '\n';
  }

  private static int lineSeparatorEnd(final String text, final int lineEnd) {
    if (lineEnd == text.length()) {
      return lineEnd;
    }
    return text.charAt(lineEnd) == '\r'
            && lineEnd + 1 < text.length()
            && text.charAt(lineEnd + 1) == '\n'
        ? lineEnd + 2
        : lineEnd + 1;
  }

  private static String providerName(final String line) {
    final int comment = line.indexOf('#');
    return (comment < 0 ? line : line.substring(0, comment)).trim();
  }
}
