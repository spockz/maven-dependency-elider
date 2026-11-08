/* WHY: Filters only graph-pruned providers while preserving unknown service declarations
 * verbatim. */

package io.github.spockz.elider.trimmer;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/** Reconciles provider declarations without changing untouched descriptor bytes. */
@SuppressWarnings({"PMD.CommentRequired", "PMD.CommentDefaultAccessModifier"})
final class ServiceDescriptorFilter {
  private ServiceDescriptorFilter() {}

  static Result reconcile(
      final byte[] original, final Set<String> knownProviders, final Set<String> retainedProviders)
      throws IOException {
    java.util.Objects.requireNonNull(original, "original");
    java.util.Objects.requireNonNull(knownProviders, "knownProviders");
    java.util.Objects.requireNonNull(retainedProviders, "retainedProviders");
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
      throw new IOException("Invalid UTF-8 service descriptor", exception);
    }
    return filterLines(text, original, knownProviders, retainedProviders);
  }

  static Result filter(
      final JarFile input, final JarEntry entry, final Set<String> removedProviders)
      throws IOException {
    final byte[] original;
    try (InputStream contents = input.getInputStream(entry)) {
      original = contents.readAllBytes();
    }
    return reconcile(original, removedProviders, Set.of());
  }

  private static Result filterLines(
      final String text,
      final byte[] original,
      final Set<String> knownProviders,
      final Set<String> retainedProviders) {
    final StringBuilder filtered = new StringBuilder(text.length());
    boolean changed = false;
    boolean retainedDeclaration = false;
    int lineStart = 0;
    while (lineStart < text.length()) {
      int lineEnd = lineStart;
      while (lineEnd < text.length() && !isLineBreak(text.charAt(lineEnd))) {
        lineEnd++;
      }
      final int separatorEnd = lineSeparatorEnd(text, lineEnd);
      final String provider = providerName(text.substring(lineStart, lineEnd));
      final boolean removed =
          !provider.isEmpty()
              && knownProviders.contains(provider)
              && !retainedProviders.contains(provider);
      changed |= removed;
      if (!removed) {
        filtered.append(text, lineStart, separatorEnd);
        retainedDeclaration |= !provider.isEmpty();
      }
      lineStart = separatorEnd;
    }
    if (!changed) {
      return new Result(Outcome.UNCHANGED, original);
    }
    if (!retainedDeclaration) {
      return new Result(Outcome.OMIT, new byte[0]);
    }
    return new Result(Outcome.REPLACED, filtered.toString().getBytes(StandardCharsets.UTF_8));
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

  enum Outcome {
    UNCHANGED,
    REPLACED,
    OMIT
  }

  record Result(Outcome outcome, byte[] bytes) {
    Result {
      java.util.Objects.requireNonNull(outcome, "outcome");
      bytes = bytes.clone();
    }

    @Override
    public byte[] bytes() {
      return bytes.clone();
    }
  }
}
