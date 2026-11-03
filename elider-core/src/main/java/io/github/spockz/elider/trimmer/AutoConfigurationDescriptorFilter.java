// WHY: Filters AutoConfiguration descriptors while preserving external ownership, properties formatting, and ordering integrity.

package io.github.spockz.elider.trimmer;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/**
 * Filters Spring Boot AutoConfiguration descriptors:
 * - META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports
 * Preserves external classes and ordering integrity, removing only classes that belonged
 * to the input archive and were actually pruned.
 */
public final class AutoConfigurationDescriptorFilter {
  public static final String IMPORTS_PATH =
      "META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports";

  private AutoConfigurationDescriptorFilter() {
    throw new AssertionError("No instances");
  }

  /**
   * Filters an AutoConfiguration.imports entry if present and any archive-owned classes were removed.
   * Handles both dot-separated (binary) and slash-separated (internal) class names.
   */
  public static Optional<byte[]> filterImports(
      final JarFile input,
      final JarEntry entry,
      final Set<String> archiveOwnedClasses,
      final Set<String> retainedClasses)
      throws IOException {
    if (!IMPORTS_PATH.equals(entry.getName())) {
      return Optional.empty();
    }
    final Set<String> normalizedOwned = normalizeNames(archiveOwnedClasses);
    final Set<String> normalizedRetained = normalizeNames(retainedClasses);

    final StringBuilder filtered = new StringBuilder();
    boolean modified = false;
    try (BufferedReader reader =
        new BufferedReader(new InputStreamReader(input.getInputStream(entry), StandardCharsets.UTF_8))) {
      String line;
      while ((line = reader.readLine()) != null) {
        final String trimmed = line.trim();
        final String className = trimmed.split("#", 2)[0].trim();
        if (className.isEmpty()) {
          filtered.append(line).append('\n');
          continue;
        }
        final String internalName = className.replace('.', '/');
        // Input-Archive Ownership Invariant:
        // Remove an entry only when its owner belonged to the input archive AND was actually removed.
        final boolean ownedByArchive = normalizedOwned.contains(internalName);
        final boolean retained = normalizedRetained.contains(internalName);
        if (ownedByArchive && !retained) {
          modified = true;
          // Omit this entry because it was owned by this archive and removed
        } else {
          filtered.append(line).append('\n');
        }
      }
    }
    return modified ? Optional.of(filtered.toString().getBytes(StandardCharsets.UTF_8)) : Optional.empty();
  }

  private static Set<String> normalizeNames(final Set<String> names) {
    final Set<String> normalized = new HashSet<>(names.size());
    for (final String name : names) {
      normalized.add(name.replace('.', '/'));
    }
    return normalized;
  }
}
