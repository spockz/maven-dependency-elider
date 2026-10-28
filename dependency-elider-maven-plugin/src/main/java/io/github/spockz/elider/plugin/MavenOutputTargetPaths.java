// WHY: Validates the final target set before a report transaction stages any files.

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Validates and stages an ordered set of output paths. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier") // This path planner is package-internal only.
final class MavenOutputTargetPaths {
  private MavenOutputTargetPaths() {
    throw new AssertionError("No instances");
  }

  static Map<Path, Path> orderedImmutable(final Map<Path, Path> paths) {
    return Collections.unmodifiableMap(new LinkedHashMap<>(paths));
  }

  static Map<Path, Path> createStagingMap(final List<Path> requested, final String token)
      throws IOException {
    final List<Path> targets = normalize(requested);
    validate(targets);
    final Map<Path, Path> staged = createStages(targets, token);
    return orderedImmutable(staged);
  }

  private static List<Path> normalize(final List<Path> requested) {
    return requested.stream().map(path -> path.toAbsolutePath().normalize()).toList();
  }

  private static void validate(final List<Path> targets) throws IOException {
    validateUnique(targets);
    rejectDirectories(targets);
    rejectOverlaps(targets);
  }

  private static void validateUnique(final List<Path> targets) throws IOException {
    final Set<Path> seen = new HashSet<>();
    for (final Path target : targets) {
      if (!seen.add(target)) {
        throw new IOException("Duplicate output target path: " + target);
      }
    }
  }

  private static void rejectDirectories(final List<Path> targets) throws IOException {
    for (final Path target : targets) {
      if (Files.isDirectory(target)) {
        throw new IOException("Output target is an existing directory: " + target);
      }
    }
  }

  private static void rejectOverlaps(final List<Path> targets) throws IOException {
    for (int left = 0; left < targets.size(); left++) {
      for (int right = left + 1; right < targets.size(); right++) {
        final Path first = targets.get(left);
        final Path second = targets.get(right);
        if (first.startsWith(second) || second.startsWith(first)) {
          throw new IOException("Output targets overlap: " + first + " and " + second);
        }
      }
    }
  }

  @SuppressWarnings("PMD.UseConcurrentHashMap") // Stage order must match target order.
  private static Map<Path, Path> createStages(final List<Path> targets, final String token)
      throws IOException {
    final Map<Path, Path> staged = new LinkedHashMap<>();
    int ordinal = 0;
    for (final Path target : targets) {
      final Path parent = target.getParent();
      if (parent == null) {
        throw new IOException("Output path has no parent directory: " + target);
      }
      Files.createDirectories(parent);
      final Path stage = parent.resolve("." + target.getFileName() + ".staged-" + token + ordinal);
      staged.put(stage, target);
      ordinal++;
    }
    return staged;
  }
}
