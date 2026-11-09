// WHY: Rejects overlapping Maven output paths before one writer can overwrite another output.

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@SuppressWarnings("PMD.CommentRequired")
final class MavenOutputTargetValidation {
  private MavenOutputTargetValidation() {}

  /* package */ static void validate(final List<Path> targets) throws IOException {
    validate(targets, List.of());
  }

  /* package */ static void validate(final List<Path> targets, final List<Path> artifactPaths)
      throws IOException {
    final List<Path> normalized =
        targets.stream().map(MavenOutputTargetValidation::normalize).toList();
    final Set<Path> artifacts =
        artifactPaths.stream()
            .map(MavenOutputTargetValidation::normalize)
            .collect(java.util.stream.Collectors.toSet());
    for (final Path target : normalized) {
      if (artifacts.contains(target)) {
        throw new IOException("Output target collides with an artifact file: " + target);
      }
    }
    final Set<Path> seen = new HashSet<>();
    for (final Path target : normalized) {
      validateTarget(target, seen);
    }
    validateNonOverlapping(normalized);
  }

  private static void validateTarget(final Path target, final Set<Path> seen) throws IOException {
    if (!seen.add(target)) {
      throw new IOException("Duplicate output target path: " + target);
    }
    if (Files.isDirectory(target)) {
      throw new IOException("Output target is an existing directory: " + target);
    }
    if (target.getParent() == null) {
      throw new IOException("Output path has no parent directory: " + target);
    }
  }

  private static void validateNonOverlapping(final List<Path> targets) throws IOException {
    for (int index = 0; index < targets.size(); index++) {
      final Path target = targets.get(index);
      for (int otherIndex = index + 1; otherIndex < targets.size(); otherIndex++) {
        final Path other = targets.get(otherIndex);
        if (target.startsWith(other) || other.startsWith(target)) {
          throw new IOException("Overlapping output target paths: " + target + " and " + other);
        }
      }
    }
  }

  private static Path normalize(final Path path) {
    return path.toAbsolutePath().normalize();
  }
}
