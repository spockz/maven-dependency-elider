/* WHY: Resolves safe output locations and measures staged archives for ArchiveSanitizer. */

package io.github.spockz.elider.trimmer;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/** Owns destination validation and staged archive measurements. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class ArchiveOutputStager {
  private ArchiveOutputStager() {}

  static OutputLocation resolveOutputLocation(final Path originalJar, final Path trimmedJar)
      throws IOException {
    final Path parent = trimmedJar.toAbsolutePath().normalize().getParent();
    final Path fileName = trimmedJar.getFileName();
    if (parent == null || fileName == null) {
      throw new IOException("Trimmed JAR path has no parent directory: " + trimmedJar);
    }
    Files.createDirectories(parent);
    final Path directory = parent.toRealPath();
    final Path outputPath = directory.resolve(fileName.toString());
    final Path originalPath = originalJar.toRealPath();
    if (outputPath.equals(originalPath)
        || (Files.exists(outputPath) && Files.isSameFile(originalPath, outputPath))) {
      throw new IOException("Trimmed JAR must not overwrite its original: " + originalJar);
    }
    return new OutputLocation(directory, outputPath, originalPath);
  }

  static WriteResult writeAndMeasure(
      final Path originalJar,
      final Path temporaryJar,
      final DependencyJarTrimmer.TrimAnalysis analysis,
      final MultiReleaseArchivePlan elevationPlan)
      throws IOException {
    final long prunedClassBytes =
        elevationPlan == null
            ? SingleReleaseArchiveWriter.write(originalJar, temporaryJar, analysis)
            : MultiReleaseArchiveWriter.write(originalJar, temporaryJar, analysis, elevationPlan);
    return new WriteResult(
        prunedClassBytes,
        SingleReleaseArchiveWriter.countEntries(originalJar),
        SingleReleaseArchiveWriter.countEntries(temporaryJar),
        ArtifactDigests.read(temporaryJar));
  }

  record OutputLocation(Path directory, Path outputPath, Path originalPath) {}

  record WriteResult(
      long prunedClassBytes,
      int originalPhysicalEntries,
      int trimmedPhysicalEntries,
      ArtifactDigests trimmedDigests) {}
}
