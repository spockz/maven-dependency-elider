/* WHY: Keeps generated paths and archive naming consistent across direct
 * output, cache, and generation publication. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.MultiReleaseClassInventory;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.stream.Collectors;
import org.apache.maven.project.MavenProject;

/** Defines generated archive, analysis, cache, and generation paths. */
final class TrimPaths {
  /** Matches Maven's default when a project has no explicit build directory. */
  private static final String DEFAULT_BUILD_DIRECTORY = "target";

  /** Identifies class entries while retaining the existing name normalization. */
  private static final String CLASS_SUFFIX = ".class";

  /** Keeps generated archive paths separate from Maven's original dependencies. */
  private static final String ELIDED_ARTIFACTS = "elided-artifacts";

  private TrimPaths() {}

  /* package */ static Path analysisLibraryDirectory(final MavenProject project) {
    return buildDirectory(project).resolve(ELIDED_ARTIFACTS).resolve(".analysis-libraries");
  }

  /* package */ static Path analysisLibraryDirectory(
      final MavenProject project, final AnalysisEnvironment environment) {
    return environment == null || environment.projectionDirectory() == null
        ? analysisLibraryDirectory(project)
        : environment.projectionDirectory();
  }

  /* package */ static Path generationPath(final MavenProject project, final String fingerprint) {
    return buildDirectory(project)
        .resolve(ELIDED_ARTIFACTS)
        .resolve(".generations")
        .resolve(fingerprint);
  }

  /* package */ static Path ephemeralGenerationPath() throws IOException {
    final Path parent = Files.createTempDirectory("dependency-elider-trim-output-");
    parent.toFile().deleteOnExit();
    final Path generation = parent.resolve("generation");
    generation.toFile().deleteOnExit();
    return generation;
  }

  /* package */ static Path cacheManifestPath(final MavenProject project) {
    return buildDirectory(project).resolve(ELIDED_ARTIFACTS).resolve(".trim-analysis-cache.json");
  }

  private static Path buildDirectory(final MavenProject project) {
    final Path configured =
        project.getBuild() == null || project.getBuild().getDirectory() == null
            ? Path.of(DEFAULT_BUILD_DIRECTORY)
            : Path.of(project.getBuild().getDirectory());
    return configured.toAbsolutePath().normalize();
  }

  /* package */ static Set<String> classNames(final Path archivePath) throws IOException {
    try (JarFile archive = new JarFile(archivePath.toFile())) {
      return archive.stream()
          .map(JarEntry::getName)
          .filter(TrimPaths::isProgramClass)
          .map(name -> name.substring(0, name.length() - CLASS_SUFFIX.length()).replace('/', '.'))
          .collect(Collectors.toUnmodifiableSet());
    }
  }

  /* package */ static boolean isProgramClass(final String name) {
    return name.endsWith(CLASS_SUFFIX) && !MultiReleaseClassInventory.isModuleDescriptor(name);
  }

  /* package */ static Path outputPath(
      final MavenProject project, final ArtifactCoordinate coordinate) {
    final String basename = coordinateFilePrefix(coordinate) + "-trimmed.jar";
    return buildDirectory(project).resolve(ELIDED_ARTIFACTS).resolve(basename);
  }

  /* package */ static String coordinateFilePrefix(final ArtifactCoordinate coordinate) {
    return safeFilePart(coordinate.groupId())
        + "-"
        + safeFilePart(coordinate.artifactId())
        + "-"
        + safeFilePart(coordinate.version())
        + (coordinate.classifier().isBlank() ? "" : "-" + safeFilePart(coordinate.classifier()));
  }

  private static String safeFilePart(final String value) {
    if (value == null || value.isBlank()) {
      return "unnamed";
    }
    return value.replaceAll("[^A-Za-z0-9._-]", "_");
  }
}
