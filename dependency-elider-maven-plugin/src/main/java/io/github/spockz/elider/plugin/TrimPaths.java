/* WHY: Keeps generated paths and archive naming consistent across direct
 * output, cache, and generation publication. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;
import java.util.TreeSet;
import java.util.jar.JarFile;
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
    return project.getBuild() == null || project.getBuild().getDirectory() == null
        ? Path.of(DEFAULT_BUILD_DIRECTORY, ELIDED_ARTIFACTS, ".analysis-libraries")
            .toAbsolutePath()
            .normalize()
        : Path.of(project.getBuild().getDirectory(), ELIDED_ARTIFACTS, ".analysis-libraries")
            .toAbsolutePath()
            .normalize();
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
    final Set<String> classNames = new TreeSet<>();
    try (JarFile archive = new JarFile(archivePath.toFile())) {
      final java.util.Enumeration<java.util.jar.JarEntry> entries = archive.entries();
      while (entries.hasMoreElements()) {
        final String name = entries.nextElement().getName();
        if (name.endsWith(CLASS_SUFFIX)
            && !"module-info.class".equals(name)
            && !name.endsWith("/module-info.class")) {
          classNames.add(
              name.substring(0, name.length() - CLASS_SUFFIX.length()).replace('/', '.'));
        }
      }
    }
    return Set.copyOf(classNames);
  }

  /* package */ static Set<String> logicalClassNames(final Path archivePath) throws IOException {
    return MultiReleaseClassInventory.logicalClassNames(archivePath);
  }

  /* package */ static Path outputPath(
      final MavenProject project, final ArtifactCoordinate coordinate) {
    final String basename =
        safeFilePart(coordinate.groupId())
            + "-"
            + safeFilePart(coordinate.artifactId())
            + "-"
            + safeFilePart(coordinate.version())
            + (coordinate.classifier().isBlank() ? "" : "-" + safeFilePart(coordinate.classifier()))
            + "-trimmed.jar";
    return project.getBuild() == null || project.getBuild().getDirectory() == null
        ? Path.of(DEFAULT_BUILD_DIRECTORY, ELIDED_ARTIFACTS, basename).toAbsolutePath().normalize()
        : Path.of(project.getBuild().getDirectory(), ELIDED_ARTIFACTS, basename)
            .toAbsolutePath()
            .normalize();
  }

  private static String safeFilePart(final String value) {
    if (value == null || value.isBlank()) {
      return "unnamed";
    }
    return value.replaceAll("[^A-Za-z0-9._-]", "_");
  }
}
