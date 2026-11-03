// WHY: Implements Spring Boot AOT asset directory discovery and test AOT isolation.

package io.github.spockz.elider.plugin;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;
import org.apache.maven.project.MavenProject;

/** Resolves Spring AOT generated production output directories while isolating test AOT assets. */
final class SpringAotAssetPaths {
  private static final String SPRING_AOT_DIR = "spring-aot";
  private static final String MAIN_DIR = "main";
  private static final String CLASSES_DIR = "classes";
  private static final String TEST_DIR = "test";

  private SpringAotAssetPaths() {
    throw new AssertionError("No instances");
  }

  /**
   * Discovers the Spring AOT main classes directory if present in the target build directory.
   * Strictly ignores and rejects any consideration of target/spring-aot/test.
   */
  static Optional<Path> resolveMainClasses(final MavenProject project) {
    if (project == null
        || project.getBuild() == null
        || project.getBuild().getDirectory() == null) {
      return Optional.empty();
    }
    final Path buildDir = Path.of(project.getBuild().getDirectory()).toAbsolutePath().normalize();
    final Path mainClasses =
        buildDir.resolve(SPRING_AOT_DIR).resolve(MAIN_DIR).resolve(CLASSES_DIR);
    if (Files.isDirectory(mainClasses)) {
      return Optional.of(mainClasses);
    }
    return Optional.empty();
  }

  /** Verifies that the path is not within the test AOT tree. */
  static boolean isTestAotPath(final Path path) {
    if (path == null) {
      return false;
    }
    final String normalized = path.toString().replace('\\', '/');
    return normalized.contains("/spring-aot/test/") || normalized.endsWith("/spring-aot/test");
  }
}
