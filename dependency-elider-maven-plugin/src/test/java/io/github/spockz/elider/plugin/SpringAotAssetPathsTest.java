// WHY: Unit tests verifying SpringAotAssetPaths correctly identifies main AOT classes and isolates
// test AOT.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;
import org.apache.maven.model.Build;
import org.apache.maven.project.MavenProject;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class SpringAotAssetPathsTest {

  @TempDir Path tempDir;

  @Test
  @DisplayName("resolveMainClasses returns present directory when spring-aot/main/classes exists")
  void resolveMainClassesWhenPresent() throws IOException {
    final Path buildDir = tempDir.resolve("target");
    final Path mainClasses = buildDir.resolve("spring-aot").resolve("main").resolve("classes");
    Files.createDirectories(mainClasses);

    final MavenProject project = new MavenProject();
    final Build build = new Build();
    build.setDirectory(buildDir.toString());
    project.setBuild(build);

    final Optional<Path> resolved = SpringAotAssetPaths.resolveMainClasses(project);

    assertThat(resolved).isPresent().contains(mainClasses.toAbsolutePath().normalize());
  }

  @Test
  @DisplayName("resolveMainClasses returns empty when spring-aot does not exist")
  void resolveMainClassesWhenMissing() {
    final Path buildDir = tempDir.resolve("target");
    final MavenProject project = new MavenProject();
    final Build build = new Build();
    build.setDirectory(buildDir.toString());
    project.setBuild(build);

    final Optional<Path> resolved = SpringAotAssetPaths.resolveMainClasses(project);

    assertThat(resolved).isEmpty();
  }

  @Test
  @DisplayName("isTestAotPath correctly isolates spring-aot/test paths from main")
  void testAotIsolation() {
    final Path testAotPath = Path.of("target/spring-aot/test/classes/MockBean.class");
    final Path mainAotPath = Path.of("target/spring-aot/main/classes/AppInit.class");
    final Path standardClass = Path.of("target/classes/App.class");

    assertAll(
        () -> assertThat(SpringAotAssetPaths.isTestAotPath(testAotPath)).isTrue(),
        () -> assertThat(SpringAotAssetPaths.isTestAotPath(mainAotPath)).isFalse(),
        () -> assertThat(SpringAotAssetPaths.isTestAotPath(standardClass)).isFalse());
  }
}
