// WHY: Proves Resolver restores the project view needed for javac attribution.

package io.github.spockz.elider.plugin;

import static io.github.spockz.elider.plugin.DetachedCompileClasspathArtifactSupport.libraryJar;
import static io.github.spockz.elider.plugin.DetachedCompileClasspathArtifactSupport.toMavenArtifact;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ArtifactFileRef;
import io.github.spockz.elider.scanner.ArtifactClassIndex;
import io.github.spockz.elider.scanner.JarIndexScanner;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.apache.maven.model.Build;
import org.apache.maven.project.MavenProject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Tests detached Maven compile attribution. JUnit supplies the implicit constructor. */
@SuppressWarnings("PMD.AtLeastOneConstructor")
final class DetachedAnalyzeCompileClasspathTest {
  /** Maven group for the generated compile artifact. */
  private static final String GROUP_ID = "org.example";

  /** Artifact identifier for the generated compile dependency. */
  private static final String ARTIFACT_ID = "compile-api";

  /** Version of the generated compile dependency. */
  private static final String VERSION = "1.0";

  /** Archive type for the generated compile dependency. */
  private static final String JAR_TYPE = "jar";

  /** Maven scope used for the compile dependency. */
  private static final String COMPILE_SCOPE = "compile";

  /** Holds source and archive fixtures for the detached project. */
  @TempDir private Path temporaryDirectory;

  @Test
  void sourceReferencesAreAttributedToDetachedResolvedCompileArtifact() throws Exception {
    final Path library = libraryJar(temporaryDirectory);
    final ArtifactCoordinate coordinate =
        new ArtifactCoordinate(GROUP_ID, ARTIFACT_ID, VERSION, JAR_TYPE, "", COMPILE_SCOPE);
    final ArtifactFileRef artifact = ArtifactFileRef.fromPath(coordinate, library);
    final Path sourceRoot = Files.createDirectories(temporaryDirectory.resolve("src"));
    final Path source = sourceRoot.resolve("app/UsesApi.java");
    Files.createDirectories(source.getParent());
    Files.writeString(
        source, "package app; public final class UsesApi { org.example.api.Api value; }\n");
    final MavenProject live = project(sourceRoot);
    final MavenProject detached = MavenAnalysisResolutionContext.currentModel(live);
    final org.apache.maven.artifact.Artifact resolved =
        toMavenArtifact(
            coordinate.groupId(),
            coordinate.artifactId(),
            coordinate.version(),
            coordinate.scope(),
            JAR_TYPE,
            JAR_TYPE,
            true,
            library);
    final Path nonClasspathJar = temporaryDirectory.resolve("maven-plugin.jar");
    Files.writeString(nonClasspathJar, "non-classpath artifact placeholder");
    final org.apache.maven.artifact.Artifact pluginArtifact =
        toMavenArtifact(
            GROUP_ID,
            "plugin-tool",
            VERSION,
            COMPILE_SCOPE,
            "maven-plugin",
            JAR_TYPE,
            false,
            nonClasspathJar);
    detached.setResolvedArtifacts(Set.of(resolved, pluginArtifact));
    detached.setArtifacts(Set.of(resolved, pluginArtifact));
    detached.setDependencyArtifacts(Set.of(resolved));
    final ArtifactClassIndex index = new JarIndexScanner().scan(List.of(artifact));
    final AnalysisEnvironment environment =
        new AnalysisEnvironment(
            Map.of(),
            Map.of("maven.compiler.release", "17", "maven.compiler.proc", "none"),
            temporaryDirectory,
            AnalysisEnvironment.JdkToolchainState.UNSELECTED,
            null);

    final ProductionAnalysisInputs.CompilerInputs inputs =
        ProductionAnalysisInputs.compilerInputs(
            detached,
            null,
            environment,
            List.of(artifact),
            index,
            true,
            false,
            Optional.empty(),
            Set.of());

    assertAll(
        "detached compile classpath preserves source attribution and leaves the live model alone",
        () -> assertThat(inputs.requiredClasses()).contains("org.example.api.Api"),
        () -> assertThat(inputs.compileVisibleCoordinates()).contains(coordinate),
        () ->
            assertThat(detached.getCompileClasspathElements())
                .contains(library.toAbsolutePath().normalize().toString())
                .doesNotContain(nonClasspathJar.toAbsolutePath().normalize().toString()),
        () -> assertThat(detached).isNotSameAs(live),
        () -> assertThat(live.getArtifacts()).isEmpty(),
        () -> assertThat(live.getDependencyArtifacts()).isNull(),
        () ->
            assertThat(live.getDependencies())
                .singleElement()
                .satisfies(
                    dependency -> assertThat(dependency.getArtifactId()).isEqualTo(ARTIFACT_ID)));
  }

  private MavenProject project(final Path sourceRoot) {
    final MavenProject project = new MavenProject();
    project.setGroupId(GROUP_ID);
    project.setArtifactId("consumer");
    project.setVersion("1");
    project.setPackaging(JAR_TYPE);
    project.setFile(temporaryDirectory.resolve("pom.xml").toFile());
    project.addCompileSourceRoot(sourceRoot.toString());
    final org.apache.maven.model.Dependency declaration = new org.apache.maven.model.Dependency();
    declaration.setGroupId(GROUP_ID);
    declaration.setArtifactId(ARTIFACT_ID);
    declaration.setVersion(VERSION);
    declaration.setScope(COMPILE_SCOPE);
    project.getDependencies().add(declaration);
    final Build build = new Build();
    build.setDirectory(temporaryDirectory.resolve("target").toString());
    build.setOutputDirectory(temporaryDirectory.resolve("target/classes").toString());
    project.setBuild(build);
    return project;
  }
}
