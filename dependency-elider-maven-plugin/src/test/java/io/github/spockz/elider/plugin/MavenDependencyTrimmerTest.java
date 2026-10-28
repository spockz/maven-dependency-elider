/* WHY: Verifies that trimming consumes the invocation scan so archive metadata is not read
 * twice. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ArtifactFileRef;
import io.github.spockz.elider.model.TraceData;
import io.github.spockz.elider.scanner.ArtifactClassIndex;
import io.github.spockz.elider.scanner.JarIndexScanner;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.stream.Stream;
import java.util.zip.ZipOutputStream;
import javax.tools.ToolProvider;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;
import org.apache.maven.model.Build;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.project.MavenProject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Verifies retained-JAR trimming uses the supplied invocation evidence. */
@SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
final class MavenDependencyTrimmerTest {
  /** Artifact identity shared by the test archive and Maven project. */
  private static final String ARTIFACT_ID = "runtime";

  /** Group shared by the fixture artifacts. */
  private static final String GROUP_ID = "org.example";

  /** Version shared by the fixture artifacts. */
  private static final String VERSION = "1.0";

  /** JAR type shared by fixture coordinates. */
  private static final String JAR_TYPE = "jar";

  /** Temporary workspace for compiled JAR fixtures. */
  @TempDir private Path tempDir;

  /** Creates the trimmer test fixture. */
  @SuppressWarnings({"PMD.UncommentedEmptyConstructor", "PMD.CommentDefaultAccessModifier"})
  MavenDependencyTrimmerTest() {}

  @Test
  void consumesDynamicRootsFromInvocationWithoutRescanningJar() throws Exception {
    final Path jar = compileJar();
    final Path normalizedJar = jar.toAbsolutePath().normalize();
    final ArtifactCoordinate coordinate =
        new ArtifactCoordinate(GROUP_ID, ARTIFACT_ID, VERSION, JAR_TYPE, "", ARTIFACT_ID);
    final Artifact artifact = runtimeArtifact(jar);
    final MavenProject project = project(artifact);
    final MavenElisionService.ArtifactSnapshot snapshot =
        new MavenElisionService.ArtifactSnapshot(artifact, coordinate, normalizedJar);
    final ArtifactFileRef artifactRef = ArtifactFileRef.fromPath(coordinate, normalizedJar);
    final ArtifactClassIndex classIndex = new JarIndexScanner().scan(List.of(artifactRef));
    final MavenDependencyTrimmer.ScanInputs scanInputs =
        new MavenDependencyTrimmer.ScanInputs(
            classIndex,
            Map.of(
                normalizedJar,
                new DependencyDynamicRoots.RootScan(Set.of("sample.Dynamic"), true)));

    final MavenDependencyTrimmer.TrimResult result = trim(project, snapshot, scanInputs);

    assertThat(result.records()).hasSize(1);
    try (JarFile trimmed = new JarFile(result.records().getFirst().trimmedPath().toFile())) {
      assertThat(trimmed.getEntry("sample/Keep.class")).isNotNull();
      assertThat(trimmed.getEntry("sample/Dynamic.class")).isNotNull();
      assertThat(trimmed.getEntry("sample/Drop.class")).isNull();
    }
    assertThatThrownBy(
            () ->
                trim(
                    project, snapshot, new MavenDependencyTrimmer.ScanInputs(classIndex, Map.of())))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Missing dynamic-root scan for retained artifact");
  }

  @Test
  void malformedSelectedPlatformClassOnCacheMissPublishesNoSuccessOutput() throws Exception {
    final Path jar = compileJar();
    final Path javaHome = Files.createDirectories(tempDir.resolve("malformed-jdk/lib")).getParent();
    try (ZipOutputStream ctSym =
        new ZipOutputStream(Files.newOutputStream(javaHome.resolve("lib/ct.sym")))) {
      ctSym.putNextEntry(new java.util.zip.ZipEntry("L/java.base/sample/Broken.sig"));
      ctSym.write(new byte[] {1, 2, 3});
      ctSym.closeEntry();
    }
    final ArtifactCoordinate coordinate =
        new ArtifactCoordinate(GROUP_ID, ARTIFACT_ID, VERSION, JAR_TYPE, "", ARTIFACT_ID);
    final Artifact artifact = runtimeArtifact(jar);
    final MavenProject project = project(artifact);
    final Path normalizedJar = jar.toAbsolutePath().normalize();
    final MavenElisionService.ArtifactSnapshot snapshot =
        new MavenElisionService.ArtifactSnapshot(artifact, coordinate, normalizedJar);
    final ArtifactFileRef artifactRef = ArtifactFileRef.fromPath(coordinate, normalizedJar);
    final ArtifactClassIndex classIndex = new JarIndexScanner().scan(List.of(artifactRef));
    final MavenDependencyTrimmer.ScanInputs scanInputs =
        new MavenDependencyTrimmer.ScanInputs(
            classIndex, Map.of(normalizedJar, new DependencyDynamicRoots.RootScan(Set.of(), true)));
    final String previousJavaHome = System.getProperty("java.home");
    final Path manifest = tempDir.resolve("build/elided-artifacts/.trim-analysis-cache.json");
    final Path output =
        tempDir.resolve("build/elided-artifacts/org.example-runtime-1.0-trimmed.jar");

    System.setProperty("java.home", javaHome.toString());
    try {
      assertThatThrownBy(() -> trim(project, snapshot, scanInputs))
          .isInstanceOf(IOException.class)
          .hasMessageContaining("Could not read JDK API signature");
    } finally {
      System.setProperty("java.home", previousJavaHome);
    }

    assertThat(manifest).doesNotExist();
    assertThat(output).doesNotExist();
    assertThat(jar).isRegularFile();
  }

  private MavenDependencyTrimmer.TrimResult trim(
      final MavenProject project,
      final MavenElisionService.ArtifactSnapshot snapshot,
      final MavenDependencyTrimmer.ScanInputs scanInputs)
      throws IOException, MojoFailureException {
    return MavenDependencyTrimmer.trim(
        new MavenDependencyTrimmer.TrimRequest(
            project,
            null,
            List.of(snapshot),
            scanInputs,
            Set.of(snapshot.coordinate()),
            TraceData.of(Set.of("sample.Keep")),
            Set.of(),
            Set.of(),
            Set.of(),
            List.of(),
            false,
            List.of(),
            false));
  }

  @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
  private Path compileJar() throws IOException {
    final Path sourceDirectory = Files.createDirectories(tempDir.resolve("sources/sample"));
    final Path outputDirectory = Files.createDirectories(tempDir.resolve("classes"));
    final Path keep = sourceDirectory.resolve("Keep.java");
    final Path dynamic = sourceDirectory.resolve("Dynamic.java");
    final Path drop = sourceDirectory.resolve("Drop.java");
    Files.writeString(keep, "package sample; public class Keep {}\n");
    Files.writeString(dynamic, "package sample; public class Dynamic {}\n");
    Files.writeString(drop, "package sample; public class Drop {}\n");
    final int compilationResult =
        ToolProvider.getSystemJavaCompiler()
            .run(
                null,
                null,
                null,
                "--release",
                "21",
                "-d",
                outputDirectory.toString(),
                keep.toString(),
                dynamic.toString(),
                drop.toString());
    if (compilationResult != 0) {
      throw new IOException("Could not compile the trimmer root reuse fixture");
    }
    final Path jar = tempDir.resolve("runtime.jar");
    try (ZipOutputStream archive = new ZipOutputStream(Files.newOutputStream(jar));
        Stream<Path> classFiles = Files.walk(outputDirectory)) {
      for (final Path classFile : classFiles.filter(Files::isRegularFile).toList()) {
        archive.putNextEntry(
            new JarEntry(outputDirectory.relativize(classFile).toString().replace('\\', '/')));
        Files.copy(classFile, archive);
        archive.closeEntry();
      }
    }
    return jar;
  }

  private static Artifact runtimeArtifact(final Path jar) {
    final Artifact artifact =
        new DefaultArtifact(
            GROUP_ID,
            ARTIFACT_ID,
            VERSION,
            ARTIFACT_ID,
            JAR_TYPE,
            null,
            new DefaultArtifactHandler("jar"));
    artifact.setFile(jar.toFile());
    return artifact;
  }

  private MavenProject project(final Artifact artifact) {
    final MavenProject project = new MavenProject();
    project.setArtifacts(Set.of(artifact));
    project.setGroupId(GROUP_ID);
    project.setArtifactId("consumer");
    project.setVersion(VERSION);
    project.getProperties().setProperty("maven.compiler.release", "21");
    final Build build = new Build();
    build.setDirectory(tempDir.resolve("build").toString());
    project.setBuild(build);
    return project;
  }
}
