// WHY: Ensures analyze rejects missing explicit evidence instead of producing a misleading result.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugin.logging.Log;
import org.apache.maven.project.MavenProject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;

/** Verifies conservative Maven artifact adaptation and explicit trace requirements. */
@SuppressWarnings({
  "PMD.AvoidAccessibilityAlteration",
  "PMD.UnitTestContainsTooManyAsserts",
  "PMD.LawOfDemeter",
  "PMD.TooManyMethods"
})
final class AnalyzeMojoTest {
  /** Temporary directory for ZIP fixtures and explicit trace files. */
  @TempDir private Path tempDir;

  /** Creates the focused test fixture. */
  @SuppressWarnings({"PMD.UncommentedEmptyConstructor", "PMD.CommentDefaultAccessModifier"})
  AnalyzeMojoTest() {}

  @Test
  @SuppressWarnings("PMD.AvoidDuplicateLiterals")
  void analyzesExplicitTraceWithoutMutatingArtifactsAndReportsCompleteInput()
      throws IOException, ReflectiveOperationException, MojoFailureException {
    final Artifact used =
        artifact("used", "1.0", "compile", "jar", "used.jar", "used/Sample.class");
    final Artifact unused =
        artifact("unused", "1.0", "compile", "jar", "unused.jar", "unused/Sample.class");
    final Artifact excluded =
        artifact("excluded", "2.0", "runtime", "jar", "excluded.jar", "excluded/Sample.class");
    final Artifact testScoped =
        artifact("test-only", "1.0", "test", "jar", "test.jar", "test/Sample.class");
    final Artifact nonJar =
        new DefaultArtifact(
            "org.example",
            "metadata",
            "1.0",
            "compile",
            "pom",
            null,
            new DefaultArtifactHandler("pom"));
    final File usedFile = used.getFile();
    final File unusedFile = unused.getFile();
    final File excludedFile = excluded.getFile();
    final File testScopedFile = testScoped.getFile();
    final Set<Artifact> artifacts =
        new LinkedHashSet<>(List.of(used, unused, excluded, testScoped, nonJar));
    final Set<Artifact> directArtifacts = new LinkedHashSet<>(Set.of(used, excluded));
    final MavenProject project = new MavenProject();
    project.setArtifacts(artifacts);
    project.setDependencyArtifacts(directArtifacts);
    final Set<Artifact> resolvedSnapshot = Set.copyOf(project.getArtifacts());
    final Set<Artifact> directSnapshot = Set.copyOf(project.getDependencyArtifacts());
    final Path trace = tempDir.resolve("runtime.lst");
    Files.writeString(trace, "used/Sample\n");
    final AnalyzeMojo mojo = new AnalyzeMojo();
    set(mojo, "project", project);
    set(mojo, "traceFiles", List.of(trace.toFile()));
    set(mojo, "excludedArtifacts", List.of("org.example:excluded"));
    final Path report = tempDir.resolve("analysis.json");
    set(mojo, "reportFile", report.toFile());
    final RecordingLog log = new RecordingLog();
    mojo.setLog(log);

    mojo.execute();

    assertThat(project.getArtifacts()).isSameAs(artifacts);
    assertThat(project.getArtifacts()).containsExactlyInAnyOrderElementsOf(resolvedSnapshot);
    assertThat(project.getDependencyArtifacts()).isSameAs(directArtifacts);
    assertThat(project.getDependencyArtifacts())
        .containsExactlyInAnyOrderElementsOf(directSnapshot);
    assertThat(used.getFile()).isSameAs(usedFile);
    assertThat(unused.getFile()).isSameAs(unusedFile);
    assertThat(excluded.getFile()).isSameAs(excludedFile);
    assertThat(testScoped.getFile()).isSameAs(testScopedFile);
    assertThat(log.messages)
        .contains(
            "  Whole artifacts: 0 / 5 (0.0%)",
            "  Classes removed: 0 / N/A (N/A; stage not run)",
            "  Methods removed: 0 / N/A (N/A; stage not run)",
            "  Fields removed: 0 / N/A (N/A; stage not run)",
            "  Cache: unavailable");
    final com.fasterxml.jackson.databind.JsonNode json =
        new com.fasterxml.jackson.databind.ObjectMapper().readTree(report.toFile());
    assertThat(json.path("staticEvidenceAvailable").asBoolean()).isFalse();
    assertThat(json.path("groups").path("applicationReferenced").isNull()).isTrue();
    assertThat(json.path("groups").path("runtimeObservedWithoutApplicationReference").isNull())
        .isTrue();
    assertThat(json.path("groups").path("neitherReferencedNorObserved").isNull()).isTrue();
    assertThat(json.path("runtimeObservedClasses").toString()).contains("used.Sample");
    assertThat(json.path("classes").toString()).contains("UNKNOWN_STATIC_EVIDENCE");
  }

  @Test
  void writesCompleteStaticGroupsAndDeterministicClassNames()
      throws IOException, ReflectiveOperationException, MojoFailureException {
    final Artifact used =
        artifact("used", "1.0", "compile", "jar", "used.jar", "used/Sample.class");
    final Artifact runtimeOnly =
        artifact(
            "runtime-only", "1.0", "compile", "jar", "runtime-only.jar", "runtimeOnly/Type.class");
    final Artifact unused =
        artifact("unused", "1.0", "compile", "jar", "unused.jar", "unused/Idle.class");
    final MavenProject project = new MavenProject();
    project.setArtifacts(new LinkedHashSet<>(List.of(used, runtimeOnly, unused)));
    final Path trace = tempDir.resolve("complete.lst");
    Files.writeString(trace, "used/Sample\nruntimeOnly/Type\n");
    final Path productionOutput = Files.createDirectories(tempDir.resolve("classes"));
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, "app/Main", null, "java/lang/Object", null);
    writer.visitField(Opcodes.ACC_PRIVATE, "used", "Lused/Sample;", null, null).visitEnd();
    writer.visitEnd();
    Files.createDirectories(productionOutput.resolve("app"));
    Files.write(productionOutput.resolve("app/Main.class"), writer.toByteArray());
    final Path report = tempDir.resolve("complete-report.json");
    final AnalyzeMojo mojo = new AnalyzeMojo();
    set(mojo, "project", project);
    set(mojo, "traceFiles", List.of(trace.toFile()));
    set(mojo, "productionOutput", productionOutput.toFile());
    set(mojo, "reportFile", report.toFile());

    mojo.execute();
    final String firstOutput = Files.readString(report);
    mojo.execute();

    assertThat(Files.readString(report)).isEqualTo(firstOutput);
    final com.fasterxml.jackson.databind.JsonNode json =
        new com.fasterxml.jackson.databind.ObjectMapper().readTree(firstOutput);
    assertThat(json.path("staticEvidenceAvailable").asBoolean()).isTrue();
    assertThat(json.path("classFilesScanned").asInt()).isEqualTo(1);
    assertThat(json.path("groups").path("applicationReferenced").toString())
        .contains("used.Sample");
    assertThat(json.path("groups").path("runtimeObservedWithoutApplicationReference").toString())
        .contains("runtimeOnly.Type");
    assertThat(json.path("groups").path("neitherReferencedNorObserved").toString())
        .contains("unused.Idle");
    assertThat(json.path("classes").toString())
        .contains("used.Sample", "runtimeOnly.Type", "unused.Idle");
  }

  @Test
  void rejectsInvalidClassOutputWithoutWritingReport()
      throws IOException, ReflectiveOperationException {
    final Fixture fixture = fixture("used/Sample\n");
    final Path report = tempDir.resolve("invalid-scan.json");
    set(fixture.mojo, "productionOutput", tempDir.resolve("missing-classes").toFile());
    set(fixture.mojo, "reportFile", report.toFile());

    assertThatThrownBy(fixture.mojo::execute)
        .isInstanceOf(MojoFailureException.class)
        .hasMessageContaining("Production class output directory is missing");
    assertThat(report).doesNotExist();
  }

  @Test
  void rejectsInvalidExclusionCoordinates() throws IOException, ReflectiveOperationException {
    final Fixture fixture = fixture("used/Sample\n");
    set(fixture.mojo, "excludedArtifacts", List.of("org.example"));

    assertThatThrownBy(fixture.mojo::execute)
        .isInstanceOf(MojoFailureException.class)
        .hasMessageContaining("Invalid elide.excludedArtifacts coordinate");
  }

  @Test
  void rejectsTraceObservationsThatMatchNoDependency()
      throws IOException, ReflectiveOperationException {
    final Fixture fixture = fixture("missing/Sample\n");

    assertThatThrownBy(fixture.mojo::execute)
        .isInstanceOf(MojoFailureException.class)
        .hasMessageContaining("no observed class matches any supplied dependency");
  }

  @Test
  void rejectsAnEmptyTraceList() throws ReflectiveOperationException {
    final AnalyzeMojo mojo = new AnalyzeMojo();
    set(mojo, "project", new MavenProject());
    set(mojo, "traceFiles", List.of());

    assertThatThrownBy(mojo::execute)
        .isInstanceOf(MojoFailureException.class)
        .hasMessageContaining("At least one supported trace input is required");
  }

  @Test
  void retainsUnsupportedTypesWithoutFile() throws IOException {
    final Artifact pom =
        new DefaultArtifact(
            "org.example",
            "metadata",
            "1.0",
            "compile",
            "pom",
            null,
            new DefaultArtifactHandler("pom"));

    assertThat(MavenElisionService.isJarCandidate(pom)).isFalse();
  }

  @Test
  void rejectsMissingResolvedArtifactFiles() {
    final Artifact jar =
        new DefaultArtifact(
            "org.example",
            "library",
            "1.0",
            "compile",
            "jar",
            null,
            new DefaultArtifactHandler("jar"));

    assertThatThrownBy(() -> MavenElisionService.isJarCandidate(jar))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Resolved artifact has no regular file");
  }

  private static void set(final Object target, final String name, final Object value)
      throws ReflectiveOperationException {
    final Field field = target.getClass().getDeclaredField(name);
    field.setAccessible(true);
    field.set(target, value);
  }

  private Artifact artifact(
      final String artifactId,
      final String version,
      final String scope,
      final String type,
      final String fileName,
      final String classEntry)
      throws IOException {
    final Path file = fileFor(fileName);
    try (ZipOutputStream output = new ZipOutputStream(Files.newOutputStream(file))) {
      output.putNextEntry(new ZipEntry(classEntry));
      output.write(new byte[] {0});
      output.closeEntry();
    }
    final Artifact artifact =
        new DefaultArtifact(
            "org.example",
            artifactId,
            version,
            scope,
            type,
            null,
            new DefaultArtifactHandler(type));
    artifact.setFile(file.toFile());
    return artifact;
  }

  private Path fileFor(final String fileName) {
    return tempDir.resolve(fileName);
  }

  private Fixture fixture(final String traceContent)
      throws IOException, ReflectiveOperationException {
    final Artifact used =
        artifact("used", "1.0", "compile", "jar", "fixture.jar", "used/Sample.class");
    final MavenProject project = new MavenProject();
    project.setArtifacts(new LinkedHashSet<>(Set.of(used)));
    final Path trace = tempDir.resolve("fixture.lst");
    Files.writeString(trace, traceContent);
    final AnalyzeMojo mojo = new AnalyzeMojo();
    set(mojo, "project", project);
    set(mojo, "traceFiles", List.of(trace.toFile()));
    set(mojo, "reportFile", tempDir.resolve("fixture-report.json").toFile());
    return new Fixture(mojo);
  }

  private record Fixture(AnalyzeMojo mojo) {}

  /** Captures informational lines emitted by the Mojo. */
  @SuppressWarnings({"PMD.TooManyMethods", "PMD.UncommentedEmptyMethodBody"})
  private static final class RecordingLog implements Log {
    /** Captured informational lines emitted by the Mojo. */
    private final List<String> messages = new java.util.ArrayList<>();

    @Override
    public boolean isDebugEnabled() {
      return false;
    }

    @Override
    public void debug(final CharSequence content) {}

    @Override
    public void debug(final CharSequence content, final Throwable error) {}

    @Override
    public void debug(final Throwable error) {}

    @Override
    public boolean isInfoEnabled() {
      return true;
    }

    @Override
    public void info(final CharSequence content) {
      messages.add(content.toString());
    }

    @Override
    public void info(final CharSequence content, final Throwable error) {
      messages.add(content.toString());
    }

    @Override
    public void info(final Throwable error) {
      messages.add(error.toString());
    }

    @Override
    public boolean isWarnEnabled() {
      return false;
    }

    @Override
    public void warn(final CharSequence content) {}

    @Override
    public void warn(final CharSequence content, final Throwable error) {}

    @Override
    public void warn(final Throwable error) {}

    @Override
    public boolean isErrorEnabled() {
      return false;
    }

    @Override
    public void error(final CharSequence content) {}

    @Override
    public void error(final CharSequence content, final Throwable error) {}

    @Override
    public void error(final Throwable error) {}
  }
}
