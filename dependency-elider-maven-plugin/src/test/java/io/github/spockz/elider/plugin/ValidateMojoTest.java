/* WHY: Verifies lightweight config and path checks fail fast in Maven's validate phase. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.function.Consumer;
import org.apache.maven.execution.DefaultMavenExecutionRequest;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.model.Build;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugin.logging.SystemStreamLog;
import org.apache.maven.project.MavenProject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

@SuppressWarnings({
  "PMD.AtLeastOneConstructor",
  "PMD.CommentDefaultAccessModifier",
  "PMD.CommentRequired",
  "PMD.LawOfDemeter"
})
final class ValidateMojoTest {
  private static final String EXAMPLE_GROUP = "com.example";

  @TempDir Path tempDir;

  @Test
  void acceptsValidDefaultAndConfiguredInputs() throws IOException {
    final Path traceFile = Files.writeString(tempDir.resolve("trace.txt"), "com.example.Main\n");
    final Path cacheDir = Files.createDirectories(tempDir.resolve("cve-cache"));
    final ValidateMojo mojo =
        newMojo(
            m -> {
              m.traceFiles = List.of(traceFile.toFile());
              m.cveCacheDirectory = cacheDir.toFile();
              m.retainedArtifacts = List.of("com.example:keep-me");
              m.trimSkipArtifacts = List.of("com.example:skip-me:1.0.0");
              m.banishedDependencies = List.of("com.example:banned");
              m.vulnerabilityMappingCatalogs = List.of("com.example:catalog:1.0.0");
              m.trimRoots = List.of("com.example.Main");
              m.retainDuplicateClassOwners = List.of("com.example.Retain*");
              m.trimDuplicateClassOwners = List.of("com.example.Trim*");
            });

    assertThatCode(mojo::execute).doesNotThrowAnyException();
  }

  @Test
  void skipsValidationWhenSkipOrIntermediateLeafOnlyApplies() {
    final ValidateMojo skipped =
        newMojo(
            m -> {
              m.skip = true;
              m.trimWorkers = 0;
            });

    final MavenProject pomParent = new MavenProject();
    pomParent.setGroupId(EXAMPLE_GROUP);
    pomParent.setArtifactId("parent");
    pomParent.setVersion("1.0.0");
    pomParent.setPackaging("pom");
    pomParent.setFile(tempDir.resolve("parent/pom.xml").toFile());
    final MavenProject child = new MavenProject();
    child.setGroupId(EXAMPLE_GROUP);
    child.setArtifactId("child");
    child.setVersion("1.0.0");
    child.setPackaging("jar");
    child.setParent(pomParent);
    final MavenSession reactorSession =
        new MavenSession(null, new DefaultMavenExecutionRequest(), null, pomParent);
    reactorSession.setProjects(List.of(pomParent, child));
    reactorSession.setProjectDependencyGraph(
        new org.apache.maven.execution.ProjectDependencyGraph() {
          @Override
          public List<MavenProject> getAllProjects() {
            return List.of(pomParent, child);
          }

          @Override
          public List<MavenProject> getSortedProjects() {
            return List.of(pomParent, child);
          }

          @Override
          public List<MavenProject> getDownstreamProjects(
              final MavenProject project, final boolean transitive) {
            return pomParent.equals(project) ? List.of(child) : List.of();
          }

          @Override
          public List<MavenProject> getUpstreamProjects(
              final MavenProject project, final boolean transitive) {
            return child.equals(project) ? List.of(pomParent) : List.of();
          }
        });

    final ValidateMojo intermediate =
        newMojo(
            m -> {
              m.project = pomParent;
              m.session = reactorSession;
              m.leafOnly = true;
              m.trimWorkers = 0;
            });

    assertAll(
        () -> assertThatCode(skipped::execute).doesNotThrowAnyException(),
        () -> assertThatCode(intermediate::execute).doesNotThrowAnyException());
  }

  @Test
  void rejectsInvalidScalarCoordinatePolicyAndMappingParameters() {
    final VulnerabilityMappingConfig invalidMapping = new VulnerabilityMappingConfig();
    invalidMapping.setGroupId(EXAMPLE_GROUP);
    invalidMapping.setArtifactId("lib");

    assertAll(
        "lightweight scalar, coordinate, policy, and mapping checks",
        () ->
            assertFails(
                m -> m.sourceRootsComplete = true,
                "elide.sourceRootsComplete is no longer supported"),
        () -> assertFails(m -> m.trimWorkers = 0, "trimWorkers must be at least 1"),
        () -> assertFails(m -> m.mrjarStrategy = "unknown-strategy", "elide.mrjarStrategy must be"),
        () ->
            assertFails(
                m -> {
                  m.retainDuplicateClassOwners = List.of("com.example.Dup");
                  m.trimDuplicateClassOwners = List.of("com.example.Dup");
                },
                "Duplicate class pattern is listed for both retain and trim"),
        () ->
            assertFails(
                m -> m.trimRoots = List.of("   "), "elide.trimRoots must not contain blank"),
        () ->
            assertFails(
                m -> m.retainedArtifacts = List.of("not-a-coordinate"), "retainedArtifacts"),
        () ->
            assertFails(
                m -> m.trimSkipArtifacts = List.of("only-group"), "elide.trimSkipArtifacts"),
        () -> assertFails(m -> m.banishedDependencies = List.of("bad-ban"), "ban"),
        () ->
            assertFails(m -> m.vulnerabilityMappingCatalogs = List.of("bad"), "catalog coordinate"),
        () -> assertFails(m -> m.cveCacheTtlHours = -1, "elide.cveCacheTtlHours"),
        () -> assertFails(m -> m.osvSnapshotUri = "http://[invalid", "elide.osvSnapshotUri"),
        () -> assertFails(m -> m.cveListGitUri = "http://[invalid", "elide.cveListGitUri"),
        () -> assertFails(m -> m.snykApiBaseUri = "https://attacker.example", "Snyk"),
        () -> assertFails(m -> m.vulnerabilityMappings = List.of(invalidMapping), "cveId"));
  }

  @Test
  void rejectsMissingOrIncompatibleInputAndOutputPaths() throws IOException {
    final Path missingTrace = tempDir.resolve("missing-trace.txt");
    final Path directoryAsTrace = Files.createDirectories(tempDir.resolve("trace-dir"));
    final Path regularFileAsCache = Files.writeString(tempDir.resolve("cache-file"), "not-a-dir");
    final Path directoryAsOutput = Files.createDirectories(tempDir.resolve("output-dir"));
    final File sharedOutput = tempDir.resolve("target/shared.json").toFile();

    assertAll(
        "input and output path sanity checks",
        () -> assertFails(m -> m.traceFiles = List.of(missingTrace.toFile()), "elide.traceFiles"),
        () ->
            assertFails(m -> m.traceFiles = List.of(directoryAsTrace.toFile()), "elide.traceFiles"),
        () ->
            assertFails(
                m -> m.cveCacheDirectory = regularFileAsCache.toFile(), "elide.cveCacheDirectory"),
        () ->
            assertFails(
                m -> m.reportFile = directoryAsOutput.toFile(),
                "Output target is an existing directory"),
        () ->
            assertFails(
                m -> {
                  m.reportFile = sharedOutput;
                  m.summaryFile = sharedOutput;
                },
                "Duplicate output target path"));
  }

  private void assertFails(final Consumer<ValidateMojo> customizer, final String expectedMessage) {
    final ValidateMojo mojo = newMojo(customizer);
    assertThatThrownBy(mojo::execute)
        .isInstanceOf(MojoFailureException.class)
        .hasMessageContaining(expectedMessage);
  }

  private ValidateMojo newMojo(final Consumer<ValidateMojo> customizer) {
    final MavenProject project = new MavenProject();
    project.setGroupId(EXAMPLE_GROUP);
    project.setArtifactId("app");
    project.setVersion("1.0.0");
    project.setPackaging("jar");
    final Build build = new Build();
    build.setDirectory(tempDir.resolve("target").toString());
    project.setBuild(build);
    final MavenSession session =
        new MavenSession(null, new DefaultMavenExecutionRequest(), null, project);
    session.setProjects(List.of(project));

    final ValidateMojo mojo = new ValidateMojo();
    mojo.setLog(new SystemStreamLog());
    mojo.project = project;
    mojo.session = session;
    mojo.leafOnly = true;
    mojo.trimWorkers = MavenDependencyTrimmer.DEFAULT_TRIM_WORKERS;
    mojo.mrjarStrategy = MavenDependencyTrimmer.MRJAR_VERTICAL_SHADING;
    mojo.cveCacheTtlHours = 24;
    mojo.osvSnapshotUri = "https://storage.googleapis.com/osv-vulnerabilities/Maven/all.zip";
    mojo.cveListGitUri = "https://github.com/CVEProject/cvelistV5.git";
    mojo.snykApiBaseUri = "https://api.snyk.io";
    mojo.reportFile = tempDir.resolve("target/dependency-elider-class-usage.json").toFile();
    mojo.sbomFile = tempDir.resolve("target/dependency-elider-sbom.cdx.json").toFile();
    mojo.baselineSbomFile = tempDir.resolve("target/baseline-sbom.cdx.json").toFile();
    mojo.vexFile = tempDir.resolve("target/dependency-elider.openvex.json").toFile();
    mojo.summaryFile = tempDir.resolve("target/dependency-elider-report.json").toFile();
    customizer.accept(mojo);
    return mojo;
  }
}
