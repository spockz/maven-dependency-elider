// WHY: Exercises the production prediction path with a captured graph and MRJAR input.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.plugin.ElisionAnalysisModel.AnalysisOptions;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.CompletenessOptions;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.DynamicRootOptions;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.TrimOptions;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.List;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;
import org.apache.maven.execution.DefaultMavenExecutionRequest;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.model.Build;
import org.apache.maven.plugin.descriptor.PluginDescriptor;
import org.apache.maven.project.MavenProject;
import org.apache.maven.toolchain.DefaultToolchainManager;
import org.codehaus.plexus.PlexusContainer;
import org.eclipse.aether.DefaultRepositorySystemSession;
import org.eclipse.aether.SessionData;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;

/** Tests captured-effective prediction, output resolution, and publication boundaries. */
final class MavenElisionServicePredictionTest {
  /** Contains project inputs and output files for each prediction scenario. */
  @TempDir private Path temporaryDirectory;

  /* package */ MavenElisionServicePredictionTest() {
    // JUnit creates each test instance through the package-visible no-argument constructor.
  }

  @Test
  void predictsCapturedEffectiveMrjarWithoutPublishingTrimState() throws Exception {
    final Fixture fixture = fixture(true);
    final DefaultRepositorySystemSession repositorySession = fixture.repositorySession();
    final SessionData sessionDataBefore = repositorySession.getData();
    final Object captureBefore =
        sessionDataBefore.get(EliderMediatedGraphCaptureDecorator.SESSION_DATA_KEY);
    final Object planBefore = sessionDataBefore.get(ResolverArtifactPlanPublisher.SESSION_DATA_KEY);
    final Path generation = TrimPaths.generationPath(fixture.project(), "prediction-only");
    final Path output = MavenGeneratedOutputs.manifestPath(fixture.project());
    Files.createDirectories(output.getParent());
    Files.writeString(output, "existing-output-manifest");
    final Path targetArchive =
        TrimPaths.analysisLibraryDirectory(fixture.project()).resolve("sentinel.jar");
    Files.createDirectories(targetArchive.getParent());
    Files.writeString(targetArchive, "existing-analysis-archive");

    final AnalyzePrediction prediction =
        new MavenElisionService().predict(fixture.project(), fixture.options(), null);
    final SessionData sessionDataAfter = repositorySession.getData();

    assertAll(
        "captured-effective Analyze predicts without publishing trim state",
        () ->
            assertThat(prediction.provenance())
                .isEqualTo(AnalyzePrediction.Provenance.CAPTURED_EFFECTIVE_RESOLVER),
        () -> assertThat(fixture.project().getArtifacts()).containsExactly(fixture.artifact()),
        () ->
            assertThat(fixture.project().getDependencyArtifacts())
                .containsExactly(fixture.artifact()),
        () ->
            assertThat(prediction.plannedTrims())
                .singleElement()
                .satisfies(
                    trim ->
                        assertAll(
                            "only target-tier classes are predicted for removal",
                            () -> assertThat(trim.removedClasses()).contains("projection.NineOnly"),
                            () ->
                                assertThat(trim.removedClasses())
                                    .doesNotContain("projection.TwentyOneOnly"))),
        () -> assertThat(fixture.artifact().getFile()).isEqualTo(fixture.archive().toFile()),
        () ->
            assertThat(sessionDataAfter.get(EliderMediatedGraphCaptureDecorator.SESSION_DATA_KEY))
                .isEqualTo(captureBefore),
        () ->
            assertThat(sessionDataAfter.get(ResolverArtifactPlanPublisher.SESSION_DATA_KEY))
                .isEqualTo(planBefore),
        () -> assertThat(generation).doesNotExist(),
        () -> assertThat(output).hasContent("existing-output-manifest"),
        () -> assertThat(targetArchive).hasContent("existing-analysis-archive"));
  }

  @Test
  void refusesCapturedEffectivePredictionWhenThePairIsMissing() throws Exception {
    final Fixture fixture = fixture(false);
    final Path reportSentinel = temporaryDirectory.resolve("unchanged-report.json");
    Files.writeString(reportSentinel, "report sentinel");

    assertAll(
        "missing captured graph refuses prediction without changing report output",
        () ->
            assertThatThrownBy(
                    () ->
                        new MavenElisionService()
                            .predict(fixture.project(), fixture.options(), null))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("missing for Analyze"),
        () -> assertThat(reportSentinel).hasContent("report sentinel"));
  }

  @Test
  void derivesProductionOutputFromBuildForCompleteBytecodePrediction() throws Exception {
    final Fixture fixture = fixture(true);
    final Path output = Path.of(fixture.project().getBuild().getOutputDirectory());
    final Path applicationClass = createProductionOutputClass(output);
    final AnalysisOptions options =
        withCompleteness(fixture.options(), new CompletenessOptions(false, true, false, true));

    final AnalyzePrediction prediction =
        new MavenElisionService().predict(fixture.project(), options, null);

    assertAll(
        "complete bytecode prediction derives and scans Maven's configured build output",
        () ->
            assertThat(prediction.evidence().bytecodeScan())
                .get()
                .extracting(scan -> scan.scope().toAbsolutePath().normalize())
                .isEqualTo(output.toAbsolutePath().normalize()),
        () ->
            assertThat(prediction.evidence().bytecodeScan().orElseThrow().classFilesScanned())
                .isEqualTo(1),
        () -> assertThat(applicationClass).exists());
  }

  @Test
  void resolvesRelativeProductionOutputAgainstProjectWhenProcessDirectoryDiffers()
      throws Exception {
    final Fixture fixture = fixture(true);
    final MavenProject project = fixture.project();
    final File projectBaseFile = project.getBasedir();
    final Path projectBasePath = projectBaseFile.toPath();
    final Path projectBase = projectBasePath.toAbsolutePath().normalize();
    final Path processDirectory =
        Path.of(System.getProperty("user.dir")).toAbsolutePath().normalize();
    fixture.project().getBuild().setOutputDirectory("target/classes");
    final Path expectedOutput = projectBase.resolve("target/classes");
    final Path applicationClass = createProductionOutputClass(expectedOutput);
    final AnalysisOptions options =
        withCompleteness(fixture.options(), new CompletenessOptions(false, true, false, true));

    final AnalyzePrediction prediction =
        new MavenElisionService().predict(fixture.project(), options, null);

    assertAll(
        "relative production output is resolved from the module base, not process cwd",
        () -> assertThat(projectBase).isNotEqualTo(processDirectory),
        () ->
            assertThat(prediction.evidence().bytecodeScan().orElseThrow().scope())
                .isEqualTo(expectedOutput),
        () ->
            assertThat(prediction.evidence().bytecodeScan().orElseThrow().classFilesScanned())
                .isEqualTo(1),
        () -> assertThat(applicationClass).exists());
  }

  @Test
  void rejectsBlankProjectProductionOutputForCompleteBytecodePrediction() throws Exception {
    final Fixture fixture = fixture(true);
    fixture.project().getBuild().setOutputDirectory("  ");
    final AnalysisOptions options =
        withCompleteness(fixture.options(), new CompletenessOptions(false, true, false, true));

    assertThatThrownBy(() -> new MavenElisionService().predict(fixture.project(), options, null))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("requires a nonblank production class output directory");
  }

  private static AnalysisOptions withCompleteness(
      final AnalysisOptions options, final CompletenessOptions completeness) {
    return new AnalysisOptions(
        options.traceFiles(),
        options.retainedArtifacts(),
        options.banishedDependencies(),
        options.productionOutput(),
        options.session(),
        completeness,
        options.trim(),
        options.dynamicRoots());
  }

  private static Path createProductionOutputClass(final Path output) throws IOException {
    final Path applicationClass = output.resolve("consumer/App.class");
    Files.createDirectories(applicationClass.getParent());
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "consumer/App", null, "java/lang/Object", null);
    writer.visitField(Opcodes.ACC_PRIVATE, "api", "Lprojection/Api;", null, null).visitEnd();
    writer.visitEnd();
    Files.write(applicationClass, writer.toByteArray());
    return applicationClass;
  }

  private Fixture fixture(final boolean capturePair) throws IOException {
    final Path fixtureDirectory = Files.createTempDirectory(temporaryDirectory, "prediction-");
    final MavenProject project = new MavenProject();
    project.setGroupId("fixture");
    project.setArtifactId("consumer");
    project.setVersion("1.0");
    project.setPackaging("jar");
    project.setFile(Files.createFile(fixtureDirectory.resolve("pom.xml")).toFile());
    project.getProperties().setProperty("maven.compiler.release", "17");
    final Build build = new Build();
    build.setDirectory(fixtureDirectory.resolve("target").toString());
    build.setOutputDirectory(fixtureDirectory.resolve("classes").toString());
    project.setBuild(build);
    final Path archive = multiReleaseArchive(fixtureDirectory);
    final DefaultArtifactHandler handler = new DefaultArtifactHandler("jar");
    handler.setAddedToClasspath(true);
    final Artifact artifact =
        new DefaultArtifact("fixture", "library", "1.0", "compile", "jar", null, handler);
    artifact.setFile(archive.toFile());
    project.setArtifacts(new LinkedHashSet<>(List.of(artifact)));
    project.setDependencyArtifacts(new LinkedHashSet<>(List.of(artifact)));
    final Path sourceRoot = Files.createDirectories(fixtureDirectory.resolve("prediction-source"));
    Files.writeString(
        sourceRoot.resolve("App.java"),
        "package consumer; public class App { private projection.Api api; }\n");
    project.addCompileSourceRoot(sourceRoot.toString());
    final DefaultRepositorySystemSession repositorySession = new DefaultRepositorySystemSession();
    if (capturePair) {
      MavenElisionGraphBindingTestSupport.appendPair(
          repositorySession, MavenElisionGraphBindingTestSupport.projectKey(project), "capture-1");
    }
    final MavenSession session = session(project, repositorySession);
    MavenOriginalInputAudit.markHookPresent(session);
    final Path trace = fixtureDirectory.resolve("captured-mrjar.lst");
    Files.writeString(trace, "consumer.App\nprojection.Api\n");
    final AnalysisOptions options =
        new AnalysisOptions(
            List.of(trace.toFile()),
            List.of(),
            List.of(),
            null,
            session,
            new CompletenessOptions(true, false, false, true),
            new TrimOptions(
                true,
                List.of(),
                false,
                List.of(),
                false,
                MavenDependencyTrimmer.DEFAULT_TRIM_WORKERS,
                MavenDependencyTrimmer.MRJAR_VERTICAL_SHADING),
            new DynamicRootOptions(false));
    return new Fixture(project, artifact, archive, repositorySession, options);
  }

  private MavenSession session(
      final MavenProject project, final DefaultRepositorySystemSession repositorySession) {
    final DefaultMavenExecutionRequest request = new DefaultMavenExecutionRequest();
    request.setBaseDirectory(project.getBasedir());
    final PlexusContainer container =
        (PlexusContainer)
            java.lang.reflect.Proxy.newProxyInstance(
                Thread.currentThread().getContextClassLoader(),
                new Class<?>[] {PlexusContainer.class},
                (proxy, method, arguments) ->
                    "lookup".equals(method.getName()) ? new DefaultToolchainManager() : null);
    final MavenSession session = new MavenSession(container, repositorySession, request, null);
    session.setCurrentProject(project);
    final PluginDescriptor descriptor = new PluginDescriptor();
    descriptor.setGroupId(PluginDescriptor.getDefaultPluginGroupId());
    descriptor.setArtifactId(PluginDescriptor.getDefaultPluginArtifactId("toolchains"));
    session.getPluginContext(descriptor, project);
    return session;
  }

  private Path multiReleaseArchive(final Path fixtureDirectory) throws IOException {
    final Path base =
        MultiReleaseProjectionFixtures.compile(
            fixtureDirectory,
            "captured-base",
            8,
            "package projection; public class Api { public static String value() { "
                + "return \"base\"; } }");
    final Path versioned =
        MultiReleaseProjectionFixtures.compile(
            fixtureDirectory,
            "captured-v21",
            21,
            "package projection; public class Api { public static String value() { "
                + "return \"upper\"; } }");
    final Path versionNine =
        MultiReleaseProjectionFixtures.compile(
            fixtureDirectory,
            "captured-v9",
            9,
            "package projection; public class Api { public static String value() { "
                + "return \"nine\"; } }");
    final Path versionNineOnly =
        MultiReleaseProjectionFixtures.compile(
            fixtureDirectory, "captured-v9-only", 9, "package projection; class NineOnly {}");
    final Path versionTwentyOneOnly =
        MultiReleaseProjectionFixtures.compile(
            fixtureDirectory,
            "captured-v21-only",
            21,
            "package projection; class TwentyOneOnly {}");
    return MultiReleaseProjectionFixtures.createMultiReleaseJar(
        fixtureDirectory, base, versionNine, versionNineOnly, versioned, versionTwentyOneOnly);
  }

  private record Fixture(
      MavenProject project,
      Artifact artifact,
      Path archive,
      DefaultRepositorySystemSession repositorySession,
      AnalysisOptions options) {}
}
