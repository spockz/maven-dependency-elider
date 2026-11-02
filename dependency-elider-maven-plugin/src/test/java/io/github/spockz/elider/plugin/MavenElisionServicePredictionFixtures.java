// WHY: Shares graph and bytecode fixtures across prediction tests.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.plugin.ElisionAnalysisModel.AnalysisOptions;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.CompletenessOptions;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.DynamicRootOptions;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.TrimOptions;
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
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;

/** Creates Maven graph, archive, and bytecode fixtures for prediction tests. */
final class MavenElisionServicePredictionFixtures {
  private MavenElisionServicePredictionFixtures() {
    throw new AssertionError("No instances");
  }

  /** Creates a prediction fixture with or without captured graph data. */
  /* default */ static Fixture create(final Path temporaryDirectory, final boolean capturePair)
      throws IOException {
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
    return new Fixture(project, fixtureDirectory, artifact, archive, repositorySession, options);
  }

  /** Writes a test consumer class to production output. */
  /* default */ static Path createProductionOutputClass(final Path output) throws IOException {
    final Path applicationClass = output.resolve("consumer/App.class");
    Files.createDirectories(applicationClass.getParent());
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "consumer/App", null, "java/lang/Object", null);
    writer.visitField(Opcodes.ACC_PRIVATE, "api", "Lprojection/Api;", null, null).visitEnd();
    writer.visitEnd();
    Files.write(applicationClass, writer.toByteArray());
    return applicationClass;
  }

  private static MavenSession session(
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

  private static Path multiReleaseArchive(final Path fixtureDirectory) throws IOException {
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

  /** Holds Maven inputs shared by prediction scenarios. */
  /* default */ record Fixture(
      MavenProject project,
      Path projectBase,
      Artifact artifact,
      Path archive,
      DefaultRepositorySystemSession repositorySession,
      AnalysisOptions options) {}
}
