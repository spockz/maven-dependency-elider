/*
 * WHY: Isolates Resolver graph wiring from compile-classpath assertions.
 */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ArtifactFileRef;
import io.github.spockz.elider.scanner.ArtifactClassIndex;
import io.github.spockz.elider.scanner.JarIndexScanner;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.apache.maven.execution.DefaultMavenExecutionRequest;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.model.Build;
import org.apache.maven.project.DependencyResolutionRequest;
import org.apache.maven.project.DependencyResolutionResult;
import org.apache.maven.project.MavenProject;
import org.apache.maven.project.ProjectDependenciesResolver;
import org.eclipse.aether.DefaultRepositorySystemSession;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.collection.DependencyGraphTransformationContext;
import org.eclipse.aether.collection.DependencyGraphTransformer;
import org.eclipse.aether.graph.DefaultDependencyNode;
import org.eclipse.aether.graph.Dependency;
import org.eclipse.aether.graph.DependencyNode;

/** Builds a Resolver and Maven graph fixture. */
@SuppressWarnings("PMD.CouplingBetweenObjects")
final class DetachedResolverCompileClasspathFixture {
  /** Group identifier shared by the fixture's direct and resolver artifacts. */
  private static final String GROUP_ID = "org.example";

  /** Compile-visible artifact identifier used to build the dependency graph. */
  private static final String ARTIFACT_ID = "compile-api";

  /** Version shared by the compile artifact and graph fixture. */
  private static final String VERSION = "1.0";

  /** Archive extension and artifact type used by the compile input. */
  private static final String JAR_TYPE = "jar";

  /** Scope used to mark dependencies in the Resolver graph. */
  private static final String COMPILE_SCOPE = "compile";

  private DetachedResolverCompileClasspathFixture() {
    // Static fixture creation keeps the helper from becoming a test instance.
  }

  /* package */ static Fixture create(final Path temporaryDirectory) throws IOException {
    final Path library = DetachedCompileClasspathArtifactSupport.libraryJar(temporaryDirectory);
    final Path nonClasspathArchive = temporaryDirectory.resolve("plugin-tool.zip");
    Files.writeString(nonClasspathArchive, "non-classpath archive");
    final ArtifactCoordinate coordinate =
        new ArtifactCoordinate(GROUP_ID, ARTIFACT_ID, VERSION, JAR_TYPE, "", COMPILE_SCOPE);
    final Path sourceRoot = Files.createDirectories(temporaryDirectory.resolve("resolver-src"));
    final Path source = sourceRoot.resolve("app/UsesApi.java");
    Files.createDirectories(source.getParent());
    Files.writeString(
        source, "package app; public final class UsesApi { org.example.api.Api value; }\n");
    final MavenProject live = project(temporaryDirectory, sourceRoot);
    live.getProperties().setProperty("maven.compiler.release", "17");
    final org.eclipse.aether.artifact.Artifact compileArtifact =
        resolverArtifact(GROUP_ID, ARTIFACT_ID, VERSION, JAR_TYPE, true, library);
    final org.eclipse.aether.artifact.Artifact pluginArtifact =
        resolverArtifact(GROUP_ID, "plugin-tool", VERSION, "zip", false, nonClasspathArchive);
    final Dependency compileDependency = new Dependency(compileArtifact, COMPILE_SCOPE, false);
    final Dependency pluginDependency = new Dependency(pluginArtifact, COMPILE_SCOPE, false);
    final DependencyNode root =
        new DefaultDependencyNode(
            new Dependency(
                new org.eclipse.aether.artifact.DefaultArtifact(
                    GROUP_ID, "consumer", "", "pom", "1"),
                "",
                false));
    final DependencyNode direct = new DefaultDependencyNode(compileDependency);
    direct.setChildren(List.of(new DefaultDependencyNode(pluginDependency)));
    root.setChildren(List.of(direct));
    final DefaultRepositorySystemSession repositorySession = new DefaultRepositorySystemSession();
    final DefaultMavenExecutionRequest request = new DefaultMavenExecutionRequest();
    request.setBaseDirectory(live.getBasedir());
    final MavenSession session = new MavenSession(null, repositorySession, request, null);
    session.setCurrentProject(live);
    final ProjectDependenciesResolver resolver =
        new ProjectDependenciesResolver() {
          @Override
          public DependencyResolutionResult resolve(
              final DependencyResolutionRequest resolutionRequest) {
            final RepositorySystemSession requestSession = resolutionRequest.getRepositorySession();
            final DependencyGraphTransformer transformer = graphTransformer(requestSession);
            final DependencyNode transformed;
            try {
              transformed = transformer.transformGraph(root, transformationContext(requestSession));
            } catch (final org.eclipse.aether.RepositoryException exception) {
              throw new AssertionError("Request-local graph capture failed", exception);
            }
            return resolutionResult(List.of(compileDependency, pluginDependency), transformed);
          }
        };
    final AnalysisEnvironment environment =
        new AnalysisEnvironment(
            Map.of(),
            Map.of(),
            temporaryDirectory,
            AnalysisEnvironment.JdkToolchainState.UNSELECTED,
            null);
    final MavenAnalysisResolutionContext context =
        MavenAnalysisResolutionContext.detachedCurrentModel(
            live, live, session, resolver, environment);
    final ArtifactFileRef artifact = ArtifactFileRef.fromPath(coordinate, library);
    final ArtifactClassIndex index = new JarIndexScanner().scan(List.of(artifact));
    final ProductionAnalysisInputs.CompilerInputs inputs =
        ProductionAnalysisInputs.compilerInputs(
            context.project(),
            null,
            environment,
            List.of(artifact),
            index,
            true,
            false,
            Optional.empty(),
            Set.of());
    return new Fixture(live, context, coordinate, library, nonClasspathArchive, inputs);
  }

  private static DependencyGraphTransformer graphTransformer(
      final RepositorySystemSession session) {
    return session.getDependencyGraphTransformer();
  }

  private static DependencyGraphTransformationContext transformationContext(
      final RepositorySystemSession session) {
    return (DependencyGraphTransformationContext)
        java.lang.reflect.Proxy.newProxyInstance(
            Thread.currentThread().getContextClassLoader(),
            new Class<?>[] {DependencyGraphTransformationContext.class},
            (proxy, method, arguments) -> "getSession".equals(method.getName()) ? session : null);
  }

  private static DependencyResolutionResult resolutionResult(
      final List<Dependency> dependencies, final DependencyNode graph) {
    return (DependencyResolutionResult)
        java.lang.reflect.Proxy.newProxyInstance(
            Thread.currentThread().getContextClassLoader(),
            new Class<?>[] {DependencyResolutionResult.class},
            (proxy, method, arguments) ->
                switch (method.getName()) {
                  case "getCollectionErrors", "getUnresolvedDependencies", "getResolutionErrors" ->
                      List.of();
                  case "getResolvedDependencies" -> dependencies;
                  case "getDependencyGraph" -> graph;
                  default -> null;
                });
  }

  private static org.eclipse.aether.artifact.Artifact resolverArtifact(
      final String groupId,
      final String artifactId,
      final String version,
      final String type,
      final boolean classpath,
      final Path file) {
    return new org.eclipse.aether.artifact.DefaultArtifact(
        groupId,
        artifactId,
        "",
        type,
        version,
        Map.of("type", type, "constitutesBuildPath", Boolean.toString(classpath)),
        file.toFile());
  }

  private static MavenProject project(final Path temporaryDirectory, final Path sourceRoot) {
    final MavenProject project = new MavenProject();
    project.setGroupId(GROUP_ID);
    project.setArtifactId("consumer");
    project.setVersion("1");
    project.setPackaging("jar");
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

  /** Returns the resolved view and live-project invariants. */
  /* default */ record Fixture(
      MavenProject live,
      MavenAnalysisResolutionContext context,
      ArtifactCoordinate coordinate,
      Path library,
      Path nonClasspathArchive,
      ProductionAnalysisInputs.CompilerInputs inputs) {}
}
