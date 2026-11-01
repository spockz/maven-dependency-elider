// WHY: Proves a detached Resolver result is restored into the project view used for javac
// attribution.

package io.github.spockz.elider.plugin;

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
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;

final class DetachedAnalyzeCompileClasspathTest {
  @TempDir private Path temporaryDirectory;

  @Test
  void sourceReferencesAreAttributedToDetachedResolvedCompileArtifact() throws Exception {
    final Path library = libraryJar();
    final ArtifactCoordinate coordinate =
        new ArtifactCoordinate("org.example", "compile-api", "1.0", "jar", "", "compile");
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
            "jar",
            "jar",
            true,
            library);
    final Path nonClasspathJar = temporaryDirectory.resolve("maven-plugin.jar");
    Files.writeString(nonClasspathJar, "non-classpath artifact placeholder");
    final org.apache.maven.artifact.Artifact pluginArtifact =
        toMavenArtifact(
            "org.example",
            "plugin-tool",
            "1.0",
            "compile",
            "maven-plugin",
            "jar",
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
                    dependency -> assertThat(dependency.getArtifactId()).isEqualTo("compile-api")));
  }

  @Test
  void resolverResultUsesMavenTypeHandlersForCompileAndNonClasspathArtifacts() throws Exception {
    final Path library = libraryJar();
    final Path nonClasspathArchive = temporaryDirectory.resolve("plugin-tool.zip");
    Files.writeString(nonClasspathArchive, "non-classpath archive");
    final ArtifactCoordinate coordinate =
        new ArtifactCoordinate("org.example", "compile-api", "1.0", "jar", "", "compile");
    final Path sourceRoot = Files.createDirectories(temporaryDirectory.resolve("resolver-src"));
    final Path source = sourceRoot.resolve("app/UsesApi.java");
    Files.createDirectories(source.getParent());
    Files.writeString(
        source, "package app; public final class UsesApi { org.example.api.Api value; }\n");
    final MavenProject live = project(sourceRoot);
    live.getProperties().setProperty("maven.compiler.release", "17");
    final org.eclipse.aether.artifact.Artifact compileArtifact =
        resolverArtifact("org.example", "compile-api", "1.0", "jar", true, library);
    final org.eclipse.aether.artifact.Artifact pluginArtifact =
        resolverArtifact("org.example", "plugin-tool", "1.0", "zip", false, nonClasspathArchive);
    final Dependency compileDependency = new Dependency(compileArtifact, "compile", false);
    final Dependency pluginDependency = new Dependency(pluginArtifact, "compile", false);
    final DependencyNode root =
        new DefaultDependencyNode(
            new Dependency(
                new org.eclipse.aether.artifact.DefaultArtifact(
                    "org.example", "consumer", "", "pom", "1"),
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
            final DependencyGraphTransformer transformer =
                requestSession.getDependencyGraphTransformer();
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

    assertAll(
        "Resolver-restored compile classpath preserves attribution and leaves the live model alone",
        () -> assertThat(inputs.requiredClasses()).contains("org.example.api.Api"),
        () -> assertThat(inputs.compileVisibleCoordinates()).contains(coordinate),
        () ->
            assertThat(context.project().getCompileClasspathElements())
                .contains(library.toAbsolutePath().normalize().toString())
                .doesNotContain(nonClasspathArchive.toAbsolutePath().normalize().toString()),
        () -> assertThat(context.project()).isNotSameAs(live),
        () -> assertThat(live.getArtifacts()).isEmpty(),
        () -> assertThat(live.getDependencyArtifacts()).isNull(),
        () ->
            assertThat(live.getDependencies())
                .singleElement()
                .satisfies(
                    dependency -> assertThat(dependency.getArtifactId()).isEqualTo("compile-api")));
  }

  private org.eclipse.aether.artifact.Artifact resolverArtifact(
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

  private static DependencyGraphTransformationContext transformationContext(
      final RepositorySystemSession session) {
    return (DependencyGraphTransformationContext)
        java.lang.reflect.Proxy.newProxyInstance(
            DependencyGraphTransformationContext.class.getClassLoader(),
            new Class<?>[] {DependencyGraphTransformationContext.class},
            (proxy, method, arguments) -> "getSession".equals(method.getName()) ? session : null);
  }

  private static DependencyResolutionResult resolutionResult(
      final List<Dependency> dependencies, final DependencyNode graph) {
    return (DependencyResolutionResult)
        java.lang.reflect.Proxy.newProxyInstance(
            DependencyResolutionResult.class.getClassLoader(),
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

  private static org.apache.maven.artifact.Artifact toMavenArtifact(
      final String groupId,
      final String artifactId,
      final String version,
      final String scope,
      final String type,
      final String extension,
      final boolean addedToClasspath,
      final Path file) {
    final org.eclipse.aether.artifact.Artifact resolverArtifact =
        new org.eclipse.aether.artifact.DefaultArtifact(
            groupId,
            artifactId,
            "",
            extension,
            version,
            Map.of("type", type, "constitutesBuildPath", Boolean.toString(addedToClasspath)),
            file.toFile());
    final org.apache.maven.artifact.Artifact mavenArtifact =
        org.apache.maven.RepositoryUtils.toArtifact(resolverArtifact);
    mavenArtifact.setScope(scope);
    return mavenArtifact;
  }

  private Path libraryJar() throws Exception {
    final Path jar = temporaryDirectory.resolve("compile-api.jar");
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(
        Opcodes.V17, Opcodes.ACC_PUBLIC, "org/example/api/Api", null, "java/lang/Object", null);
    writer.visitEnd();
    try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(jar))) {
      zip.putNextEntry(new ZipEntry("org/example/api/Api.class"));
      zip.write(writer.toByteArray());
      zip.closeEntry();
    }
    return jar;
  }

  private MavenProject project(final Path sourceRoot) {
    final MavenProject project = new MavenProject();
    project.setGroupId("org.example");
    project.setArtifactId("consumer");
    project.setVersion("1");
    project.setPackaging("jar");
    project.setFile(temporaryDirectory.resolve("pom.xml").toFile());
    project.addCompileSourceRoot(sourceRoot.toString());
    final org.apache.maven.model.Dependency declaration = new org.apache.maven.model.Dependency();
    declaration.setGroupId("org.example");
    declaration.setArtifactId("compile-api");
    declaration.setVersion("1.0");
    declaration.setScope("compile");
    project.getDependencies().add(declaration);
    final Build build = new Build();
    build.setDirectory(temporaryDirectory.resolve("target").toString());
    build.setOutputDirectory(temporaryDirectory.resolve("target/classes").toString());
    project.setBuild(build);
    return project;
  }
}
