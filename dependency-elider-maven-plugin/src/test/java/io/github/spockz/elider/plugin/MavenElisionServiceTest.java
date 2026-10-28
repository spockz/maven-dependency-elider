// WHY: Guards ordered artifact snapshots and rejects scope-erasing identity contradictions.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ArtifactFileRef;
import io.github.spockz.elider.model.ElisionDecision;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import javax.tools.ToolProvider;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;
import org.apache.maven.model.Plugin;
import org.apache.maven.model.PluginExecution;
import org.apache.maven.project.MavenProject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Verifies Maven elision preparation without mutating Maven state. */
@SuppressWarnings({
  "PMD.AvoidDuplicateLiterals",
  "PMD.CouplingBetweenObjects",
  "PMD.LawOfDemeter",
  "PMD.AvoidInstantiatingObjectsInLoops",
  "PMD.TooManyMethods",
  "PMD.UnitTestContainsTooManyAsserts"
})
final class MavenElisionServiceTest {
  /** Temporary directory for resolved JAR path checks. */
  @TempDir private Path tempDir;

  /** Creates the focused test fixture. */
  @SuppressWarnings({"PMD.UncommentedEmptyConstructor", "PMD.CommentDefaultAccessModifier"})
  MavenElisionServiceTest() {}

  @Test
  void analysisSnapshotPreservesResolvedArtifactOrder() {
    final Artifact first = artifact("first", "compile");
    final Artifact second = artifact("second", "compile");
    final Set<Artifact> ordered = new LinkedHashSet<>(List.of(first, second));
    final MavenElisionService.Analysis analysis =
        new MavenElisionService.Analysis(
            MavenElisionService.snapshots(ordered), false, List.of(), decision(Set.of(), Set.of()));

    assertThat(new ArrayList<>(analysis.resolvedArtifacts())).containsExactly(first, second);
  }

  @Test
  void dynamicRootScanIsReusedForArtifactsSharingOneJarPath() throws IOException {
    final Path jar = writeJar("shared-dynamic-roots.jar");
    final ArtifactCoordinate first = coordinateFor("first", "compile");
    final ArtifactCoordinate second = coordinateFor("second", "runtime");
    final List<ArtifactFileRef> candidates =
        List.of(ArtifactFileRef.fromPath(first, jar), ArtifactFileRef.fromPath(second, jar));
    final List<Path> scannedPaths = new ArrayList<>();
    final DependencyDynamicRoots.RootScan expectedScan =
        new DependencyDynamicRoots.RootScan(Set.of("library.Provider"), true);

    final MavenElisionService.DynamicRootInputs inputs =
        MavenElisionService.dynamicRoots(
            candidates,
            path -> {
              scannedPaths.add(path);
              return expectedScan;
            });

    assertThat(scannedPaths).containsExactly(jar);
    assertThat(inputs.classNames()).containsExactly("library.Provider");
    assertThat(inputs.declaringArtifacts()).containsExactlyInAnyOrder(first, second);
    assertThat(inputs.scansByPath()).containsEntry(jar, expectedScan);
  }

  @Test
  void analysisSnapshotsAreOrderedImmutableAndDetachedFromSourceCollections() {
    final Artifact first = artifact("first", "compile");
    final Artifact second = artifact("second", "compile");
    final List<MavenElisionService.ArtifactSnapshot> source =
        new ArrayList<>(MavenElisionService.snapshots(List.of(first, second)));
    final MavenElisionService.Analysis analysis =
        new MavenElisionService.Analysis(source, false, List.of(), decision(Set.of(), Set.of()));
    source.clear();

    assertThat(analysis.resolvedSnapshots())
        .extracting(MavenElisionService.ArtifactSnapshot::artifact)
        .containsExactly(first, second);
    assertThatThrownBy(() -> analysis.resolvedSnapshots().clear())
        .isInstanceOf(UnsupportedOperationException.class);
    assertThatThrownBy(() -> analysis.resolvedArtifacts().clear())
        .isInstanceOf(UnsupportedOperationException.class);
  }

  @Test
  @SuppressWarnings("PMD.LawOfDemeter")
  void artifactSnapshotKeepsScopeAndNormalizedFilePath() throws IOException {
    final Artifact dependency = resolvedArtifact("library", "runtime", "library.jar");
    final File dependencyFile = dependency.getFile();
    final Path dependencyPath = dependencyFile.toPath();
    final Path expectedPath = dependencyPath.toAbsolutePath().normalize();

    final MavenElisionService.ArtifactSnapshot snapshot =
        MavenElisionService.snapshots(List.of(dependency)).getFirst();

    assertThat(snapshot.artifact()).isSameAs(dependency);
    assertThat(snapshot.coordinate()).isEqualTo(coordinate("runtime"));
    assertThat(snapshot.filePath()).isEqualTo(expectedPath);
  }

  @Test
  void planSnapshotsAreOrderedImmutableAndDetachedFromSourceCollections() {
    final Artifact first = artifact("first", "compile");
    final Artifact second = artifact("second", "compile");
    final Set<Artifact> source = new LinkedHashSet<>(List.of(first, second));
    final Set<Artifact> directSource = new LinkedHashSet<>(List.of(second));
    final MavenElisionService.ApplyPlan plan =
        new MavenElisionService.ApplyPlan(source, true, directSource);
    source.clear();
    directSource.clear();

    assertThat(new ArrayList<>(plan.resolvedArtifacts())).containsExactly(first, second);
    assertThat(plan.directArtifactsPresent()).isTrue();
    assertThat(plan.directArtifacts()).containsExactly(second);
    assertThatThrownBy(() -> plan.resolvedArtifacts().clear())
        .isInstanceOf(UnsupportedOperationException.class);
  }

  @Test
  void planRejectsScopeVariantsWithContradictoryDecisions() {
    final ArtifactCoordinate retained = coordinate("compile");
    final ArtifactCoordinate elided = coordinate("runtime");
    final ElisionDecision contradictory = decision(Set.of(retained), Set.of(elided));
    final MavenElisionService.Analysis analysis =
        new MavenElisionService.Analysis(List.of(), false, List.of(), contradictory);

    assertThatThrownBy(() -> new MavenElisionService().plan(new MavenProject(), analysis))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Contradictory retained and elided artifact identities");
  }

  @Test
  @SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
  void planFiltersDirectScopeVariantsAndPreservesUnrepresentedEntries() throws IOException {
    final Path jar = writeJar("library.jar");
    final Artifact resolved = artifact("library", "compile");
    resolved.setFile(jar.toFile());
    final Artifact direct = artifact("library", "runtime");
    direct.setFile(jar.toFile());
    final Artifact unrepresented =
        new DefaultArtifact(
            "org.example",
            "metadata",
            "1.0",
            "compile",
            "pom",
            null,
            new DefaultArtifactHandler("pom"));
    final MavenProject project = new MavenProject();
    project.setArtifacts(new LinkedHashSet<>(List.of(resolved)));
    project.setDependencyArtifacts(new LinkedHashSet<>(List.of(direct, unrepresented)));
    final MavenElisionService.Analysis analysis =
        new MavenElisionService.Analysis(
            MavenElisionService.snapshots(List.of(resolved)),
            true,
            MavenElisionService.snapshots(List.of(direct, unrepresented)),
            decision(Set.of(), Set.of(coordinate("compile"))));

    final MavenElisionService.ApplyPlan plan = new MavenElisionService().plan(project, analysis);

    assertThat(plan.resolvedArtifacts()).isEmpty();
    assertThat(plan.directArtifactsPresent()).isTrue();
    assertThat(plan.directArtifacts()).containsExactly(direct, unrepresented);
    assertThat(project.getDependencyArtifacts()).containsExactlyInAnyOrder(direct, unrepresented);
  }

  @Test
  void planRejectsConflictingResolvedAndDirectPathsEvenWhenRetained() throws IOException {
    final Artifact resolved = artifact("library", "compile");
    resolved.setFile(writeJar("resolved.jar").toFile());
    final Artifact direct = artifact("library", "runtime");
    direct.setFile(writeJar("direct.jar").toFile());
    final MavenProject project = new MavenProject();
    project.setArtifacts(new LinkedHashSet<>(List.of(resolved)));
    project.setDependencyArtifacts(Set.of(direct));
    final MavenElisionService.Analysis analysis =
        new MavenElisionService.Analysis(
            MavenElisionService.snapshots(List.of(resolved)),
            true,
            MavenElisionService.snapshots(List.of(direct)),
            decision(Set.of(coordinate("compile")), Set.of()));

    assertThatThrownBy(() -> new MavenElisionService().plan(project, analysis))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Conflicting direct artifact file");
    assertThat(project.getArtifacts()).containsExactly(resolved);
    assertThat(project.getDependencyArtifacts()).containsExactly(direct);
  }

  @Test
  void planRejectsArtifactCoordinateChangesAfterAnalysis() throws Exception {
    final Artifact dependency = resolvedArtifact("library", "compile", "library.jar");
    final MavenProject project = projectWith(dependency, null);
    final MavenElisionService.Analysis analysis = analyze(project, "coordinate.lst");
    dependency.setVersion("2.0");

    assertThatThrownBy(() -> new MavenElisionService().plan(project, analysis))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("artifact coordinate changed after analysis");
    assertThat(project.getArtifacts()).containsExactly(dependency);
    assertThat(project.getDependencyArtifacts()).isNull();
  }

  @Test
  void planRejectsArtifactScopeChangesAfterAnalysis() throws Exception {
    final Artifact dependency = resolvedArtifact("library", "compile", "library.jar");
    final MavenProject project = projectWith(dependency, null);
    final MavenElisionService.Analysis analysis = analyze(project, "scope.lst");
    dependency.setScope("runtime");

    assertThatThrownBy(() -> new MavenElisionService().plan(project, analysis))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("artifact coordinate changed after analysis");
    assertThat(project.getArtifacts()).containsExactly(dependency);
  }

  @Test
  void planRejectsArtifactReferenceReplacementAfterAnalysis() throws Exception {
    final Artifact dependency = resolvedArtifact("library", "compile", "library.jar");
    final MavenProject project = projectWith(dependency, null);
    final MavenElisionService.Analysis analysis = analyze(project, "reference.lst");
    final Artifact replacement = artifact("library", "compile");
    replacement.setFile(dependency.getFile());
    project.setArtifacts(new LinkedHashSet<>(List.of(replacement)));

    assertThatThrownBy(() -> new MavenElisionService().plan(project, analysis))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("artifact order or reference changed after analysis");
    assertThat(project.getArtifacts()).containsExactly(replacement);
  }

  @Test
  void planRejectsArtifactPathChangesAfterAnalysis() throws Exception {
    final Artifact dependency = resolvedArtifact("library", "compile", "library.jar");
    final MavenProject project = projectWith(dependency, null);
    final MavenElisionService.Analysis analysis = analyze(project, "path.lst");
    dependency.setFile(writeJar("changed.jar").toFile());

    assertThatThrownBy(() -> new MavenElisionService().plan(project, analysis))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("artifact file path changed after analysis");
    assertThat(project.getArtifacts()).containsExactly(dependency);
  }

  @Test
  void servicePreservesAbsentAndEmptyDirectViewDistinction() throws Exception {
    final Artifact absentViewArtifact = resolvedArtifact("absent", "compile", "absent.jar");
    final MavenProject absentProject = projectWith(absentViewArtifact, null);
    final MavenElisionService.Analysis absentAnalysis = analyze(absentProject, "absent.lst");
    final MavenElisionService.ApplyPlan absentPlan =
        new MavenElisionService().plan(absentProject, absentAnalysis);

    final Artifact emptyViewArtifact = resolvedArtifact("empty", "compile", "empty.jar");
    final MavenProject emptyProject = projectWith(emptyViewArtifact, new LinkedHashSet<>());
    final MavenElisionService.Analysis emptyAnalysis = analyze(emptyProject, "empty.lst");
    final MavenElisionService.ApplyPlan emptyPlan =
        new MavenElisionService().plan(emptyProject, emptyAnalysis);

    assertThat(absentAnalysis.directArtifactsPresent()).isFalse();
    assertThat(absentPlan.directArtifactsPresent()).isFalse();
    assertThat(absentPlan.directArtifacts()).isEmpty();
    assertThat(emptyAnalysis.directArtifactsPresent()).isTrue();
    assertThat(emptyPlan.directArtifactsPresent()).isTrue();
    assertThat(emptyPlan.directArtifacts()).isEmpty();
  }

  @Test
  void serviceRejectsConflictingPathsWithinResolvedView() throws IOException {
    final Artifact first = resolvedArtifact("library", "compile", "resolved-a.jar");
    final Artifact second = resolvedArtifact("library", "runtime", "resolved-b.jar");
    final MavenProject project = projectWith(identitySet(first, second), null);

    assertThatThrownBy(() -> new MavenElisionService().analyze(project, List.of(), List.of(), null))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Conflicting files for artifact identity");
    assertThat(project.getArtifacts()).containsExactlyInAnyOrder(first, second);
  }

  @Test
  void generatedSourceOwnerStaysAvailableAtInitializeWhenItsRootIsNotPresentYet() throws Exception {
    final Artifact observed = resolvedArtifact("observed", "compile", "observed.jar");
    observed.setFile(writeJar("observed.jar", "observed/RuntimeEntry.class").toFile());
    final Artifact generatedOwner = resolvedArtifact("generated", "compile", "generated.jar");
    generatedOwner.setFile(writeJar("generated.jar", "generated/GeneratedType.class").toFile());
    final Artifact runtimeOnly = resolvedArtifact("runtime-only", "runtime", "runtime-only.jar");
    runtimeOnly.setFile(writeJar("runtime-only.jar", "unused/RuntimeOnly.class").toFile());
    final MavenProject project =
        projectWith(new LinkedHashSet<>(List.of(observed, generatedOwner, runtimeOnly)), null);
    final Path generatedSources = tempDir.resolve("generated-sources");
    project.addCompileSourceRoot(generatedSources.toString());
    final Plugin generator = new Plugin();
    generator.setGroupId("org.codehaus.mojo");
    generator.setArtifactId("build-helper-maven-plugin");
    final PluginExecution execution = new PluginExecution();
    execution.setPhase("generate-sources");
    execution.setGoals(List.of("add-source"));
    generator.addExecution(execution);
    project.getBuild().addPlugin(generator);
    final Path trace = tempDir.resolve("generated-source-runtime.lst");
    Files.writeString(trace, "observed/RuntimeEntry\n");

    final MavenElisionService.Analysis analysis =
        new MavenElisionService().analyze(project, List.of(trace.toFile()), List.of(), null);

    assertThat(Files.exists(generatedSources)).isFalse();
    assertThat(analysis.decision().retainedArtifacts())
        .containsExactlyInAnyOrder(
            coordinateFor("observed", "compile"), generatedOwnerCoordinate());
    assertThat(analysis.decision().elidedArtifacts())
        .containsExactly(coordinateFor("runtime-only", "runtime"));
    assertThat(analysis.decision().getRetainedClasses(generatedOwnerCoordinate()))
        .containsExactly("generated.GeneratedType");
  }

  @Test
  void emptyCurrentSourceRootsRetainCompileClasspathAndStillElideRuntimeOnlyJar() throws Exception {
    final Artifact observed = resolvedArtifact("observed-empty", "compile", "observed-empty.jar");
    observed.setFile(writeJar("observed-empty.jar", "observed/RuntimeEntry.class").toFile());
    final Artifact compileOnly = resolvedArtifact("compile-only", "compile", "compile-only.jar");
    compileOnly.setFile(writeJar("compile-only.jar", "future/GeneratedType.class").toFile());
    final Artifact runtimeOnly = resolvedArtifact("runtime-idle", "runtime", "runtime-idle.jar");
    runtimeOnly.setFile(writeJar("runtime-idle.jar", "unused/RuntimeOnly.class").toFile());
    final MavenProject project =
        projectWith(new LinkedHashSet<>(List.of(observed, compileOnly, runtimeOnly)), null);
    final Path trace = tempDir.resolve("empty-source-roots-runtime.lst");
    Files.writeString(trace, "observed/RuntimeEntry\n");

    final MavenElisionService.Analysis analysis =
        new MavenElisionService().analyze(project, List.of(trace.toFile()), List.of(), null);

    assertThat(project.getCompileSourceRoots()).isEmpty();
    assertThat(analysis.decision().retainedArtifacts())
        .containsExactlyInAnyOrder(
            coordinateFor("observed-empty", "compile"), coordinateFor("compile-only", "compile"));
    assertThat(analysis.decision().elidedArtifacts())
        .containsExactly(coordinateFor("runtime-idle", "runtime"));
    assertThat(analysis.decision().getRetainedClasses(coordinateFor("compile-only", "compile")))
        .containsExactly("future.GeneratedType");
  }

  @Test
  void explicitCompleteSourceRootsAllowUnusedCompileJarElision() throws Exception {
    final Artifact used = resolvedArtifact("source-used", "compile", "source-used.jar");
    used.setFile(compileJar("source-used.jar", "library.Used").toFile());
    final Artifact unused = resolvedArtifact("source-unused", "compile", "source-unused.jar");
    unused.setFile(compileJar("source-unused.jar", "library.Unused").toFile());
    final Artifact observed =
        resolvedArtifact("runtime-observed", "runtime", "runtime-observed.jar");
    observed.setFile(writeJar("runtime-observed.jar", "observed/Entry.class").toFile());
    final MavenProject project =
        projectWith(new LinkedHashSet<>(List.of(used, unused, observed)), null);
    final Path sourceRoot = Files.createDirectories(tempDir.resolve("complete-app-src"));
    final Path source = sourceRoot.resolve("app/UsesDependency.java");
    Files.createDirectories(source.getParent());
    Files.writeString(
        source, "package app; public final class UsesDependency { library.Used value; }\n");
    project.addCompileSourceRoot(sourceRoot.toString());
    project.getProperties().setProperty("maven.compiler.release", "21");
    project.getProperties().setProperty("maven.compiler.proc", "none");
    final Plugin enforcer = new Plugin();
    enforcer.setGroupId("org.apache.maven.plugins");
    enforcer.setArtifactId("maven-enforcer-plugin");
    final PluginExecution enforcement = new PluginExecution();
    enforcement.setPhase("validate");
    enforcement.setGoals(List.of("enforce"));
    enforcer.addExecution(enforcement);
    project.getBuild().addPlugin(enforcer);
    final String usedJarPath = used.getFile().getPath();
    assertThat(project.getCompileClasspathElements()).contains(usedJarPath);
    final Path trace = tempDir.resolve("complete-source-runtime.lst");
    Files.writeString(trace, "observed/Entry\n");

    final MavenElisionService.Analysis analysis =
        new MavenElisionService()
            .analyze(project, List.of(trace.toFile()), List.of(), null, null, true);

    assertThat(analysis.decision().retainedArtifacts())
        .containsExactlyInAnyOrder(
            coordinateFor("source-used", "compile"), coordinateFor("runtime-observed", "runtime"));
    assertThat(analysis.decision().elidedArtifacts())
        .containsExactly(coordinateFor("source-unused", "compile"));
  }

  @Test
  void completeSourceRootsRejectUnknownSourceGenerationExecution() throws Exception {
    final Artifact used = resolvedArtifact("generation-used", "compile", "generation-used.jar");
    used.setFile(compileJar("generation-used.jar", "library.Used").toFile());
    final Artifact unused =
        resolvedArtifact("generation-unused", "compile", "generation-unused.jar");
    unused.setFile(compileJar("generation-unused.jar", "library.Unused").toFile());
    final MavenProject project = projectWith(new LinkedHashSet<>(List.of(used, unused)), null);
    final Path sourceRoot = Files.createDirectories(tempDir.resolve("generated-app-src"));
    final Path source = sourceRoot.resolve("app/UsesDependency.java");
    Files.createDirectories(source.getParent());
    Files.writeString(
        source, "package app; public final class UsesDependency { library.Used value; }\n");
    project.addCompileSourceRoot(sourceRoot.toString());
    project.getProperties().setProperty("maven.compiler.release", "21");
    project.getProperties().setProperty("maven.compiler.proc", "none");
    final Plugin generator = new Plugin();
    generator.setGroupId("org.codehaus.mojo");
    generator.setArtifactId("build-helper-maven-plugin");
    final PluginExecution generation = new PluginExecution();
    generation.setPhase("generate-sources");
    generation.setGoals(List.of("add-source"));
    generator.addExecution(generation);
    project.getBuild().addPlugin(generator);
    final Path trace = tempDir.resolve("unknown-generator.lst");
    Files.writeString(trace, "unobserved/RuntimeEntry\n");

    assertThatThrownBy(
            () ->
                new MavenElisionService()
                    .analyze(project, List.of(trace.toFile()), List.of(), null, null, true))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("source-generation lifecycle execution");
  }

  @Test
  void planRejectsConflictingPathsWithinDirectViewAndLeavesProjectUnchanged() throws IOException {
    final Artifact resolved = resolvedArtifact("library", "compile", "resolved.jar");
    final Artifact firstDirect = resolvedArtifact("library", "runtime", "direct-a.jar");
    final Artifact secondDirect = resolvedArtifact("library", "test", "direct-b.jar");
    final Set<Artifact> direct = identitySet(firstDirect, secondDirect);
    final MavenProject project = projectWith(resolved, direct);
    final MavenElisionService.Analysis analysis =
        new MavenElisionService.Analysis(
            MavenElisionService.snapshots(List.of(resolved)),
            true,
            MavenElisionService.snapshots(direct),
            decision(Set.of(coordinate("compile")), Set.of()));

    assertThatThrownBy(() -> new MavenElisionService().plan(project, analysis))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Conflicting files for artifact identity");
    assertThat(project.getArtifacts()).containsExactly(resolved);
    assertThat(project.getDependencyArtifacts())
        .containsExactlyInAnyOrder(firstDirect, secondDirect);
  }

  private static Artifact artifact(final String artifactId, final String scope) {
    return new DefaultArtifact(
        "org.example",
        artifactId,
        "1.0",
        scope,
        "jar",
        null,
        new DefaultArtifactHandler("jar") {
          @Override
          public boolean isAddedToClasspath() {
            return true;
          }
        });
  }

  private static ArtifactCoordinate coordinate(final String scope) {
    return new ArtifactCoordinate("org.example", "library", "1.0", "jar", "", scope);
  }

  private static ElisionDecision decision(
      final Set<ArtifactCoordinate> retained, final Set<ArtifactCoordinate> elided) {
    return new ElisionDecision(retained, elided, Map.of(), Map.of(), 0L);
  }

  private Path writeJar(final String name) throws IOException {
    return writeJar(name, "library/Unused.class");
  }

  private Path writeJar(final String name, final String classEntry) throws IOException {
    final Path jar = tempDir.resolve(name);
    try (ZipOutputStream output = new ZipOutputStream(Files.newOutputStream(jar))) {
      output.putNextEntry(new ZipEntry(classEntry));
      output.write(new byte[] {0});
      output.closeEntry();
    }
    return jar;
  }

  private Path compileJar(final String jarName, final String className) throws IOException {
    final String packageName = className.substring(0, className.lastIndexOf('.'));
    final String simpleName = className.substring(className.lastIndexOf('.') + 1);
    final Path source =
        tempDir
            .resolve(jarName + "-src")
            .resolve(packageName.replace('.', '/'))
            .resolve(simpleName + ".java");
    Files.createDirectories(source.getParent());
    Files.writeString(source, "package " + packageName + "; public class " + simpleName + " {}\n");
    final Path output = Files.createDirectories(tempDir.resolve(jarName + "-classes"));
    final int result =
        ToolProvider.getSystemJavaCompiler()
            .run(null, null, null, "--release", "21", "-d", output.toString(), source.toString());
    if (result != 0) {
      throw new IOException("Could not compile the complete-source test dependency");
    }
    final Path jar = tempDir.resolve(jarName);
    try (JarOutputStream archive = new JarOutputStream(Files.newOutputStream(jar));
        java.util.stream.Stream<Path> paths = Files.walk(output)) {
      for (final Path classFile : paths.filter(Files::isRegularFile).toList()) {
        archive.putNextEntry(
            new JarEntry(output.relativize(classFile).toString().replace('\\', '/')));
        Files.copy(classFile, archive);
        archive.closeEntry();
      }
    }
    return jar;
  }

  private static ArtifactCoordinate generatedOwnerCoordinate() {
    return new ArtifactCoordinate("org.example", "generated", "1.0", "jar", "", "compile");
  }

  private static ArtifactCoordinate coordinateFor(final String artifactId, final String scope) {
    return new ArtifactCoordinate("org.example", artifactId, "1.0", "jar", "", scope);
  }

  private Artifact resolvedArtifact(final String artifactId, final String scope, final String name)
      throws IOException {
    final Artifact artifact = artifact(artifactId, scope);
    artifact.setFile(writeJar(name).toFile());
    return artifact;
  }

  private MavenProject projectWith(final Artifact resolved, final Set<Artifact> directArtifacts) {
    return projectWith(new LinkedHashSet<>(Set.of(resolved)), directArtifacts);
  }

  private MavenProject projectWith(
      final Set<Artifact> resolved, final Set<Artifact> directArtifacts) {
    final MavenProject project = new MavenProject();
    project.setArtifacts(resolved);
    project.setDependencyArtifacts(directArtifacts);
    return project;
  }

  private MavenElisionService.Analysis analyze(final MavenProject project, final String traceName)
      throws IOException, org.apache.maven.plugin.MojoFailureException {
    final Path trace = tempDir.resolve(traceName);
    Files.writeString(trace, "library/Unused\n");
    return new MavenElisionService().analyze(project, List.of(trace.toFile()), List.of(), null);
  }

  @SafeVarargs
  private static Set<Artifact> identitySet(final Artifact... artifacts) {
    final Set<Artifact> result = Collections.newSetFromMap(new IdentityHashMap<>());
    Collections.addAll(result, artifacts);
    return result;
  }
}
