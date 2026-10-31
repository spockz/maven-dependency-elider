// WHY: Guards ordered artifact snapshots and rejects scope-erasing identity contradictions.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ArtifactFileRef;
import io.github.spockz.elider.model.ElisionDecision;
import io.github.spockz.elider.test.CompilationFixtureSupport;
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
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;
import org.apache.maven.model.Plugin;
import org.apache.maven.model.PluginExecution;
import org.apache.maven.project.MavenProject;
import org.codehaus.plexus.util.xml.Xpp3Dom;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Verifies Maven elision preparation without mutating Maven state. */
@SuppressWarnings({
  "PMD.AvoidDuplicateLiterals",
  "PMD.CouplingBetweenObjects",
  "PMD.LawOfDemeter",
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
    final ElisionAnalysisModel.Analysis analysis =
        ElisionAnalysisTestFixtures.analysis(
            new ElisionAnalysisModel.ArtifactViews(
                MavenArtifactInventory.snapshots(ordered), false, List.of()),
            decision(Set.of(), Set.of()));

    assertThat(new ArrayList<>(analysis.artifacts().resolvedArtifacts()))
        .containsExactly(first, second);
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

    final ElisionAnalysisModel.DynamicRootInputs inputs =
        DynamicRootOrchestrator.dynamicRoots(
            candidates,
            (path, context) -> {
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
    final List<ElisionAnalysisModel.ArtifactSnapshot> source =
        new ArrayList<>(MavenArtifactInventory.snapshots(List.of(first, second)));
    final ElisionAnalysisModel.Analysis analysis =
        ElisionAnalysisTestFixtures.analysis(
            new ElisionAnalysisModel.ArtifactViews(source, false, List.of()),
            decision(Set.of(), Set.of()));
    source.clear();

    assertThat(analysis.artifacts().resolvedSnapshots())
        .extracting(ElisionAnalysisModel.ArtifactSnapshot::artifact)
        .containsExactly(first, second);
    assertThatThrownBy(() -> analysis.artifacts().resolvedSnapshots().clear())
        .isInstanceOf(UnsupportedOperationException.class);
    assertThatThrownBy(() -> analysis.artifacts().resolvedArtifacts().clear())
        .isInstanceOf(UnsupportedOperationException.class);
  }

  @Test
  @SuppressWarnings("PMD.LawOfDemeter")
  void artifactSnapshotKeepsScopeAndNormalizedFilePath() throws IOException {
    final Artifact dependency = resolvedArtifact("library", "runtime", "library.jar");
    final File dependencyFile = dependency.getFile();
    final Path dependencyPath = dependencyFile.toPath();
    final Path expectedPath = dependencyPath.toAbsolutePath().normalize();

    final ElisionAnalysisModel.ArtifactSnapshot snapshot =
        MavenArtifactInventory.snapshots(List.of(dependency)).getFirst();

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
    final ElisionAnalysisModel.ApplyPlan plan =
        new ElisionAnalysisModel.ApplyPlan(source, true, directSource);
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
    final ElisionAnalysisModel.Analysis analysis =
        ElisionAnalysisTestFixtures.analysis(
            new ElisionAnalysisModel.ArtifactViews(List.of(), false, List.of()), contradictory);

    assertThatThrownBy(() -> MavenArtifactInventory.plan(new MavenProject(), analysis))
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
    final ElisionAnalysisModel.Analysis analysis =
        ElisionAnalysisTestFixtures.analysis(
            new ElisionAnalysisModel.ArtifactViews(
                MavenArtifactInventory.snapshots(List.of(resolved)),
                true,
                MavenArtifactInventory.snapshots(List.of(direct, unrepresented))),
            decision(Set.of(), Set.of(coordinate("compile"))));

    final ElisionAnalysisModel.ApplyPlan plan = MavenArtifactInventory.plan(project, analysis);

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
    final ElisionAnalysisModel.Analysis analysis =
        ElisionAnalysisTestFixtures.analysis(
            new ElisionAnalysisModel.ArtifactViews(
                MavenArtifactInventory.snapshots(List.of(resolved)),
                true,
                MavenArtifactInventory.snapshots(List.of(direct))),
            decision(Set.of(coordinate("compile")), Set.of()));

    assertThatThrownBy(() -> MavenArtifactInventory.plan(project, analysis))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Conflicting direct artifact file");
    assertThat(project.getArtifacts()).containsExactly(resolved);
    assertThat(project.getDependencyArtifacts()).containsExactly(direct);
  }

  @Test
  void planRejectsArtifactCoordinateChangesAfterAnalysis() throws Exception {
    final Artifact dependency = resolvedArtifact("library", "compile", "library.jar");
    final MavenProject project = projectWith(dependency, null);
    final ElisionAnalysisModel.Analysis analysis = analyze(project, "coordinate.lst");
    dependency.setVersion("2.0");

    assertThatThrownBy(() -> MavenArtifactInventory.plan(project, analysis))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("artifact coordinate changed after analysis");
    assertThat(project.getArtifacts()).containsExactly(dependency);
    assertThat(project.getDependencyArtifacts()).isNull();
  }

  @Test
  void planRejectsArtifactScopeChangesAfterAnalysis() throws Exception {
    final Artifact dependency = resolvedArtifact("library", "compile", "library.jar");
    final MavenProject project = projectWith(dependency, null);
    final ElisionAnalysisModel.Analysis analysis = analyze(project, "scope.lst");
    dependency.setScope("runtime");

    assertThatThrownBy(() -> MavenArtifactInventory.plan(project, analysis))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("artifact coordinate changed after analysis");
    assertThat(project.getArtifacts()).containsExactly(dependency);
  }

  @Test
  void planRejectsArtifactReferenceReplacementAfterAnalysis() throws Exception {
    final Artifact dependency = resolvedArtifact("library", "compile", "library.jar");
    final MavenProject project = projectWith(dependency, null);
    final ElisionAnalysisModel.Analysis analysis = analyze(project, "reference.lst");
    final Artifact replacement = artifact("library", "compile");
    replacement.setFile(dependency.getFile());
    project.setArtifacts(new LinkedHashSet<>(List.of(replacement)));

    assertThatThrownBy(() -> MavenArtifactInventory.plan(project, analysis))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("artifact order or reference changed after analysis");
    assertThat(project.getArtifacts()).containsExactly(replacement);
  }

  @Test
  void planRejectsArtifactPathChangesAfterAnalysis() throws Exception {
    final Artifact dependency = resolvedArtifact("library", "compile", "library.jar");
    final MavenProject project = projectWith(dependency, null);
    final ElisionAnalysisModel.Analysis analysis = analyze(project, "path.lst");
    dependency.setFile(writeJar("changed.jar").toFile());

    assertThatThrownBy(() -> MavenArtifactInventory.plan(project, analysis))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("artifact file path changed after analysis");
    assertThat(project.getArtifacts()).containsExactly(dependency);
  }

  @Test
  void servicePreservesAbsentAndEmptyDirectViewDistinction() throws Exception {
    final Artifact absentViewArtifact = resolvedArtifact("absent", "compile", "absent.jar");
    final MavenProject absentProject = projectWith(absentViewArtifact, null);
    final ElisionAnalysisModel.Analysis absentAnalysis = analyze(absentProject, "absent.lst");
    final ElisionAnalysisModel.ApplyPlan absentPlan =
        MavenArtifactInventory.plan(absentProject, absentAnalysis);

    final Artifact emptyViewArtifact = resolvedArtifact("empty", "compile", "empty.jar");
    final MavenProject emptyProject = projectWith(emptyViewArtifact, new LinkedHashSet<>());
    final ElisionAnalysisModel.Analysis emptyAnalysis = analyze(emptyProject, "empty.lst");
    final ElisionAnalysisModel.ApplyPlan emptyPlan =
        MavenArtifactInventory.plan(emptyProject, emptyAnalysis);

    assertThat(absentAnalysis.artifacts().directArtifactsPresent()).isFalse();
    assertThat(absentPlan.directArtifactsPresent()).isFalse();
    assertThat(absentPlan.directArtifacts()).isEmpty();
    assertThat(emptyAnalysis.artifacts().directArtifactsPresent()).isTrue();
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

    final ElisionAnalysisModel.Analysis analysis =
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

    final ElisionAnalysisModel.Analysis analysis =
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

    final ElisionAnalysisModel.Analysis analysis =
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
  @DisplayName("ADR-0010/generated bytecode attribution elides unused compile jars")
  void generatedBytecodeAttributionElidesUnusedCompileJar() throws Exception {
    final Artifact used = resolvedArtifact("bytecode-used", "compile", "bytecode-used.jar");
    used.setFile(compileJar("bytecode-used.jar", "library.Used").toFile());
    final Artifact unused = resolvedArtifact("bytecode-unused", "compile", "bytecode-unused.jar");
    unused.setFile(compileJar("bytecode-unused.jar", "library.Unused").toFile());
    final Artifact observed =
        resolvedArtifact("bytecode-observed", "runtime", "bytecode-observed.jar");
    observed.setFile(writeJar("bytecode-observed.jar", "observed/Entry.class").toFile());
    final MavenProject project =
        projectWith(new LinkedHashSet<>(List.of(used, unused, observed)), null);
    final Path output = Files.createDirectories(tempDir.resolve("compiled-production"));
    final Path source = tempDir.resolve("compiled-production-src/app/GeneratedType.java");
    Files.createDirectories(source.getParent());
    Files.writeString(
        source, "package app; public final class GeneratedType { library.Used value; }\n");
    CompilationFixtureSupport.compile(
        output, List.of(source), 21, "-classpath", used.getFile().getPath());
    project.addCompileSourceRoot(tempDir.resolve("compiled-production-src").toString());
    project.getBuild().setOutputDirectory(output.toString());
    project.getProperties().setProperty("maven.compiler.release", "21");
    final Plugin generator = new Plugin();
    generator.setGroupId("org.openapitools");
    generator.setArtifactId("openapi-generator-maven-plugin");
    final PluginExecution generation = new PluginExecution();
    generation.setPhase("generate-sources");
    generation.setGoals(List.of("generate"));
    generator.addExecution(generation);
    project.getBuild().addPlugin(generator);
    final Plugin compiler = new Plugin();
    compiler.setGroupId("org.apache.maven.plugins");
    compiler.setArtifactId("maven-compiler-plugin");
    compiler.setVersion("3.13.0");
    compiler.setConfiguration(new Xpp3Dom("configuration"));
    final Xpp3Dom processorPaths = new Xpp3Dom("annotationProcessorPaths");
    processorPaths.addChild(new Xpp3Dom("path"));
    ((Xpp3Dom) compiler.getConfiguration()).addChild(processorPaths);
    project.getBuild().addPlugin(compiler);
    final Path trace = tempDir.resolve("production-bytecode.lst");
    Files.writeString(trace, "observed/Entry\n");

    final ElisionAnalysisModel.Analysis analysis =
        new MavenElisionService()
            .analyze(
                project,
                new ElisionAnalysisModel.AnalysisOptions(
                    List.of(trace.toFile()),
                    List.of(),
                    output.toFile(),
                    null,
                    new ElisionAnalysisModel.CompletenessOptions(false, true, false, true),
                    new ElisionAnalysisModel.TrimOptions(
                        false,
                        List.of(),
                        false,
                        List.of(),
                        false,
                        MavenDependencyTrimmer.DEFAULT_TRIM_WORKERS,
                        MavenDependencyTrimmer.MRJAR_VERTICAL_SHADING),
                    new ElisionAnalysisModel.DynamicRootOptions(true)));

    assertThat(analysis.decision().retainedArtifacts())
        .containsExactlyInAnyOrder(
            coordinateFor("bytecode-used", "compile"),
            coordinateFor("bytecode-observed", "runtime"));
    assertThat(analysis.decision().elidedArtifacts())
        .containsExactly(coordinateFor("bytecode-unused", "compile"));
  }

  @Test
  @DisplayName("ADR-0010/post-compile source-bytecode union retains inlined constant owners")
  void inlinedConstantOwnerIsRetainedForArtifactAndJarTrimming() throws Exception {
    final ConstantFixture fixture = constantFixture("inlined-constant");
    final ElisionAnalysisModel.Analysis artifactAnalysis =
        new MavenElisionService().analyze(fixture.project(), postCompileOptions(fixture, false));

    assertThat(artifactAnalysis.evidence().bytecodeScan().orElseThrow().referencedClasses())
        .doesNotContain("library.Constants");
    assertThat(artifactAnalysis.evidence().classUsageReport().classes())
        .anySatisfy(
            usage -> {
              assertThat(usage.className()).isEqualTo("library.Constants");
              assertThat(usage.category().name()).isEqualTo("NEITHER_REFERENCED_NOR_OBSERVED");
              assertThat(usage.applicationBytecodeReferenced()).isFalse();
              assertThat(usage.runtimeObserved()).isFalse();
            });
    assertThat(artifactAnalysis.decision().retainedArtifacts())
        .contains(coordinateFor("inlined-constant", "compile"));
    assertThat(
            artifactAnalysis
                .decision()
                .getRetainedClasses(coordinateFor("inlined-constant", "compile")))
        .contains("library.Constants")
        .doesNotContain("library.Dead");

    final ElisionAnalysisModel.Analysis trimAnalysis =
        new MavenElisionService().analyze(fixture.project(), postCompileOptions(fixture, true));

    assertThat(trimAnalysis.trimResult().records())
        .anySatisfy(
            record -> {
              assertThat(record.coordinate())
                  .isEqualTo(coordinateFor("inlined-constant", "compile"));
              assertThat(record.totalClasses()).isEqualTo(2);
              assertThat(record.retainedClasses()).isEqualTo(1);
            });
    assertThat(trimAnalysis.evidence().sourceAttributionFallback()).isNull();

    final MavenElisionService service = new MavenElisionService();
    final ElisionAnalysisModel.PreparedAnalysis sourcePrepared =
        service.prepare(fixture.project(), postCompileOptions(fixture, false));
    Files.writeString(
        fixture.source(),
        "package app; public final class Consumer { "
            + "String value = \"constant\"; generated.Model model; }\n");
    final ElisionAnalysisModel.PreparedAnalysis bytecodeOnlyPrepared =
        service.prepare(fixture.project(), postCompileOptions(fixture, false));
    assertThat(bytecodeOnlyPrepared.graphBinding().operationFingerprint())
        .isNotEqualTo(sourcePrepared.graphBinding().operationFingerprint());
  }

  @Test
  @DisplayName("ADR-0010/post-compile attribution failure retains all compile evidence")
  void incompletePostCompileAttributionFallsBackConservatively() throws Exception {
    final Artifact first = resolvedArtifact("fallback-first", "compile", "fallback-first.jar");
    first.setFile(
        CompilationFixtureSupport.compileToJar(
                tempDir.resolve("fallback-first.jar"),
                tempDir.resolve("fallback-first-src"),
                Map.of(
                    "library/Api.java",
                    "package library; public final class Api {}\n",
                    "library/ApiHelper.java",
                    "package library; public final class ApiHelper {}\n"),
                null)
            .toFile());
    final Artifact second = resolvedArtifact("fallback-second", "compile", "fallback-second.jar");
    second.setFile(compileJar("fallback-second.jar", "other.Unused").toFile());
    final Artifact runtime =
        resolvedArtifact("fallback-runtime", "runtime", "fallback-runtime.jar");
    runtime.setFile(compileJar("fallback-runtime.jar", "observed.Entry").toFile());
    final MavenProject project =
        projectWith(new LinkedHashSet<>(List.of(first, second, runtime)), null);
    project.getProperties().setProperty("maven.compiler.release", "21");
    final Path output = Files.createDirectories(tempDir.resolve("fallback-output"));
    project.getBuild().setOutputDirectory(output.toString());
    final Path compiledClass = output.resolve("app/UsesGeneratedMember.class");
    Files.createDirectories(compiledClass.getParent());
    Files.write(compiledClass, emptyClass("app/UsesGeneratedMember"));
    final Path sourceRoot = Files.createDirectories(tempDir.resolve("fallback-source-root"));
    final Path source = sourceRoot.resolve("app/UsesGeneratedMember.java");
    Files.createDirectories(source.getParent());
    Files.writeString(
        source,
        "package app; public final class UsesGeneratedMember { "
            + "library.Api generated = library.Api.builder(); }\n");
    project.addCompileSourceRoot(sourceRoot.toString());
    final Path trace = tempDir.resolve("fallback-runtime.lst");
    Files.writeString(trace, "observed/Entry\n");
    final ElisionAnalysisModel.AnalysisOptions options =
        new ElisionAnalysisModel.AnalysisOptions(
            List.of(trace.toFile()),
            List.of(),
            output.toFile(),
            null,
            new ElisionAnalysisModel.CompletenessOptions(false, true, false, true),
            new ElisionAnalysisModel.TrimOptions(
                true,
                List.of(),
                false,
                List.of(),
                false,
                MavenDependencyTrimmer.DEFAULT_TRIM_WORKERS,
                MavenDependencyTrimmer.MRJAR_VERTICAL_SHADING),
            new ElisionAnalysisModel.DynamicRootOptions(true));

    final ElisionAnalysisModel.Analysis analysis =
        new MavenElisionService().analyze(project, options);

    assertThat(analysis.evidence().sourceAttributionFallback())
        .contains("Cannot resolve production source references");
    assertThat(analysis.decision().retainedArtifacts())
        .contains(
            coordinateFor("fallback-first", "compile"),
            coordinateFor("fallback-second", "compile"),
            coordinateFor("fallback-runtime", "runtime"));
    assertThat(analysis.decision().getRetainedClasses(coordinateFor("fallback-first", "compile")))
        .containsExactlyInAnyOrder("library.Api", "library.ApiHelper");
    assertThat(analysis.decision().getRetainedClasses(coordinateFor("fallback-second", "compile")))
        .containsExactly("other.Unused");
    final RecordingMavenLog log = new RecordingMavenLog();
    ElisionSummary.reportAnalysis(log, analysis, null, true);
    assertThat(log.warnings()).anyMatch(message -> message.contains("used conservative fallback"));
  }

  @Test
  @DisplayName("ADR-0010/post-compile source options accept default javac and disable processors")
  void postCompileSourceOptionsUseDefaultJavacWithoutProcessors() throws IOException {
    assertThat(MavenCompilerSettings.postCompileSourceOptions(new MavenProject(), null))
        .containsExactly("-proc:none");
  }

  private ConstantFixture constantFixture(final String name) throws IOException {
    final Path fixtureRoot = Files.createTempDirectory(tempDir, name + "-");
    final Path jar =
        CompilationFixtureSupport.compileToJar(
            fixtureRoot.resolve(name + ".jar"),
            fixtureRoot.resolve(name + "-library-src"),
            Map.of(
                "library/Constants.java",
                "package library; public final class Constants { "
                    + "public static final String VALUE = \"constant\"; }\n",
                "library/Dead.java",
                "package library; public final class Dead {}\n"),
            null);
    final Artifact constantLibrary = resolvedArtifact(name, "compile", name + ".jar");
    constantLibrary.setFile(jar.toFile());
    try (java.util.jar.JarFile archive = new java.util.jar.JarFile(jar.toFile())) {
      assertThat(archive.getEntry("library/Constants.class"))
          .as("archive entries: %s", archive.stream().map(java.util.jar.JarEntry::getName).toList())
          .isNotNull();
    }
    final Artifact runtime = resolvedArtifact(name + "-runtime", "runtime", name + "-runtime.jar");
    runtime.setFile(
        CompilationFixtureSupport.compileToJar(
                fixtureRoot.resolve(name + "-runtime.jar"),
                fixtureRoot.resolve(name + "-runtime-src"),
                Map.of("observed/Entry.java", "package observed; public class Entry {}\n"),
                null)
            .toFile());
    final MavenProject project =
        projectWith(new LinkedHashSet<>(List.of(constantLibrary, runtime)), null);
    project.getProperties().setProperty("maven.compiler.release", "21");
    final Path output = Files.createDirectories(fixtureRoot.resolve(name + "-output"));
    project.getBuild().setOutputDirectory(output.toString());
    final Path modelSource = fixtureRoot.resolve(name + "-generated-src/generated/Model.java");
    Files.createDirectories(modelSource.getParent());
    Files.writeString(modelSource, "package generated; public final class Model {}\n");
    CompilationFixtureSupport.compile(output, List.of(modelSource));
    final Path sourceRoot = Files.createDirectories(fixtureRoot.resolve(name + "-source-root"));
    final Path source = sourceRoot.resolve("app/Consumer.java");
    Files.createDirectories(source.getParent());
    Files.writeString(
        source,
        "package app; public final class Consumer { "
            + "String value = library.Constants.VALUE; generated.Model model; }\n");
    CompilationFixtureSupport.compile(
        output, List.of(source), 21, "-classpath", jar + File.pathSeparator + output);
    project.addCompileSourceRoot(sourceRoot.toString());
    final Plugin compiler = new Plugin();
    compiler.setGroupId("org.apache.maven.plugins");
    compiler.setArtifactId("maven-compiler-plugin");
    compiler.setVersion("3.13.0");
    final Xpp3Dom compilerConfiguration = new Xpp3Dom("configuration");
    final Xpp3Dom processorPaths = new Xpp3Dom("annotationProcessorPaths");
    processorPaths.addChild(new Xpp3Dom("path"));
    compilerConfiguration.addChild(processorPaths);
    final Xpp3Dom processors = new Xpp3Dom("annotationProcessors");
    processors.addChild(new Xpp3Dom("annotationProcessor", "missing.MustNotRun"));
    compilerConfiguration.addChild(processors);
    compiler.setConfiguration(compilerConfiguration);
    project.getBuild().addPlugin(compiler);
    final Path trace = fixtureRoot.resolve(name + "-runtime.lst");
    Files.writeString(trace, "observed/Entry\n");
    return new ConstantFixture(project, output, trace, source);
  }

  private static ElisionAnalysisModel.AnalysisOptions postCompileOptions(
      final ConstantFixture fixture, final boolean trimJars) {
    return new ElisionAnalysisModel.AnalysisOptions(
        List.of(fixture.trace().toFile()),
        List.of(),
        fixture.output().toFile(),
        null,
        new ElisionAnalysisModel.CompletenessOptions(false, true, false, true),
        new ElisionAnalysisModel.TrimOptions(
            trimJars,
            List.of(),
            false,
            List.of(),
            false,
            MavenDependencyTrimmer.DEFAULT_TRIM_WORKERS,
            MavenDependencyTrimmer.MRJAR_VERTICAL_SHADING),
        new ElisionAnalysisModel.DynamicRootOptions(true));
  }

  private static byte[] emptyClass(final String internalName) {
    final org.objectweb.asm.ClassWriter writer = new org.objectweb.asm.ClassWriter(0);
    writer.visit(
        org.objectweb.asm.Opcodes.V21,
        org.objectweb.asm.Opcodes.ACC_PUBLIC,
        internalName,
        null,
        "java/lang/Object",
        null);
    writer.visitEnd();
    return writer.toByteArray();
  }

  private record ConstantFixture(MavenProject project, Path output, Path trace, Path source) {}

  @Test
  @DisplayName("ADR-0010/source and bytecode completeness assertions are mutually exclusive")
  void completenessAssertionsAreMutuallyExclusive() {
    final ElisionAnalysisModel.AnalysisOptions options =
        new ElisionAnalysisModel.AnalysisOptions(
            List.of(),
            List.of(),
            null,
            null,
            new ElisionAnalysisModel.CompletenessOptions(true, true, false, true),
            new ElisionAnalysisModel.TrimOptions(
                false,
                List.of(),
                false,
                List.of(),
                false,
                MavenDependencyTrimmer.DEFAULT_TRIM_WORKERS,
                MavenDependencyTrimmer.MRJAR_VERTICAL_SHADING),
            new ElisionAnalysisModel.DynamicRootOptions(true));

    assertThatThrownBy(() -> new MavenElisionService().prepare(new MavenProject(), options))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("are mutually exclusive");
  }

  @Test
  @DisplayName("ADR-0010/source completeness rejects compiler processor paths")
  void sourceCompletenessRejectsCompilerAnnotationProcessorPaths() throws Exception {
    final Artifact observed =
        resolvedArtifact("source-processor-observed", "compile", "observed.jar");
    observed.setFile(compileJar("observed.jar", "library.Observed").toFile());
    final MavenProject project = projectWith(new LinkedHashSet<>(List.of(observed)), null);
    project.getProperties().setProperty("maven.compiler.release", "21");
    final Path sourceRoot = Files.createDirectories(tempDir.resolve("source-processor-root"));
    final Path source = sourceRoot.resolve("app/Application.java");
    Files.createDirectories(source.getParent());
    Files.writeString(source, "package app; public final class Application {}\n");
    project.addCompileSourceRoot(sourceRoot.toString());
    final Plugin compiler = new Plugin();
    compiler.setGroupId("org.apache.maven.plugins");
    compiler.setArtifactId("maven-compiler-plugin");
    compiler.setVersion("3.13.0");
    final Xpp3Dom configuration = new Xpp3Dom("configuration");
    final Xpp3Dom processorPaths = new Xpp3Dom("annotationProcessorPaths");
    processorPaths.addChild(new Xpp3Dom("path"));
    configuration.addChild(processorPaths);
    compiler.setConfiguration(configuration);
    project.getBuild().addPlugin(compiler);
    final Path trace = tempDir.resolve("source-processor.lst");
    Files.writeString(trace, "library/Observed\n");
    final ElisionAnalysisModel.AnalysisOptions options =
        new ElisionAnalysisModel.AnalysisOptions(
            List.of(trace.toFile()),
            List.of(),
            null,
            null,
            new ElisionAnalysisModel.CompletenessOptions(true, false, false, true),
            new ElisionAnalysisModel.TrimOptions(
                false,
                List.of(),
                false,
                List.of(),
                false,
                MavenDependencyTrimmer.DEFAULT_TRIM_WORKERS,
                MavenDependencyTrimmer.MRJAR_VERTICAL_SHADING),
            new ElisionAnalysisModel.DynamicRootOptions(true));

    assertThatThrownBy(() -> new MavenElisionService().analyze(project, options))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("source-generation lifecycle execution");
  }

  @Test
  @DisplayName("ADR-0010/empty production bytecode output fails closed")
  void emptyProductionBytecodeOutputFailsClosed() throws Exception {
    final MavenProject project = projectWith(Set.of(), null);
    final Path output = Files.createDirectories(tempDir.resolve("empty-production"));
    final Path trace = tempDir.resolve("empty-production.lst");
    Files.writeString(trace, "trace.Class\n");

    assertThatThrownBy(
            () ->
                new MavenElisionService()
                    .analyze(
                        project,
                        new ElisionAnalysisModel.AnalysisOptions(
                            List.of(trace.toFile()),
                            List.of(),
                            output.toFile(),
                            null,
                            new ElisionAnalysisModel.CompletenessOptions(false, true, false, true),
                            new ElisionAnalysisModel.TrimOptions(
                                false,
                                List.of(),
                                false,
                                List.of(),
                                false,
                                MavenDependencyTrimmer.DEFAULT_TRIM_WORKERS,
                                MavenDependencyTrimmer.MRJAR_VERTICAL_SHADING),
                            new ElisionAnalysisModel.DynamicRootOptions(true))))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("requires compiled production class files");
  }

  @Test
  void planRejectsConflictingPathsWithinDirectViewAndLeavesProjectUnchanged() throws IOException {
    final Artifact resolved = resolvedArtifact("library", "compile", "resolved.jar");
    final Artifact firstDirect = resolvedArtifact("library", "runtime", "direct-a.jar");
    final Artifact secondDirect = resolvedArtifact("library", "test", "direct-b.jar");
    final Set<Artifact> direct = identitySet(firstDirect, secondDirect);
    final MavenProject project = projectWith(resolved, direct);
    final ElisionAnalysisModel.Analysis analysis =
        ElisionAnalysisTestFixtures.analysis(
            new ElisionAnalysisModel.ArtifactViews(
                MavenArtifactInventory.snapshots(List.of(resolved)),
                true,
                MavenArtifactInventory.snapshots(direct)),
            decision(Set.of(coordinate("compile")), Set.of()));

    assertThatThrownBy(() -> MavenArtifactInventory.plan(project, analysis))
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
    final Path jar = tempDir.resolve(jarName);
    final Path sourceDirectory = tempDir.resolve(jarName + "-src");
    return CompilationFixtureSupport.compileToJar(
        jar,
        sourceDirectory,
        Map.of(
            className.replace('.', '/') + ".java",
            "package " + packageName + "; public class " + simpleName + " {}\n"),
        null);
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

  private ElisionAnalysisModel.Analysis analyze(final MavenProject project, final String traceName)
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
