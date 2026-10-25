// WHY: Guards ordered artifact snapshots and rejects scope-erasing identity contradictions.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.spockz.elider.model.ArtifactCoordinate;
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
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;
import org.apache.maven.project.MavenProject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Verifies Maven elision preparation without mutating Maven state. */
@SuppressWarnings({
  "PMD.AvoidDuplicateLiterals",
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
    assertThat(plan.directArtifacts()).containsExactly(unrepresented);
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

    assertThatThrownBy(() -> new MavenElisionService().analyze(project, List.of(), List.of()))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Conflicting files for artifact identity");
    assertThat(project.getArtifacts()).containsExactlyInAnyOrder(first, second);
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
        "org.example", artifactId, "1.0", scope, "jar", null, new DefaultArtifactHandler("jar"));
  }

  private static ArtifactCoordinate coordinate(final String scope) {
    return new ArtifactCoordinate("org.example", "library", "1.0", "jar", "", scope);
  }

  private static ElisionDecision decision(
      final Set<ArtifactCoordinate> retained, final Set<ArtifactCoordinate> elided) {
    return new ElisionDecision(retained, elided, Map.of(), Map.of(), 0L);
  }

  private Path writeJar(final String name) throws IOException {
    final Path jar = tempDir.resolve(name);
    try (ZipOutputStream output = new ZipOutputStream(Files.newOutputStream(jar))) {
      output.putNextEntry(new ZipEntry("library/Unused.class"));
      output.write(new byte[] {0});
      output.closeEntry();
    }
    return jar;
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
    return new MavenElisionService().analyze(project, List.of(trace.toFile()), List.of());
  }

  @SafeVarargs
  private static Set<Artifact> identitySet(final Artifact... artifacts) {
    final Set<Artifact> result = Collections.newSetFromMap(new IdentityHashMap<>());
    Collections.addAll(result, artifacts);
    return result;
  }
}
