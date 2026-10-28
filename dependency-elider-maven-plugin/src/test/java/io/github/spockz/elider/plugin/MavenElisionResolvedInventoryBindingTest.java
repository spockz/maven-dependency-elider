/* WHY: Verifies exact local inventory compatibility and digest stability. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ElisionDecision;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;
import org.eclipse.aether.DefaultRepositorySystemSession;
import org.eclipse.aether.graph.DefaultDependencyNode;
import org.eclipse.aether.graph.Dependency;
import org.eclipse.aether.graph.DependencyNode;
import org.junit.jupiter.api.Test;

/** Verifies local inventory compatibility and digest checks. */
@SuppressWarnings({"PMD.UnitTestContainsTooManyAsserts"})
final class MavenElisionResolvedInventoryBindingTest extends MavenElisionGraphBindingTestSupport {
  /** Maven group shared by the graph and artifact fixture. */
  private static final String FIXTURE_GROUP = "fixture";

  /** Retained Maven test-jar identity in the unsupported-type case. */
  private static final String LIBRARY_ID = "library";

  /** Stable contents used for the one-JAR binding cases. */
  private static final String JAR_BYTES = "jar bytes";

  /** Maven scope used by both fixture artifacts and graph nodes. */
  private static final String COMPILE_SCOPE = "compile";

  /** Maven type whose artifact handler maps to the JAR resolver extension. */
  private static final String TEST_JAR_TYPE = "test-jar";

  /** Standard classifier used for Maven test JARs. */
  private static final String TESTS_CLASSIFIER = "tests";

  /** Resolver extension used for fixture archives. */
  private static final String JAR_EXTENSION = "jar";

  /** Creates this focused behavior test group. */
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  MavenElisionResolvedInventoryBindingTest() {
    super();
  }

  @Test
  void rejectsGraphInventoryThatDoesNotMatchResolvedArtifacts() throws Exception {
    final Fixture fixture = fixture(true, JAR_BYTES);
    final Artifact other = artifact("other.jar", "2.0");
    final MavenElisionService.ArtifactSnapshot mismatch =
        new MavenElisionService.ArtifactSnapshot(other, coordinate("2.0"), artifactPath(other));
    final MavenElisionGraphBinding.Result result = fixture.bind(List.of(mismatch));

    assertThat(result.evaluation().failClosed()).isTrue();
    assertThat(result.evaluation().elidedArtifacts()).isEmpty();
  }

  @Test
  void rejectsSameGavceWithDifferentGraphScope() throws Exception {
    final Fixture fixture = fixture(true, JAR_BYTES);
    fixture.replaceGraphScope("runtime");

    final MavenElisionGraphBinding.Result result = fixture.bind(List.of(fixture.snapshot()));

    assertThat(result.evaluation().failClosed()).isTrue();
    assertThat(result.evaluation().elidedArtifacts()).isEmpty();
    assertThat(result.evaluation().failClosedReason()).contains("complete resolved GAVCE/scope");
  }

  @Test
  void rejectsChangedJarDigestAtAnalysisUse() throws Exception {
    final Fixture fixture = fixture(true, "initial jar bytes");
    final MavenElisionGraphBinding.Result result = fixture.bind(List.of(fixture.snapshot()));
    Files.writeString(fixture.snapshot().filePath(), "changed jar bytes");

    assertThatThrownBy(
            () ->
                MavenElisionGraphBinding.verifyInventoryFingerprint(
                    List.of(fixture.snapshot()), result.inventoryFingerprint()))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("changed after fingerprinting");
  }

  @Test
  void rejectsDuplicateGavceInventoryBeforePairSelection() throws Exception {
    final Fixture fixture = fixture(true, JAR_BYTES);
    final Artifact other = artifact("other-copy.jar", VERSION);
    final MavenElisionGraphBinding.Result result =
        fixture.bind(
            List.of(
                fixture.snapshot(),
                new MavenElisionService.ArtifactSnapshot(
                    other, coordinate(VERSION), artifactPath(other))));

    assertThat(result.evaluation().failClosed()).isTrue();
    assertThat(result.evaluation().failClosedReason()).contains("Duplicate resolved artifact");
  }

  @Test
  void rejectsUnscannedMavenTypeWhoseResolverExtensionIsJar() throws Exception {
    final Fixture fixture = fixture(true, JAR_BYTES);
    final Artifact testJar =
        new DefaultArtifact(
            FIXTURE_GROUP,
            LIBRARY_ID,
            VERSION,
            COMPILE_SCOPE,
            TEST_JAR_TYPE,
            TESTS_CLASSIFIER,
            new DefaultArtifactHandler(JAR_EXTENSION));
    testJar.setFile(fixture.snapshot().filePath().toFile());
    final ArtifactCoordinate testJarCoordinate =
        new ArtifactCoordinate(
            FIXTURE_GROUP, LIBRARY_ID, VERSION, TEST_JAR_TYPE, TESTS_CLASSIFIER, COMPILE_SCOPE);
    final MavenElisionService.ArtifactSnapshot testJarSnapshot =
        new MavenElisionService.ArtifactSnapshot(
            testJar, testJarCoordinate, fixture.snapshot().filePath());
    final Artifact dropJar =
        new DefaultArtifact(
            FIXTURE_GROUP,
            "drop-library",
            VERSION,
            COMPILE_SCOPE,
            JAR_EXTENSION,
            null,
            new DefaultArtifactHandler(JAR_EXTENSION));
    final Path dropPath = Files.createFile(temporaryDirectory.resolve("drop-library.jar"));
    Files.writeString(dropPath, "drop jar bytes");
    dropJar.setFile(dropPath.toFile());
    final ArtifactCoordinate dropCoordinate =
        new ArtifactCoordinate(
            FIXTURE_GROUP, "drop-library", VERSION, JAR_EXTENSION, "", COMPILE_SCOPE);
    final MavenElisionService.ArtifactSnapshot dropSnapshot =
        new MavenElisionService.ArtifactSnapshot(dropJar, dropCoordinate, dropPath);
    appendPairWithTestJarAncestor(fixture.repositorySession(), projectKey(fixture.project()));
    final ElisionDecision rawDecision =
        new ElisionDecision(
            Set.of(testJarCoordinate), Set.of(dropCoordinate), Map.of(), Map.of(), 0L);
    final MavenElisionGraphBinding.Result result =
        fixture.bind(List.of(testJarSnapshot, dropSnapshot), rawDecision);

    assertThat(result.evaluation().failClosed()).isTrue();
    assertThat(result.evaluation().elidedArtifacts()).isEmpty();
    assertThat(result.evaluation().failClosedReason())
        .contains("No plan-absent graph pair matches");
  }

  /** WHY: Keeps an unscanned test JAR ancestor of a raw elision candidate. */
  @SuppressWarnings("PMD.LawOfDemeter")
  private static void appendPairWithTestJarAncestor(
      final DefaultRepositorySystemSession session, final String projectKey) {
    final DependencyNode root = node("consumer", "pom", "", "1.0");
    final DependencyNode testJar = node(LIBRARY_ID, JAR_EXTENSION, TESTS_CLASSIFIER, VERSION);
    final DependencyNode droppedJar = node("drop-library", JAR_EXTENSION, "", VERSION);
    root.setChildren(List.of(testJar));
    testJar.setChildren(List.of(droppedJar));
    droppedJar.setChildren(List.of());
    final ResolverArtifactGraphCapturePair pair =
        new ResolverArtifactGraphCapturePair(
            projectKey,
            "test-jar-capture",
            2L,
            false,
            null,
            0L,
            ResolverArtifactGraphSnapshot.capture(root, projectKey, false, null, 0L, 2L),
            ResolverArtifactGraphSnapshot.capture(root, projectKey, false, null, 0L, 2L));
    final Object existing =
        session.getData().get(EliderMediatedGraphCaptureDecorator.SESSION_DATA_KEY);
    final ResolverArtifactGraphSnapshotStore store =
        ResolverArtifactGraphSnapshotStore.fromPayload(existing);
    session
        .getData()
        .set(
            EliderMediatedGraphCaptureDecorator.SESSION_DATA_KEY,
            existing,
            store.append(pair).toPayload());
  }

  private static DefaultDependencyNode node(
      final String artifactId,
      final String extension,
      final String classifier,
      final String version) {
    return new DefaultDependencyNode(
        new Dependency(
            new org.eclipse.aether.artifact.DefaultArtifact(
                FIXTURE_GROUP, artifactId, classifier, extension, version),
            COMPILE_SCOPE,
            false));
  }
}
