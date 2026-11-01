// WHY: Verifies ban conflicts use effective direct declarations independently from resolved views.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.ArtifactSnapshot;
import java.nio.file.Path;
import java.util.List;
import org.apache.maven.model.Dependency;
import org.apache.maven.plugin.MojoFailureException;
import org.junit.jupiter.api.Test;

/** Verifies policy conflicts against first-level Maven declarations. */
final class BanishedDependencyPolicyTest {
  /** Shared group identity used by exact ban policy fixtures. */
  private static final String GROUP_ID = "org.example";

  /** Shared artifact identity used by matching and conflict scenarios. */
  private static final String LIBRARY_ID = "library";

  /** Exact request used by matching and conflict scenarios. */
  private static final String LIBRARY_REQUEST = GROUP_ID + ":" + LIBRARY_ID;

  /** Maven artifact type accepted by policy matching. */
  private static final String JAR_TYPE = "jar";

  /** First version used to prove ban matching ignores version. */
  private static final String FIRST_VERSION = "1.0";

  /** Second version used to prove ban matching ignores version. */
  private static final String SECOND_VERSION = "2.0";

  /** Supported Maven scope used by resolved artifact fixtures. */
  private static final String COMPILE_SCOPE = "compile";

  /** Required explicit constructor for the repository's test-class PMD rule. */
  @SuppressWarnings({"PMD.CommentDefaultAccessModifier", "PMD.UncommentedEmptyConstructor"})
  BanishedDependencyPolicyTest() {}

  @Test
  void rejectsFirstLevelDeclarationWhenDirectArtifactViewOmitsIt() {
    final Dependency declaration = new Dependency();
    declaration.setGroupId(GROUP_ID);
    declaration.setArtifactId("direct");

    assertThatThrownBy(
            () ->
                BanishedDependencyPolicy.resolve(
                    List.of(),
                    List.of(GROUP_ID + ":direct"),
                    List.of(declaration),
                    List.of(),
                    List.of(),
                    List.of()))
        .isInstanceOf(MojoFailureException.class)
        .hasMessageContaining("direct first-level dependency: org.example:direct");
  }

  @Test
  void trimsAndDeduplicatesExactCoordinatesAndRejectsMalformedOrWildcardRequests()
      throws MojoFailureException {
    assertAll(
        "ban identities accept only exact G:A coordinates",
        () ->
            assertThat(
                    BanishedDependencyPolicy.normalize(
                        List.of(" " + LIBRARY_REQUEST + " ", LIBRARY_REQUEST, GROUP_ID + ":other")))
                .containsExactly(
                    new BanishedDependency(GROUP_ID, LIBRARY_ID),
                    new BanishedDependency(GROUP_ID, "other")),
        () ->
            assertThatThrownBy(() -> BanishedDependencyPolicy.normalize(List.of("org.example")))
                .isInstanceOf(MojoFailureException.class)
                .hasMessageContaining("expected exact groupId:artifactId"),
        () ->
            assertThatThrownBy(() -> BanishedDependencyPolicy.normalize(List.of("*:library")))
                .isInstanceOf(MojoFailureException.class)
                .hasMessageContaining("without wildcards"),
        () ->
            assertThatThrownBy(
                    () -> BanishedDependencyPolicy.normalize(List.of("org.example:lib?")))
                .isInstanceOf(MojoFailureException.class)
                .hasMessageContaining("without wildcards"));
  }

  @Test
  void reportsCurrentMatchesAcrossVersionsAndClassifiersSeparatelyFromUnmatchedRequests()
      throws MojoFailureException {
    final List<ArtifactSnapshot> resolved =
        List.of(
            snapshot(LIBRARY_ID, FIRST_VERSION, JAR_TYPE, "", COMPILE_SCOPE),
            snapshot(LIBRARY_ID, SECOND_VERSION, JAR_TYPE, "tests", "runtime"));

    final BanishedDependencyPolicy.Resolution result =
        resolve(
            List.of(),
            List.of(LIBRARY_REQUEST, GROUP_ID + ":missing"),
            List.of(),
            List.of(),
            resolved,
            List.of());

    assertAll(
        "current matches and unmatched requests remain separately observable",
        () -> {
          final BanishedDependencyPolicy.Match matchedLibrary =
              result.matches().stream()
                  .filter(match -> LIBRARY_ID.equals(match.dependency().artifactId()))
                  .findFirst()
                  .orElseThrow();
          assertThat(matchedLibrary.artifacts())
              .extracting(snapshot -> snapshot.coordinate().version())
              .containsExactly(FIRST_VERSION, SECOND_VERSION);
        },
        () ->
            assertThat(result.noCurrentInventoryMatch())
                .containsExactly(new BanishedDependency(GROUP_ID, "missing")));
  }

  @Test
  void rejectsUnsupportedResolvedTypesAndScopes() {
    assertAll(
        "only compile/runtime JAR matches are supported",
        () ->
            assertThatThrownBy(
                    () ->
                        resolve(
                            List.of(),
                            List.of(LIBRARY_REQUEST),
                            List.of(),
                            List.of(),
                            List.of(snapshot(LIBRARY_ID, FIRST_VERSION, "pom", "", "compile")),
                            List.of()))
                .isInstanceOf(MojoFailureException.class)
                .hasMessageContaining("unsupported resolved artifact"),
        () ->
            assertThatThrownBy(
                    () ->
                        resolve(
                            List.of(),
                            List.of(LIBRARY_REQUEST),
                            List.of(),
                            List.of(),
                            List.of(snapshot(LIBRARY_ID, FIRST_VERSION, JAR_TYPE, "", "test")),
                            List.of()))
                .isInstanceOf(MojoFailureException.class)
                .hasMessageContaining("unsupported resolved artifact"),
        () ->
            assertThatThrownBy(
                    () ->
                        resolve(
                            List.of(),
                            List.of(LIBRARY_REQUEST),
                            List.of(),
                            List.of(),
                            List.of(
                                snapshot(LIBRARY_ID, FIRST_VERSION, JAR_TYPE, "", COMPILE_SCOPE),
                                snapshot(
                                    LIBRARY_ID, SECOND_VERSION, "test-jar", "tests", "runtime")),
                            List.of()))
                .isInstanceOf(MojoFailureException.class)
                .hasMessageContaining("unsupported resolved artifact")
                .hasMessageContaining("test-jar:tests"));
  }

  @Test
  void rejectsRetentionAndConfiguredPassThroughConflictsWithoutLiveViewMatches() {
    assertAll(
        "ban requests cannot conflict with retained or byte-identical artifacts",
        () ->
            assertThatThrownBy(
                    () ->
                        resolve(
                            List.of(LIBRARY_REQUEST),
                            List.of("org.example:library"),
                            List.of(),
                            List.of(),
                            List.of(),
                            List.of()))
                .isInstanceOf(MojoFailureException.class)
                .hasMessageContaining("conflicts with elide.retainedArtifacts"),
        () ->
            assertThatThrownBy(
                    () ->
                        resolve(
                            List.of(),
                            List.of("org.example:library"),
                            List.of(),
                            List.of(LIBRARY_REQUEST + ":" + FIRST_VERSION + ":" + JAR_TYPE + ":"),
                            List.of(),
                            List.of()))
                .isInstanceOf(MojoFailureException.class)
                .hasMessageContaining("conflicts with matching elide.trimSkipArtifacts"));
  }

  @Test
  void rejectsDirectArtifactViewMatchIndependentlyFromDeclarations() {
    assertThatThrownBy(
            () ->
                resolve(
                    List.of(),
                    List.of(GROUP_ID + ":direct"),
                    List.of(),
                    List.of(),
                    List.of(),
                    List.of(snapshot("direct", FIRST_VERSION, JAR_TYPE, "", "compile"))))
        .isInstanceOf(MojoFailureException.class)
        .hasMessageContaining("direct artifact-view member: org.example:direct");
  }

  private static BanishedDependencyPolicy.Resolution resolve(
      final List<String> retained,
      final List<String> requests,
      final List<Dependency> firstLevel,
      final List<String> trimSkip,
      final List<ArtifactSnapshot> resolved,
      final List<ArtifactSnapshot> direct)
      throws MojoFailureException {
    return BanishedDependencyPolicy.resolve(
        retained, requests, firstLevel, trimSkip, resolved, direct);
  }

  private static ArtifactSnapshot snapshot(
      final String artifactId,
      final String version,
      final String type,
      final String classifier,
      final String scope) {
    return new ArtifactSnapshot(
        null,
        new ArtifactCoordinate(GROUP_ID, artifactId, version, type, classifier, scope),
        Path.of(artifactId + "." + type));
  }
}
