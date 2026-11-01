// WHY: Verifies global retention matching across Maven scopes and optional version selectors.

package io.github.spockz.elider.engine;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.spockz.elider.model.ArtifactCoordinate;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** Verifies global artifact retention matching. */
@SuppressWarnings("PMD.AvoidDuplicateLiterals")
final class RetentionConfigTest {
  /** Creates the focused test fixture. */
  @SuppressWarnings({"PMD.UncommentedEmptyConstructor", "PMD.CommentDefaultAccessModifier"})
  RetentionConfigTest() {}

  @Test
  void versionlessGlobalRetentionMatchesAnyScopeAndVersion() {
    final ArtifactCoordinate retained =
        new ArtifactCoordinate("org.example", "unused", null, "jar", "", "compile");
    final PruneConfig config =
        new PruneConfig(Set.of(), Set.of(), Set.of("compile", "runtime"), Set.of(retained));

    assertThat(
            config.keeps(
                new ArtifactCoordinate("org.example", "unused", "2.0", "jar", "", "runtime")))
        .isTrue();
  }

  @Test
  void globalRetentionDoesNotMatchOtherArtifacts() {
    final ArtifactCoordinate retained =
        new ArtifactCoordinate("org.example", "unused", null, "jar", "", "compile");
    final PruneConfig config =
        new PruneConfig(Set.of(), Set.of(), Set.of("compile", "runtime"), Set.of(retained));

    assertThat(
            config.keeps(
                new ArtifactCoordinate("org.example", "other", "2.0", "jar", "", "runtime")))
        .isFalse();
  }

  @Test
  void versionedRetentionRequiresTheSameVersion() {
    final PruneConfig config =
        configFor(
            new ArtifactCoordinate("org.example", "unused", "1.0", "jar", "tests", "compile"));

    assertThat(
            config.keeps(
                new ArtifactCoordinate("org.example", "unused", "2.0", "jar", "tests", "runtime")))
        .isFalse();
  }

  @Test
  void retentionRequiresTheSameType() {
    final PruneConfig config =
        configFor(
            new ArtifactCoordinate("org.example", "unused", "1.0", "jar", "tests", "compile"));

    assertThat(
            config.keeps(
                new ArtifactCoordinate("org.example", "unused", "1.0", "zip", "tests", "runtime")))
        .isFalse();
  }

  @Test
  void retentionRequiresTheSameClassifier() {
    final PruneConfig config =
        configFor(
            new ArtifactCoordinate("org.example", "unused", "1.0", "jar", "tests", "compile"));

    assertThat(
            config.keeps(
                new ArtifactCoordinate("org.example", "unused", "1.0", "jar", "", "runtime")))
        .isFalse();
  }

  private static PruneConfig configFor(final ArtifactCoordinate retainedCoordinate) {
    return new PruneConfig(
        Set.of(), Set.of(), Set.of("compile", "runtime"), Set.of(retainedCoordinate));
  }
}
