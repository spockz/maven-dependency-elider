/* WHY: Verifies immutable class-origin evidence preserves ambiguity when traces merge. */

package io.github.spockz.elider.model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Path;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** Covers trace origin evidence and merge behavior. */
class TraceDataTest {
  /** Class shared by the origin observations. */
  private final String sharedClass;

  /** Absolute source path used for the first observation. */
  private final Path firstJarPath;

  /** Initializes stable inputs shared by origin evidence tests. */
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  TraceDataTest() {
    sharedClass = "example.Shared";
    firstJarPath = Path.of("/tmp/first.jar");
  }

  @Test
  void attributedThenClassOnlyKeepsAmbiguity() {
    final TraceData attributed = attributed(firstJarPath);
    final TraceData classOnly = TraceData.of(Set.of(sharedClass));

    assertThat(attributed.merge(classOnly).originsFor(sharedClass))
        .isEqualTo(new OriginEvidence(Set.of(firstJarPath), true));
  }

  @Test
  void classOnlyThenAttributedKeepsAmbiguity() {
    final TraceData attributed = attributed(firstJarPath);
    final TraceData classOnly = TraceData.of(Set.of(sharedClass));

    assertThat(classOnly.merge(attributed).originsFor(sharedClass))
        .isEqualTo(new OriginEvidence(Set.of(firstJarPath), true));
  }

  @Test
  void legacyConstructorCreatesUnknownEvidence() {
    assertThat(new TraceData(Set.of(sharedClass)).originsFor(sharedClass))
        .isEqualTo(OriginEvidence.unknown());
  }

  @Test
  void knownOriginsUnionAcrossSources() {
    final Path firstPath = firstJarPath;
    final Path secondPath = Path.of("/tmp/second.jar");
    final TraceData merged = attributed(firstPath).merge(attributed(secondPath));

    assertThat(merged.originsFor(sharedClass))
        .isEqualTo(new OriginEvidence(Set.of(firstPath, secondPath), false));
  }

  @Test
  void originMapIsImmutable() {
    final TraceData merged = attributed(firstJarPath);

    assertThatThrownBy(() -> merged.originEvidenceByClass().clear())
        .isInstanceOf(UnsupportedOperationException.class);
  }

  @Test
  void originPathsAreImmutable() {
    final TraceData merged = attributed(firstJarPath);

    assertThatThrownBy(() -> merged.originsFor(sharedClass).jarPaths().clear())
        .isInstanceOf(UnsupportedOperationException.class);
  }

  @Test
  void rejectsEvidenceForAbsentClasses() {
    assertThatThrownBy(
            () ->
                new TraceData(
                    Set.of("example.Present"),
                    Set.of("example/Present"),
                    Map.of("example.Absent", OriginEvidence.unknown())))
        .isInstanceOf(IllegalArgumentException.class);
  }

  private TraceData attributed(final Path path) {
    return TraceData.fromClassOrigins(Map.of(sharedClass, new OriginEvidence(Set.of(path), false)));
  }
}
