/* WHY: Verifies local cache identity and snapshot build compatibility rules. */

package io.github.spockz.elider.model;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/** Verifies local cache identity and snapshot build compatibility rules. */
class CacheProducerIdentityTest {
  /** Digest used by canonical snapshot identity fixtures. */
  private static final String DIGEST = "a".repeat(64);

  /** Shared released coordinate fixture values. */
  private static final String GROUP_ID = "io.example";

  /** Artifact for the released producer fixture. */
  private static final String ARTIFACT_ID = "plugin";

  /** Released version used by exact-identity cases. */
  private static final String RELEASED_VERSION = "1.2.3";

  /** Error phrase emitted for non-canonical producer digests. */
  private static final String CANONICAL_DIGEST_ERROR = "canonical SHA-256";

  /** Released identity shared by the compatibility scenarios. */
  private final CacheProducerIdentity releasedIdentity;

  /** Initializes shared state for the identity compatibility cases. */
  protected CacheProducerIdentityTest() {
    releasedIdentity = released();
  }

  @Test
  void releasedIdentityRequiresExactCoordinatesWithoutBuildIdentity() {
    final CacheProducerIdentity identity = releasedIdentity;
    final boolean exactMatch = identity.isCompatibleWith(releasedIdentity);
    final boolean groupMismatch =
        identity.isCompatibleWith(
            new CacheProducerIdentity("different-group", ARTIFACT_ID, RELEASED_VERSION, null));
    final boolean artifactMismatch =
        identity.isCompatibleWith(
            new CacheProducerIdentity(GROUP_ID, "different-artifact", RELEASED_VERSION, null));
    final boolean versionMismatch =
        identity.isCompatibleWith(new CacheProducerIdentity(GROUP_ID, ARTIFACT_ID, "1.2.4", null));
    final CacheProducerIdentity releaseWithDigest =
        new CacheProducerIdentity(GROUP_ID, ARTIFACT_ID, RELEASED_VERSION, DIGEST);
    final boolean differingReleaseDigestIsCompatible =
        releaseWithDigest.isCompatibleWith(
            new CacheProducerIdentity(GROUP_ID, ARTIFACT_ID, RELEASED_VERSION, "b".repeat(64)));
    final CacheProducerIdentity.CompatibilityIdentity normalizedRelease =
        releaseWithDigest.canonicalCompatibilityIdentity();
    assertAll(
        () -> assertTrue(exactMatch, "released identity should match exact coordinates"),
        () -> assertFalse(groupMismatch, "group mismatch must reject the cache"),
        () -> assertFalse(artifactMismatch, "artifact mismatch must reject the cache"),
        () -> assertFalse(versionMismatch, "version mismatch must reject the cache"),
        () ->
            assertTrue(
                releaseWithDigest.isCompatibleWith(releasedIdentity),
                "release build metadata does not change GAV compatibility"),
        () ->
            assertTrue(
                differingReleaseDigestIsCompatible,
                "different optional release digests remain compatible for the exact GAV"),
        () ->
            org.assertj.core.api.Assertions.assertThat(normalizedRelease.buildIdentity()).isNull(),
        () ->
            assertThatThrownBy(
                    () ->
                        new CacheProducerIdentity(
                            GROUP_ID, ARTIFACT_ID, RELEASED_VERSION, "A".repeat(64)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining(CANONICAL_DIGEST_ERROR));
  }

  @Test
  void snapshotIdentityRequiresTheExactCanonicalBuildDigest() {
    final CacheProducerIdentity identity = snapshot(DIGEST);
    final boolean exactBuild = identity.isCompatibleWith(snapshot(DIGEST));
    final boolean differentBuild = identity.isCompatibleWith(snapshot("b".repeat(64)));
    final CacheProducerIdentity.CompatibilityIdentity normalizedSnapshot =
        identity.canonicalCompatibilityIdentity();
    assertAll(
        () -> assertTrue(exactBuild, "snapshot identity should match its exact build digest"),
        () -> assertFalse(differentBuild, "a different snapshot build must reject the cache"),
        () ->
            org.assertj.core.api.Assertions.assertThat(normalizedSnapshot.buildIdentity())
                .isEqualTo(DIGEST),
        () ->
            assertThatThrownBy(() -> snapshot(null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining(CANONICAL_DIGEST_ERROR),
        () ->
            assertThatThrownBy(() -> snapshot("A".repeat(64)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining(CANONICAL_DIGEST_ERROR),
        () ->
            assertThatThrownBy(() -> snapshot("not-a-digest"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining(CANONICAL_DIGEST_ERROR));
  }

  private static CacheProducerIdentity released() {
    return new CacheProducerIdentity(GROUP_ID, ARTIFACT_ID, RELEASED_VERSION, null);
  }

  private static CacheProducerIdentity snapshot(final String digest) {
    return new CacheProducerIdentity(GROUP_ID, ARTIFACT_ID, RELEASED_VERSION + "-SNAPSHOT", digest);
  }
}
