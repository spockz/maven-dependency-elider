/* WHY: Keeps local cache compatibility tied to the exact producer build. */

package io.github.spockz.elider.model;

import java.util.Objects;

/** Immutable producer identity stored beside a local cache document. */
public record CacheProducerIdentity(
    String groupId, String artifactId, String version, String buildIdentity) {
  /** Validates exact coordinates and requires a canonical build digest for snapshots. */
  public CacheProducerIdentity {
    requireText(groupId, "groupId");
    requireText(artifactId, "artifactId");
    requireText(version, "version");
    if (version.endsWith("-SNAPSHOT")) {
      if (buildIdentity == null || !buildIdentity.matches("[0-9a-f]{64}")) {
        throw new IllegalArgumentException(
            "SNAPSHOT producer buildIdentity must be a canonical SHA-256 digest");
      }
    } else if (buildIdentity != null && !buildIdentity.matches("[0-9a-f]{64}")) {
      throw new IllegalArgumentException(
          "Released producer buildIdentity must be a canonical SHA-256 digest");
    }
  }

  /** Returns the normalized producer value used by compatibility and fingerprints. */
  public CompatibilityIdentity canonicalCompatibilityIdentity() {
    return new CompatibilityIdentity(
        groupId, artifactId, version, version.endsWith("-SNAPSHOT") ? buildIdentity : null);
  }

  /** Returns whether this persisted producer is compatible with the running producer. */
  public boolean isCompatibleWith(final CacheProducerIdentity running) {
    Objects.requireNonNull(running, "running");
    return canonicalCompatibilityIdentity().equals(running.canonicalCompatibilityIdentity());
  }

  /** Structured cache identity with release-only metadata normalized away. */
  public record CompatibilityIdentity(
      String groupId, String artifactId, String version, String buildIdentity) {}

  private static void requireText(final String value, final String field) {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException(field + " must not be blank");
    }
  }
}
