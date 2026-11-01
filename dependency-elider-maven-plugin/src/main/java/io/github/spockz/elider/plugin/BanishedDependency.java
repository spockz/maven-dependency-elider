// WHY: Represents the policy's exact G:A identity independently from Maven artifact coordinates.

package io.github.spockz.elider.plugin;

import java.util.Objects;

/** Exact group and artifact identity selected by the ban policy. */
record BanishedDependency(String groupId, String artifactId)
    implements Comparable<BanishedDependency> {
  /** Number of coordinate pieces accepted by the exact G:A policy. */
  private static final int PART_COUNT = 2;

  BanishedDependency {
    requirePart(groupId, "groupId");
    requirePart(artifactId, "artifactId");
  }

  /* default */ static BanishedDependency parse(final String raw) {
    if (raw == null) {
      throw new IllegalArgumentException("coordinate is null");
    }
    final String[] parts = raw.trim().split(":", -1);
    if (parts.length != PART_COUNT) {
      throw new IllegalArgumentException("expected exactly groupId:artifactId");
    }
    return new BanishedDependency(parts[0].trim(), parts[1].trim());
  }

  @Override
  public int compareTo(final BanishedDependency other) {
    final int groupComparison = groupId.compareTo(other.groupId);
    if (groupComparison == 0) {
      return artifactId.compareTo(other.artifactId);
    }
    return groupComparison;
  }

  @Override
  public String toString() {
    return groupId + ":" + artifactId;
  }

  private static void requirePart(final String value, final String label) {
    Objects.requireNonNull(value, label);
    if (value.isBlank()
        || value.indexOf(':') >= 0
        || value.indexOf('*') >= 0
        || value.indexOf('?') >= 0
        || value.chars().anyMatch(Character::isWhitespace)) {
      throw new IllegalArgumentException("invalid " + label);
    }
  }
}
