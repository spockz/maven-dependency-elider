/* WHY: Retains package and version scope even when an OSV record has no CVE alias. */

package io.github.spockz.elider.model;

import java.util.List;
import java.util.Objects;

/** Original Maven ecosystem package and its OSV versions and range events. */
public record OsvAffectedPackage(
    String ecosystem,
    String packageName,
    ArtifactCoordinate coordinate,
    List<String> versions,
    List<OsvAffectedRange> ranges) {
  /** Validates the package identity and freezes source scope collections. */
  public OsvAffectedPackage {
    requireText(ecosystem, "ecosystem");
    requireText(packageName, "packageName");
    Objects.requireNonNull(coordinate, "coordinate");
    Objects.requireNonNull(versions, "versions");
    versions.forEach(value -> requireText(value, "version"));
    versions = List.copyOf(versions);
    Objects.requireNonNull(ranges, "ranges");
    ranges.forEach(value -> Objects.requireNonNull(value, "range"));
    ranges = List.copyOf(ranges);
  }

  private static void requireText(final String value, final String field) {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException(field + " must not be blank");
    }
  }
}
