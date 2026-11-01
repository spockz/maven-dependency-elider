/* WHY: Preserves source version semantics without converting CNA ranges to Maven ranges. */

package io.github.spockz.elider.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/** Raw version, status and version-type claim from a CVE affected product. */
public record CveVersionClaim(
    String version,
    String status,
    String versionType,
    String lessThan,
    String lessThanOrEqual,
    List<Map<String, String>> changes) {
  /** Validates version fields and snapshots unparsed range events. */
  public CveVersionClaim {
    if (version == null || version.isBlank()) {
      throw new IllegalArgumentException("version must not be blank");
    }
    if (status == null || status.isBlank()) {
      throw new IllegalArgumentException("status must not be blank");
    }
    if (versionType != null && versionType.isBlank()) {
      throw new IllegalArgumentException("versionType must not be blank when present");
    }
    requireOptionalText(lessThan, "lessThan");
    requireOptionalText(lessThanOrEqual, "lessThanOrEqual");
    Objects.requireNonNull(changes, "changes");
    final List<Map<String, String>> copy = new ArrayList<>();
    changes.forEach(change -> copy.add(immutableChange(change)));
    changes = Collections.unmodifiableList(copy);
  }

  private static Map<String, String> immutableChange(final Map<String, String> change) {
    Objects.requireNonNull(change, "change");
    for (final Map.Entry<String, String> field : change.entrySet()) {
      if (field.getKey() == null
          || field.getKey().isBlank()
          || field.getValue() == null
          || field.getValue().isBlank()) {
        throw new IllegalArgumentException("change fields and values must not be blank");
      }
    }
    return Map.copyOf(change);
  }

  private static void requireOptionalText(final String value, final String field) {
    if (value != null && value.isBlank()) {
      throw new IllegalArgumentException(field + " must not be blank when present");
    }
  }
}
