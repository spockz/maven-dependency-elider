/* WHY: Retains CNA product and version claims without treating them as OSV scope. */

package io.github.spockz.elider.model;

import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;

/** Original product and version data from one CVE CNA affected entry. */
public record CveAffectedEntryContext(
    String entryIdentity,
    String vendor,
    String product,
    String packageUrl,
    String collectionUrl,
    String defaultStatus,
    List<CveVersionClaim> versions,
    Set<String> programFiles,
    Set<String> programRoutines) {
  /** Validates the locator and freezes the original version claims. */
  public CveAffectedEntryContext {
    requireText(entryIdentity, "entryIdentity");
    requireText(product, "product");
    if (defaultStatus != null && defaultStatus.isBlank()) {
      throw new IllegalArgumentException("defaultStatus must not be blank when present");
    }
    Objects.requireNonNull(versions, "versions");
    versions.forEach(value -> Objects.requireNonNull(value, "version claim"));
    versions = List.copyOf(versions);
    programFiles = immutableClaims(programFiles, "programFiles");
    programRoutines = immutableClaims(programRoutines, "programRoutines");
  }

  private static Set<String> immutableClaims(final Set<String> values, final String field) {
    Objects.requireNonNull(values, field);
    final Set<String> copy = new TreeSet<>();
    for (final String value : values) {
      if (value == null || value.isBlank()) {
        throw new IllegalArgumentException(field + " must contain non-blank values");
      }
      copy.add(value);
    }
    return Collections.unmodifiableSet(copy);
  }

  private static void requireText(final String value, final String field) {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException(field + " must not be blank");
    }
  }
}
