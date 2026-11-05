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
    CveSourceRecordMetadata sourceRecord,
    String vendor,
    String product,
    String packageUrl,
    String collectionUrl,
    String packageName,
    String defaultStatus,
    List<CveVersionClaim> versions,
    Set<String> programFiles,
    Set<String> programRoutines) {
  /** Validates the locator and freezes the original version claims. */
  public CveAffectedEntryContext {
    requireText(entryIdentity, "entryIdentity");
    Objects.requireNonNull(sourceRecord, "sourceRecord");
    if (product != null && product.isBlank()) {
      throw new IllegalArgumentException("product must not be blank when present");
    }
    if (defaultStatus != null && defaultStatus.isBlank()) {
      throw new IllegalArgumentException("defaultStatus must not be blank when present");
    }
    Objects.requireNonNull(versions, "versions");
    versions.forEach(value -> Objects.requireNonNull(value, "version claim"));
    versions = List.copyOf(versions);
    programFiles = immutableClaims(programFiles, "programFiles");
    programRoutines = immutableClaims(programRoutines, "programRoutines");
  }

  /** Admits one exact affected claim and rejects range or change claims. */
  public boolean hasUnambiguousExactAffectedVersion(final String version) {
    if (version == null
        || version.isBlank()
        || versions.stream().anyMatch(CveAffectedEntryContext::hasRangeOrChangeClaim)) {
      return false;
    }
    final List<CveVersionClaim> matchingClaims =
        versions.stream().filter(claim -> version.equals(claim.version())).toList();
    return matchingClaims.size() == 1 && "affected".equals(matchingClaims.getFirst().status());
  }

  private static boolean hasRangeOrChangeClaim(final CveVersionClaim claim) {
    return claim.lessThan() != null
        || claim.lessThanOrEqual() != null
        || !claim.changes().isEmpty();
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
