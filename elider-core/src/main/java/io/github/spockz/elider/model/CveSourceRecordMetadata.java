/* WHY: Preserves the source CVE identity/state used to admit structured claims. */

package io.github.spockz.elider.model;

import java.util.Set;
import java.util.regex.Pattern;

/** CVE metadata and source digest retained with CNA entries. */
public record CveSourceRecordMetadata(
    boolean cveMetadataPresent,
    boolean cveMetadataObject,
    boolean cveIdPresent,
    String cveId,
    boolean statePresent,
    String state,
    String sourceRecordSha256) {
  /** Lowercase SHA-256 representation used by all persisted evidence. */
  private static final Pattern SHA256 = Pattern.compile("[0-9a-f]{64}");

  /** Validates presence/value pairs while retaining missing and explicit-null states. */
  public CveSourceRecordMetadata {
    if (cveMetadataObject && !cveMetadataPresent) {
      throw new IllegalArgumentException("cveMetadata object cannot be absent");
    }
    if (!cveMetadataObject && (cveIdPresent || statePresent || cveId != null || state != null)) {
      throw new IllegalArgumentException("CVE metadata fields require an object source value");
    }
    if (!cveIdPresent && cveId != null) {
      throw new IllegalArgumentException("cveId value requires a present field");
    }
    if (!statePresent && state != null) {
      throw new IllegalArgumentException("state value requires a present field");
    }
    if (cveId != null && cveId.isBlank()) {
      throw new IllegalArgumentException("cveId must not be blank when textual");
    }
    if (state != null && state.isBlank()) {
      throw new IllegalArgumentException("state must not be blank when textual");
    }
    if (sourceRecordSha256 == null || !SHA256.matcher(sourceRecordSha256).matches()) {
      throw new IllegalArgumentException("sourceRecordSha256 must be a canonical SHA-256");
    }
  }

  /** Returns whether this source record identifies the requested published CVE. */
  public boolean authorizesStructuredClaims(
      final String requestedCveId, final String osvId, final Set<String> aliases) {
    return cveMetadataPresent
        && cveMetadataObject
        && cveIdPresent
        && requestedCveId != null
        && requestedCveId.equals(cveId)
        && (requestedCveId.equals(osvId) || aliases.contains(requestedCveId))
        && statePresent
        && "PUBLISHED".equals(state);
  }
}
