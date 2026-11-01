/* WHY: Keeps source identity and integrity attached to advisory claims as they are persisted. */

package io.github.spockz.elider.model;

import java.net.URI;
import java.util.Locale;
import java.util.Objects;

/** Immutable source identity for one advisory evidence item. */
public record AdvisoryProvenance(
    EvidenceOrigin origin, String sourceRecordId, URI sourceUrl, String sourceRecordSha256) {
  /** Validates source identity, optional HTTP URL, and optional SHA-256 digest. */
  public AdvisoryProvenance {
    Objects.requireNonNull(origin, "origin");
    if (sourceRecordId == null || sourceRecordId.isBlank()) {
      throw new IllegalArgumentException("sourceRecordId must not be blank");
    }
    if (sourceUrl != null
        && (!sourceUrl.isAbsolute()
            || !("http".equalsIgnoreCase(sourceUrl.getScheme())
                || "https".equalsIgnoreCase(sourceUrl.getScheme())))) {
      throw new IllegalArgumentException("sourceUrl must be an absolute HTTP(S) URI");
    }
    if (sourceRecordSha256 != null) {
      if (!sourceRecordSha256.matches("(?i)[0-9a-f]{64}")) {
        throw new IllegalArgumentException("sourceRecordSha256 must be a SHA-256 hex digest");
      }
      sourceRecordSha256 = sourceRecordSha256.toLowerCase(Locale.ROOT);
    }
  }
}
