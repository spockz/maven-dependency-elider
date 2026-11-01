/* WHY: Keeps CNA claim serialization separate from OSV and advisory evidence encoding. */

package io.github.spockz.elider.scanner;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.spockz.elider.model.CveAffectedEntryContext;
import io.github.spockz.elider.model.CveSourceRecordMetadata;
import io.github.spockz.elider.model.CveVersionClaim;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/** Writes the original CNA affected-entry claims into the typed cache document. */
final class CnaAffectedEntryCodec {
  private CnaAffectedEntryCodec() {}

  /** Writes one CNA entry from within the scanner package. */
  /* package */
  static void write(final ObjectNode target, final CveAffectedEntryContext entry) {
    target.put("entryIdentity", entry.entryIdentity());
    writeSourceRecord(target.putObject("sourceRecord"), entry.sourceRecord());
    putOptional(target, "vendor", entry.vendor());
    target.put("product", entry.product());
    putOptional(target, "packageUrl", entry.packageUrl());
    putOptional(target, "collectionUrl", entry.collectionUrl());
    putOptional(target, "packageName", entry.packageName());
    putOptional(target, "defaultStatus", entry.defaultStatus());
    final ArrayNode versions = target.putArray("versions");
    entry.versions().forEach(value -> writeVersion(versions.addObject(), value));
    writeStrings(target.putArray("programFiles"), entry.programFiles());
    writeStrings(target.putArray("programRoutines"), entry.programRoutines());
  }

  private static void writeSourceRecord(
      final ObjectNode target, final CveSourceRecordMetadata sourceRecord) {
    target.put("cveMetadataPresent", sourceRecord.cveMetadataPresent());
    target.put("cveMetadataObject", sourceRecord.cveMetadataObject());
    target.put("cveIdPresent", sourceRecord.cveIdPresent());
    putOptional(target, "cveId", sourceRecord.cveId());
    target.put("statePresent", sourceRecord.statePresent());
    putOptional(target, "state", sourceRecord.state());
    target.put("sourceRecordSha256", sourceRecord.sourceRecordSha256());
  }

  private static void writeVersion(final ObjectNode target, final CveVersionClaim claim) {
    target.put("version", claim.version());
    target.put("status", claim.status());
    putOptional(target, "versionType", claim.versionType());
    putOptional(target, "lessThan", claim.lessThan());
    putOptional(target, "lessThanOrEqual", claim.lessThanOrEqual());
    final ArrayNode changes = target.putArray("changes");
    for (final Map<String, String> change : claim.changes()) {
      final ObjectNode changeNode = changes.addObject();
      change.entrySet().stream()
          .sorted(Map.Entry.comparingByKey())
          .forEach(item -> changeNode.put(item.getKey(), item.getValue()));
    }
  }

  private static void putOptional(final ObjectNode target, final String field, final String value) {
    if (value == null) {
      target.putNull(field);
    } else {
      target.put(field, value);
    }
  }

  private static void writeStrings(final ArrayNode target, final Set<String> values) {
    new TreeSet<>(values).forEach(target::add);
  }
}
