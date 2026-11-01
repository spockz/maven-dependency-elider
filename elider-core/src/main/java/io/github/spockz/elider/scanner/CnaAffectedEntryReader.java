/* WHY: Keeps strict persisted CNA entry parsing separate from advisory record decoding. */

package io.github.spockz.elider.scanner;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.spockz.elider.model.CveAffectedEntryContext;
import io.github.spockz.elider.model.CveSourceRecordMetadata;
import java.io.IOException;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.TreeSet;

/** Reads persisted CNA product entries and their original source claims. */
final class CnaAffectedEntryReader {
  /** Schema field names for structured file claims. */
  private static final String PROGRAM_FILES = "programFiles";

  /** Schema field names for structured routine claims. */
  private static final String PROGRAM_ROUTINES = "programRoutines";

  /** Required and permitted persisted CNA-entry fields. */
  private static final Set<String> ENTRY_FIELDS =
      Set.of(
          "entryIdentity",
          "sourceRecord",
          "vendor",
          "product",
          "packageUrl",
          "collectionUrl",
          "packageName",
          "defaultStatus",
          "versions",
          PROGRAM_FILES,
          PROGRAM_ROUTINES);

  /** Required and permitted source-record metadata fields. */
  private static final Set<String> SOURCE_RECORD_FIELDS =
      Set.of(
          "cveMetadataPresent",
          "cveMetadataObject",
          "cveIdPresent",
          "cveId",
          "statePresent",
          "state",
          "sourceRecordSha256");

  private CnaAffectedEntryReader() {}

  /** Reads one strict CNA entry in the advisory document. */
  /* package */ static CveAffectedEntryContext read(final JsonNode node) throws IOException {
    requireObject(node, "CNA affected entry");
    requireFields(node, ENTRY_FIELDS, "CNA affected entry");
    return new CveAffectedEntryContext(
        requiredText(node, "entryIdentity"),
        readSourceRecord(node.get("sourceRecord")),
        optionalText(node, "vendor"),
        requiredText(node, "product"),
        optionalText(node, "packageUrl"),
        optionalText(node, "collectionUrl"),
        optionalText(node, "packageName"),
        optionalText(node, "defaultStatus"),
        CnaVersionClaimReader.read(node.get("versions")),
        readStrings(node.get(PROGRAM_FILES), PROGRAM_FILES),
        readStrings(node.get(PROGRAM_ROUTINES), PROGRAM_ROUTINES));
  }

  private static CveSourceRecordMetadata readSourceRecord(final JsonNode node) throws IOException {
    requireObject(node, "CVE source record metadata");
    requireFields(node, SOURCE_RECORD_FIELDS, "CVE source record metadata");
    final JsonNode cveIdNode = node.get("cveId");
    final JsonNode stateNode = node.get("state");
    final String cveId = nullableText(cveIdNode, "CVE source cveId");
    final String state = nullableText(stateNode, "CVE source state");
    try {
      return new CveSourceRecordMetadata(
          requiredBoolean(node, "cveMetadataPresent"),
          requiredBoolean(node, "cveMetadataObject"),
          requiredBoolean(node, "cveIdPresent"),
          cveId,
          requiredBoolean(node, "statePresent"),
          state,
          requiredText(node, "sourceRecordSha256"));
    } catch (final IllegalArgumentException exception) {
      throw new IOException("Invalid CVE source record metadata", exception);
    }
  }

  private static Set<String> readStrings(final JsonNode node, final String field)
      throws IOException {
    if (node == null || !node.isArray()) {
      throw new IOException(field + " must be an array");
    }
    final Set<String> values = new TreeSet<>();
    for (final JsonNode item : node) {
      if (!item.isTextual() || !values.add(item.textValue())) {
        throw new IOException(field + " must contain unique strings");
      }
    }
    return Set.copyOf(values);
  }

  private static String nullableText(final JsonNode node, final String field) throws IOException {
    if (node.isNull()) {
      return null;
    }
    if (!node.isTextual()) {
      throw new IOException(field + " must be text or null");
    }
    return node.textValue();
  }

  /** Reads a required nonblank field for the adjacent version-claim codec. */
  /* package */ static String requiredText(final JsonNode node, final String field)
      throws IOException {
    final JsonNode value = node.get(field);
    if (value == null || !value.isTextual() || value.textValue().isBlank()) {
      throw new IOException(field + " must be a non-empty string");
    }
    return value.textValue();
  }

  /** Reads an optional text-or-null field for the adjacent version-claim codec. */
  /* package */ static String optionalText(final JsonNode node, final String field)
      throws IOException {
    final JsonNode value = node.get(field);
    if (value == null || value.isNull()) {
      return null;
    }
    if (!value.isTextual()) {
      throw new IOException(field + " must be a string or null");
    }
    return value.textValue();
  }

  private static boolean requiredBoolean(final JsonNode node, final String field)
      throws IOException {
    final JsonNode value = node.get(field);
    if (value == null || !value.isBoolean()) {
      throw new IOException(field + " must be a boolean");
    }
    return value.booleanValue();
  }

  /** Ensures the adjacent version-claim codec receives an object. */
  /* package */ static void requireObject(final JsonNode node, final String name)
      throws IOException {
    if (node == null || !node.isObject()) {
      throw new IOException(name + " must be an object");
    }
  }

  /** Ensures exact schema fields for the adjacent version-claim codec. */
  /* package */ static void requireFields(
      final JsonNode node, final Set<String> allowed, final String name) throws IOException {
    final Iterator<String> iterator = node.fieldNames();
    final Set<String> present = new HashSet<>();
    while (iterator.hasNext()) {
      final String field = iterator.next();
      if (!allowed.contains(field)) {
        throw new IOException(name + " contains unknown field: " + field);
      }
      present.add(field);
    }
    if (!present.containsAll(allowed)) {
      throw new IOException(name + " is missing required fields");
    }
  }
}
