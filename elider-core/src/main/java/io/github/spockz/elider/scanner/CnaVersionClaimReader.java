/* WHY: Keeps strict CNA range decoding separate from source-entry parsing. */

package io.github.spockz.elider.scanner;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.spockz.elider.model.CveVersionClaim;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Reads original CNA version and change claims. */
final class CnaVersionClaimReader {
  /** Required and permitted persisted CNA version fields. */
  private static final Set<String> VERSION_FIELDS =
      Set.of("version", "status", "versionType", "lessThan", "lessThanOrEqual", "changes");

  private CnaVersionClaimReader() {}

  /** Reads each original version claim without interpreting its range semantics. */
  /* package */ static List<CveVersionClaim> read(final JsonNode nodes) throws IOException {
    if (nodes == null || !nodes.isArray()) {
      throw new IOException("CNA versions must be an array");
    }
    final List<CveVersionClaim> versions = new ArrayList<>();
    for (final JsonNode version : nodes) {
      CnaAffectedEntryReader.requireObject(version, "CNA version");
      CnaAffectedEntryReader.requireFields(version, VERSION_FIELDS, "CNA version");
      versions.add(
          new CveVersionClaim(
              CnaAffectedEntryReader.requiredText(version, "version"),
              CnaAffectedEntryReader.requiredText(version, "status"),
              CnaAffectedEntryReader.optionalText(version, "versionType"),
              CnaAffectedEntryReader.optionalText(version, "lessThan"),
              CnaAffectedEntryReader.optionalText(version, "lessThanOrEqual"),
              readChanges(version.get("changes"))));
    }
    return List.copyOf(versions);
  }

  private static List<Map<String, String>> readChanges(final JsonNode nodes) throws IOException {
    if (nodes == null) {
      return List.of();
    }
    if (!nodes.isArray()) {
      throw new IOException("CNA version changes must be an array");
    }
    final List<Map<String, String>> changes = new ArrayList<>();
    for (final JsonNode node : nodes) {
      CnaAffectedEntryReader.requireObject(node, "CNA version change");
      changes.add(readChange(node));
    }
    return List.copyOf(changes);
  }

  @SuppressWarnings("PMD.UseConcurrentHashMap")
  private static Map<String, String> readChange(final JsonNode node) throws IOException {
    final Map<String, String> fields = new LinkedHashMap<>();
    final Iterator<Map.Entry<String, JsonNode>> iterator = node.fields();
    while (iterator.hasNext()) {
      final Map.Entry<String, JsonNode> field = iterator.next();
      if (!field.getValue().isTextual()) {
        throw new IOException("CNA version change fields must be strings");
      }
      fields.put(field.getKey(), field.getValue().textValue());
    }
    return Map.copyOf(fields);
  }
}
