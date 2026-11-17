/* WHY: Centralizes CVE List v5 record shape validation, metadata decoding, and path resolution. */

package io.github.spockz.elider.advisory;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.spockz.elider.model.CveAffectedEntryContext;
import io.github.spockz.elider.model.CveSourceRecordMetadata;
import io.github.spockz.elider.model.CveVersionClaim;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/** Shared CVE List v5 JSON record helpers for live reads and incremental indexing. */
@SuppressWarnings({
  "PMD.GodClass",
  "PMD.TooManyMethods",
  "PMD.CyclomaticComplexity",
  "PMD.UseConcurrentHashMap",
  "PMD.CommentDefaultAccessModifier",
  "PMD.AvoidLiteralsInIfCondition",
  "PMD.AvoidInstantiatingObjectsInLoops"
})
final class CveListRecordSupport {
  /** JSON container wrapper field name. */
  private static final String CONTAINERS_FIELD = "containers";

  /** JSON package/routine name field name. */
  private static final String NAME_FIELD = "name";

  /** JSON affected versions array field name. */
  private static final String VERSIONS_FIELD = "versions";

  private CveListRecordSupport() {}

  /** Decodes one CVE affected entry while retaining the container that supplied it. */
  static CveAffectedEntryContext readCveAffectedContext(
      final JsonNode entry,
      final String containerPath,
      final int index,
      final CveSourceRecordMetadata sourceRecord) {
    final String product = entry.path("product").textValue();
    final List<CveVersionClaim> versions = new ArrayList<>();
    final JsonNode versionsNode = entry.path(VERSIONS_FIELD);
    if (versionsNode.isArray()) {
      for (final JsonNode version : versionsNode) {
        final String value = version.path("version").asText("");
        final String status = version.path("status").asText("");
        final String versionType = version.path("versionType").asText(null);
        if (!value.isBlank() && !status.isBlank()) {
          versions.add(
              new CveVersionClaim(
                  value,
                  status,
                  versionType,
                  optionalText(version, "lessThan"),
                  optionalText(version, "lessThanOrEqual"),
                  readVersionChanges(version.path("changes"))));
        }
      }
    }
    return new CveAffectedEntryContext(
        containerPath + ".affected[" + index + "]",
        sourceRecord,
        entry.path("vendor").asText(null),
        product,
        entry.path("packageURL").asText(null),
        entry.path("collectionURL").asText(null),
        entry.path("packageName").asText(null),
        optionalText(entry, "defaultStatus"),
        versions,
        readTextArray(entry.path("programFiles")),
        readRoutineNames(entry.path("programRoutines")));
  }

  /** Applies structural checks to supported affected entries in a live source record. */
  static void validateCveSourceShape(final JsonNode root) {
    validateCveSourceRecordShape(root);
    final JsonNode containers = optionalObject(root, CONTAINERS_FIELD, CONTAINERS_FIELD);
    if (containers == null) {
      return;
    }
    final JsonNode cna = optionalObject(containers, "cna", "containers.cna");
    if (cna != null) {
      validateAffectedEntries(cna, "containers.cna");
    }
    final JsonNode adp = optionalArray(containers, "adp", "containers.adp");
    if (adp != null) {
      for (int adpIndex = 0; adpIndex < adp.size(); adpIndex++) {
        final JsonNode adpContainer = adp.get(adpIndex);
        if (!adpContainer.isObject()) {
          throw new IllegalArgumentException("containers.adp[" + adpIndex + "] must be an object");
        }
        validateAffectedEntries(adpContainer, "containers.adp[" + adpIndex + "]");
      }
    }
  }

  /** Validates record structure without rejecting malformed affected rows. */
  static void validateCveSourceRecordShape(final JsonNode root) {
    optionalObject(root, CONTAINERS_FIELD, CONTAINERS_FIELD);
  }

  /** Validates one skippable affected entry at its original locator. */
  static void validateCveAffectedEntry(
      final JsonNode entry, final String containerPath, final int index) {
    validateCnaAffectedEntry(entry, index, containerPath);
  }

  /** Decodes cveMetadata fields for live validation and indexing. */
  static CveSourceRecordMetadata readCveSourceMetadata(
      final JsonNode root, final String sourceRecordSha256) {
    final JsonNode metadata = root.get("cveMetadata");
    if (metadata == null) {
      return new CveSourceRecordMetadata(
          false, false, false, null, false, null, sourceRecordSha256);
    }
    if (!metadata.isObject()) {
      return new CveSourceRecordMetadata(true, false, false, null, false, null, sourceRecordSha256);
    }
    final JsonNode cveIdNode = metadata.get("cveId");
    final JsonNode stateNode = metadata.get("state");
    if (isInvalidNullableSourceText(cveIdNode) || isInvalidNullableSourceText(stateNode)) {
      throw new IllegalArgumentException("cveMetadata.cveId and state must be text or null");
    }
    return new CveSourceRecordMetadata(
        true,
        true,
        cveIdNode != null,
        cveIdNode == null || cveIdNode.isNull() ? null : cveIdNode.textValue(),
        stateNode != null,
        stateNode == null || stateNode.isNull() ? null : stateNode.textValue(),
        sourceRecordSha256);
  }

  /** Locates the canonical CVEList path used by indexing and live validation. */
  static String locateCveRecord(final Path gitDir, final String cveId) {
    if (gitDir == null || cveId == null || !Files.isDirectory(gitDir)) {
      return null;
    }
    final String[] parts = cveId.split("-");
    if (parts.length < 3) {
      return null;
    }
    final String thousandPrefix =
        parts[2].length() > 3 ? parts[2].substring(0, parts[2].length() - 3) + "xxx" : "0xxx";
    final Path path =
        gitDir.resolve("cves").resolve(parts[1]).resolve(thousandPrefix).resolve(cveId + ".json");
    return Files.isRegularFile(path) ? path.toString() : null;
  }

  private static void validateAffectedEntries(
      final JsonNode container, final String containerPath) {
    final JsonNode affected = optionalArray(container, "affected", containerPath + ".affected");
    if (affected != null) {
      for (int index = 0; index < affected.size(); index++) {
        validateCnaAffectedEntry(affected.get(index), index, containerPath);
      }
    }
  }

  private static void validateCnaAffectedEntry(
      final JsonNode entry, final int index, final String containerPath) {
    final String context = containerPath + ".affected[" + index + "]";
    if (!entry.isObject()) {
      throw new IllegalArgumentException(context + " must be an object");
    }
    for (final String field :
        List.of(
            "product", "vendor", "packageURL", "collectionURL", "packageName", "defaultStatus")) {
      optionalCnaText(entry, field, context);
    }
    final JsonNode versions = optionalArray(entry, VERSIONS_FIELD, context + ".versions");
    if (versions != null) {
      for (int versionIndex = 0; versionIndex < versions.size(); versionIndex++) {
        validateCnaVersion(versions.get(versionIndex), context + ".versions[" + versionIndex + "]");
      }
    }
    validateCnaStringArray(entry, "programFiles", context);
    validateCnaRoutines(entry, context);
  }

  private static void validateCnaVersion(final JsonNode version, final String context) {
    if (!version.isObject()) {
      throw new IllegalArgumentException(context + " must be an object");
    }
    requiredCnaText(version, "version", context);
    requiredCnaText(version, "status", context);
    for (final String field : List.of("versionType", "lessThan", "lessThanOrEqual")) {
      optionalCnaText(version, field, context);
    }
    final JsonNode changes = optionalArray(version, "changes", context + ".changes");
    if (changes == null) {
      return;
    }
    for (int changeIndex = 0; changeIndex < changes.size(); changeIndex++) {
      final JsonNode change = changes.get(changeIndex);
      if (!change.isObject()) {
        throw new IllegalArgumentException(context + ".changes entries must be objects");
      }
      change
          .fields()
          .forEachRemaining(
              field -> {
                if (!field.getValue().isTextual()) {
                  throw new IllegalArgumentException(context + ".changes values must be strings");
                }
              });
    }
  }

  private static void validateCnaStringArray(
      final JsonNode entry, final String field, final String context) {
    final JsonNode values = optionalArray(entry, field, context + "." + field);
    if (values == null) {
      return;
    }
    for (final JsonNode value : values) {
      if (!value.isTextual() || value.textValue().isBlank()) {
        throw new IllegalArgumentException(context + "." + field + " must contain strings");
      }
    }
  }

  private static void validateCnaRoutines(final JsonNode entry, final String context) {
    final JsonNode routines = optionalArray(entry, "programRoutines", context + ".programRoutines");
    if (routines == null) {
      return;
    }
    for (final JsonNode routine : routines) {
      if (routine.isTextual()) {
        if (routine.textValue().isBlank()) {
          throw new IllegalArgumentException(context + ".programRoutines must contain names");
        }
      } else if (routine.isObject()) {
        requiredCnaText(routine, NAME_FIELD, context + ".programRoutines entry");
      } else {
        throw new IllegalArgumentException(context + ".programRoutines entries must be names");
      }
    }
  }

  private static JsonNode optionalObject(
      final JsonNode parent, final String field, final String context) {
    final JsonNode value = parent.get(field);
    if (value == null) {
      return null;
    }
    if (!value.isObject()) {
      throw new IllegalArgumentException(context + " must be an object");
    }
    return value;
  }

  private static JsonNode optionalArray(
      final JsonNode parent, final String field, final String context) {
    final JsonNode value = parent.get(field);
    if (value == null) {
      return null;
    }
    if (!value.isArray()) {
      throw new IllegalArgumentException(context + " must be an array");
    }
    return value;
  }

  private static void requiredCnaText(
      final JsonNode parent, final String field, final String context) {
    final JsonNode value = parent.get(field);
    if (value == null || !value.isTextual() || value.textValue().isBlank()) {
      throw new IllegalArgumentException(context + "." + field + " must be a non-blank string");
    }
  }

  private static void optionalCnaText(
      final JsonNode parent, final String field, final String context) {
    final JsonNode value = parent.get(field);
    if (value != null && !value.isNull() && !value.isTextual()) {
      throw new IllegalArgumentException(context + "." + field + " must be a string or null");
    }
  }

  private static boolean isInvalidNullableSourceText(final JsonNode value) {
    return value != null && !value.isNull() && !value.isTextual();
  }

  private static Set<String> readTextArray(final JsonNode node) {
    if (!node.isArray()) {
      return Set.of();
    }
    final Set<String> values = new TreeSet<>();
    node.forEach(
        value -> {
          if (value.isTextual() && !value.textValue().isBlank()) {
            values.add(value.textValue());
          }
        });
    return Set.copyOf(values);
  }

  private static Set<String> readRoutineNames(final JsonNode node) {
    if (!node.isArray()) {
      return Set.of();
    }
    final Set<String> values = new TreeSet<>();
    for (final JsonNode value : node) {
      final JsonNode name = value.isObject() ? value.path(NAME_FIELD) : value;
      if (name.isTextual() && !name.textValue().isBlank()) {
        values.add(name.textValue());
      }
    }
    return Set.copyOf(values);
  }

  private static List<Map<String, String>> readVersionChanges(final JsonNode node) {
    if (!node.isArray()) {
      return List.of();
    }
    final List<Map<String, String>> changes = new ArrayList<>();
    for (final JsonNode change : node) {
      if (!change.isObject()) {
        continue;
      }
      final Map<String, String> fields = new LinkedHashMap<>();
      change
          .fields()
          .forEachRemaining(
              field -> {
                if (field.getValue().isTextual()) {
                  fields.put(field.getKey(), field.getValue().textValue());
                }
              });
      if (!fields.isEmpty()) {
        changes.add(fields);
      }
    }
    return List.copyOf(changes);
  }

  private static String optionalText(final JsonNode node, final String field) {
    final JsonNode value = node.get(field);
    return value != null && value.isTextual() ? value.textValue() : null;
  }
}
