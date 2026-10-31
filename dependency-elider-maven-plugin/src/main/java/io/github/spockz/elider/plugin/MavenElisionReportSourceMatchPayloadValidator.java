// WHY: Validates saved physical class matches independently from their source-claim row.

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Validates saved source-file match rows in report snapshots. */
final class MavenElisionReportSourceMatchPayloadValidator {
  /** Exact fields for a saved class-file match. */
  private static final Set<String> MATCH_FIELDS =
      Set.of(
          "programFile",
          "physicalJarEntry",
          "multiReleaseTier",
          "classEntry",
          "sourceFileAttribute",
          "packagePathComparison",
          "originalArchiveSha256");

  private MavenElisionReportSourceMatchPayloadValidator() {}

  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  static void validate(final JsonNode matches, final JsonNode programFiles) throws IOException {
    if (matches == null || !matches.isArray()) {
      throw new IOException("Elision report source review matches must be an array");
    }
    for (final JsonNode match : matches) {
      validateMatch(match, programFiles);
    }
  }

  private static void validateMatch(final JsonNode match, final JsonNode programFiles)
      throws IOException {
    if (!match.isObject() || !fieldNames(match).equals(MATCH_FIELDS)) {
      throw new IOException("Elision report source match fields do not match schema version 1");
    }
    final String physicalEntry = requiredText(match.get("physicalJarEntry"), "physicalJarEntry");
    final int tier = validateTier(match.get("multiReleaseTier"));
    final String classEntry = requiredText(match.get("classEntry"), "classEntry");
    final String sourceFile = requiredText(match.get("sourceFileAttribute"), "sourceFileAttribute");
    final String packageComparison =
        requiredText(match.get("packagePathComparison"), "packagePathComparison");
    final String programFile = requiredText(match.get("programFile"), "programFile");
    MavenElisionReportSourceMatchConsistencyValidator.validateJson(
        stringValues(programFiles),
        physicalEntry,
        tier,
        classEntry,
        sourceFile,
        programFile,
        packageComparison);
    validateSha256(match.get("originalArchiveSha256"));
  }

  private static int validateTier(final JsonNode tier) throws IOException {
    if (tier == null
        || !tier.isIntegralNumber()
        || !tier.canConvertToInt()
        || (tier.intValue() != 0 && tier.intValue() < 9)) {
      throw new IOException("Elision report source match tier must be zero or at least 9");
    }
    return tier.intValue();
  }

  private static void validateSha256(final JsonNode value) throws IOException {
    if (value == null || !value.isTextual() || !value.textValue().matches("[0-9a-f]{64}")) {
      throw new IOException("Elision report source match archive digest must be lowercase SHA-256");
    }
  }

  private static List<String> stringValues(final JsonNode values) throws IOException {
    final List<String> result = new ArrayList<>();
    for (final JsonNode value : values) {
      if (!value.isTextual()) {
        throw new IOException("Elision report source review programFiles item must be text");
      }
      result.add(value.textValue());
    }
    return List.copyOf(result);
  }

  private static void validateNonBlank(final JsonNode value, final String name) throws IOException {
    if (value == null || !value.isTextual() || value.textValue().isBlank()) {
      throw new IOException("Elision report source match " + name + " must be nonblank text");
    }
  }

  private static String requiredText(final JsonNode value, final String name) throws IOException {
    validateNonBlank(value, name);
    return value.textValue();
  }

  private static Set<String> fieldNames(final JsonNode row) {
    final Set<String> names = new HashSet<>();
    row.fieldNames().forEachRemaining(names::add);
    return names;
  }
}
