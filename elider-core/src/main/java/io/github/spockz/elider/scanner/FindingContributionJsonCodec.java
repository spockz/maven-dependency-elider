/* WHY: Shares normalized contribution serialization between caches and saved reports. */

package io.github.spockz.elider.scanner;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.spockz.elider.model.VulnerabilityFindingContribution;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/** Strict shared JSON representation for source-neutral contribution facts. */
@SuppressWarnings("PMD.CommentRequired")
public final class FindingContributionJsonCodec {
  private static final String VALUE = "value";
  private static final String KIND = "kind";
  private static final Set<String> CONTRIBUTION_FIELDS =
      Set.of(
          "vulnerabilityId",
          "aliases",
          "groupId",
          "artifactId",
          "type",
          "classifier",
          "versionClaims",
          "codeGroup",
          "prerequisiteGroup",
          "priority",
          "intent",
          "provenance",
          "sourceProvenance");
  private static final Set<String> VERSION_FIELDS =
      Set.of("rawPredicate", "normalizedMavenRange", "status", "diagnostic");
  private static final Set<String> GROUP_FIELDS = Set.of("supplied", VALUE);
  private static final Set<String> CODE_FIELDS = Set.of(KIND, "reference");
  private static final Set<String> REFERENCE_FIELDS = Set.of(KIND, VALUE, "originalValues");
  private static final Set<String> PREREQUISITE_FIELDS =
      Set.of("requiresDependency", "requiresClass");
  private static final Set<String> PROVENANCE_FIELDS =
      Set.of("origin", "sourceRecordId", "sourceUrl", "sourceRecordSha256");
  private static final Set<String> CONTRIBUTION_TEXT_FIELDS =
      Set.of(
          "vulnerabilityId", "groupId", "artifactId", "type", "priority", "intent", "provenance");

  private static final ObjectMapper MAPPER =
      new ObjectMapper()
          .enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
          .enable(DeserializationFeature.FAIL_ON_MISSING_CREATOR_PROPERTIES);

  private FindingContributionJsonCodec() {
    throw new AssertionError("No instances");
  }

  /** Encodes contribution facts; cache admission remains a separate container rule. */
  public static JsonNode encode(final List<VulnerabilityFindingContribution> contributions) {
    Objects.requireNonNull(contributions, "contributions");
    contributions.forEach(value -> Objects.requireNonNull(value, "contribution"));
    return MAPPER.valueToTree(contributions);
  }

  /** Decodes immutable facts, including manual contributions in saved reports. */
  public static List<VulnerabilityFindingContribution> decode(final JsonNode node)
      throws IOException {
    for (final JsonNode contribution : FindingJsonFields.requiredArray(node, "contributions")) {
      validateContribution(contribution);
    }
    try {
      return List.copyOf(
          Arrays.asList(MAPPER.treeToValue(node, VulnerabilityFindingContribution[].class)));
    } catch (final IllegalArgumentException
        | com.fasterxml.jackson.core.JsonProcessingException failure) {
      throw new IOException("Invalid generic finding contributions", failure);
    }
  }

  private static void validateContribution(final JsonNode node) throws IOException {
    FindingJsonFields.requireShape(node, CONTRIBUTION_FIELDS, "contribution");
    for (final String field : CONTRIBUTION_TEXT_FIELDS) {
      FindingJsonFields.requiredText(node, field);
    }
    FindingJsonFields.requiredString(node, "classifier");
    FindingJsonFields.requireTextArray(node.get("aliases"), "aliases");
    for (final JsonNode version :
        FindingJsonFields.requiredArray(node.get("versionClaims"), "versionClaims")) {
      FindingJsonFields.requireShape(version, VERSION_FIELDS, "version claim");
      FindingJsonFields.requiredText(version, "rawPredicate");
      FindingJsonFields.requiredText(version, "status");
      FindingJsonFields.nullableText(version, "normalizedMavenRange");
      FindingJsonFields.nullableText(version, "diagnostic");
    }
    validateClaimGroup(node.get("codeGroup"), true);
    validateClaimGroup(node.get("prerequisiteGroup"), false);
    for (final JsonNode provenance :
        FindingJsonFields.requiredArray(node.get("sourceProvenance"), "sourceProvenance")) {
      FindingJsonFields.requireShape(provenance, PROVENANCE_FIELDS, "source provenance");
      FindingJsonFields.requiredText(provenance, "origin");
      FindingJsonFields.requiredText(provenance, "sourceRecordId");
      FindingJsonFields.nullableText(provenance, "sourceUrl");
      FindingJsonFields.nullableText(provenance, "sourceRecordSha256");
    }
  }

  private static void validateClaimGroup(final JsonNode node, final boolean code)
      throws IOException {
    FindingJsonFields.requireShape(node, GROUP_FIELDS, "claim group");
    if (!node.get("supplied").isBoolean()) {
      throw new IOException("claim group supplied must be a boolean");
    }
    final JsonNode values = node.get(VALUE);
    if (values.isNull()) {
      return;
    }
    for (final JsonNode claim : FindingJsonFields.requiredArray(values, "claim group value")) {
      if (code) {
        FindingJsonFields.requireShape(claim, CODE_FIELDS, "code claim");
        FindingJsonFields.requiredText(claim, KIND);
        final JsonNode reference = claim.get("reference");
        FindingJsonFields.requireShape(reference, REFERENCE_FIELDS, "code reference");
        FindingJsonFields.requiredText(reference, KIND);
        FindingJsonFields.requiredText(reference, VALUE);
        FindingJsonFields.requireTextArray(reference.get("originalValues"), "originalValues");
      } else {
        FindingJsonFields.requireShape(claim, PREREQUISITE_FIELDS, "prerequisite claim");
        FindingJsonFields.requiredText(claim, "requiresDependency");
        FindingJsonFields.requiredText(claim, "requiresClass");
      }
    }
  }
}
