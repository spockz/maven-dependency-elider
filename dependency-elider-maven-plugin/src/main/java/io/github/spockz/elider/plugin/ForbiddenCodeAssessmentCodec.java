// WHY: Rejects malformed persisted policy observations before Jackson can coerce their types.

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

@SuppressWarnings({
  "PMD.CommentDefaultAccessModifier",
  "PMD.CommentRequired",
  "PMD.AvoidDuplicateLiterals"
})
final class ForbiddenCodeAssessmentCodec {
  private static final ObjectMapper JSON = new ObjectMapper();
  private static final Set<String> FIELDS =
      Set.of(
          "cveId",
          "symbol",
          "componentKind",
          "componentIdentity",
          "versionScope",
          "componentVersion",
          "targetRelease",
          "assertsAffected",
          "versionApplicability",
          "mode",
          "status",
          "evidenceKind",
          "provider",
          "matches",
          "complete",
          "reason",
          "provenance",
          "sourceUrl",
          "enforcementEnabled");
  private static final Set<String> MATCH_FIELDS =
      Set.of("provider", "entry", "tier", "resolvedOwner", "descriptors");

  private ForbiddenCodeAssessmentCodec() {}

  static JsonNode write(final List<ForbiddenCodeAssessment> assessments) {
    return JSON.valueToTree(assessments);
  }

  static List<ForbiddenCodeAssessment> read(final JsonNode node) throws IOException {
    MavenElisionReportJsonPayloadShape.requireArray(node, "forbiddenCodeAssessments");
    final List<ForbiddenCodeAssessment> result = new ArrayList<>();
    for (final JsonNode row : node) {
      MavenElisionReportJsonPayloadShape.requireObject(row, FIELDS, "forbiddenCodeAssessment");
      for (final String field :
          List.of(
              "cveId",
              "symbol",
              "componentKind",
              "versionScope",
              "versionApplicability",
              "mode",
              "status",
              "evidenceKind",
              "reason",
              "provenance")) {
        MavenElisionReportJsonPayloadShape.requireText(row.get(field), field, ".*\\S.*");
      }
      for (final String field :
          List.of("componentIdentity", "componentVersion", "provider", "sourceUrl")) {
        nullableText(row.get(field), field);
      }
      for (final String field : List.of("assertsAffected", "complete", "enforcementEnabled")) {
        MavenElisionReportJsonPayloadShape.requireBoolean(row.get(field), field);
      }
      nullableInteger(row.get("targetRelease"), "targetRelease");
      MavenElisionReportJsonPayloadShape.requireArray(row.get("matches"), "matches");
      for (final JsonNode match : row.get("matches")) {
        MavenElisionReportJsonPayloadShape.requireObject(match, MATCH_FIELDS, "match");
        for (final String field : List.of("provider", "entry", "resolvedOwner")) {
          nullableText(match.get(field), field);
        }
        nullableInteger(match.get("tier"), "tier");
        MavenElisionReportJsonPayloadShape.stringArray(match.get("descriptors"), "descriptors");
      }
      try {
        result.add(JSON.treeToValue(row, ForbiddenCodeAssessment.class));
      } catch (final IllegalArgumentException
          | com.fasterxml.jackson.core.JsonProcessingException e) {
        throw new IOException("Invalid forbidden code assessment: " + e.getMessage(), e);
      }
    }
    return List.copyOf(result);
  }

  private static void nullableText(final JsonNode node, final String field) throws IOException {
    if (node == null || !(node.isNull() || node.isTextual() && !node.textValue().isBlank())) {
      throw new IOException(field + " must be null or nonblank text");
    }
  }

  private static void nullableInteger(final JsonNode node, final String field) throws IOException {
    if (node == null || !(node.isNull() || node.isIntegralNumber() && node.canConvertToInt())) {
      throw new IOException(field + " must be null or integer");
    }
  }
}
