// WHY: Rejects report findings that disagree with their frozen pre-injection snapshot.

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;

/** Validates exact schema and canonical findings without Jackson scalar coercion. */
@SuppressWarnings({"PMD.CommentDefaultAccessModifier", "PMD.CommentRequired"})
final class ExclusionReviewPayloadValidator {
  private static final ObjectMapper JSON = new ObjectMapper();

  private ExclusionReviewPayloadValidator() {}

  @SuppressWarnings("PMD.CyclomaticComplexity")
  static void validate(final JsonNode node) throws IOException {
    if (node == null
        || !node.isObject()
        || !node.path("available").isBoolean()
        || !node.path("unavailableReason").isTextual()) {
      throw new IOException("Invalid exclusion review payload");
    }
    try {
      final ExclusionReview expected;
      if (node.get("available").booleanValue()) {
        expected =
            ExclusionReview.from(
                ExclusionProvenancePayload.decode(
                    JSON.convertValue(node.get("snapshot"), Object.class)));
      } else {
        expected = ExclusionReview.unavailable(node.get("unavailableReason").textValue());
      }
      if (!node.equals(JSON.valueToTree(expected))) {
        throw new IOException("Exclusion review does not match its frozen snapshot");
      }
    } catch (final IllegalArgumentException | IllegalStateException exception) {
      throw new IOException("Invalid exclusion review payload", exception);
    }
  }
}
