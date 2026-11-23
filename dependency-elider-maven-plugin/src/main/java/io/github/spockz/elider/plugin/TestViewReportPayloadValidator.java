// WHY: Rejects malformed test-view JSON before primitive coercion can turn it into evidence.

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/** Exact version-one shape and type checks for detached test-view reports. */
@SuppressWarnings({"PMD.CommentDefaultAccessModifier", "PMD.TestClassWithoutTestCases"})
final class TestViewReportPayloadValidator {
  /** The exact top-level fields accepted for the independent schema. */
  private static final Set<String> REPORT_FIELDS =
      Set.of(
          "schemaVersion",
          "projectGroupId",
          "projectArtifactId",
          "projectVersion",
          "projectBaseDirectory",
          "productionReportSha256",
          "status",
          "reason",
          "testOutputDirectory",
          "inputArtifacts",
          "additions",
          "additionsJar",
          "conservativeFallbackUsed");

  /** Shared field name for rows tied to one original artifact. */
  private static final String IDENTITY_FIELD = "identity";

  /** The exact fields accepted for one original-versus-effective input. */
  private static final Set<String> INPUT_FIELDS =
      Set.of(IDENTITY_FIELD, "originalJar", "effectiveJar");

  /** The exact fields accepted for one test-only addition. */
  private static final Set<String> ADDITION_FIELDS = Set.of(IDENTITY_FIELD, "classes");

  private TestViewReportPayloadValidator() {}

  @SuppressWarnings("PMD.CyclomaticComplexity")
  static TestViewReportSnapshot decode(final JsonNode payload) throws IOException {
    shape(payload, REPORT_FIELDS, "Test-view report");
    final JsonNode version = payload.get("schemaVersion");
    if (version == null || !version.isInt() || version.intValue() != 1) {
      throw new IOException("Unsupported test-view report schema version; rerun test preparation");
    }
    final TestViewReportSnapshot.Status status = status(payload);
    final JsonNode fallback = payload.get("conservativeFallbackUsed");
    if (fallback == null || !fallback.isBoolean()) {
      throw new IOException("Test-view report conservativeFallbackUsed must be boolean");
    }
    final List<TestViewReportSnapshot.InputArtifact> inputs = inputs(payload);
    final List<TestViewReportSnapshot.Addition> additions = additions(payload);
    try {
      return new TestViewReportSnapshot(
          version.intValue(),
          text(payload, "projectGroupId"),
          text(payload, "projectArtifactId"),
          text(payload, "projectVersion"),
          text(payload, "projectBaseDirectory"),
          text(payload, "productionReportSha256"),
          status,
          nullableText(payload, "reason"),
          nullableText(payload, "testOutputDirectory"),
          inputs,
          additions,
          nullableText(payload, "additionsJar"),
          fallback.booleanValue());
    } catch (final IllegalArgumentException exception) {
      throw new IOException("Invalid test-view report: " + exception.getMessage(), exception);
    }
  }

  private static TestViewReportSnapshot.Status status(final JsonNode payload) throws IOException {
    final String statusName = text(payload, "status");
    try {
      return TestViewReportSnapshot.Status.valueOf(statusName);
    } catch (final IllegalArgumentException exception) {
      throw new IOException("Unknown test-view report status: " + statusName, exception);
    }
  }

  private static List<TestViewReportSnapshot.InputArtifact> inputs(final JsonNode payload)
      throws IOException {
    final List<TestViewReportSnapshot.InputArtifact> inputs = new ArrayList<>();
    for (final JsonNode row : array(payload, "inputArtifacts")) {
      shape(row, INPUT_FIELDS, "Test-view input artifact");
      inputs.add(
          new TestViewReportSnapshot.InputArtifact(
              text(row, IDENTITY_FIELD),
              text(row, "originalJar"),
              nullableText(row, "effectiveJar")));
    }
    return inputs;
  }

  private static List<TestViewReportSnapshot.Addition> additions(final JsonNode payload)
      throws IOException {
    final List<TestViewReportSnapshot.Addition> additions = new ArrayList<>();
    for (final JsonNode row : array(payload, "additions")) {
      shape(row, ADDITION_FIELDS, "Test-view addition");
      additions.add(new TestViewReportSnapshot.Addition(text(row, IDENTITY_FIELD), classes(row)));
    }
    return additions;
  }

  private static List<String> classes(final JsonNode row) throws IOException {
    final List<String> classes = new ArrayList<>();
    for (final JsonNode name : array(row, "classes")) {
      if (!name.isTextual() || name.textValue().isBlank()) {
        throw new IOException("Test-view added class must be nonblank text");
      }
      classes.add(name.textValue());
    }
    return classes;
  }

  private static void shape(final JsonNode node, final Set<String> fields, final String label)
      throws IOException {
    if (node == null
        || !node.isObject()
        || !MavenElisionReportJsonPayloadShape.fieldNames(node).equals(fields)) {
      throw new IOException(label + " fields do not match schema version 1");
    }
  }

  private static List<JsonNode> array(final JsonNode parent, final String field)
      throws IOException {
    final JsonNode node = parent.get(field);
    if (node == null || !node.isArray()) {
      throw new IOException("Test-view report " + field + " must be an array");
    }
    final List<JsonNode> values = new ArrayList<>();
    node.forEach(values::add);
    return values;
  }

  private static String text(final JsonNode parent, final String field) throws IOException {
    final JsonNode node = parent.get(field);
    if (node == null || !node.isTextual() || node.textValue().isBlank()) {
      throw new IOException("Test-view report " + field + " must be nonblank text");
    }
    return node.textValue();
  }

  private static String nullableText(final JsonNode parent, final String field) throws IOException {
    final JsonNode node = parent.get(field);
    if (node != null && node.isNull()) {
      return null;
    }
    return text(parent, field);
  }
}
