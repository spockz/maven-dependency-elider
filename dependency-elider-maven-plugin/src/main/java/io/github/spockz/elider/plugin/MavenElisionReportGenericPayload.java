/* WHY: Saves effective assessment decisions and source observations without replaying analysis. */

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.AssessmentIntent;
import io.github.spockz.elider.model.ClaimGroupStatus;
import io.github.spockz.elider.model.CodeAttributionResolver;
import io.github.spockz.elider.model.CodeClaim;
import io.github.spockz.elider.model.CodeReference;
import io.github.spockz.elider.model.PrerequisiteClaim;
import io.github.spockz.elider.model.VersionApplicability;
import io.github.spockz.elider.model.VersionCoverageClaim;
import io.github.spockz.elider.scanner.FindingContributionJsonCodec;
import io.github.spockz.elider.scanner.FindingSource;
import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

/** Strict schema for captured generic assessment rows and source health. */
@SuppressWarnings({
  "PMD.CouplingBetweenObjects",
  "PMD.GodClass",
  "PMD.TooManyMethods",
  "PMD.CommentRequired",
  "PMD.AvoidDuplicateLiterals"
})
final class MavenElisionReportGenericPayload {
  private static final ObjectMapper JSON = new ObjectMapper();
  private static final Set<String> FINDING_FIELDS =
      Set.of(
          "vulnerabilityId",
          "aliases",
          "candidate",
          "applicability",
          "intent",
          "codeGroupStatus",
          "codeAttribution",
          "heuristicLeads",
          "prerequisiteGroupStatus",
          "effectivePrerequisites",
          "unresolvedVersionClaims",
          "overriddenFields",
          "enrichedFields",
          "outcome",
          "detail",
          "inventoryDisposition",
          "contributions");
  private static final Set<String> OBSERVATION_FIELDS =
      Set.of(
          "source",
          "status",
          "revision",
          "lastSuccessfulSync",
          "diagnostic",
          "observationDiagnostics",
          "contributionCount");

  private MavenElisionReportGenericPayload() {}

  // Each row retains its own immutable snapshot.
  @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
  /* package */ static ArrayNode findings(final List<GenericFindingAssessment> findings)
      throws IOException {
    final ArrayNode rows = JSON.createArrayNode();
    for (final GenericFindingAssessment finding : findings) {
      MavenElisionReportProofValidator.validate(finding);
      final ObjectNode row = JSON.createObjectNode();
      row.put("vulnerabilityId", finding.vulnerabilityId());
      row.set("aliases", JSON.valueToTree(new TreeSet<>(finding.aliases())));
      row.set("candidate", JSON.valueToTree(finding.candidate()));
      row.put("applicability", finding.applicability().name());
      row.put("intent", finding.intent().map(Enum::name).orElse(null));
      row.put("codeGroupStatus", finding.codeGroupStatus().name());
      row.set("codeAttribution", JSON.valueToTree(finding.codeAttribution()));
      row.set("heuristicLeads", JSON.valueToTree(finding.heuristicLeads()));
      row.put("prerequisiteGroupStatus", finding.prerequisiteGroupStatus().name());
      row.set("effectivePrerequisites", JSON.valueToTree(finding.effectivePrerequisites()));
      row.set("unresolvedVersionClaims", JSON.valueToTree(finding.unresolvedVersionClaims()));
      row.set("overriddenFields", JSON.valueToTree(new TreeSet<>(finding.overriddenFields())));
      row.set("enrichedFields", JSON.valueToTree(new TreeSet<>(finding.enrichedFields())));
      row.put("outcome", finding.outcome().name());
      row.put("detail", finding.detail());
      row.put("inventoryDisposition", finding.inventoryDisposition().name());
      row.set("contributions", FindingContributionJsonCodec.encode(finding.contributions()));
      rows.add(row);
    }
    return rows;
  }

  /* package */ static ArrayNode observations(final List<FindingSourceObservation> observations) {
    final ArrayNode rows = JSON.createArrayNode();
    for (final FindingSourceObservation observation : observations) {
      final ObjectNode row = JSON.createObjectNode();
      row.put("source", observation.source().map(Enum::name).orElse(null));
      row.put("status", observation.status().name());
      row.put("revision", observation.revision());
      row.put(
          "lastSuccessfulSync",
          observation.lastSuccessfulSync() == null
              ? null
              : observation.lastSuccessfulSync().toString());
      row.put("diagnostic", observation.diagnostic());
      row.set("observationDiagnostics", JSON.valueToTree(observation.observationDiagnostics()));
      row.put("contributionCount", observation.contributionCount());
      rows.add(row);
    }
    return rows;
  }

  // Each report row has independent nested evidence.
  @SuppressWarnings({
    "PMD.AvoidInstantiatingObjectsInLoops",
    "PMD.CognitiveComplexity",
    "PMD.CyclomaticComplexity"
  })
  /* package */ static List<GenericFindingAssessment> readFindings(final JsonNode node)
      throws IOException {
    final List<GenericFindingAssessment> rows = new ArrayList<>();
    for (final JsonNode row : array(node, "genericFindings")) {
      shape(row, FINDING_FIELDS, "generic finding");
      final JsonNode candidate = row.get("candidate");
      shape(
          candidate,
          Set.of("groupId", "artifactId", "version", "type", "classifier", "scope"),
          "candidate");
      final ArtifactCoordinate coordinate =
          new ArtifactCoordinate(
              text(candidate, "groupId"),
              text(candidate, "artifactId"),
              text(candidate, "version"),
              text(candidate, "type"),
              string(candidate, "classifier"),
              text(candidate, "scope"));
      final List<CodeAttributionResolver.DeclarationResult> attribution = new ArrayList<>();
      for (final JsonNode item : array(row.get("codeAttribution"), "codeAttribution")) {
        shape(item, Set.of("claim", "status", "classFamily", "reasons"), "attribution");
        final JsonNode claim = item.get("claim");
        shape(claim, Set.of("kind", "reference"), "code claim");
        final CodeClaim code =
            new CodeClaim(
                enumeration(claim, "kind", CodeClaim.Kind.class),
                reference(claim.get("reference")));
        final List<CodeAttributionResolver.Reason> reasons = new ArrayList<>();
        for (final JsonNode reason : array(item.get("reasons"), "reasons")) {
          reasons.add(enumValue(reason, CodeAttributionResolver.Reason.class));
        }
        attribution.add(
            new CodeAttributionResolver.DeclarationResult(
                code,
                enumeration(item, "status", CodeAttributionResolver.Status.class),
                strings(item.get("classFamily"), "classFamily"),
                reasons));
      }
      final List<CodeReference> leads = new ArrayList<>();
      for (final JsonNode lead : array(row.get("heuristicLeads"), "heuristicLeads")) {
        leads.add(reference(lead));
      }
      final List<PrerequisiteClaim> prerequisites = new ArrayList<>();
      for (final JsonNode item :
          array(row.get("effectivePrerequisites"), "effectivePrerequisites")) {
        shape(item, Set.of("requiresDependency", "requiresClass"), "prerequisite");
        prerequisites.add(
            new PrerequisiteClaim(text(item, "requiresDependency"), text(item, "requiresClass")));
      }
      final List<VersionCoverageClaim> coverage = new ArrayList<>();
      for (final JsonNode item :
          array(row.get("unresolvedVersionClaims"), "unresolvedVersionClaims")) {
        shape(
            item,
            Set.of("rawPredicate", "normalizedMavenRange", "status", "diagnostic"),
            "coverage");
        final VersionCoverageClaim claim =
            new VersionCoverageClaim(
                text(item, "rawPredicate"),
                nullable(item, "normalizedMavenRange"),
                enumeration(item, "status", VersionApplicability.class),
                nullable(item, "diagnostic"));
        if (claim.status() != VersionApplicability.UNRESOLVED) {
          throw new IOException("Report unresolved coverage must be unresolved");
        }
        coverage.add(claim);
      }
      final String intent = nullable(row, "intent");
      final GenericFindingAssessment finding =
          new GenericFindingAssessment(
              text(row, "vulnerabilityId"),
              strings(row.get("aliases"), "aliases"),
              coordinate,
              enumeration(row, "applicability", VersionApplicability.class),
              intent == null
                  ? Optional.empty()
                  : Optional.of(enumName(intent, AssessmentIntent.class)),
              enumeration(row, "codeGroupStatus", ClaimGroupStatus.class),
              attribution,
              leads,
              enumeration(row, "prerequisiteGroupStatus", ClaimGroupStatus.class),
              prerequisites,
              coverage,
              strings(row.get("overriddenFields"), "overriddenFields"),
              strings(row.get("enrichedFields"), "enrichedFields"),
              enumeration(row, "outcome", GenericFindingAssessment.Outcome.class),
              text(row, "detail"),
              enumeration(
                  row,
                  "inventoryDisposition",
                  MavenVulnerabilityAssessment.InventoryDisposition.class),
              FindingContributionJsonCodec.decode(row.get("contributions")));
      MavenElisionReportProofValidator.validate(finding);
      rows.add(finding);
    }
    return List.copyOf(rows);
  }

  @SuppressWarnings("PMD.CyclomaticComplexity")
  /* package */ static List<FindingSourceObservation> readObservations(final JsonNode node)
      throws IOException {
    final List<FindingSourceObservation> rows = new ArrayList<>();
    for (final JsonNode row : array(node, "sourceObservations")) {
      shape(row, OBSERVATION_FIELDS, "source observation");
      final String source = nullable(row, "source");
      final String lastSync = nullable(row, "lastSuccessfulSync");
      final JsonNode count = row.get("contributionCount");
      if (!count.isIntegralNumber() || !count.canConvertToInt() || count.intValue() < 0) {
        throw new IOException("Invalid observation count");
      }
      try {
        rows.add(
            new FindingSourceObservation(
                source == null
                    ? Optional.empty()
                    : Optional.of(enumName(source, FindingSource.class)),
                enumeration(row, "status", FindingSourceObservation.Status.class),
                nullable(row, "revision"),
                lastSync == null ? null : Instant.parse(lastSync),
                nullable(row, "diagnostic"),
                textList(row.get("observationDiagnostics"), "observationDiagnostics"),
                count.intValue()));
      } catch (final IllegalArgumentException | java.time.DateTimeException exception) {
        throw new IOException("Invalid source observation", exception);
      }
    }
    return List.copyOf(rows);
  }

  private static CodeReference reference(final JsonNode node) throws IOException {
    shape(node, Set.of("kind", "value", "originalValues"), "code reference");
    return new CodeReference(
        enumeration(node, "kind", CodeReference.Kind.class),
        text(node, "value"),
        strings(node.get("originalValues"), "originalValues"));
  }

  private static void shape(final JsonNode node, final Set<String> expected, final String name)
      throws IOException {
    if (node == null || !node.isObject()) {
      throw new IOException(name + " must be an object");
    }
    final Set<String> actual = new HashSet<>();
    node.fieldNames().forEachRemaining(actual::add);
    if (!actual.equals(expected)) {
      throw new IOException(name + " has invalid fields");
    }
  }

  private static JsonNode array(final JsonNode node, final String name) throws IOException {
    if (node == null || !node.isArray()) {
      throw new IOException(name + " must be an array");
    }
    return node;
  }

  private static Set<String> strings(final JsonNode node, final String name) throws IOException {
    final Set<String> values = new TreeSet<>();
    for (final JsonNode item : array(node, name)) {
      if (!item.isTextual() || item.textValue().isBlank() || !values.add(item.textValue())) {
        throw new IOException(name + " must contain distinct nonblank strings");
      }
    }
    return values;
  }

  private static List<String> textList(final JsonNode node, final String name) throws IOException {
    final List<String> values = new ArrayList<>();
    for (final JsonNode item : array(node, name)) {
      if (!item.isTextual() || item.textValue().isBlank()) {
        throw new IOException(name + " must contain nonblank strings");
      }
      values.add(item.textValue());
    }
    return List.copyOf(values);
  }

  private static String text(final JsonNode node, final String key) throws IOException {
    final String value = string(node, key);
    if (value.isBlank()) {
      throw new IOException(key + " must not be blank");
    }
    return value;
  }

  private static String string(final JsonNode node, final String key) throws IOException {
    final JsonNode value = node.get(key);
    if (value == null || !value.isTextual()) {
      throw new IOException(key + " must be text");
    }
    return value.textValue();
  }

  private static String nullable(final JsonNode node, final String key) throws IOException {
    final JsonNode value = node.get(key);
    if (value == null) {
      throw new IOException("Missing " + key);
    }
    return value.isNull() ? null : text(node, key);
  }

  private static <T extends Enum<T>> T enumeration(
      final JsonNode node, final String key, final Class<T> type) throws IOException {
    return enumName(text(node, key), type);
  }

  private static <T extends Enum<T>> T enumValue(final JsonNode node, final Class<T> type)
      throws IOException {
    if (!node.isTextual()) {
      throw new IOException("Enum must be text");
    }
    return enumName(node.textValue(), type);
  }

  private static <T extends Enum<T>> T enumName(final String name, final Class<T> type)
      throws IOException {
    try {
      return Enum.valueOf(type, name);
    } catch (final IllegalArgumentException exception) {
      throw new IOException("Unknown " + type.getSimpleName() + ": " + name, exception);
    }
  }
}
