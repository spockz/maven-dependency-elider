/* WHY: Persists Analyze forecasts without turning them into physical proof evidence. */

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.PreconditionClassInventory.ProviderKind;
import io.github.spockz.elider.model.PrerequisiteClaim;
import io.github.spockz.elider.model.PrerequisiteGroup;
import io.github.spockz.elider.model.PrerequisiteOperator;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/** Strict schema-v1 codec for detached prerequisite predictions. */
final class MavenElisionReportPrerequisitePredictionCodec {
  /** Mapper for the explicitly shaped schema payload. */
  private static final ObjectMapper JSON = new ObjectMapper();

  /** Top-level forecast fields. */
  private static final Set<String> PREDICTION_FIELDS =
      Set.of("candidate", "baselineInventoryFingerprint", "planFingerprint", "groups", "detail");

  /** Operator-group wrapper fields. */
  private static final Set<String> GROUP_FIELDS = Set.of("group", "members", "disarmed");

  /** Forecast member fields. */
  private static final Set<String> MEMBER_FIELDS =
      Set.of("claim", "state", "reason", "providers", "detail");

  /** Baseline provider fields. */
  private static final Set<String> PROVIDER_FIELDS =
      Set.of("kind", "coordinate", "baselinePath", "baselineSha256", "plan");

  /** Member and prediction detail field. */
  private static final String DETAIL = "detail";

  /** Serialized member arrays. */
  private static final String MEMBERS = "members";

  /** Serialized provider-kind field. */
  private static final String KIND = "kind";

  /** Claim dependency field. */
  private static final String REQUIRES_DEPENDENCY = "requiresDependency";

  /** Claim class field. */
  private static final String REQUIRES_CLASS = "requiresClass";

  /** Root path used in decoder diagnostics. */
  private static final String ROOT_PATH = "prerequisitePrediction";

  private MavenElisionReportPrerequisitePredictionCodec() {}

  /* package */ static JsonNode encode(final Optional<PrerequisitePrediction> prediction) {
    if (prediction.isEmpty()) {
      return JSON.nullNode();
    }
    final PrerequisitePrediction value = prediction.orElseThrow();
    final ObjectNode node = JSON.createObjectNode();
    node.set("candidate", JSON.valueToTree(value.candidate()));
    node.put("baselineInventoryFingerprint", value.baselineInventoryFingerprint());
    node.put("planFingerprint", value.planFingerprint());
    node.put(DETAIL, value.detail());
    final ArrayNode groups = node.putArray("groups");
    for (final PrerequisitePrediction.GroupForecast forecast : value.groups()) {
      final ObjectNode group = groups.addObject();
      group.set("group", JSON.valueToTree(forecast.group()));
      group.put("disarmed", forecast.disarmed());
      final ArrayNode members = group.putArray(MEMBERS);
      for (final PrerequisitePrediction.MemberForecast member : forecast.members()) {
        final ObjectNode memberNode = members.addObject();
        memberNode.set("claim", JSON.valueToTree(member.claim()));
        memberNode.put("state", member.state().name());
        memberNode.put("reason", member.reason().name());
        memberNode.put(DETAIL, member.detail());
        final ArrayNode providers = memberNode.putArray("providers");
        for (final PrerequisitePrediction.ProviderForecast provider : member.providers()) {
          final ObjectNode providerNode = providers.addObject();
          providerNode.put(KIND, provider.kind().name());
          providerNode.set("coordinate", JSON.valueToTree(provider.coordinate()));
          providerNode.put("baselinePath", provider.baselinePath().toString());
          providerNode.put("baselineSha256", provider.baselineSha256());
          providerNode.put("plan", provider.plan().name());
        }
      }
    }
    return node;
  }

  /* package */ static Optional<PrerequisitePrediction> decode(final JsonNode node)
      throws IOException {
    if (node == null || node.isNull()) {
      return Optional.empty();
    }
    try {
      MavenElisionReportPredictionJson.shape(node, PREDICTION_FIELDS, ROOT_PATH);
      final JsonNode candidateNode = node.get("candidate");
      MavenElisionReportPredictionJson.shape(
          candidateNode,
          Set.of("groupId", "artifactId", "version", "type", "classifier", "scope"),
          ROOT_PATH + ".candidate");
      final ArtifactCoordinate candidate =
          JSON.treeToValue(candidateNode, ArtifactCoordinate.class);
      final List<PrerequisitePrediction.GroupForecast> groups = new ArrayList<>();
      for (final JsonNode group :
          MavenElisionReportPredictionJson.array(node, "groups", ROOT_PATH + ".groups")) {
        groups.add(readGroup(group));
      }
      if (groups.stream().map(PrerequisitePrediction.GroupForecast::group).distinct().count()
          != groups.size()) {
        throw new IOException("prerequisitePrediction.groups contains duplicates");
      }
      return Optional.of(
          new PrerequisitePrediction(
              candidate,
              MavenElisionReportPredictionJson.text(node, "baselineInventoryFingerprint"),
              MavenElisionReportPredictionJson.text(node, "planFingerprint"),
              groups,
              MavenElisionReportPredictionJson.nullableText(node, DETAIL)));
    } catch (final IllegalArgumentException exception) {
      throw new IOException("Invalid " + ROOT_PATH + ": " + exception.getMessage(), exception);
    }
  }

  private static PrerequisitePrediction.GroupForecast readGroup(final JsonNode group)
      throws IOException {
    MavenElisionReportPredictionJson.shape(group, GROUP_FIELDS, ROOT_PATH + ".groups[]");
    return new PrerequisitePrediction.GroupForecast(
        readSelectedGroup(group.get("group")),
        readMembers(group),
        MavenElisionReportPredictionJson.bool(group, "disarmed"));
  }

  private static PrerequisiteGroup readSelectedGroup(final JsonNode selected) throws IOException {
    MavenElisionReportPredictionJson.shape(
        selected, Set.of("operator", MEMBERS), ROOT_PATH + ".groups[].group");
    final Set<String> claimFields = Set.of(REQUIRES_DEPENDENCY, REQUIRES_CLASS);
    final Set<PrerequisiteClaim> selectedMembers = new java.util.HashSet<>();
    for (final JsonNode member :
        MavenElisionReportPredictionJson.array(
            selected, MEMBERS, ROOT_PATH + ".groups[].group.members")) {
      MavenElisionReportPredictionJson.shape(
          member, claimFields, ROOT_PATH + ".groups[].group.members[]");
      if (!selectedMembers.add(
          new PrerequisiteClaim(
              MavenElisionReportPredictionJson.text(member, REQUIRES_DEPENDENCY),
              MavenElisionReportPredictionJson.text(member, REQUIRES_CLASS)))) {
        throw new IOException(ROOT_PATH + ".groups[].group.members contains duplicates");
      }
    }
    return new PrerequisiteGroup(
        MavenElisionReportPredictionJson.enumValue(
            selected, "operator", PrerequisiteOperator.class),
        selectedMembers);
  }

  private static List<PrerequisitePrediction.MemberForecast> readMembers(final JsonNode group)
      throws IOException {
    final List<PrerequisitePrediction.MemberForecast> members = new ArrayList<>();
    for (final JsonNode member :
        MavenElisionReportPredictionJson.array(group, MEMBERS, ROOT_PATH + ".groups[].members")) {
      members.add(readMember(member));
    }
    if (members.stream().map(PrerequisitePrediction.MemberForecast::claim).distinct().count()
        != members.size()) {
      throw new IOException(ROOT_PATH + ".groups[].members contains duplicates");
    }
    return List.copyOf(members);
  }

  private static PrerequisitePrediction.MemberForecast readMember(final JsonNode member)
      throws IOException {
    MavenElisionReportPredictionJson.shape(
        member, MEMBER_FIELDS, ROOT_PATH + ".groups[].members[]");
    final JsonNode claim = member.get("claim");
    MavenElisionReportPredictionJson.shape(
        claim,
        Set.of(REQUIRES_DEPENDENCY, REQUIRES_CLASS),
        ROOT_PATH + ".groups[].members[].claim");
    return new PrerequisitePrediction.MemberForecast(
        new PrerequisiteClaim(
            MavenElisionReportPredictionJson.text(claim, REQUIRES_DEPENDENCY),
            MavenElisionReportPredictionJson.text(claim, REQUIRES_CLASS)),
        MavenElisionReportPredictionJson.enumValue(
            member, "state", PrerequisitePrediction.MemberState.class),
        MavenElisionReportPredictionJson.enumValue(
            member, "reason", PrerequisitePrediction.MemberReason.class),
        readProviders(member),
        MavenElisionReportPredictionJson.nullableText(member, DETAIL));
  }

  private static List<PrerequisitePrediction.ProviderForecast> readProviders(final JsonNode member)
      throws IOException {
    final List<PrerequisitePrediction.ProviderForecast> providers = new ArrayList<>();
    for (final JsonNode provider :
        MavenElisionReportPredictionJson.array(
            member, "providers", ROOT_PATH + ".groups[].members[].providers")) {
      providers.add(readProvider(provider));
    }
    return List.copyOf(providers);
  }

  private static PrerequisitePrediction.ProviderForecast readProvider(final JsonNode provider)
      throws IOException {
    MavenElisionReportPredictionJson.shape(
        provider, PROVIDER_FIELDS, ROOT_PATH + ".groups[].members[].providers[]");
    final JsonNode coordinateNode = provider.get("coordinate");
    final ArtifactCoordinate coordinate = readCoordinate(coordinateNode);
    final String providerPath = MavenElisionReportPredictionJson.text(provider, "baselinePath");
    if (!Path.of(providerPath).isAbsolute()) {
      throw new IOException(
          ROOT_PATH + ".groups[].members[].providers[].baselinePath must be absolute");
    }
    return new PrerequisitePrediction.ProviderForecast(
        MavenElisionReportPredictionJson.enumValue(provider, KIND, ProviderKind.class),
        coordinate,
        Path.of(providerPath),
        MavenElisionReportPredictionJson.text(provider, "baselineSha256"),
        MavenElisionReportPredictionJson.enumValue(
            provider, "plan", PrerequisitePrediction.ProviderPlan.class));
  }

  private static ArtifactCoordinate readCoordinate(final JsonNode coordinateNode)
      throws IOException {
    if (coordinateNode == null || coordinateNode.isNull()) {
      return null;
    }
    MavenElisionReportPredictionJson.shape(
        coordinateNode,
        Set.of("groupId", "artifactId", "version", "type", "classifier", "scope"),
        ROOT_PATH + ".groups[].members[].providers[].coordinate");
    return JSON.treeToValue(coordinateNode, ArtifactCoordinate.class);
  }
}
