/* WHY: Encodes detached proof observations with strict paths and no
 * proof-capable reconstruction. */

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.spockz.elider.applicability.PreconditionClassInventory.ProviderKind;
import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.PrerequisiteAbsenceAttribution;
import io.github.spockz.elider.model.PrerequisiteClaim;
import io.github.spockz.elider.model.PrerequisiteGroup;
import io.github.spockz.elider.model.PrerequisiteMemberObservation;
import io.github.spockz.elider.model.PrerequisiteOperator;
import java.io.IOException;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

/** Strict detached prerequisite evidence codec for persisted report rows. */
// Keep field checks close so nested errors retain their schema paths.
@SuppressWarnings({
  "PMD.CouplingBetweenObjects",
  "PMD.GodClass",
  "PMD.CyclomaticComplexity",
  "PMD.TooManyMethods"
})
final class MavenElisionReportPrerequisiteProofCodec {
  /** Candidate binding field in saved proof evidence. */
  private static final String CANDIDATE_FIELD = "candidate";

  /** Physical candidate path field in saved proof evidence. */
  private static final String AFFECTED_ARTIFACT_PATH_FIELD = "affectedArtifactPath";

  /** Typed group observations field in saved proof evidence. */
  private static final String GROUPS_FIELD = "groups";

  /** Derived cause field shared by group, member, and provider rows. */
  private static final String ATTRIBUTION_FIELD = "attribution";

  /** Jackson mapper used by the adjacent report schema codec. */
  private static final ObjectMapper JSON = new ObjectMapper();

  /** Required keys at the detached proof root. */
  private static final Set<String> PROOF_FIELDS =
      Set.of(
          CANDIDATE_FIELD,
          "finalInventoryFingerprint",
          AFFECTED_ARTIFACT_PATH_FIELD,
          "postElisionSha256",
          GROUPS_FIELD,
          "baselineDetail");

  /** Required keys for one group outcome. */
  private static final Set<String> GROUP_FIELDS = Set.of("operator", ATTRIBUTION_FIELD, "members");

  /** Required keys for one member outcome. */
  private static final Set<String> MEMBER_FIELDS =
      Set.of("claim", "state", ATTRIBUTION_FIELD, "providers");

  /** Required keys for a checked member claim. */
  private static final Set<String> CLAIM_FIELDS = Set.of("requiresDependency", "requiresClass");

  /** Required keys for one provider transition. */
  private static final Set<String> PROVIDER_FIELDS =
      Set.of(
          "kind",
          "coordinate",
          "baselinePath",
          "baselineSha256",
          "finalPath",
          "finalSha256",
          ATTRIBUTION_FIELD);

  private MavenElisionReportPrerequisiteProofCodec() {}

  /* package */ static JsonNode encode(final Optional<PrerequisiteProofEvidence> optionalEvidence) {
    if (optionalEvidence.isEmpty()) {
      return JSON.nullNode();
    }
    final PrerequisiteProofEvidence evidence = optionalEvidence.orElseThrow();
    final ObjectNode proof = JSON.createObjectNode();
    proof.put(CANDIDATE_FIELD, evidence.candidate().toString());
    proof.put("finalInventoryFingerprint", evidence.finalInventoryFingerprint());
    proof.put(AFFECTED_ARTIFACT_PATH_FIELD, evidence.affectedArtifactPath().toString());
    proof.put("postElisionSha256", evidence.postElisionSha256());
    final ArrayNode groups = proof.putArray(GROUPS_FIELD);
    for (final PrerequisiteProofEvidence.GroupEvidence group : evidence.groups()) {
      encodeGroup(groups.addObject(), group);
    }
    proof.put("baselineDetail", evidence.baselineDetail());
    return proof;
  }

  private static void encodeGroup(
      final ObjectNode node, final PrerequisiteProofEvidence.GroupEvidence evidence) {
    node.put("operator", evidence.group().operator().name());
    node.put(ATTRIBUTION_FIELD, evidence.attribution().name());
    final ArrayNode members = node.putArray("members");
    for (final PrerequisiteProofEvidence.MemberEvidence member : evidence.members()) {
      encodeMember(members.addObject(), member);
    }
  }

  private static void encodeMember(
      final ObjectNode node, final PrerequisiteProofEvidence.MemberEvidence evidence) {
    final ObjectNode claim = node.putObject("claim");
    claim.put("requiresDependency", evidence.claim().requiresDependency());
    claim.put("requiresClass", evidence.claim().requiresClass());
    node.put("state", evidence.state().name());
    node.put(ATTRIBUTION_FIELD, evidence.attribution().name());
    final ArrayNode providers = node.putArray("providers");
    for (final PrerequisiteProofEvidence.ProviderEvidence provider : evidence.providers()) {
      encodeProvider(providers.addObject(), provider);
    }
  }

  private static void encodeProvider(
      final ObjectNode node, final PrerequisiteProofEvidence.ProviderEvidence evidence) {
    node.put("kind", evidence.kind().name());
    node.put("coordinate", evidence.coordinate() == null ? null : evidence.coordinate().toString());
    putPath(node, "baselinePath", evidence.baselinePath());
    node.put("baselineSha256", evidence.baselineSha256());
    putPath(node, "finalPath", evidence.finalPath());
    node.put("finalSha256", evidence.finalSha256());
    node.put(ATTRIBUTION_FIELD, evidence.attribution().name());
  }

  private static void putPath(final ObjectNode node, final String name, final Path path) {
    node.put(name, path == null ? null : path.toString());
  }

  /* package */ static Optional<PrerequisiteProofEvidence> decode(
      final JsonNode node, final ArtifactCoordinate rowCandidate) throws IOException {
    if (node == null || node.isNull()) {
      return Optional.empty();
    }
    shape(node, PROOF_FIELDS, "prerequisiteProof");
    final ArtifactCoordinate candidate = coordinate(text(node, CANDIDATE_FIELD), CANDIDATE_FIELD);
    if (!candidate.equals(rowCandidate)) {
      throw error(CANDIDATE_FIELD, "does not match the generic finding component");
    }
    final String finalFingerprint = text(node, "finalInventoryFingerprint");
    final Path affectedPath =
        path(text(node, AFFECTED_ARTIFACT_PATH_FIELD), AFFECTED_ARTIFACT_PATH_FIELD);
    final String postElisionSha256 = text(node, "postElisionSha256");
    final List<PrerequisiteProofEvidence.GroupEvidence> groups =
        readGroups(array(node.get(GROUPS_FIELD), GROUPS_FIELD));
    final String baselineDetail = nullableText(node, "baselineDetail");
    try {
      return Optional.of(
          new PrerequisiteProofEvidence(
              candidate,
              finalFingerprint,
              affectedPath,
              postElisionSha256,
              groups,
              baselineDetail));
    } catch (final IllegalArgumentException exception) {
      throw error("prerequisiteProof", exception.getMessage(), exception);
    }
  }

  // Each row needs its own immutable group outcome and indexed diagnostic path.
  @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
  private static List<PrerequisiteProofEvidence.GroupEvidence> readGroups(final ArrayNode nodes)
      throws IOException {
    final List<PrerequisiteProofEvidence.GroupEvidence> groups = new ArrayList<>();
    final Set<PrerequisiteGroup> uniqueGroups = new HashSet<>();
    for (int index = 0; index < nodes.size(); index++) {
      final String path = "groups[" + index + "]";
      final JsonNode node = nodes.get(index);
      shape(node, GROUP_FIELDS, path);
      final PrerequisiteOperator operator =
          enumeration(node, "operator", PrerequisiteOperator.class, path);
      final PrerequisiteAbsenceAttribution groupAttribution =
          enumeration(node, ATTRIBUTION_FIELD, PrerequisiteAbsenceAttribution.class, path);
      final List<PrerequisiteProofEvidence.MemberEvidence> members =
          readMembers(array(node.get("members"), path + ".members"), path + ".members");
      final PrerequisiteGroup group;
      try {
        group =
            new PrerequisiteGroup(
                operator,
                members.stream()
                    .map(PrerequisiteProofEvidence.MemberEvidence::claim)
                    .collect(java.util.stream.Collectors.toCollection(TreeSet::new)));
      } catch (final IllegalArgumentException exception) {
        throw error(path, exception.getMessage(), exception);
      }
      if (!uniqueGroups.add(group)) {
        throw error(path, "duplicate prerequisite proof group");
      }
      try {
        groups.add(new PrerequisiteProofEvidence.GroupEvidence(group, groupAttribution, members));
      } catch (final IllegalArgumentException exception) {
        throw error(path, exception.getMessage(), exception);
      }
    }
    return List.copyOf(groups);
  }

  // Each row needs its own immutable member outcome and indexed diagnostic path.
  @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
  private static List<PrerequisiteProofEvidence.MemberEvidence> readMembers(
      final ArrayNode nodes, final String path) throws IOException {
    final List<PrerequisiteProofEvidence.MemberEvidence> members = new ArrayList<>();
    final Set<PrerequisiteClaim> uniqueClaims = new HashSet<>();
    for (int index = 0; index < nodes.size(); index++) {
      final String memberPath = path + "[" + index + "]";
      final JsonNode node = nodes.get(index);
      shape(node, MEMBER_FIELDS, memberPath);
      final JsonNode claimNode = node.get("claim");
      shape(claimNode, CLAIM_FIELDS, memberPath + ".claim");
      final PrerequisiteClaim claim;
      try {
        claim =
            new PrerequisiteClaim(
                text(claimNode, "requiresDependency"), text(claimNode, "requiresClass"));
      } catch (final IllegalArgumentException exception) {
        throw error(memberPath + ".claim", exception.getMessage(), exception);
      }
      if (!uniqueClaims.add(claim)) {
        throw error(memberPath + ".claim", "duplicate prerequisite member");
      }
      final PrerequisiteMemberObservation.State state =
          enumeration(node, "state", PrerequisiteMemberObservation.State.class, memberPath);
      final PrerequisiteAbsenceAttribution attribution =
          enumeration(node, ATTRIBUTION_FIELD, PrerequisiteAbsenceAttribution.class, memberPath);
      final List<PrerequisiteProofEvidence.ProviderEvidence> providers =
          readProviders(
              array(node.get("providers"), memberPath + ".providers"), memberPath + ".providers");
      try {
        members.add(
            new PrerequisiteProofEvidence.MemberEvidence(claim, state, attribution, providers));
      } catch (final IllegalArgumentException exception) {
        throw error(memberPath, exception.getMessage(), exception);
      }
    }
    return List.copyOf(members);
  }

  private static List<PrerequisiteProofEvidence.ProviderEvidence> readProviders(
      final ArrayNode nodes, final String path) throws IOException {
    final List<PrerequisiteProofEvidence.ProviderEvidence> providers = new ArrayList<>();
    for (int index = 0; index < nodes.size(); index++) {
      final String providerPath = path + "[" + index + "]";
      final JsonNode node = nodes.get(index);
      shape(node, PROVIDER_FIELDS, providerPath);
      providers.add(readProvider(node, providerPath));
    }
    return List.copyOf(providers);
  }

  private static PrerequisiteProofEvidence.ProviderEvidence readProvider(
      final JsonNode node, final String providerPath) throws IOException {
    final ProviderKind kind = enumeration(node, "kind", ProviderKind.class, providerPath);
    final String coordinateText = nullableText(node, "coordinate");
    final ArtifactCoordinate coordinate =
        coordinateText == null ? null : coordinate(coordinateText, providerPath + ".coordinate");
    if (kind == ProviderKind.DEPENDENCY_ARCHIVE && coordinate == null) {
      throw error(providerPath + ".coordinate", "is required for a dependency provider");
    }
    if (kind != ProviderKind.DEPENDENCY_ARCHIVE && coordinate != null) {
      throw error(providerPath + ".coordinate", "must be absent for an application provider");
    }
    final Path baselinePath = optionalPath(node, "baselinePath", providerPath);
    final String baselineSha256 = nullableText(node, "baselineSha256");
    final Path finalPath = optionalPath(node, "finalPath", providerPath);
    final String finalSha256 = nullableText(node, "finalSha256");
    final PrerequisiteAbsenceAttribution attribution =
        enumeration(node, ATTRIBUTION_FIELD, PrerequisiteAbsenceAttribution.class, providerPath);
    try {
      return new PrerequisiteProofEvidence.ProviderEvidence(
          kind, coordinate, baselinePath, baselineSha256, finalPath, finalSha256, attribution);
    } catch (final IllegalArgumentException exception) {
      throw error(providerPath, exception.getMessage(), exception);
    }
  }

  private static Path optionalPath(final JsonNode node, final String name, final String parent)
      throws IOException {
    final String value = nullableText(node, name);
    return value == null ? null : path(value, parent + "." + name);
  }

  private static Path path(final String value, final String field) throws IOException {
    try {
      final Path path = Path.of(value);
      if (!path.isAbsolute()) {
        throw error(field, "must be absolute");
      }
      return path.normalize();
    } catch (final InvalidPathException exception) {
      throw error(field, "is not a valid path", exception);
    }
  }

  private static ArtifactCoordinate coordinate(final String value, final String field)
      throws IOException {
    try {
      return MavenElisionReportSourceCoordinateValidator.parseCanonical(value);
    } catch (final IllegalArgumentException exception) {
      throw error(field, "is not a canonical Maven coordinate", exception);
    }
  }

  private static <T extends Enum<T>> T enumeration(
      final JsonNode node, final String field, final Class<T> type, final String parent)
      throws IOException {
    final String value = text(node, field);
    try {
      return Enum.valueOf(type, value);
    } catch (final IllegalArgumentException exception) {
      throw error(parent + "." + field, "has an unsupported value", exception);
    }
  }

  private static ArrayNode array(final JsonNode node, final String field) throws IOException {
    if (node == null || !node.isArray()) {
      throw error(field, "must be an array");
    }
    return (ArrayNode) node;
  }

  private static String text(final JsonNode node, final String field) throws IOException {
    final JsonNode value = node == null ? null : node.get(field);
    if (value == null || !value.isTextual() || value.textValue().isBlank()) {
      throw error(field, "must be nonblank text");
    }
    return value.textValue();
  }

  private static String nullableText(final JsonNode node, final String field) throws IOException {
    final JsonNode value = node.get(field);
    if (value == null || value.isNull()) {
      return null;
    }
    return text(node, field);
  }

  private static void shape(final JsonNode node, final Set<String> fields, final String path)
      throws IOException {
    if (node == null || !node.isObject()) {
      throw error(path, "must be an object");
    }
    final Set<String> actual = new HashSet<>();
    for (final java.util.Map.Entry<String, JsonNode> entry : node.properties()) {
      actual.add(entry.getKey());
    }
    if (!actual.equals(fields)) {
      final Set<String> missing = new TreeSet<>(fields);
      missing.removeAll(actual);
      final Set<String> unknown = new TreeSet<>(actual);
      unknown.removeAll(fields);
      throw error(path, "has invalid fields; missing=" + missing + ", unknown=" + unknown);
    }
  }

  private static IOException error(final String field, final String message) {
    return new IOException("genericFindings.prerequisiteProof." + field + " " + message);
  }

  private static IOException error(
      final String field, final String message, final Throwable cause) {
    return new IOException("genericFindings.prerequisiteProof." + field + " " + message, cause);
  }
}
