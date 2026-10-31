/* WHY: Writes reviewable advisory evidence with a stable v1 discriminator and field shape. */

package io.github.spockz.elider.scanner;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.spockz.elider.model.AdvisoryEvidence;
import io.github.spockz.elider.model.AdvisoryProvenance;
import io.github.spockz.elider.model.AdvisoryScope;
import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.CorroboratedSourceClassCandidate;
import io.github.spockz.elider.model.HeuristicCandidateEvidence;
import io.github.spockz.elider.model.PackageAdvisoryEvidence;
import io.github.spockz.elider.model.StructuredSourceClassEvidence;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;

/** Deterministic v1 writer for review-only advisory evidence. */
@SuppressWarnings("PMD.AvoidDuplicateLiterals")
public final class AdvisoryEvidenceWriter {
  /** JSON mapper used to emit deterministic object fields. */
  private final ObjectMapper mapper;

  /** Creates a writer using the project's Jackson defaults. */
  public AdvisoryEvidenceWriter() {
    this(new ObjectMapper());
  }

  /** Creates a writer using the supplied mapper. */
  public AdvisoryEvidenceWriter(final ObjectMapper mapper) {
    this.mapper = Objects.requireNonNull(mapper, "mapper");
  }

  /** Encodes cacheable advisory-source evidence in stable order. */
  public byte[] encode(final List<? extends AdvisoryEvidence> evidence) throws IOException {
    Objects.requireNonNull(evidence, "evidence");
    final List<ObjectNode> nodes = new ArrayList<>();
    for (final AdvisoryEvidence item : evidence) {
      nodes.add(writeEvidence(Objects.requireNonNull(item, "evidence item")));
    }
    nodes.sort(java.util.Comparator.comparing(ObjectNode::toString));
    final ObjectNode root = mapper.createObjectNode();
    root.put("schemaVersion", 1);
    final ArrayNode array = root.putArray("evidence");
    nodes.forEach(array::add);
    return mapper.writeValueAsBytes(root);
  }

  private ObjectNode writeEvidence(final AdvisoryEvidence evidence) {
    final ObjectNode node = mapper.createObjectNode();
    if (evidence instanceof StructuredSourceClassEvidence structured) {
      node.put("kind", "structured-source-class");
      writeCommon(node, structured.scope(), structured.provenance());
      node.put("affectedProductIdentity", structured.affectedProductIdentity());
      writeStrings(node.putArray("programFiles"), structured.programFiles());
      writeStrings(node.putArray("programRoutines"), structured.programRoutines());
      writeAttribution(node.putObject("fileClassAttribution"), structured.fileClassAttribution());
      writeAttribution(
          node.putObject("routineClassAttribution"), structured.routineClassAttribution());
    } else if (evidence instanceof CorroboratedSourceClassCandidate corroborated) {
      node.put("kind", "corroborated-source-class-candidate");
      writeCommon(node, corroborated.scope(), corroborated.provenance());
      node.put("affectedProductIdentity", corroborated.affectedProductIdentity());
      node.put("programFile", corroborated.programFile());
      node.put("classEntry", corroborated.classEntry());
      if (corroborated.sourceFileAttribute() == null) {
        node.putNull("sourceFileAttribute");
      } else {
        node.put("sourceFileAttribute", corroborated.sourceFileAttribute());
      }
      node.put("packagePathComparison", corroborated.packagePathComparison());
      node.put("conventionalLayoutAssumed", corroborated.conventionalLayoutAssumed());
      node.put("mappingStatus", corroborated.mappingStatus().name());
    } else if (evidence instanceof HeuristicCandidateEvidence heuristic) {
      node.put("kind", "heuristic-candidate");
      writeCommon(node, heuristic.scope(), heuristic.provenance());
      writeStrings(node.putArray("candidateClasses"), heuristic.candidateClasses());
      writeStrings(node.putArray("candidateDependencies"), heuristic.candidateDependencies());
    } else if (evidence instanceof PackageAdvisoryEvidence packageAdvisory) {
      node.put("kind", "package-advisory");
      writeCommon(node, packageAdvisory.scope(), packageAdvisory.provenance());
    } else {
      throw new IllegalArgumentException(
          "Owner proof evidence is not part of the cacheable advisory document");
    }
    return node;
  }

  private static void writeCommon(
      final ObjectNode node, final AdvisoryScope scope, final AdvisoryProvenance provenance) {
    final ObjectNode scopeNode = node.putObject("scope");
    scopeNode.put("cveId", scope.cveId());
    final ArtifactCoordinate coordinateValue = scope.affectedCoordinate();
    final ObjectNode coordinate = scopeNode.putObject("affectedCoordinate");
    coordinate.put("groupId", coordinateValue.groupId());
    coordinate.put("artifactId", coordinateValue.artifactId());
    if (coordinateValue.version() == null) {
      coordinate.putNull("version");
    } else {
      coordinate.put("version", coordinateValue.version());
    }
    coordinate.put("type", coordinateValue.type());
    coordinate.put("classifier", coordinateValue.classifier());
    coordinate.put("scope", coordinateValue.scope());
    scopeNode.put("versionRangeSpec", scope.versionRangeSpec());

    final ObjectNode provenanceNode = node.putObject("provenance");
    provenanceNode.put("origin", provenance.origin().name());
    provenanceNode.put("sourceRecordId", provenance.sourceRecordId());
    if (provenance.sourceUrl() == null) {
      provenanceNode.putNull("sourceUrl");
    } else {
      provenanceNode.put("sourceUrl", provenance.sourceUrl().toString());
    }
    if (provenance.sourceRecordSha256() == null) {
      provenanceNode.putNull("sourceRecordSha256");
    } else {
      provenanceNode.put("sourceRecordSha256", provenance.sourceRecordSha256());
    }
  }

  private static void writeStrings(final ArrayNode target, final Set<String> values) {
    new TreeSet<>(values).forEach(target::add);
  }

  private static void writeAttribution(
      final ObjectNode target, final Map<String, Set<String>> attribution) {
    attribution.entrySet().stream()
        .sorted(Map.Entry.comparingByKey())
        .forEach(
            entry -> {
              final ArrayNode classes = target.putArray(entry.getKey());
              writeStrings(classes, entry.getValue());
            });
  }
}
