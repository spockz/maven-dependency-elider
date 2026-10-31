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
import io.github.spockz.elider.model.CveAffectedEntryContext;
import io.github.spockz.elider.model.HeuristicCandidateEvidence;
import io.github.spockz.elider.model.OsvAdvisoryRecord;
import io.github.spockz.elider.model.OsvAffectedPackage;
import io.github.spockz.elider.model.OsvAffectedRange;
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

  /** Encodes OSV-owned cacheable advisory records in stable order. */
  public byte[] encode(final List<OsvAdvisoryRecord> records) throws IOException {
    return mapper.writeValueAsBytes(encodeTree(records));
  }

  /** Builds the validated deterministic advisory document as a native JSON tree. */
  public ObjectNode encodeTree(final List<OsvAdvisoryRecord> records) {
    Objects.requireNonNull(records, "records");
    final List<ObjectNode> nodes = new ArrayList<>();
    final Set<String> ids = new TreeSet<>();
    for (final OsvAdvisoryRecord record : records) {
      Objects.requireNonNull(record, "OSV record");
      if (!ids.add(record.osvId())) {
        throw new IllegalArgumentException("Duplicate OSV record ID: " + record.osvId());
      }
      nodes.add(writeRecord(record));
    }
    nodes.sort(java.util.Comparator.comparing(node -> node.path("osvId").asText()));
    final ObjectNode root = mapper.createObjectNode();
    root.put("schemaVersion", 1);
    final ArrayNode array = root.putArray("records");
    nodes.forEach(array::add);
    return root;
  }

  private ObjectNode writeRecord(final OsvAdvisoryRecord record) {
    final ObjectNode node = mapper.createObjectNode();
    node.put("osvId", record.osvId());
    writeStrings(node.putArray("aliases"), record.aliases());
    final ArrayNode affectedPackages = node.putArray("affectedPackages");
    record.affectedPackages().stream()
        .sorted(
            java.util.Comparator.comparing(OsvAffectedPackage::ecosystem)
                .thenComparing(OsvAffectedPackage::packageName))
        .forEach(value -> writeAffectedPackage(affectedPackages.addObject(), value));
    final ArrayNode cnaEntries = node.putArray("cnaAffectedEntries");
    record.cnaAffectedEntries().stream()
        .sorted(java.util.Comparator.comparing(CveAffectedEntryContext::entryIdentity))
        .forEach(entry -> writeCnaEntry(cnaEntries.addObject(), entry));
    final List<ObjectNode> evidence =
        record.evidence().stream()
            .map(this::writeEvidence)
            .sorted(java.util.Comparator.comparing(ObjectNode::toString))
            .toList();
    final ArrayNode evidenceNodes = node.putArray("evidence");
    evidence.forEach(evidenceNodes::add);
    return node;
  }

  private static void writeAffectedPackage(
      final ObjectNode target, final OsvAffectedPackage affectedPackage) {
    target.put("ecosystem", affectedPackage.ecosystem());
    target.put("packageName", affectedPackage.packageName());
    final ArtifactCoordinate coordinateValue = affectedPackage.coordinate();
    final ObjectNode coordinate = target.putObject("coordinate");
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
    final ArrayNode versions = target.putArray("versions");
    affectedPackage.versions().forEach(versions::add);
    final ArrayNode ranges = target.putArray("ranges");
    for (final OsvAffectedRange range : affectedPackage.ranges()) {
      final ObjectNode rangeNode = ranges.addObject();
      rangeNode.put("type", range.type());
      if (range.repo() == null) {
        rangeNode.putNull("repo");
      } else {
        rangeNode.put("repo", range.repo());
      }
      final ArrayNode events = rangeNode.putArray("events");
      for (final Map<String, String> event : range.events()) {
        final ObjectNode eventNode = events.addObject();
        event.entrySet().stream()
            .sorted(Map.Entry.comparingByKey())
            .forEach(item -> eventNode.put(item.getKey(), item.getValue()));
      }
    }
  }

  private static void writeCnaEntry(final ObjectNode target, final CveAffectedEntryContext entry) {
    CnaAffectedEntryCodec.write(target, entry);
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
    if (scope.cveId() == null) {
      scopeNode.putNull("cveId");
    } else {
      scopeNode.put("cveId", scope.cveId());
    }
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
    scopeNode.put("ecosystem", scope.ecosystem());
    scopeNode.put("packageName", scope.packageName());

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
