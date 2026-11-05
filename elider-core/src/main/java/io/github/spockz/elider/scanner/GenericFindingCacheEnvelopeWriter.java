/* WHY: Writes generic findings directly instead of wrapping the OSV-owned cache shape. */

package io.github.spockz.elider.scanner;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.spockz.elider.model.CacheProducerIdentity;
import java.io.IOException;
import java.util.Objects;

/** Deterministic schema-v1 writer for generic finding cache envelopes. */
public final class GenericFindingCacheEnvelopeWriter {
  /** Mapper used to build the strict JSON tree. */
  private final ObjectMapper mapper;

  /** Creates the strict version-one generic envelope writer. */
  public GenericFindingCacheEnvelopeWriter() {
    this(new ObjectMapper());
  }

  /** Creates a writer around the supplied mapper for focused tests. */
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  GenericFindingCacheEnvelopeWriter(final ObjectMapper mapper) {
    this.mapper = Objects.requireNonNull(mapper, "mapper");
  }

  /** Encodes a validated producer-bound envelope as UTF-8 JSON. */
  public byte[] encode(final GenericFindingCacheEnvelope envelope) throws IOException {
    Objects.requireNonNull(envelope, "envelope");
    final CacheProducerIdentity producer = envelope.producer();
    final ObjectNode root = mapper.createObjectNode();
    root.put("schemaVersion", 1);
    root.set("producer", producerNode(producer));
    final ObjectNode sources = root.putObject("sources");
    for (final FindingSource source : FindingSource.values()) {
      final FindingSourceSnapshot snapshot = envelope.sources().get(source);
      if (snapshot != null) {
        sources.set(source.name(), sourceNode(snapshot));
      }
    }
    return mapper.writeValueAsBytes(root);
  }

  private ObjectNode producerNode(final CacheProducerIdentity producer) {
    final ObjectNode node = mapper.createObjectNode();
    node.put("groupId", producer.groupId());
    node.put("artifactId", producer.artifactId());
    node.put("version", producer.version());
    putNullable(node, "buildIdentity", producer.buildIdentity());
    return node;
  }

  private ObjectNode sourceNode(final FindingSourceSnapshot snapshot) throws IOException {
    final ObjectNode node = mapper.createObjectNode();
    node.put("source", snapshot.source().name());
    putNullable(node, "revision", snapshot.revision());
    putNullable(
        node,
        "lastSuccessfulSync",
        snapshot.lastSuccessfulSync() == null ? null : snapshot.lastSuccessfulSync().toString());
    node.put("status", snapshot.status().name());
    putNullable(node, "diagnostic", snapshot.diagnostic());
    node.set("contributions", FindingContributionJsonCodec.encode(snapshot.contributions()));
    node.set("observationDiagnostics", mapper.valueToTree(snapshot.observationDiagnostics()));
    return node;
  }

  private static void putNullable(final ObjectNode node, final String field, final String value) {
    if (value == null) {
      node.putNull(field);
    } else {
      node.put(field, value);
    }
  }
}
