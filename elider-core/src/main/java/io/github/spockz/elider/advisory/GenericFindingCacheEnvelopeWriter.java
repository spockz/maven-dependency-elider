/* WHY: Writes generic findings directly instead of wrapping the OSV-owned cache shape. */

package io.github.spockz.elider.advisory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.spockz.elider.model.CacheProducerIdentity;
import java.io.IOException;
import java.util.Objects;

/** Deterministic schema-v1 writer for generic finding cache envelopes. */
public final class GenericFindingCacheEnvelopeWriter {
  /** Default JSON mapper for generic finding cache envelopes. */
  private static final ObjectMapper DEFAULT_MAPPER = new ObjectMapper();

  /** Mapper used to build the strict JSON tree. */
  private final ObjectMapper mapper;

  /** Creates the strict version-one generic envelope writer. */
  public GenericFindingCacheEnvelopeWriter() {
    this(DEFAULT_MAPPER);
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
    root.set("producer", FindingJsonFields.writeProducer(mapper, producer));
    final ObjectNode sources = root.putObject("sources");
    for (final FindingSource source : FindingSource.values()) {
      final FindingSourceSnapshot snapshot = envelope.sources().get(source);
      if (snapshot != null) {
        sources.set(source.name(), sourceNode(snapshot));
      }
    }
    return mapper.writeValueAsBytes(root);
  }

  private ObjectNode sourceNode(final FindingSourceSnapshot snapshot) throws IOException {
    final ObjectNode node = mapper.createObjectNode();
    node.put("source", snapshot.source().name());
    FindingJsonFields.putNullable(node, "revision", snapshot.revision());
    FindingJsonFields.putNullable(
        node,
        "lastSuccessfulSync",
        snapshot.lastSuccessfulSync() == null ? null : snapshot.lastSuccessfulSync().toString());
    node.put("status", snapshot.status().name());
    FindingJsonFields.putNullable(node, "diagnostic", snapshot.diagnostic());
    node.set("contributions", FindingContributionJsonCodec.encode(snapshot.contributions()));
    node.set("observationDiagnostics", mapper.valueToTree(snapshot.observationDiagnostics()));
    return node;
  }
}
