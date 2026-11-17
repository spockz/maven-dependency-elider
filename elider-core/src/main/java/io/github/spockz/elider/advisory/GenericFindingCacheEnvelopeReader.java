/* WHY: Rejects stale or malformed local cache payloads before exposing generic findings. */

package io.github.spockz.elider.advisory;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.spockz.elider.model.CacheProducerIdentity;
import io.github.spockz.elider.model.VulnerabilityFindingContribution;
import java.io.IOException;
import java.io.InputStream;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/** Strict schema-v1 reader for producer-bound generic finding caches. */
public final class GenericFindingCacheEnvelopeReader {
  /** Producer field shared by the shape and value checks. */
  private static final String PRODUCER = "producer";

  /** Complete fields of the current cache container. */
  private static final Set<String> ROOT_FIELDS = Set.of("schemaVersion", PRODUCER, "sources");

  /** Complete fields of each independent source partition. */
  private static final Set<String> SOURCE_FIELDS =
      Set.of(
          "source",
          "revision",
          "lastSuccessfulSync",
          "status",
          "diagnostic",
          "contributions",
          "observationDiagnostics");

  /** Default strict JSON mapper for generic finding cache envelopes. */
  private static final ObjectMapper DEFAULT_MAPPER =
      new ObjectMapper()
          .enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
          .enable(DeserializationFeature.FAIL_ON_MISSING_CREATOR_PROPERTIES);

  /** JSON parser configured for strict model construction. */
  private final ObjectMapper mapper;

  /** Creates a reader for the current generic cache format. */
  public GenericFindingCacheEnvelopeReader() {
    this(DEFAULT_MAPPER);
  }

  /* default */ GenericFindingCacheEnvelopeReader(final ObjectMapper mapper) {
    this.mapper =
        Objects.requireNonNull(mapper, "mapper")
            .enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .enable(DeserializationFeature.FAIL_ON_MISSING_CREATOR_PROPERTIES);
  }

  /** Validates the complete cache and binds its producer. */
  public GenericFindingCacheEnvelope read(
      final InputStream input, final CacheProducerIdentity runningProducer) throws IOException {
    Objects.requireNonNull(input, "input");
    Objects.requireNonNull(runningProducer, "runningProducer");
    final JsonNode root =
        FindingJsonFields.readSchemaV1EnvelopeRoot(
            mapper, input, ROOT_FIELDS, "Generic finding cache envelope");
    final CacheProducerIdentity producer =
        FindingJsonFields.readProducer(root.get(PRODUCER), "generic finding cache");
    if (!producer.isCompatibleWith(runningProducer)) {
      throw new IOException("Generic finding cache producer identity does not match this plugin");
    }
    return new GenericFindingCacheEnvelope(producer, readSources(root.get("sources")));
  }

  @SuppressWarnings("PMD.UseConcurrentHashMap") // Local collection, frozen by the envelope.
  private Map<FindingSource, FindingSourceSnapshot> readSources(final JsonNode sources)
      throws IOException {
    FindingJsonFields.requireObject(sources, "sources");
    final Map<FindingSource, FindingSourceSnapshot> snapshots = new EnumMap<>(FindingSource.class);
    for (final Map.Entry<String, JsonNode> field : sources.properties()) {
      final FindingSource source;
      try {
        source = FindingSource.valueOf(field.getKey());
      } catch (final IllegalArgumentException exception) {
        throw new IOException("Unknown finding source partition: " + field.getKey(), exception);
      }
      snapshots.put(source, readSnapshot(field.getValue(), source));
    }
    return snapshots;
  }

  private FindingSourceSnapshot readSnapshot(
      final JsonNode node, final FindingSource expectedSource) throws IOException {
    FindingJsonFields.requireShape(node, SOURCE_FIELDS, "source snapshot");
    final FindingSource source;
    final FindingSourceSnapshot.Status status;
    try {
      source = FindingSource.valueOf(FindingJsonFields.requiredText(node, "source"));
      status = FindingSourceSnapshot.Status.valueOf(FindingJsonFields.requiredText(node, "status"));
    } catch (final IllegalArgumentException exception) {
      throw new IOException("Invalid finding source snapshot state", exception);
    }
    if (source != expectedSource) {
      throw new IOException("Finding source partition key does not match snapshot source");
    }
    final String revision = FindingJsonFields.nullableText(node, "revision");
    final Instant lastSuccessfulSync = readTimestamp(node);
    final String diagnostic = FindingJsonFields.nullableText(node, "diagnostic");
    final JsonNode observationNodes = node.get("observationDiagnostics");
    FindingJsonFields.requireTextArray(observationNodes, "source observationDiagnostics");
    final List<String> observations = new ArrayList<>();
    observationNodes.forEach(value -> observations.add(value.textValue()));
    final JsonNode contributionNodes = node.get("contributions");
    final List<VulnerabilityFindingContribution> contributions =
        FindingContributionJsonCodec.decode(contributionNodes);
    try {
      return new FindingSourceSnapshot(
          source, revision, lastSuccessfulSync, status, diagnostic, contributions, observations);
    } catch (final IllegalArgumentException exception) {
      throw new IOException("Invalid generic finding source snapshot", exception);
    }
  }

  private static Instant readTimestamp(final JsonNode node) throws IOException {
    final String text = FindingJsonFields.nullableText(node, "lastSuccessfulSync");
    if (text == null) {
      return null;
    }
    try {
      return Instant.parse(text);
    } catch (final DateTimeParseException exception) {
      throw new IOException("source.lastSuccessfulSync must be an RFC 3339 timestamp", exception);
    }
  }
}
