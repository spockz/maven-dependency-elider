/* WHY: Rejects stale or malformed local cache payloads before exposing generic findings. */

package io.github.spockz.elider.scanner;

import com.fasterxml.jackson.core.JsonParser;
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
import java.util.Iterator;
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

  /** Complete fields of the plugin binary identity. */
  private static final Set<String> PRODUCER_FIELDS =
      Set.of("groupId", "artifactId", "version", "buildIdentity");

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

  /** JSON parser configured for strict model construction. */
  private final ObjectMapper mapper;

  /** Creates a reader for the current generic cache format. */
  public GenericFindingCacheEnvelopeReader() {
    this(new ObjectMapper());
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
    final JsonNode root = readRoot(input);
    final CacheProducerIdentity producer = readProducer(root.get(PRODUCER));
    if (!producer.isCompatibleWith(runningProducer)) {
      throw new IOException("Generic finding cache producer identity does not match this plugin");
    }
    return new GenericFindingCacheEnvelope(producer, readSources(root.get("sources")));
  }

  private JsonNode readRoot(final InputStream input) throws IOException {
    final JsonNode root;
    try (JsonParser parser = mapper.getFactory().createParser(input)) {
      parser.enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
      root = mapper.readTree(parser);
      if (parser.nextToken() != null) {
        throw new IOException("Generic finding cache contains trailing JSON content");
      }
    }
    FindingJsonFields.requireShape(root, ROOT_FIELDS, "Generic finding cache envelope");
    final JsonNode schema = root.get("schemaVersion");
    if (schema == null
        || !schema.isIntegralNumber()
        || !schema.canConvertToInt()
        || schema.intValue() != 1) {
      throw new IOException("Unsupported generic finding cache schemaVersion");
    }
    return root;
  }

  @SuppressWarnings("PMD.UseConcurrentHashMap") // Local collection, frozen by the envelope.
  private Map<FindingSource, FindingSourceSnapshot> readSources(final JsonNode sources)
      throws IOException {
    FindingJsonFields.requireObject(sources, "sources");
    final Map<FindingSource, FindingSourceSnapshot> snapshots = new EnumMap<>(FindingSource.class);
    final Iterator<Map.Entry<String, JsonNode>> fields = sources.fields();
    while (fields.hasNext()) {
      final Map.Entry<String, JsonNode> field = fields.next();
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

  private static CacheProducerIdentity readProducer(final JsonNode node) throws IOException {
    FindingJsonFields.requireShape(node, PRODUCER_FIELDS, PRODUCER);
    final String buildIdentity = FindingJsonFields.nullableText(node, "buildIdentity");
    try {
      return new CacheProducerIdentity(
          FindingJsonFields.requiredText(node, "groupId"),
          FindingJsonFields.requiredText(node, "artifactId"),
          FindingJsonFields.requiredText(node, "version"),
          buildIdentity);
    } catch (final IllegalArgumentException exception) {
      throw new IOException("Invalid generic finding cache producer identity", exception);
    }
  }
}
