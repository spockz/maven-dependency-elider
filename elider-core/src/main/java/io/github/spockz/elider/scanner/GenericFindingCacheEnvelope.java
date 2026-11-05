/* WHY: Stores source-independent contributions behind the local producer boundary. */

package io.github.spockz.elider.scanner;

import io.github.spockz.elider.model.CacheProducerIdentity;
import io.github.spockz.elider.model.VulnerabilityFindingContribution;
import java.util.Collections;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/** Immutable schema-v1 generic finding cache envelope contents. */
@SuppressWarnings("PMD.UseConcurrentHashMap")
// Enum order is deterministic and the published map is immutable.
public record GenericFindingCacheEnvelope(
    CacheProducerIdentity producer, Map<FindingSource, FindingSourceSnapshot> sources) {
  /** Validates the producer and snapshots both independent source partitions. */
  public GenericFindingCacheEnvelope {
    Objects.requireNonNull(producer, "producer");
    Objects.requireNonNull(sources, "sources");
    final Map<FindingSource, FindingSourceSnapshot> copy = new EnumMap<>(FindingSource.class);
    sources.forEach(
        (source, snapshot) -> {
          Objects.requireNonNull(source, "source");
          Objects.requireNonNull(snapshot, "snapshot");
          if (source != snapshot.source()) {
            throw new IllegalArgumentException("source key must match snapshot source");
          }
          copy.put(source, snapshot);
        });
    sources = Collections.unmodifiableMap(copy);
  }

  /** Returns all persisted source contributions in deterministic source order. */
  public List<VulnerabilityFindingContribution> contributions() {
    return sources.values().stream()
        .flatMap(snapshot -> snapshot.contributions().stream())
        .toList();
  }

  /** Replaces the observation for one source while preserving every other partition. */
  public GenericFindingCacheEnvelope withSourceSnapshot(final FindingSourceSnapshot snapshot) {
    final Map<FindingSource, FindingSourceSnapshot> updated = new EnumMap<>(FindingSource.class);
    updated.putAll(sources);
    updated.put(snapshot.source(), snapshot);
    return new GenericFindingCacheEnvelope(producer, updated);
  }
}
