/* WHY: Retains upstream OSV range events without flattening or altering their boundaries. */

package io.github.spockz.elider.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

/** Original OSV range type and ordered event fields for one affected package. */
public record OsvAffectedRange(String type, String repo, List<Map<String, String>> events) {
  /** Freezes event maps while preserving their source order. */
  public OsvAffectedRange {
    if (type == null || type.isBlank()) {
      throw new IllegalArgumentException("type must not be blank");
    }
    Objects.requireNonNull(events, "events");
    final List<Map<String, String>> copy = new ArrayList<>();
    for (final Map<String, String> event : events) {
      Objects.requireNonNull(event, "event");
      copy.add(Map.copyOf(new TreeMap<>(event)));
    }
    events = Collections.unmodifiableList(copy);
  }
}
