// WHY: Converts validated report range nodes into shared raw OSV applicability claims.

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Spliterators;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

/** Reads raw package versions and ranges after their JSON shape has been validated. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class MavenElisionReportAffectedRangePayloadReader {
  /** Ordered range event field name. */
  private static final String EVENTS = "events";

  /** OSV range type field name. */
  private static final String TYPE = "type";

  /** Optional upstream repository field name. */
  private static final String REPO = "repo";

  private MavenElisionReportAffectedRangePayloadReader() {}

  static List<String> versions(final JsonNode array) {
    return StreamSupport.stream(array.spliterator(), false).map(JsonNode::textValue).toList();
  }

  static List<MavenElisionReportSnapshot.AffectedRange> ranges(final JsonNode array) {
    return StreamSupport.stream(array.spliterator(), false)
        .map(MavenElisionReportAffectedRangePayloadReader::range)
        .toList();
  }

  private static MavenElisionReportSnapshot.AffectedRange range(final JsonNode range) {
    final List<Map<String, String>> events =
        StreamSupport.stream(range.get(EVENTS).spliterator(), false)
            .map(MavenElisionReportAffectedRangePayloadReader::event)
            .toList();
    return new MavenElisionReportSnapshot.AffectedRange(
        range.get(TYPE).textValue(),
        range.get(REPO).isNull() ? null : range.get(REPO).textValue(),
        events);
  }

  private static Map<String, String> event(final JsonNode event) {
    final Iterator<Map.Entry<String, JsonNode>> fields = event.fields();
    return StreamSupport.stream(
            Spliterators.spliteratorUnknownSize(fields, java.util.Spliterator.ORDERED), false)
        .collect(
            Collectors.toUnmodifiableMap(Map.Entry::getKey, entry -> entry.getValue().textValue()));
  }
}
