/* WHY: Shares structured OSV JSON fixtures across core tests. */

package io.github.spockz.elider.scanner;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

/** Builds valid minimal OSV Maven records for source-ingestion tests. */
public final class OsvSnapshotFixtures {
  /** Creates the static OSV source fixture utility. */
  private OsvSnapshotFixtures() {}

  /** Creates one OSV record with a Maven range and optional CVE alias. */
  public static String osvJson(final String recordId, final String cve) {
    return osvJson(recordId, cve, "2026-10-31T00:00:00Z", "org.example:library");
  }

  /** Creates a record with an explicit source revision and package. */
  public static String osvJson(
      final String recordId, final String cve, final String modified, final String packageName) {
    final ObjectMapper mapper = new ObjectMapper();
    final ObjectNode record = mapper.createObjectNode();
    record.put("id", recordId);
    record.put("modified", modified);
    final ArrayNode aliases = record.putArray("aliases");
    if (cve != null) {
      aliases.add(cve);
    }
    final ObjectNode affected = record.putArray("affected").addObject();
    affected.putObject("package").put("ecosystem", "Maven").put("name", packageName);
    final ObjectNode range = affected.putArray("ranges").addObject();
    range.put("type", "ECOSYSTEM");
    final ArrayNode events = range.putArray("events");
    events.addObject().put("introduced", "0");
    events.addObject().put("fixed", "2.0");
    return record.toString();
  }

  /** Creates a source tombstone for one previously indexed OSV owner. */
  public static String withdrawnJson(final String recordId, final String modified) {
    final ObjectMapper mapper = new ObjectMapper();
    final ObjectNode record = mapper.createObjectNode();
    record.put("id", recordId);
    record.put("modified", modified);
    record.put("withdrawn", modified);
    record.putArray("affected");
    return record.toString();
  }
}
