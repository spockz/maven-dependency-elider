/* WHY: Centralizes structured OSV source JSON fixtures shared by indexer and cache tests. */

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
    final ObjectMapper mapper = new ObjectMapper();
    final ObjectNode record = mapper.createObjectNode();
    record.put("id", recordId);
    final ArrayNode aliases = record.putArray("aliases");
    if (cve != null) {
      aliases.add(cve);
    }
    final ObjectNode affected = record.putArray("affected").addObject();
    affected.putObject("package").put("ecosystem", "Maven").put("name", "org.example:library");
    final ObjectNode range = affected.putArray("ranges").addObject();
    range.put("type", "ECOSYSTEM");
    final ArrayNode events = range.putArray("events");
    events.addObject().put("introduced", "0");
    events.addObject().put("fixed", "2.0");
    return record.toString();
  }
}
