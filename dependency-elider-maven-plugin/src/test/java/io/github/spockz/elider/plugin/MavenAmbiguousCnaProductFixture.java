// WHY: Supplies ambiguous exact Maven CNA products for assessment/report regressions.

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/** Creates a CVE source record with two matching product entries in either order. */
final class MavenAmbiguousCnaProductFixture {
  /** JSON mapper used to write the synthetic CVE input. */
  private static final ObjectMapper JSON = new ObjectMapper();

  private MavenAmbiguousCnaProductFixture() {}

  /* package */ static Path write(final Path directory, final boolean reverse) throws IOException {
    final Path record = directory.resolve("cves/2025/12xxx/CVE-2025-12345.json");
    Files.createDirectories(record.getParent());
    final ObjectNode root = JSON.createObjectNode();
    root.putObject("cveMetadata")
        .put("cveId", MavenCorroboratedSourceArchiveFixtures.CVE_ID)
        .put("state", "PUBLISHED");
    final ArrayNode affected = root.putObject("containers").putObject("cna").putArray("affected");
    final ObjectNode affectedProduct = product("src/main/java/org/example/Outer.java", "affected");
    final ObjectNode unaffectedProduct =
        product("src/main/java/org/example/Helper.java", "unaffected");
    affected.add(reverse ? unaffectedProduct : affectedProduct);
    affected.add(reverse ? affectedProduct : unaffectedProduct);
    JSON.writeValue(record.toFile(), root);
    return record;
  }

  private static ObjectNode product(final String programFile, final String status) {
    final ObjectNode entry = JSON.createObjectNode();
    entry
        .put("vendor", "Example")
        .put("product", MavenCorroboratedSourceArchiveFixtures.ARTIFACT_ID)
        .put("packageURL", "pkg:maven/org.example/demo");
    entry
        .putArray("versions")
        .addObject()
        .put("version", MavenCorroboratedSourceArchiveFixtures.VERSION)
        .put("status", status);
    entry.putArray("programFiles").add(programFile);
    return entry;
  }
}
