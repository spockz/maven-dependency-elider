// WHY: Compiles pinned CycloneDX and OpenVEX JSON Schemas once per JVM across metadata tests.

package io.github.spockz.elider.metadata;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.networknt.schema.JsonSchema;
import com.networknt.schema.JsonSchemaFactory;
import com.networknt.schema.SpecVersion;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@SuppressWarnings({"PMD.CommentDefaultAccessModifier", "PMD.CommentRequired"})
final class PinnedJsonSchemaCache {
  private static final ObjectMapper JSON = new ObjectMapper();
  private static final Map<String, JsonSchema> SCHEMAS = new ConcurrentHashMap<>();

  private PinnedJsonSchemaCache() {}

  static JsonSchema cycloneDx16() {
    return schema(
        "/schema/bom-1.6.schema.json",
        SpecVersion.VersionFlag.V7,
        "18f57f7482593bad9f21b4feed09084640cbeff419d62ad5090c5ceccca5b37d");
  }

  static JsonSchema openVex020() {
    return schema(
        "/schema/openvex-0.2.0.schema.json",
        SpecVersion.VersionFlag.V202012,
        "9373597734ed1d3ea5161a8b46d3866c4a8cfe76fd632fdd16aef01fb34b3238");
  }

  private static JsonSchema schema(
      final String resource, final SpecVersion.VersionFlag version, final String expectedSha256) {
    return SCHEMAS.computeIfAbsent(
        resource + "@" + version + "#" + expectedSha256,
        ignored -> loadSchema(resource, version, expectedSha256));
  }

  private static JsonSchema loadSchema(
      final String resource, final SpecVersion.VersionFlag version, final String expectedSha256) {
    try (InputStream input = PinnedJsonSchemaCache.class.getResourceAsStream(resource)) {
      assertThat(input).isNotNull();
      final byte[] schemaBytes = input.readAllBytes();
      assertThat(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(schemaBytes)))
          .isEqualTo(expectedSha256);
      return JsonSchemaFactory.getInstance(version).getSchema(JSON.readTree(schemaBytes));
    } catch (final IOException exception) {
      throw new UncheckedIOException("Failed to load pinned JSON schema " + resource, exception);
    } catch (final NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 is unavailable", exception);
    }
  }
}
