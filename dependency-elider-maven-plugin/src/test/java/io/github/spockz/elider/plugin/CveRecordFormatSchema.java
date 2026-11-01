// WHY: Validates synthetic CVE fixtures against the repository-pinned upstream record format.

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.networknt.schema.JsonSchemaFactory;
import com.networknt.schema.SpecVersion;
import com.networknt.schema.ValidationMessage;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Set;

/** Checks the pinned CVE Record Format 5.2.0 schema before fixture use. */
final class CveRecordFormatSchema {
  /** Classpath path of the bundled upstream schema. */
  private static final String SCHEMA_RESOURCE = "/schema/cve-record-format-5.2.0-bundled.json";

  /** Expected SHA-256 pins schema bytes to the documented upstream release. */
  private static final String SCHEMA_SHA256 =
      "44c703322b1fcc532bc1c93f3993a0ba042c1a2831aae8cf39c4fbb707d03c8f";

  /** JSON reader used for the pinned schema. */
  private static final ObjectMapper JSON = new ObjectMapper();

  private CveRecordFormatSchema() {}

  /* package */ static Set<ValidationMessage> validate(final JsonNode record) throws IOException {
    final byte[] schemaBytes = readSchemaBytes();
    final JsonNode schemaDocument = JSON.readTree(schemaBytes);
    return JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V7)
        .getSchema(schemaDocument)
        .validate(record);
  }

  private static byte[] readSchemaBytes() throws IOException {
    try (InputStream input = CveRecordFormatSchema.class.getResourceAsStream(SCHEMA_RESOURCE)) {
      if (input == null) {
        throw new IOException("Pinned CVE schema resource is missing: " + SCHEMA_RESOURCE);
      }
      final byte[] bytes = input.readAllBytes();
      if (!SCHEMA_SHA256.equals(sha256(bytes))) {
        throw new IOException("Pinned CVE schema digest differs from its recorded release");
      }
      return bytes;
    }
  }

  private static String sha256(final byte[] bytes) throws IOException {
    try {
      return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    } catch (final NoSuchAlgorithmException exception) {
      throw new IOException("SHA-256 is unavailable for CVE schema pinning", exception);
    }
  }
}
