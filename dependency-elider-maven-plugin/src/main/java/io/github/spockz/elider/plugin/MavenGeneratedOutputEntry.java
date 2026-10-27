/* WHY: Validates one manifest entry before it can authorize deletion of an output. */

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;

/** Deletes unchanged outputs authorized by the manifest. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class MavenGeneratedOutputEntry {
  private MavenGeneratedOutputEntry() {}

  static void clear(final JsonNode output, final Set<Path> allowed, final Path manifest)
      throws IOException {
    final Path path = outputPath(output, manifest);
    final String digest = outputDigest(output, manifest);
    if (allowed.contains(path)
        && Files.isRegularFile(path)
        && ArtifactFileDigest.sha256(path).equals(digest)) {
      Files.delete(path);
    }
  }

  static void validateFields(
      final JsonNode object, final Set<String> supported, final Path manifest) throws IOException {
    final java.util.Iterator<String> keys = object.fieldNames();
    while (keys.hasNext()) {
      final String key = keys.next();
      if (!supported.contains(key)) {
        throw new IOException(
            "Unsupported generated output manifest field " + key + " in " + manifest);
      }
    }
  }

  private static Path outputPath(final JsonNode output, final Path manifest) throws IOException {
    if (!output.isObject()) {
      throw new IOException("Malformed generated output entry in " + manifest);
    }
    validateFields(output, Set.of("path", "sha256"), manifest);
    final JsonNode pathNode = output.get("path");
    if (pathNode == null || !pathNode.isTextual()) {
      throw new IOException("Malformed generated output path in " + manifest);
    }
    return Path.of(pathNode.textValue()).toAbsolutePath().normalize();
  }

  private static String outputDigest(final JsonNode output, final Path manifest)
      throws IOException {
    final JsonNode digest = output.get("sha256");
    if (digest == null || !digest.isTextual() || !digest.textValue().matches("[0-9a-f]{64}")) {
      throw new IOException("Malformed generated output digest in " + manifest);
    }
    return digest.textValue();
  }
}
