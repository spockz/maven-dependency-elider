/* WHY: Persists output ownership separately from the resolver's output path policy. */

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/** Reads and writes the digest-backed list of outputs owned by the plugin. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class MavenGeneratedOutputManifest {
  /** Strict parser for plugin-owned output manifests. */
  private static final ObjectMapper JSON =
      new ObjectMapper().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);

  private MavenGeneratedOutputManifest() {}

  static void clear(final Path manifest, final Collection<Path> allowedOutputs) throws IOException {
    if (!Files.isRegularFile(manifest)) {
      return;
    }
    clearEntries(readOutputs(manifest), allowedPaths(allowedOutputs), manifest);
    Files.delete(manifest);
  }

  static void write(final Path manifest, final Collection<Path> generated) throws IOException {
    final ArrayNode outputs = JSON.createArrayNode();
    for (final Path path : generated) {
      final Path absolute = path.toAbsolutePath().normalize();
      if (Files.isRegularFile(absolute)) {
        final ObjectNode output = outputs.addObject();
        output.put("path", absolute.toString());
        output.put("sha256", ArtifactFileDigest.sha256(absolute));
      }
    }
    final ObjectNode document = JSON.createObjectNode();
    document.set("outputs", outputs);
    final Path parent = manifest.getParent();
    if (parent == null) {
      throw new IOException("Generated output manifest must have a parent directory: " + manifest);
    }
    Files.createDirectories(parent);
    JSON.writeValue(manifest.toFile(), document);
  }

  static void writeStage(
      final Path stage, final Collection<Path> generated, final Map<Path, Path> stagedByTarget)
      throws IOException {
    final ArrayNode outputs = JSON.createArrayNode();
    for (final Path path : generated) {
      final Path absolute = path.toAbsolutePath().normalize();
      final Path staged = stagedByTarget.get(absolute);
      if (staged == null || !Files.isRegularFile(staged)) {
        throw new IOException("Generated output has no staged file: " + absolute);
      }
      final ObjectNode output = outputs.addObject();
      output.put("path", absolute.toString());
      output.put("sha256", ArtifactFileDigest.sha256(staged));
    }
    final ObjectNode document = JSON.createObjectNode();
    document.set("outputs", outputs);
    final Path parent = stage.getParent();
    if (parent == null) {
      throw new IOException("Generated output manifest stage must have a parent: " + stage);
    }
    Files.createDirectories(parent);
    JSON.writeValue(stage.toFile(), document);
  }

  static Optional<String> unchangedOwnedOutputDigest(final Path manifest, final Path target)
      throws IOException {
    if (MavenPreconditionOutputState.definitelyAbsent(manifest)) {
      return Optional.empty();
    }
    if (!Files.isRegularFile(manifest)) {
      return Optional.empty();
    }
    final Path normalizedTarget = target.toAbsolutePath().normalize();
    final Set<Path> seen = new HashSet<>();
    Optional<String> matchingDigest = Optional.empty();
    for (final JsonNode output : readOutputs(manifest)) {
      final Path path = MavenGeneratedOutputEntry.outputPath(output, manifest);
      final String digest = MavenGeneratedOutputEntry.outputDigest(output, manifest);
      if (!seen.add(path)) {
        throw new IOException("Duplicate generated output manifest path: " + path);
      }
      if (normalizedTarget.equals(path)) {
        final boolean unchanged =
            MavenGeneratedOutputEntry.matches(output, normalizedTarget, manifest);
        if (unchanged) {
          matchingDigest = Optional.of(digest);
        }
      }
    }
    return matchingDigest;
  }

  private static Set<Path> allowedPaths(final Collection<Path> paths) {
    return paths.stream()
        .map(path -> path.toAbsolutePath().normalize())
        .collect(Collectors.toSet());
  }

  private static void clearEntries(
      final JsonNode outputs, final Set<Path> allowed, final Path manifest) throws IOException {
    for (final JsonNode output : outputs) {
      MavenGeneratedOutputEntry.clear(output, allowed, manifest);
    }
  }

  private static JsonNode readOutputs(final Path manifest) throws IOException {
    final JsonNode document;
    try (JsonParser parser = JSON.getFactory().createParser(Files.newInputStream(manifest))) {
      document = JSON.readTree(parser);
      if (parser.nextToken() != null) {
        throw new IOException("Trailing data in dependency elider output manifest: " + manifest);
      }
    }
    final JsonNode outputs = document == null ? null : document.get("outputs");
    if (document == null || !document.isObject() || outputs == null || !outputs.isArray()) {
      throw new IOException("Malformed dependency elider output ownership manifest: " + manifest);
    }
    MavenGeneratedOutputEntry.validateFields(document, Set.of("outputs"), manifest);
    return outputs;
  }
}
