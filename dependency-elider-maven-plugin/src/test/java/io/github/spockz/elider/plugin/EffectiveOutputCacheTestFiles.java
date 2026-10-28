// WHY: Shares cache-path and manifest mutations across effective-output transaction tests.

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Stream;
import org.apache.maven.project.MavenProject;

/** Test-only access to cache records, manifests, and generation directories. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class EffectiveOutputCacheTestFiles {
  /** Codec for reading and writing test-owned cache manifests. */
  private static final ObjectMapper JSON = new ObjectMapper();

  private EffectiveOutputCacheTestFiles() {
    throw new AssertionError("No instances");
  }

  /** Finds the output record for a fixture artifact. */
  static ArtifactTrimRecord record(
      final List<ArtifactTrimRecord> records, final ArtifactCoordinate coordinate) {
    return records.stream()
        .filter(value -> value.coordinate().equals(coordinate))
        .findFirst()
        .orElseThrow();
  }

  /** Resolves the cache manifest path for a fixture project. */
  static Path cacheManifest(final MavenProject project) {
    return Path.of(
        project.getBuild().getDirectory(), "elided-artifacts", ".trim-analysis-cache.json");
  }

  /** Resolves the private output-generation directory for a fixture project. */
  static Path generationDirectory(final MavenProject project) {
    return Path.of(project.getBuild().getDirectory(), "elided-artifacts", ".generations");
  }

  /** Counts published generations for transaction assertions. */
  static long generationCount(final MavenProject project) throws IOException {
    try (Stream<Path> generations = Files.list(generationDirectory(project))) {
      return generations.count();
    }
  }

  /** Mutates the first manifest entry for cache invalidation tests. */
  static void mutateCacheEntry(
      final Path manifest, final java.util.function.Consumer<ObjectNode> mutation)
      throws IOException {
    final ObjectNode root = (ObjectNode) JSON.readTree(manifest.toFile());
    final ArrayNode entries = (ArrayNode) root.get("entries");
    mutation.accept((ObjectNode) entries.get(0));
    JSON.writeValue(manifest.toFile(), root);
  }

  /** Creates a structurally valid manifest root for malformed-shape cases. */
  static ObjectNode manifestNode(final String fingerprint) {
    final ObjectNode root = JSON.createObjectNode();
    root.put("fingerprint", fingerprint);
    root.putArray("entries");
    return root;
  }

  /** Writes a test-owned malformed or modified manifest root. */
  static void writeManifest(final Path manifest, final ObjectNode root) throws IOException {
    JSON.writeValue(manifest.toFile(), root);
  }
}
