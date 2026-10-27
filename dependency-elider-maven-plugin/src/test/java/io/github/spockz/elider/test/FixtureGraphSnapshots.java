/* WHY: Writes test-only evidence for packaged mediated-graph capture across lifecycle requests. */

package io.github.spockz.elider.test;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.project.MavenProject;
import org.eclipse.aether.RepositorySystemSession;

/** Extracts only JDK payload fields needed by the packaged lifecycle assertions. */
@SuppressWarnings({"PMD.CommentDefaultAccessModifier", "PMD.CommentRequired", "PMD.LawOfDemeter"})
final class FixtureGraphSnapshots {
  private static final String GRAPH_SNAPSHOT_KEY =
      "io.github.spockz.elider.resolver.graph-snapshots.v1";

  private FixtureGraphSnapshots() {}

  static void write(
      final MavenSession session,
      final MavenProject project,
      final File reportDirectory,
      final String mode)
      throws IOException {
    final RepositorySystemSession repositorySession = session.getRepositorySession();
    final Object payload = repositorySession.getData().get(GRAPH_SNAPSHOT_KEY);
    final List<String> lines = new ArrayList<>();
    lines.add("schema\t1");
    if (!(payload instanceof Map<?, ?> store)) {
      lines.add("missing\ttrue");
      writeLines(reportDirectory, mode, lines);
      return;
    }
    final String projectKey = projectKey(project);
    int captureIndex = 0;
    for (final Object snapshotValue : projectSnapshots(store, projectKey)) {
      if (!(snapshotValue instanceof Map<?, ?> snapshot)) {
        throw new IOException("Graph snapshot entry is not a map");
      }
      appendSnapshot(lines, snapshot, captureIndex);
      captureIndex++;
    }
    writeLines(reportDirectory, mode, lines);
  }

  private static List<?> projectSnapshots(final Map<?, ?> store, final String projectKey)
      throws IOException {
    final Object snapshotsValue = store.get("snapshots");
    if (!(snapshotsValue instanceof Map<?, ?> projects)) {
      throw new IOException("Graph snapshot store has invalid projects payload");
    }
    final Object projectValues = projects.get(projectKey);
    if (projectValues == null) {
      return List.of();
    }
    if (projectValues instanceof List<?> values) {
      return values;
    }
    throw new IOException("Project graph snapshots are not a list");
  }

  private static String projectKey(final MavenProject project) {
    return List.of(
            project.getBasedir().toPath().toAbsolutePath().normalize().toString(),
            project.getGroupId(),
            project.getArtifactId(),
            project.getVersion())
        .stream()
        .map(
            value ->
                java.util.Base64.getUrlEncoder()
                    .withoutPadding()
                    .encodeToString(value.getBytes(java.nio.charset.StandardCharsets.UTF_8)))
        .collect(java.util.stream.Collectors.joining("."));
  }

  private static void appendSnapshot(
      final List<String> lines, final Map<?, ?> snapshot, final int captureIndex)
      throws IOException {
    final Object nodesValue = snapshot.get("nodes");
    if (!(nodesValue instanceof List<?> nodes)) {
      throw new IOException("Graph snapshot nodes are not a list");
    }
    lines.add(
        "snapshot\t"
            + captureIndex
            + "\t"
            + snapshot.get("planPresent")
            + "\t"
            + value(snapshot.get("planFingerprint"))
            + "\t"
            + snapshot.get("planGeneration")
            + "\t"
            + snapshot.get("captureGeneration")
            + "\t"
            + snapshot.get("graphFingerprint"));
    for (final Object nodeValue : nodes) {
      if (!(nodeValue instanceof Map<?, ?> node)) {
        throw new IOException("Graph snapshot node is not a map");
      }
      appendNode(lines, node, captureIndex);
    }
  }

  private static void appendNode(
      final List<String> lines, final Map<?, ?> node, final int captureIndex) {
    final Object artifactValue = node.get("artifact");
    if (artifactValue instanceof Map<?, ?> artifact && Boolean.TRUE.equals(node.get("reachable"))) {
      lines.add("node\t" + captureIndex + "\t" + node.get("id") + "\t" + coordinate(artifact));
    }
  }

  private static String coordinate(final Map<?, ?> artifact) {
    return artifact.get("groupId")
        + ":"
        + artifact.get("artifactId")
        + ":"
        + artifact.get("version")
        + ":"
        + artifact.get("extension")
        + ":"
        + artifact.get("classifier");
  }

  private static String value(final Object value) {
    return value == null ? "<absent>" : value.toString();
  }

  private static void writeLines(final File directory, final String mode, final List<String> lines)
      throws IOException {
    Files.createDirectories(directory.toPath());
    Files.write(directory.toPath().resolve("graph-" + mode + ".tsv"), lines);
  }
}
