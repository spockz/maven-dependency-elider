/* WHY: Writes request-local resolver graph and artifact evidence for packaged lifecycle tests. */

package io.github.spockz.elider.test;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.eclipse.aether.artifact.Artifact;
import org.eclipse.aether.graph.Dependency;
import org.eclipse.aether.graph.DependencyNode;

/** Serializes independent TEST resolution results and artifact evidence. */
@SuppressWarnings({"PMD.CommentDefaultAccessModifier", "PMD.LawOfDemeter"})
final class FixtureResolvedGraphSnapshot {
  private FixtureResolvedGraphSnapshot() {}

  @SuppressWarnings("PMD.UseConcurrentHashMap") // Resolver nodes are identity-distinct occurrences.
  static void writeGraph(final File reportDirectory, final DependencyNode root) throws IOException {
    final List<String> lines = new ArrayList<>();
    lines.add("schema\t1");
    if (root == null) {
      lines.add("root\tmissing");
      writeLines(reportDirectory, "explicit-test-resolver", lines);
      return;
    }
    final Map<DependencyNode, String> ids = new IdentityHashMap<>();
    final Set<DependencyNode> seen = Collections.newSetFromMap(new IdentityHashMap<>());
    final Deque<DependencyNode> queue = new ArrayDeque<>();
    ids.put(root, "n0");
    seen.add(root);
    queue.add(root);
    while (!queue.isEmpty()) {
      final DependencyNode parent = queue.removeFirst();
      final List<DependencyNode> children = parent.getChildren();
      if (children == null) {
        throw new IOException("Explicit TEST resolver graph has incomplete children");
      }
      for (final DependencyNode child : children) {
        if (child == null) {
          throw new IOException("Explicit TEST resolver graph has a null child");
        }
        final String childId = ids.computeIfAbsent(child, ignored -> "n" + ids.size());
        lines.add("edge\t" + ids.get(parent) + "\t" + childId);
        if (seen.add(child)) {
          queue.addLast(child);
        }
      }
    }
    appendNodes(lines, ids);
    writeLines(reportDirectory, "explicit-test-resolver", lines);
  }

  static void writeDependencies(final File reportDirectory, final List<Dependency> dependencies)
      throws IOException {
    final List<String> lines = new ArrayList<>();
    lines.add("schema\t1");
    for (final Dependency dependency : dependencies) {
      final Artifact artifact = dependency.getArtifact();
      final File file = artifact.getFile();
      if (file == null) {
        throw new IOException(
            "Resolved TEST dependency has no artifact file: " + coordinate(artifact));
      }
      final Path path = file.toPath().toAbsolutePath().normalize();
      if (!Files.isRegularFile(path)) {
        throw new IOException("Resolved TEST dependency is not a file: " + path);
      }
      lines.add(
          "resolved-dependency\t"
              + coordinate(artifact)
              + "\t"
              + encode(path.toString())
              + "\t"
              + sha256(path));
    }
    writeLines(reportDirectory, "explicit-test-resolved-dependencies", lines);
  }

  private static void appendNodes(final List<String> lines, final Map<DependencyNode, String> ids)
      throws IOException {
    final List<Map.Entry<DependencyNode, String>> orderedNodes =
        ids.entrySet().stream().sorted(Map.Entry.comparingByValue()).toList();
    for (final Map.Entry<DependencyNode, String> entry : orderedNodes) {
      final DependencyNode node = entry.getKey();
      lines.add("node\t" + entry.getValue() + "\t" + coordinate(node));
      appendResolvedArtifact(lines, entry.getValue(), node);
    }
  }

  private static void appendResolvedArtifact(
      final List<String> lines, final String nodeId, final DependencyNode node) throws IOException {
    final File file = node.getArtifact().getFile();
    if (file == null) {
      return;
    }
    final Path path = file.toPath().toAbsolutePath().normalize();
    if (!Files.isRegularFile(path)) {
      throw new IOException("Resolved TEST artifact is not a file: " + path);
    }
    lines.add(
        "resolved-artifact\t"
            + nodeId
            + "\t"
            + coordinate(node)
            + "\t"
            + encode(path.toString())
            + "\t"
            + sha256(path));
  }

  private static String encode(final String value) {
    return java.util.Base64.getUrlEncoder()
        .withoutPadding()
        .encodeToString(value.getBytes(java.nio.charset.StandardCharsets.UTF_8));
  }

  private static String sha256(final Path path) throws IOException {
    try {
      final MessageDigest digest = MessageDigest.getInstance("SHA-256");
      try (InputStream input = Files.newInputStream(path)) {
        final byte[] buffer = new byte[8192];
        int count = input.read(buffer);
        while (count >= 0) {
          digest.update(buffer, 0, count);
          count = input.read(buffer);
        }
      }
      return java.util.HexFormat.of().formatHex(digest.digest());
    } catch (final NoSuchAlgorithmException exception) {
      throw new AssertionError("SHA-256 is unavailable", exception);
    }
  }

  private static String coordinate(final DependencyNode node) {
    return coordinate(node.getArtifact());
  }

  private static String coordinate(final Artifact artifact) {
    return artifact.getGroupId()
        + ":"
        + artifact.getArtifactId()
        + ":"
        + artifact.getVersion()
        + ":"
        + artifact.getExtension()
        + ":"
        + artifact.getClassifier();
  }

  private static void writeLines(final File directory, final String mode, final List<String> lines)
      throws IOException {
    Files.createDirectories(directory.toPath());
    Files.write(directory.toPath().resolve("graph-" + mode + ".tsv"), lines);
  }
}
