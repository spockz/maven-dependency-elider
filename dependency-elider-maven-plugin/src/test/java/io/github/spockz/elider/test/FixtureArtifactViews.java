/* WHY: Captures project artifact identity and file provenance at lifecycle boundaries. */

package io.github.spockz.elider.test;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.project.MavenProject;

/** Writes the fixture's tab-separated snapshot. */
@SuppressWarnings({
  "PMD.AvoidSynchronizedStatement",
  "PMD.CommentDefaultAccessModifier",
  "PMD.LawOfDemeter",
  "PMD.UseConcurrentHashMap"
})
final class FixtureArtifactViews {
  /** Assigns unique per-process tokens to object references. */
  private static final Map<Object, Integer> IDENTITY_TOKENS = new IdentityHashMap<>();

  /** Supplies the next token for a previously unseen reference. */
  private static int nextIdentityToken = 1;

  private FixtureArtifactViews() {}

  static void write(
      final MavenProject project, final File directory, final String name, final String scope)
      throws IOException {
    final Path outputDirectory = directory.toPath();
    Files.createDirectories(outputDirectory);
    final List<String> lines = new ArrayList<>();
    lines.add("scope\t" + scope);
    lines.add(
        "project\t"
            + identityToken(project)
            + "\t"
            + project.getGroupId()
            + ":"
            + project.getArtifactId());
    append(lines, "DIRECT", project.getDependencyArtifacts());
    append(lines, "RESOLVED", project.getArtifacts());
    Files.write(outputDirectory.resolve(name + ".tsv"), lines);
  }

  private static void append(
      final List<String> lines, final String viewName, final Set<Artifact> artifacts)
      throws IOException {
    if (artifacts == null) {
      lines.add("view\t" + viewName + "\tmissing\t-1");
      return;
    }
    lines.add("view\t" + viewName + "\t" + identityToken(artifacts) + "\t" + artifacts.size());
    final List<Artifact> ordered = new ArrayList<>(artifacts);
    ordered.sort(Comparator.comparing(FixtureArtifactViews::coordinate));
    for (final Artifact artifact : ordered) {
      final File file = artifact.getFile();
      final Path path = file == null ? null : file.toPath().toAbsolutePath().normalize();
      lines.add(
          "artifact\t"
              + viewName
              + "\t"
              + identityToken(artifact)
              + "\t"
              + coordinate(artifact)
              + "\t"
              + (path == null ? "<missing>" : encodePath(path))
              + "\t"
              + (path == null ? "<missing>" : sha256(path)));
    }
  }

  private static String coordinate(final Artifact artifact) {
    return artifact.getGroupId()
        + ":"
        + artifact.getArtifactId()
        + ":"
        + artifact.getVersion()
        + ":"
        + artifact.getType()
        + ":"
        + (artifact.getClassifier() == null ? "" : artifact.getClassifier());
  }

  private static String encodePath(final Path path) {
    return Base64.getEncoder().encodeToString(path.toString().getBytes(StandardCharsets.UTF_8));
  }

  private static int identityToken(final Object reference) {
    synchronized (IDENTITY_TOKENS) {
      return IDENTITY_TOKENS.computeIfAbsent(reference, ignored -> nextIdentityToken++);
    }
  }

  private static String sha256(final Path path) throws IOException {
    try {
      return HexFormat.of()
          .formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(path)));
    } catch (NoSuchAlgorithmException exception) {
      throw new IllegalStateException("Java runtime does not provide SHA-256", exception);
    }
  }
}
