// WHY: Carries allowed original test inputs from the plugin realm to the lifecycle extension.

package io.github.spockz.elider.plugin;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.project.MavenProject;

/** Immutable, classloader-neutral handoff for the opt-in Maven 3 test view. */
@SuppressWarnings({
  "PMD.AvoidLiteralsInIfCondition",
  "PMD.CommentDefaultAccessModifier",
  "PMD.CommentRequired",
  "PMD.CyclomaticComplexity",
  "PMD.GodClass",
  "PMD.LawOfDemeter"
})
final class EliderTestViewPlan {
  static final String ENABLE_PROPERTY = "elide.testCompilationView";
  static final String ADDITIONS_PROPERTY = "elide.testAdditionsJar";
  private static final String SESSION_KEY = "io.github.spockz.elider.test-compilation-view.v1";

  private EliderTestViewPlan() {}

  static boolean requested(final MavenSession session, final MavenProject project) {
    final String configured = property(session, project, ENABLE_PROPERTY);
    if (configured == null || "false".equalsIgnoreCase(configured)) {
      return false;
    }
    if ("true".equalsIgnoreCase(configured)) {
      return true;
    }
    throw new IllegalArgumentException(ENABLE_PROPERTY + " must be true or false");
  }

  static Prepared prepare(
      final MavenSession session, final MavenProject project, final boolean bansRequested)
      throws IOException {
    if (!requested(session, project)) {
      return null;
    }
    if (!MavenOriginalInputAudit.hookPresent(session)) {
      throw new IOException("Test compilation view requires the Elider core extension");
    }
    if (session.getProjects() == null || session.getProjects().size() != 1) {
      throw new IOException("Test compilation view currently requires one Maven project");
    }
    if (bansRequested) {
      throw new IOException(
          "Test compilation view with elide.banishedDependencies is not yet supported");
    }
    final String additions = additionPath(property(session, project, ADDITIONS_PROPERTY));
    final List<Map<String, String>> rows = new ArrayList<>();
    final Set<Identity> identities = new HashSet<>();
    for (final Artifact artifact : project.getArtifacts()) {
      final Descriptor descriptor = Descriptor.fromArtifact(artifact);
      if (!identities.add(descriptor.identity())) {
        throw new IOException("Ambiguous original test artifact: " + descriptor.identity());
      }
      rows.add(descriptor.toPayload());
    }
    return new Prepared(
        Map.of(
            "project", projectKey(project),
            "artifacts", List.copyOf(rows),
            "addition", additions));
  }

  static void publish(final MavenSession session, final Prepared prepared) throws IOException {
    if (session == null || session.getRepositorySession() == null) {
      throw new IOException("Cannot publish test compilation view without a resolver session");
    }
    session.getRepositorySession().getData().set(SESSION_KEY, prepared.payload());
  }

  static Plan read(final MavenSession session, final MavenProject project) {
    if (session == null || session.getRepositorySession() == null) {
      return null;
    }
    final Object value = session.getRepositorySession().getData().get(SESSION_KEY);
    if (value == null) {
      return null;
    }
    if (!(value instanceof Map<?, ?> payload)
        || !projectKey(project).equals(payload.get("project"))
        || !(payload.get("addition") instanceof String addition)
        || !(payload.get("artifacts") instanceof List<?> rows)) {
      throw new IllegalStateException("Malformed or mismatched test compilation view plan");
    }
    final List<Descriptor> descriptors = new ArrayList<>(rows.size());
    final Set<Identity> identities = new HashSet<>();
    for (final Object row : rows) {
      if (!(row instanceof Map<?, ?> fields)) {
        throw new IllegalStateException("Malformed test compilation artifact entry");
      }
      final Descriptor descriptor = Descriptor.fromPayload(fields);
      if (!identities.add(descriptor.identity())) {
        throw new IllegalStateException("Duplicate test compilation artifact entry");
      }
      descriptors.add(descriptor);
    }
    return new Plan(List.copyOf(descriptors), addition);
  }

  static void clear(final MavenSession session) {
    if (session != null && session.getRepositorySession() != null) {
      session.getRepositorySession().getData().set(SESSION_KEY, null);
    }
  }

  private static String additionPath(final String configured) throws IOException {
    if (configured == null || configured.isBlank()) {
      return "";
    }
    final Path path = Path.of(configured).toAbsolutePath().normalize();
    if (!path.toString().endsWith(".jar") || !Files.isRegularFile(path)) {
      throw new IOException("Test additions JAR is missing or invalid: " + path);
    }
    return path.toString();
  }

  private static String property(
      final MavenSession session, final MavenProject project, final String name) {
    final String user = session == null ? null : session.getUserProperties().getProperty(name);
    return user == null ? project.getProperties().getProperty(name) : user;
  }

  private static String projectKey(final MavenProject project) {
    if (project == null || project.getBasedir() == null) {
      throw new IllegalStateException("Test compilation view requires a project base directory");
    }
    return project.getBasedir().toPath().toAbsolutePath().normalize() + ":" + project.getId();
  }

  record Prepared(Map<String, Object> payload) {}

  record Plan(List<Descriptor> artifacts, String addition) {}

  record Identity(
      String groupId,
      String artifactId,
      String version,
      String type,
      String classifier,
      String scope) {
    static Identity of(final Artifact artifact) {
      return new Identity(
          artifact.getGroupId(),
          artifact.getArtifactId(),
          artifact.getVersion(),
          artifact.getType(),
          artifact.getClassifier() == null ? "" : artifact.getClassifier(),
          artifact.getScope() == null ? "" : artifact.getScope());
    }
  }

  record Descriptor(Identity identity, String path) {
    static Descriptor fromArtifact(final Artifact artifact) throws IOException {
      final File file = artifact.getFile();
      if (file == null || !Files.exists(file.toPath())) {
        throw new IOException("Original test artifact has no file: " + artifact.getId());
      }
      return new Descriptor(
          Identity.of(artifact), file.toPath().toAbsolutePath().normalize().toString());
    }

    Map<String, String> toPayload() {
      return Map.of(
          "groupId", identity.groupId(),
          "artifactId", identity.artifactId(),
          "version", identity.version(),
          "type", identity.type(),
          "classifier", identity.classifier(),
          "scope", identity.scope(),
          "path", path);
    }

    static Descriptor fromPayload(final Map<?, ?> fields) {
      return new Descriptor(
          new Identity(
              field(fields, "groupId"),
              field(fields, "artifactId"),
              field(fields, "version"),
              field(fields, "type"),
              field(fields, "classifier"),
              field(fields, "scope")),
          field(fields, "path"));
    }

    private static String field(final Map<?, ?> fields, final String name) {
      if (!(fields.get(name) instanceof String value)) {
        throw new IllegalStateException("Malformed test compilation artifact " + name);
      }
      return value;
    }
  }
}
