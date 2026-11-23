// WHY: Prevents a later goal from preparing additions from stale test output in another Maven
// invocation.

package io.github.spockz.elider.plugin;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Optional;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.MojoExecution;
import org.apache.maven.project.MavenProject;

/** Session-local proof that the scoped test compiler callback completed. */
@SuppressWarnings({
  "PMD.AvoidDuplicateLiterals",
  "PMD.CommentDefaultAccessModifier",
  "PMD.CommentRequired",
  "PMD.LawOfDemeter"
})
final class EliderTestCompilationEvidence {
  private static final String KEY = "io.github.spockz.elider.test-compiler-completed.v1";
  private static final String CLEAN_KEY = "io.github.spockz.elider.test-view-clean.v1";
  private static final String PREPARED_KEY = "io.github.spockz.elider.test-view-prepared.v1";

  private EliderTestCompilationEvidence() {}

  static void complete(
      final MavenSession session, final MavenProject project, final MojoExecution execution) {
    session
        .getRepositorySession()
        .getData()
        .set(
            KEY,
            Map.of(
                "project",
                projectKey(project),
                "compilerVersion",
                String.valueOf(execution.getVersion()),
                "executionId",
                String.valueOf(execution.getExecutionId()),
                "configuration",
                String.valueOf(execution.getConfiguration())));
  }

  static void require(final MavenSession session, final MavenProject project) {
    final Object value = session.getRepositorySession().getData().get(KEY);
    if (!(value instanceof Map<?, ?> payload)
        || !projectKey(project).equals(payload.get("project"))) {
      throw new IllegalStateException(
          "Test additions require successful test compilation in this Maven invocation");
    }
  }

  static String compilerConfiguration(final MavenSession session, final MavenProject project) {
    require(session, project);
    final Map<?, ?> payload = (Map<?, ?>) session.getRepositorySession().getData().get(KEY);
    return payload.get("compilerVersion")
        + "\n"
        + payload.get("executionId")
        + "\n"
        + payload.get("configuration");
  }

  static void clear(final MavenSession session) {
    session.getRepositorySession().getData().set(KEY, null);
    session.getRepositorySession().getData().set(PREPARED_KEY, null);
  }

  static void markClean(final MavenSession session, final MavenProject project) {
    final boolean cleared =
        project.getBuild() != null
            && outputCleared(project, project.getBuild().getOutputDirectory())
            && outputCleared(project, project.getBuild().getTestOutputDirectory());
    session.getRepositorySession().getData().set(CLEAN_KEY, cleared ? projectKey(project) : null);
  }

  private static boolean outputCleared(final MavenProject project, final String outputDirectory) {
    if (outputDirectory == null || outputDirectory.isBlank()) {
      return false;
    }
    final Path output = Path.of(outputDirectory);
    final Path resolved =
        output.isAbsolute() ? output : project.getBasedir().toPath().resolve(output);
    return Files.notExists(resolved);
  }

  static boolean cleaned(final MavenSession session, final MavenProject project) {
    return projectKey(project).equals(session.getRepositorySession().getData().get(CLEAN_KEY));
  }

  static void prepared(
      final MavenSession session, final MavenProject project, final Optional<Path> addition) {
    session
        .getRepositorySession()
        .getData()
        .set(
            PREPARED_KEY,
            Map.of(
                "project", projectKey(project), "path", addition.map(Path::toString).orElse("")));
  }

  static Optional<Path> expectedAddition(final MavenSession session, final MavenProject project) {
    final Object value = session.getRepositorySession().getData().get(PREPARED_KEY);
    if (!(value instanceof Map<?, ?> payload)
        || !projectKey(project).equals(payload.get("project"))
        || !(payload.get("path") instanceof String path)) {
      throw new IllegalStateException("Test additions preparation has no matching result");
    }
    return path.isEmpty() ? Optional.empty() : Optional.of(Path.of(path));
  }

  private static String projectKey(final MavenProject project) {
    return project.getBasedir().toPath().toAbsolutePath().normalize() + ":" + project.getId();
  }
}
