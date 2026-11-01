// WHY: Verifies audit isolation through a packaged lifecycle probe.

package io.github.spockz.elider.test;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import javax.inject.Inject;
import javax.inject.Named;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.plugins.annotations.ResolutionScope;
import org.apache.maven.project.DefaultDependencyResolutionRequest;
import org.apache.maven.project.DependencyResolutionException;
import org.apache.maven.project.DependencyResolutionResult;
import org.apache.maven.project.MavenProject;
import org.apache.maven.project.ProjectDependenciesResolver;
import org.eclipse.aether.DefaultRepositorySystemSession;
import org.eclipse.aether.DefaultSessionData;
import org.eclipse.aether.RepositorySystemSession;

/** Runs an isolated Resolver audit request. */
@SuppressWarnings({"PMD.AtLeastOneConstructor", "PMD.CommentRequired", "PMD.LawOfDemeter"})
@Mojo(name = "audit-inventory", requiresDependencyResolution = ResolutionScope.TEST)
public final class MavenOriginalInputAuditProbeMojo extends AbstractMojo {
  private static final String AUDIT_MODE_CONFIG_KEY =
      "io.github.spockz.elider.plugin.MavenOriginalInputAudit.auditMode";
  private static final String CAPTURE_STORE_KEY =
      "io.github.spockz.elider.plugin.BanishedDependencyLifecycleActivation.captureStore";
  private static final String GRAPH_STORE_KEY =
      "io.github.spockz.elider.resolver.graph-snapshots.v1";
  private static final String PLAN_STORE_KEY = "io.github.spockz.elider.resolver.artifact-plans.v1";

  @Parameter(defaultValue = "${project}", readonly = true, required = true)
  private MavenProject project;

  @Parameter(defaultValue = "${session}", readonly = true, required = true)
  private MavenSession session;

  @Parameter(property = "audit.inventory.reportFile", required = true)
  private File reportFile;

  @Inject
  @Named("default")
  private ProjectDependenciesResolver resolver;

  @Override
  public void execute() throws MojoExecutionException {
    try {
      executeProbe();
    } catch (final DependencyResolutionException | IOException exception) {
      throw new MojoExecutionException("Cannot verify the original-input audit result", exception);
    }
  }

  private void executeProbe()
      throws DependencyResolutionException, IOException, MojoExecutionException {
    if (project == null || session == null || resolver == null || reportFile == null) {
      throw new MojoExecutionException("Original-input audit probe is missing Maven components");
    }
    final RepositorySystemSession liveSession = liveSession();
    final LiveState before = LiveState.capture(project, liveSession);
    final MavenProject auditProject = new MavenProject(project);
    auditProject.setDependencyArtifacts(null);
    auditProject.setResolvedArtifacts(Set.of());
    auditProject.setArtifactFilter(null);
    auditProject.setManagedVersionMap(null);
    final DependencyResolutionResult result = resolveAuditMode(auditProject, liveSession);
    validateResult(result);
    before.verifyUnchanged(project, liveSession);
    writeInventory(result, before.resolved(), before.direct());
  }

  private RepositorySystemSession liveSession() throws IOException {
    final RepositorySystemSession liveSession = session.getRepositorySession();
    if (liveSession == null || liveSession.getData() == null) {
      throw new IOException("Audit-mode probe requires the live Resolver session data");
    }
    return liveSession;
  }

  @SuppressWarnings("PMD.UseConcurrentHashMap")
  private DependencyResolutionResult resolveAuditMode(
      final MavenProject auditProject, final RepositorySystemSession liveSession)
      throws DependencyResolutionException {
    final DefaultRepositorySystemSession auditSession =
        new DefaultRepositorySystemSession(liveSession);
    auditSession.setData(new DefaultSessionData());
    final Map<String, Object> config = new HashMap<>(liveSession.getConfigProperties());
    config.put(AUDIT_MODE_CONFIG_KEY, Boolean.TRUE);
    auditSession.setConfigProperties(config);
    return resolver.resolve(new DefaultDependencyResolutionRequest(auditProject, auditSession));
  }

  private static void validateResult(final DependencyResolutionResult result) throws IOException {
    if (result == null
        || result.getDependencyGraph() == null
        || result.getCollectionErrors() == null
        || result.getUnresolvedDependencies() == null
        || result.getResolvedDependencies() == null
        || !result.getCollectionErrors().isEmpty()
        || !result.getUnresolvedDependencies().isEmpty()) {
      throw new IOException("Audit-mode resolver returned an incomplete dependency result");
    }
  }

  private static List<String> liveResolved(final MavenProject project) {
    return project.getArtifacts().stream()
        .map(MavenOriginalInputAuditProbeMojo::coordinate)
        .sorted()
        .toList();
  }

  @SuppressWarnings("PMD.CompareObjectsWithEquals")
  private static boolean sameReference(final Object first, final Object second) {
    return first == second;
  }

  private static List<String> liveDirect(final MavenProject project) {
    return project.getDependencyArtifacts() == null
        ? List.of()
        : project.getDependencyArtifacts().stream()
            .map(MavenOriginalInputAuditProbeMojo::coordinate)
            .sorted()
            .toList();
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

  private void writeInventory(
      final DependencyResolutionResult result,
      final List<String> liveResolved,
      final List<String> liveDirect)
      throws IOException {
    final List<String> lines = new ArrayList<>();
    lines.add("state\tunchanged");
    liveResolved.forEach(value -> lines.add("live-resolved\t" + value));
    liveDirect.forEach(value -> lines.add("live-direct\t" + value));
    result.getResolvedDependencies().stream()
        .map(org.eclipse.aether.graph.Dependency::getArtifact)
        .filter(Objects::nonNull)
        .map(artifact -> artifact.getGroupId() + ":" + artifact.getArtifactId())
        .sorted()
        .forEach(value -> lines.add("audit-resolved\t" + value));
    result.getDependencyGraph().getChildren().stream()
        .map(org.eclipse.aether.graph.DependencyNode::getArtifact)
        .filter(Objects::nonNull)
        .map(artifact -> artifact.getGroupId() + ":" + artifact.getArtifactId())
        .sorted()
        .forEach(value -> lines.add("audit-direct\t" + value));
    if (reportFile.toPath().getParent() != null) {
      Files.createDirectories(reportFile.toPath().getParent());
    }
    Files.write(reportFile.toPath(), lines);
  }

  private record LiveState(
      List<String> resolved,
      List<String> direct,
      boolean directViewPresent,
      Object capture,
      Object graph,
      Object plan) {
    private static LiveState capture(
        final MavenProject project, final RepositorySystemSession session) {
      return new LiveState(
          liveResolved(project),
          liveDirect(project),
          project.getDependencyArtifacts() != null,
          session.getData().get(CAPTURE_STORE_KEY),
          session.getData().get(GRAPH_STORE_KEY),
          session.getData().get(PLAN_STORE_KEY));
    }

    private void verifyUnchanged(final MavenProject project, final RepositorySystemSession session)
        throws IOException {
      if (!resolved.equals(liveResolved(project))
          || !direct.equals(liveDirect(project))
          || directViewPresent != Objects.nonNull(project.getDependencyArtifacts())
          || !sameReference(capture, session.getData().get(CAPTURE_STORE_KEY))
          || !sameReference(graph, session.getData().get(GRAPH_STORE_KEY))
          || !sameReference(plan, session.getData().get(PLAN_STORE_KEY))) {
        throw new IOException("Audit-mode resolver request changed live views or shared state");
      }
    }
  }
}
