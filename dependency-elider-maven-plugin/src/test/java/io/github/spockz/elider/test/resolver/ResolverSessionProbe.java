/* WHY: Tests whether Maven lifecycle resolution can use a planned workspace artifact. */

package io.github.spockz.elider.test.resolver;

import java.io.File;
import java.util.List;
import javax.inject.Named;
import javax.inject.Singleton;
import org.apache.maven.project.MavenProject;
import org.apache.maven.project.RepositorySessionDecorator;
import org.eclipse.aether.DefaultRepositorySystemSession;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.artifact.Artifact;
import org.eclipse.aether.repository.WorkspaceReader;
import org.eclipse.aether.repository.WorkspaceRepository;
import org.eclipse.sisu.Priority;

/** Decorates only the fixture consumer's planned keep-library workspace resolution. */
@SuppressWarnings({
  "PMD.AtLeastOneConstructor",
  "PMD.CompareObjectsWithEquals",
  "PMD.CommentDefaultAccessModifier",
  "PMD.CommentRequired",
  "PMD.LawOfDemeter",
  "PMD.SystemPrintln"
})
@Named("resolver-probe-session")
@Priority(10)
@Singleton
public final class ResolverSessionProbe implements RepositorySessionDecorator {
  // Package access shares the plan key between the helper Mojo and this decorator.
  static final String PLAN_KEY = "io.github.spockz.elider.test.resolver.workspace-plan";

  private static final String PROJECT_ARTIFACT = "lifecycle-probe-consumer";

  private static final String KEEP_GROUP = "io.github.spockz.elider.test";

  private static final String KEEP_ARTIFACT = "keep-library";

  private static final String KEEP_VERSION = "1.0.0";

  private static final String KEEP_EXTENSION = "jar";

  @Override
  public RepositorySystemSession decorate(
      final MavenProject project, final RepositorySystemSession session) {
    if (!PROJECT_ARTIFACT.equals(project.getArtifact().getArtifactId())) {
      return session;
    }
    final Object token = session.getData().get(ResolverRequestTokens.REQUEST_TOKEN_KEY);
    session.getData().set(ResolverRequestTokens.REQUEST_TOKEN_KEY, null);
    final Object plan = session.getData().get(PLAN_KEY);
    System.out.println(
        "SESSION_DECORATOR requestToken="
            + token
            + " project="
            + PROJECT_ARTIFACT
            + " plan="
            + (plan == null ? "none" : "keep-library")
            + " inputWorkspaceReader="
            + (session.getWorkspaceReader() == null
                ? "none"
                : session.getWorkspaceReader().getClass().getName()));
    if (!(plan instanceof String filePath)) {
      return session;
    }
    final WorkspaceReader reader =
        new PlannedWorkspaceReader(session.getWorkspaceReader(), filePath, token);
    final DefaultRepositorySystemSession decoratedSession =
        new DefaultRepositorySystemSession(session).setWorkspaceReader(reader);
    System.out.println(
        "SESSION_COPY requestToken=" + token + " copied=" + (decoratedSession != session));
    return decoratedSession;
  }

  /** Overrides one artifact and delegates the rest. */
  public static final class PlannedWorkspaceReader implements WorkspaceReader {
    private final WorkspaceReader delegate;

    private final File replacementFile;

    private final Object requestToken;

    private final WorkspaceRepository repository = new WorkspaceRepository("resolver-probe");

    /** Creates a planned artifact reader. */
    public PlannedWorkspaceReader(
        final WorkspaceReader delegate, final String replacementFile, final Object requestToken) {
      this.delegate = delegate;
      this.replacementFile = new File(replacementFile);
      this.requestToken = requestToken;
    }

    @Override
    public WorkspaceRepository getRepository() {
      return delegate == null ? repository : delegate.getRepository();
    }

    @Override
    public File findArtifact(final Artifact artifact) {
      if (isPlannedArtifact(artifact)) {
        System.out.println(
            "WORKSPACE_LOOKUP requestToken="
                + requestToken
                + " artifact="
                + coordinate(artifact)
                + " file="
                + replacementFile);
        return replacementFile;
      }
      return delegate == null ? null : delegate.findArtifact(artifact);
    }

    @Override
    public List<String> findVersions(final Artifact artifact) {
      if (isPlannedArtifact(artifact)) {
        return List.of(KEEP_VERSION);
      }
      return delegate == null ? List.of() : delegate.findVersions(artifact);
    }

    private static boolean isPlannedArtifact(final Artifact artifact) {
      return KEEP_GROUP.equals(artifact.getGroupId())
          && KEEP_ARTIFACT.equals(artifact.getArtifactId())
          && KEEP_VERSION.equals(artifact.getVersion())
          && KEEP_EXTENSION.equals(artifact.getExtension())
          && (artifact.getClassifier() == null || artifact.getClassifier().isEmpty());
    }

    private static String coordinate(final Artifact artifact) {
      return artifact.getGroupId()
          + ":"
          + artifact.getArtifactId()
          + ":"
          + artifact.getExtension()
          + ":"
          + artifact.getClassifier()
          + ":"
          + artifact.getVersion();
    }
  }
}
