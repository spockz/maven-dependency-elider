// WHY: Carries validated retained-JAR paths into Maven's live dependency-resolution requests.

package io.github.spockz.elider.plugin;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.inject.Named;
import javax.inject.Singleton;
import org.apache.maven.model.Model;
import org.apache.maven.project.MavenProject;
import org.apache.maven.project.RepositorySessionDecorator;
import org.apache.maven.repository.internal.MavenWorkspaceReader;
import org.eclipse.aether.DefaultRepositorySystemSession;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.artifact.Artifact;
import org.eclipse.aether.repository.WorkspaceReader;
import org.eclipse.aether.repository.WorkspaceRepository;
import org.eclipse.sisu.Priority;

/** Supplies validated trim outputs to later project resolution. */
@SuppressWarnings("PMD.LawOfDemeter")
@Named("elider-retained-artifact-session")
@Priority(10)
@Singleton
public final class EliderRepositorySessionDecorator implements RepositorySessionDecorator {
  /** Workspace identity used only if Maven has no prior reader. */
  private static final WorkspaceRepository EMPTY_REPOSITORY =
      new WorkspaceRepository("elider-retained-artifact-plan");

  /** Creates the indexed production session decorator. */
  public EliderRepositorySessionDecorator() {
    super();
  }

  @Override
  public RepositorySystemSession decorate(
      final MavenProject project, final RepositorySystemSession session) {
    if (project == null || project.getBasedir() == null || session == null) {
      return session;
    }
    final ResolverArtifactPlan.ProjectIdentity projectIdentity =
        new ResolverArtifactPlan.ProjectIdentity(
            project.getBasedir().toPath(),
            project.getGroupId(),
            project.getArtifactId(),
            project.getVersion());
    final Object payload = session.getData().get(ResolverArtifactPlanPublisher.SESSION_DATA_KEY);
    final ResolverArtifactPlan plan =
        ResolverArtifactPlanStore.fromPayload(payload).find(projectIdentity);
    if (plan == null || plan.replacements().isEmpty()) {
      return session;
    }
    plan.replacements()
        .values()
        .forEach(
            replacement -> {
              if (!Files.isRegularFile(replacement.path())) {
                throw new IllegalStateException(
                    "Planned retained artifact file is missing: " + replacement.path());
              }
            });
    final WorkspaceReader reader =
        new PlannedWorkspaceReader(session.getWorkspaceReader(), plan.replacements());
    return new DefaultRepositorySystemSession(session).setWorkspaceReader(reader);
  }

  /** Overrides exact planned artifacts and delegates every other lookup. */
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  static final class PlannedWorkspaceReader implements MavenWorkspaceReader {
    /** Previously configured workspace reader. */
    private final WorkspaceReader delegate;

    /** Exact artifact identities and validated replacement metadata. */
    private final Map<ResolverArtifactPlan.ArtifactIdentity, ResolverArtifactPlan.Replacement>
        replacements;

    /** Creates a reader over the currently configured Maven workspace. */
    PlannedWorkspaceReader(
        final WorkspaceReader delegate,
        final Map<ResolverArtifactPlan.ArtifactIdentity, ResolverArtifactPlan.Replacement>
            replacements) {
      this.delegate = delegate;
      this.replacements = replacements;
    }

    @Override
    public WorkspaceRepository getRepository() {
      return workspaceRepository();
    }

    @Override
    public Model findModel(final Artifact artifact) {
      return delegate instanceof MavenWorkspaceReader mavenReader
          ? mavenReader.findModel(artifact)
          : null;
    }

    @Override
    public File findArtifact(final Artifact artifact) {
      final ResolverArtifactPlan.Replacement replacement = replacements.get(identityOf(artifact));
      if (replacement != null) {
        verifyReplacement(replacement);
        return replacement.path().toFile();
      }
      return delegate == null ? null : delegate.findArtifact(artifact);
    }

    @Override
    public List<String> findVersions(final Artifact artifact) {
      final Set<String> versions = new LinkedHashSet<>();
      if (delegate != null) {
        versions.addAll(delegate.findVersions(artifact));
      }
      for (final ResolverArtifactPlan.ArtifactIdentity identity : replacements.keySet()) {
        if (identity.hasFamily(
            artifact.getGroupId(),
            artifact.getArtifactId(),
            artifact.getExtension(),
            artifact.getClassifier() == null ? "" : artifact.getClassifier())) {
          versions.add(identity.version());
        }
      }
      return List.copyOf(versions);
    }

    private static ResolverArtifactPlan.ArtifactIdentity identityOf(final Artifact artifact) {
      return new ResolverArtifactPlan.ArtifactIdentity(
          artifact.getGroupId(),
          artifact.getArtifactId(),
          artifact.getVersion(),
          artifact.getExtension(),
          artifact.getClassifier() == null ? "" : artifact.getClassifier());
    }

    private WorkspaceRepository workspaceRepository() {
      return delegate == null ? EMPTY_REPOSITORY : delegate.getRepository();
    }

    private static void verifyReplacement(final ResolverArtifactPlan.Replacement replacement) {
      try {
        if (!Files.isRegularFile(replacement.path())
            || !replacement.sha256().equals(ArtifactFileDigest.sha256(replacement.path()))) {
          throw new IllegalStateException(
              "Planned retained artifact changed after validation: " + replacement.path());
        }
      } catch (final IOException exception) {
        throw new IllegalStateException(
            "Cannot verify planned retained artifact: " + replacement.path(), exception);
      }
    }
  }
}
