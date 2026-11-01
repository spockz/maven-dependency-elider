// WHY: Rejects workspace/unknown resolver origins and gives accepted sources stable provenance.

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.nio.file.Path;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.repository.ArtifactRepository;
import org.eclipse.aether.repository.LocalRepository;
import org.eclipse.aether.repository.LocalRepositoryManager;
import org.eclipse.aether.repository.RemoteRepository;
import org.eclipse.aether.repository.WorkspaceRepository;
import org.eclipse.aether.resolution.ArtifactResult;

/** Names the repository origin of one resolved Maven source artifact. */
final class SourceRepositoryOrigin {
  private SourceRepositoryOrigin() {}

  @SuppressWarnings("PMD.LawOfDemeter") // Resolver's repository type is encoded in its result.
  /* default */ static String identify(
      final ArtifactResult result, final RepositorySystemSession session, final Path artifact)
      throws IOException {
    final ArtifactRepository repository = result.getRepository();
    if (repository instanceof WorkspaceRepository) {
      throw new IOException("Maven workspace sources are not accepted as repository artifacts");
    }
    if (repository instanceof RemoteRepository remote) {
      return remote(remote);
    }
    if (repository instanceof LocalRepository local) {
      return local(local, session, artifact);
    }
    if (repository == null) {
      return local(configuredLocal(session), session, artifact);
    }
    throw new IOException("Maven source artifact has unknown repository provenance");
  }

  private static String remote(final RemoteRepository repository) throws IOException {
    if (repository.getId() == null
        || repository.getId().isBlank()
        || repository.getUrl() == null
        || repository.getUrl().isBlank()) {
      throw new IOException("Maven remote source repository identity is incomplete");
    }
    return "remote:" + repository.getId() + "@" + repository.getUrl();
  }

  @SuppressWarnings(
      "PMD.LawOfDemeter") // Maven exposes its configured local repository via manager.
  private static LocalRepository configuredLocal(final RepositorySystemSession session)
      throws IOException {
    final LocalRepositoryManager manager = session.getLocalRepositoryManager();
    if (manager == null || manager.getRepository() == null) {
      throw new IOException("Maven local source repository provenance is unavailable");
    }
    return manager.getRepository();
  }

  @SuppressWarnings(
      "PMD.LawOfDemeter") // The artifact must be contained by Maven's configured repo.
  private static String local(
      final LocalRepository repository, final RepositorySystemSession session, final Path artifact)
      throws IOException {
    if (repository.getId() == null || repository.getId().isBlank()) {
      throw new IOException("Maven local source repository identity is incomplete");
    }
    final LocalRepository configured = configuredLocal(session);
    final Path root = configured.getBasedir().toPath().toRealPath();
    final Path resolved = artifact.toRealPath();
    if (!repository.getId().equals(configured.getId()) || !resolved.startsWith(root)) {
      throw new IOException("Resolved source artifact is outside the named local repository");
    }
    final String relative = root.relativize(resolved).toString().replace('\\', '/');
    return "local:" + repository.getId() + ":" + relative;
  }
}
