// WHY: Verifies Maven source resolution cannot consume workspace artifacts or lose repository
// origin.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIOException;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.model.ArtifactCoordinate;
import java.io.IOException;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.apache.maven.execution.DefaultMavenExecutionRequest;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.project.MavenProject;
import org.eclipse.aether.DefaultRepositorySystemSession;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.repository.ArtifactRepository;
import org.eclipse.aether.repository.LocalRepository;
import org.eclipse.aether.repository.LocalRepositoryManager;
import org.eclipse.aether.repository.RemoteRepository;
import org.eclipse.aether.repository.WorkspaceReader;
import org.eclipse.aether.repository.WorkspaceRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Checks isolated source resolution and stable repository provenance. */
@SuppressWarnings("PMD.AtLeastOneConstructor") // JUnit supplies the test instance lifecycle.
final class MavenSourceClassifierResolverTest {
  /** Maven session method handled by the local repository-manager fixture. */
  private static final String GET_LOCAL_REPOSITORY_METHOD = "getRepository";

  /** Exact Maven identity used by resolver origin fixtures. */
  private static final ArtifactCoordinate CANDIDATE =
      new ArtifactCoordinate("org.example", "demo", "1.0", "jar", "", "compile");

  /** Isolates repository artifacts for each resolver scenario. */
  @TempDir private Path temporaryDirectory;

  @Test
  void workspaceReaderIsClearedAndNamedRemoteArtifactIsResolved() throws IOException {
    final Path workspaceSources =
        Files.writeString(temporaryDirectory.resolve("workspace.jar"), "workspace");
    final Path remoteSources =
        Files.writeString(temporaryDirectory.resolve("remote.jar"), "remote");
    final AtomicInteger workspaceLookups = new AtomicInteger();
    final WorkspaceReader workspaceReader = workspaceReader(workspaceSources, workspaceLookups);
    final DefaultRepositorySystemSession repositorySession =
        new DefaultRepositorySystemSession().setWorkspaceReader(workspaceReader);
    final AtomicBoolean observedIsolatedSession = new AtomicBoolean();
    final RemoteRepository remote =
        new RemoteRepository.Builder(
                "central-fixture", "default", "https://repo.example.invalid/maven2")
            .build();
    final MavenSourceClassifierResolver resolver =
        new MavenSourceClassifierResolver(
            MavenSourceCorrespondenceTestArtifacts.resolver(
                remoteSources,
                remote,
                session -> observedIsolatedSession.set(session.getWorkspaceReader() == null)));

    final MavenSourceClassifierResolver.ResolvedSourceArtifact result =
        resolver.resolve(CANDIDATE, project(), session(repositorySession));

    final boolean isolated = observedIsolatedSession.get();
    final int lookupCount = workspaceLookups.get();
    assertAll(
        () ->
            org.junit.jupiter.api.Assertions.assertTrue(
                isolated, "The resolver must receive a session without the workspace reader"),
        () ->
            org.junit.jupiter.api.Assertions.assertEquals(
                0, lookupCount, "No lookup may reach the same-GAV workspace source"),
        () -> assertThat(result.path()).isEqualTo(remoteSources.toAbsolutePath().normalize()),
        () ->
            assertThat(result.repositoryProvenance())
                .isEqualTo("remote:central-fixture@https://repo.example.invalid/maven2"));
  }

  @Test
  void workspaceAndUnknownRepositoryResultsAreRejected() throws IOException {
    final Path sources = Files.writeString(temporaryDirectory.resolve("sources.jar"), "sources");
    final ArtifactRepository unknown = unknownRepository();

    assertAll(
        () ->
            assertThatIOException()
                .isThrownBy(
                    () ->
                        resolve(
                            sources,
                            new WorkspaceRepository("workspace"),
                            new DefaultRepositorySystemSession()))
                .withMessageContaining("workspace sources are not accepted"),
        () ->
            assertThatIOException()
                .isThrownBy(() -> resolve(sources, unknown, new DefaultRepositorySystemSession()))
                .withMessageContaining("unknown repository provenance"));
  }

  @Test
  void namedLocalRepositoryProvenanceIsAcceptedOnlyForItsContainedArtifact() throws IOException {
    final Path repositoryRoot =
        Files.createDirectories(temporaryDirectory.resolve("local-repository"));
    final Path localArtifact =
        Files.createDirectories(repositoryRoot.resolve("org/example/demo/1.0"))
            .resolve("demo-1.0-sources.jar");
    Files.writeString(localArtifact, "sources");
    final LocalRepository local = new LocalRepository(repositoryRoot.toFile());
    final LocalRepositoryManager manager = localRepositoryManager(local);
    final DefaultRepositorySystemSession repositorySession =
        new DefaultRepositorySystemSession().setLocalRepositoryManager(manager);

    final MavenSourceClassifierResolver.ResolvedSourceArtifact result =
        resolve(localArtifact, local, repositorySession);

    assertThat(result.repositoryProvenance())
        .isEqualTo("local:" + local.getId() + ":org/example/demo/1.0/demo-1.0-sources.jar");
  }

  private MavenSourceClassifierResolver.ResolvedSourceArtifact resolve(
      final Path sources,
      final ArtifactRepository repository,
      final RepositorySystemSession session)
      throws IOException {
    return new MavenSourceClassifierResolver(
            MavenSourceCorrespondenceTestArtifacts.resolver(sources, repository, ignored -> {}))
        .resolve(CANDIDATE, project(), session(session));
  }

  private static MavenProject project() {
    final MavenProject project = new MavenProject();
    project.setRemoteArtifactRepositories(List.of());
    return project;
  }

  private static MavenSession session(final RepositorySystemSession repositorySession) {
    return new MavenSession(null, repositorySession, new DefaultMavenExecutionRequest(), null);
  }

  private static WorkspaceReader workspaceReader(final Path artifact, final AtomicInteger lookups) {
    return new WorkspaceReader() {
      @Override
      public WorkspaceRepository getRepository() {
        return new WorkspaceRepository("fixture-workspace");
      }

      @Override
      public java.io.File findArtifact(final org.eclipse.aether.artifact.Artifact requested) {
        lookups.incrementAndGet();
        return artifact.toFile();
      }

      @Override
      public List<String> findVersions(final org.eclipse.aether.artifact.Artifact requested) {
        lookups.incrementAndGet();
        return List.of(CANDIDATE.version());
      }
    };
  }

  @SuppressWarnings("PMD.CompareObjectsWithEquals") // Proxy equality must use object identity.
  private static ArtifactRepository unknownRepository() {
    return (ArtifactRepository)
        Proxy.newProxyInstance(
            Thread.currentThread().getContextClassLoader(),
            new Class<?>[] {ArtifactRepository.class},
            (proxy, method, arguments) ->
                switch (method.getName()) {
                  case "getId" -> "unknown-origin";
                  case "getContentType" -> "unknown";
                  case "toString" -> "unknown-origin";
                  case "hashCode" -> System.identityHashCode(proxy);
                  case "equals" -> proxy == arguments[0];
                  default -> throw new UnsupportedOperationException(method.getName());
                });
  }

  @SuppressWarnings("PMD.CompareObjectsWithEquals") // Proxy equality must use object identity.
  private static LocalRepositoryManager localRepositoryManager(final LocalRepository repository) {
    return (LocalRepositoryManager)
        Proxy.newProxyInstance(
            Thread.currentThread().getContextClassLoader(),
            new Class<?>[] {LocalRepositoryManager.class},
            (proxy, method, arguments) -> {
              return switch (method.getName()) {
                case GET_LOCAL_REPOSITORY_METHOD -> repository;
                case "toString" -> "fixture-local-repository-manager";
                case "hashCode" -> System.identityHashCode(proxy);
                case "equals" -> proxy == arguments[0];
                default -> throw new UnsupportedOperationException(method.getName());
              };
            });
  }
}
