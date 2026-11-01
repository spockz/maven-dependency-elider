// WHY: Maps exact artifact identities to source JARs for one assessment's resolver fixture.

package io.github.spockz.elider.plugin;

import java.lang.reflect.Proxy;
import java.nio.file.Path;
import java.util.Map;
import java.util.function.Consumer;
import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.artifact.Artifact;
import org.eclipse.aether.artifact.DefaultArtifact;
import org.eclipse.aether.repository.ArtifactRepository;
import org.eclipse.aether.resolution.ArtifactRequest;
import org.eclipse.aether.resolution.ArtifactResult;

/** Creates a resolver fixture with an exact source-JAR map. */
@SuppressWarnings({"PMD.CommentDefaultAccessModifier", "PMD.LawOfDemeter"})
final class MavenMultiSourceResolverFixture {
  /** Resolver method handled by the test proxy. */
  private static final String RESOLVE_ARTIFACT_METHOD = "resolveArtifact";

  private MavenMultiSourceResolverFixture() {}

  @SuppressWarnings("PMD.CompareObjectsWithEquals") // Proxy equality must remain identity-based.
  static RepositorySystem resolver(
      final Map<String, Path> sourcesByArtifact,
      final ArtifactRepository repository,
      final Consumer<RepositorySystemSession> sessionObserver) {
    return (RepositorySystem)
        Proxy.newProxyInstance(
            Thread.currentThread().getContextClassLoader(),
            new Class<?>[] {RepositorySystem.class},
            (proxy, method, arguments) -> {
              if (RESOLVE_ARTIFACT_METHOD.equals(method.getName())) {
                sessionObserver.accept((RepositorySystemSession) arguments[0]);
                return resolveSourceArtifact(sourcesByArtifact, repository, arguments);
              }
              return switch (method.getName()) {
                case "toString" -> "Multi-source correspondence resolver fixture";
                case "hashCode" -> System.identityHashCode(proxy);
                case "equals" -> proxy == arguments[0];
                default -> throw new UnsupportedOperationException(method.getName());
              };
            });
  }

  private static ArtifactResult resolveSourceArtifact(
      final Map<String, Path> sourcesByArtifact,
      final ArtifactRepository repository,
      final Object... arguments) {
    final ArtifactRequest request = (ArtifactRequest) arguments[1];
    final Artifact expected = request.getArtifact();
    final String key =
        expected.getGroupId() + ":" + expected.getArtifactId() + ":" + expected.getVersion();
    final Path sources = sourcesByArtifact.get(key);
    if (sources == null) {
      throw new IllegalArgumentException("No source fixture for exact candidate " + key);
    }
    final Artifact resolved =
        new DefaultArtifact(
                expected.getGroupId(),
                expected.getArtifactId(),
                expected.getClassifier(),
                expected.getExtension(),
                expected.getVersion())
            .setFile(sources.toFile());
    return new ArtifactResult(request).setArtifact(resolved).setRepository(repository);
  }
}
