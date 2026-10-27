/* WHY: Records lifecycle requests before the resolver call. */

package io.github.spockz.elider.test.resolver;

import java.util.List;
import javax.inject.Named;
import javax.inject.Singleton;
import org.apache.maven.RepositoryUtils;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.eventspy.EventSpy;
import org.apache.maven.project.DependencyResolutionRequest;
import org.eclipse.aether.graph.DefaultDependencyNode;
import org.eclipse.aether.graph.Dependency;
import org.eclipse.aether.graph.DependencyFilter;
import org.eclipse.aether.graph.DependencyNode;
import org.eclipse.sisu.Priority;

/** Records filtered acceptance for direct dependencies on the live request event. */
@SuppressWarnings({
  "PMD.AtLeastOneConstructor",
  "PMD.CommentRequired",
  "PMD.LawOfDemeter",
  "PMD.SystemPrintln"
})
@Named("resolver-probe-event-spy")
@Priority(10)
@Singleton
public final class ResolverRequestEventSpy implements EventSpy {
  private static final String PROJECT_ARTIFACT = "lifecycle-probe-consumer";

  @Override
  public void init(final Context context) {
    // The probe has no startup state.
  }

  @Override
  public void onEvent(final Object event) {
    if (event instanceof DependencyResolutionRequest request
        && PROJECT_ARTIFACT.equals(request.getMavenProject().getArtifact().getArtifactId())) {
      final int requestToken = ResolverRequestTokens.tokenFor(request);
      request
          .getRepositorySession()
          .getData()
          .set(ResolverRequestTokens.REQUEST_TOKEN_KEY, requestToken);
      System.out.println(
          "RESOLVER_REQUEST requestToken="
              + requestToken
              + " project="
              + PROJECT_ARTIFACT
              + " filter="
              + filterDecisions(
                  request.getResolutionFilter(),
                  request.getMavenProject().getDependencyArtifacts()));
    }
  }

  @Override
  public void close() {
    // The probe owns no resources.
  }

  private static List<String> filterDecisions(
      final DependencyFilter filter, final java.util.Set<Artifact> artifacts) {
    if (filter == null) {
      return List.of("none");
    }
    return artifacts.stream()
        .sorted(java.util.Comparator.comparing(Artifact::getArtifactId))
        .map(artifact -> decision(filter, artifact))
        .toList();
  }

  private static String decision(final DependencyFilter filter, final Artifact artifact) {
    final Dependency dependency = RepositoryUtils.toDependency(artifact, List.of());
    final DependencyNode node = new DefaultDependencyNode(dependency);
    return artifact.getArtifactId() + "=" + filter.accept(node, List.of());
  }
}
