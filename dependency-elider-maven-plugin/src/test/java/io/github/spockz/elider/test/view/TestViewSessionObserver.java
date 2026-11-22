// WHY: Observes whether a fresh post-test resolver request passes the production decorator.

package io.github.spockz.elider.test.view;

import javax.inject.Named;
import javax.inject.Singleton;
import org.apache.maven.project.MavenProject;
import org.apache.maven.project.RepositorySessionDecorator;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.repository.WorkspaceReader;
import org.eclipse.sisu.Priority;

/** Test-only observer after the production session decorator. */
@Named("adr0016-resolver-observer")
@Priority(-1000)
@Singleton
@SuppressWarnings({
  "PMD.AtLeastOneConstructor",
  "PMD.LawOfDemeter",
  "PMD.SystemPrintln",
  "PMD.TestClassWithoutTestCases"
})
public final class TestViewSessionObserver implements RepositorySessionDecorator {
  /** Identifies the marked probe call across Maven realms. */
  private static final String PROBE_REQUEST_KEY = "io.github.spockz.elider.test.probe-request";

  @Override
  public RepositorySystemSession decorate(
      final MavenProject project, final RepositorySystemSession session) {
    if (project != null && "test-view-consumer".equals(project.getArtifactId())) {
      final WorkspaceReader reader = session.getWorkspaceReader();
      final Object plan =
          session.getData().get("io.github.spockz.elider.resolver.artifact-plans.v1");
      System.out.println(
          "ADR0016 resolver-decorator-observer probeRequest="
              + Boolean.TRUE.equals(session.getData().get(PROBE_REQUEST_KEY))
              + " planPresent="
              + (plan != null)
              + " reader="
              + (reader == null ? "none" : reader.getClass().getName()));
    }
    return session;
  }
}
