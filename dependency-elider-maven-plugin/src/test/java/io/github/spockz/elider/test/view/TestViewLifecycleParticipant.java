// WHY: Observes listener chaining and restoration in the real Maven fixture without changing views.

package io.github.spockz.elider.test.view;

import java.io.File;
import java.util.IdentityHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import javax.inject.Named;
import javax.inject.Singleton;
import org.apache.maven.AbstractMavenLifecycleParticipant;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.execution.AbstractExecutionListener;
import org.apache.maven.execution.ExecutionEvent;
import org.apache.maven.execution.ExecutionListener;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.MojoExecution;
import org.apache.maven.project.MavenProject;

/** Checks the production listener from a separate core extension. */
@Named
@Singleton
@SuppressWarnings({
  "PMD.AtLeastOneConstructor",
  "PMD.SystemPrintln",
  "PMD.TestClassWithoutTestCases"
})
public final class TestViewLifecycleParticipant extends AbstractMavenLifecycleParticipant {
  @Override
  @SuppressWarnings("PMD.LawOfDemeter")
  public void afterSessionStart(final MavenSession session) {
    final ExecutionListener prior = session.getRequest().getExecutionListener();
    session.getRequest().setExecutionListener(new Observer(prior));
    System.out.println("ADR0016 registered chained=" + (prior != null));
  }

  @SuppressWarnings({
    "PMD.CommentRequired",
    "PMD.CompareObjectsWithEquals",
    "PMD.LawOfDemeter",
    "PMD.TooManyMethods",
    "PMD.UseConcurrentHashMap"
  })
  private static final class Observer extends AbstractExecutionListener {
    private final ExecutionListener prior;
    private MavenProject project;
    private Set<Artifact> production;
    private final Map<Artifact, File> productionFiles = new IdentityHashMap<>();

    private Observer(final ExecutionListener prior) {
      super();
      this.prior = prior;
    }

    @Override
    public void mojoStarted(final ExecutionEvent event) {
      if (prior != null) {
        prior.mojoStarted(event);
      }
      if (isGoal(event.getMojoExecution(), "maven-compiler-plugin", "testCompile")
          && event.getProject() == project) {
        System.out.println(
            "ADR0016 compiler-original before-configuration="
                + event.getProject().getArtifacts().stream()
                    .anyMatch(a -> "test-only-library".equals(a.getArtifactId())));
      }
    }

    @Override
    public void mojoSucceeded(final ExecutionEvent event) {
      if (prior != null) {
        prior.mojoSucceeded(event);
      }
      if (isGoal(event.getMojoExecution(), "dependency-elider-maven-plugin", "elide")
          && "test-view-consumer".equals(event.getProject().getArtifactId())) {
        project = event.getProject();
        production = new LinkedHashSet<>(project.getArtifacts());
        for (final Artifact artifact : production) {
          productionFiles.put(artifact, artifact.getFile());
        }
      } else if (isGoal(event.getMojoExecution(), "maven-compiler-plugin", "testCompile")
          && event.getProject() == project) {
        System.out.println("ADR0016 production-restored outcome=success value=" + restored());
      }
    }

    @Override
    public void mojoFailed(final ExecutionEvent event) {
      if (prior != null) {
        prior.mojoFailed(event);
      }
      if (isGoal(event.getMojoExecution(), "maven-compiler-plugin", "testCompile")
          && event.getProject() == project) {
        System.out.println("ADR0016 production-restored outcome=failure value=" + restored());
      }
    }

    @Override
    public void projectFailed(final ExecutionEvent event) {
      if (prior != null) {
        prior.projectFailed(event);
      }
      if (event.getProject() == project) {
        System.out.println("ADR0016 project-failed-production=" + restored());
      }
    }

    @Override
    public void projectSucceeded(final ExecutionEvent event) {
      if (prior != null) {
        prior.projectSucceeded(event);
      }
    }

    @Override
    public void sessionEnded(final ExecutionEvent event) {
      if (prior != null) {
        prior.sessionEnded(event);
      }
    }

    @Override
    public void projectDiscoveryStarted(final ExecutionEvent event) {
      if (prior != null) {
        prior.projectDiscoveryStarted(event);
      }
    }

    @Override
    public void sessionStarted(final ExecutionEvent event) {
      if (prior != null) {
        prior.sessionStarted(event);
      }
    }

    @Override
    public void projectSkipped(final ExecutionEvent event) {
      if (prior != null) {
        prior.projectSkipped(event);
      }
    }

    @Override
    public void projectStarted(final ExecutionEvent event) {
      if (prior != null) {
        prior.projectStarted(event);
      }
    }

    @Override
    public void mojoSkipped(final ExecutionEvent event) {
      if (prior != null) {
        prior.mojoSkipped(event);
      }
    }

    @Override
    public void forkStarted(final ExecutionEvent event) {
      if (prior != null) {
        prior.forkStarted(event);
      }
    }

    @Override
    public void forkSucceeded(final ExecutionEvent event) {
      if (prior != null) {
        prior.forkSucceeded(event);
      }
    }

    @Override
    public void forkFailed(final ExecutionEvent event) {
      if (prior != null) {
        prior.forkFailed(event);
      }
    }

    @Override
    public void forkedProjectStarted(final ExecutionEvent event) {
      if (prior != null) {
        prior.forkedProjectStarted(event);
      }
    }

    @Override
    public void forkedProjectSucceeded(final ExecutionEvent event) {
      if (prior != null) {
        prior.forkedProjectSucceeded(event);
      }
    }

    @Override
    public void forkedProjectFailed(final ExecutionEvent event) {
      if (prior != null) {
        prior.forkedProjectFailed(event);
      }
    }

    private boolean restored() {
      return production != null
          && production.equals(project.getArtifacts())
          && production.stream().allMatch(a -> productionFiles.get(a).equals(a.getFile()));
    }

    private static boolean isGoal(
        final MojoExecution execution, final String artifactId, final String goal) {
      return execution != null
          && artifactId.equals(execution.getArtifactId())
          && goal.equals(execution.getGoal());
    }
  }
}
