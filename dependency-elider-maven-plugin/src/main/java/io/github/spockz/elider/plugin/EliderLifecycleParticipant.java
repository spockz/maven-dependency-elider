// WHY: Connects Maven's project-read callback to the standalone tree preparation flow.

package io.github.spockz.elider.plugin;

import javax.inject.Named;
import javax.inject.Singleton;
import org.apache.maven.AbstractMavenLifecycleParticipant;
import org.apache.maven.MavenExecutionException;
import org.apache.maven.execution.MavenSession;

/** Schedules configured elision before eligible standalone tree requests. */
@Named
@Singleton
public final class EliderLifecycleParticipant extends AbstractMavenLifecycleParticipant {
  /** Required for Maven's component instantiation. */
  public EliderLifecycleParticipant() {
    super();
  }

  @Override
  public void afterProjectsRead(final MavenSession session) throws MavenExecutionException {
    EliderTreePreparation.schedule(session);
  }
}
