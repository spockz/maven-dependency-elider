// WHY: Guards Maven lifecycle mutation until integration behavior is verified.
// It prevents later phases from consuming an unproven artifact set.

package io.github.spockz.elider.plugin;

import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.plugins.annotations.ResolutionScope;

/** Fails before Maven project state is accessed. */
@Mojo(
    name = "elide",
    defaultPhase = LifecyclePhase.INITIALIZE,
    requiresDependencyResolution = ResolutionScope.TEST,
    threadSafe = true)
public final class ElideMojo extends AbstractMojo {
  /** Maven switch that disables this goal without side effects. */
  @Parameter(property = "elide.skip", defaultValue = "false")
  private boolean skip;

  /** Fails before reading or changing the Maven project artifact sets. */
  @Override
  public void execute() throws MojoFailureException {
    if (skip) {
      return;
    }
    throw new MojoFailureException(
        "The elide goal is disabled: INITIALIZE artifact mutation has not been verified against "
            + "forked Maven 3.9 resolution, classpath, and packaging behavior. Use the nonmutating "
            + "analyze goal with explicit -Delide.traceFiles=... inputs.");
  }

  /** Creates a Mojo instance for Maven injection. */
  public ElideMojo() {
    super();
  }
}
