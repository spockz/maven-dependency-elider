// WHY: Limits the allowed original dependency view to Maven's test compiler callback window.

package io.github.spockz.elider.plugin;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.execution.AbstractExecutionListener;
import org.apache.maven.execution.ExecutionEvent;
import org.apache.maven.execution.ExecutionListener;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.MojoExecution;
import org.apache.maven.project.MavenProject;
import org.codehaus.plexus.util.xml.Xpp3Dom;

/** Chained Maven 3 listener for the opt-in, single-project test compilation view. */
@SuppressWarnings({
  "PMD.AvoidCatchingGenericException",
  "PMD.CommentDefaultAccessModifier",
  "PMD.CompareObjectsWithEquals",
  "PMD.CommentRequired",
  "PMD.CyclomaticComplexity",
  "PMD.NullAssignment",
  "PMD.TooManyMethods",
  "PMD.UseConcurrentHashMap"
})
final class EliderTestViewExecutionListener extends AbstractExecutionListener {
  private static final String COMPILER_PLUGIN = "maven-compiler-plugin";
  private static final String TEST_COMPILE = "testCompile";
  private static final String SUREFIRE_CLASSPATH_PROPERTY = "maven.test.additionalClasspath";
  private final MavenSession session;
  private final ExecutionListener prior;
  private MavenProject project;
  private Set<Artifact> originals;
  private final Map<Artifact, File> originalFiles = new IdentityHashMap<>();
  private Set<Artifact> production;
  private final Map<Artifact, File> productionFiles = new IdentityHashMap<>();
  private EliderTestViewPlan.Plan plan;
  private boolean compilerView;

  EliderTestViewExecutionListener(final MavenSession session, final ExecutionListener prior) {
    super();
    this.session = session;
    this.prior = prior;
  }

  @Override
  public void mojoStarted(final ExecutionEvent event) {
    final MojoExecution execution = event.getMojoExecution();
    if (isGoal(execution, COMPILER_PLUGIN, TEST_COMPILE)) {
      beginCompilerView(event.getProject());
      try {
        if (prior != null) {
          prior.mojoStarted(event);
        }
      } catch (final RuntimeException failure) {
        restoreProduction();
        throw failure;
      }
      return;
    }
    if (prior != null) {
      prior.mojoStarted(event);
    }
    if (isGoal(execution, "dependency-elider-maven-plugin", "elide")) {
      captureOriginal(event.getProject());
    } else if (isGoal(execution, "maven-surefire-plugin", "test")) {
      addTestRuntimeJar(event.getProject(), execution);
    }
  }

  @Override
  public void mojoSucceeded(final ExecutionEvent event) {
    if (isGoal(event.getMojoExecution(), COMPILER_PLUGIN, TEST_COMPILE)) {
      restoreProduction();
    } else if (isGoal(event.getMojoExecution(), "dependency-elider-maven-plugin", "elide")) {
      captureProduction(event.getProject());
    }
    if (prior != null) {
      prior.mojoSucceeded(event);
    }
  }

  @Override
  public void mojoFailed(final ExecutionEvent event) {
    if (isGoal(event.getMojoExecution(), COMPILER_PLUGIN, TEST_COMPILE)) {
      restoreProduction();
    } else if (isGoal(event.getMojoExecution(), "dependency-elider-maven-plugin", "elide")) {
      clear();
    }
    if (prior != null) {
      prior.mojoFailed(event);
    }
  }

  @Override
  public void mojoSkipped(final ExecutionEvent event) {
    if (isGoal(event.getMojoExecution(), COMPILER_PLUGIN, TEST_COMPILE)) {
      restoreProduction();
    }
    if (prior != null) {
      prior.mojoSkipped(event);
    }
  }

  @Override
  public void projectFailed(final ExecutionEvent event) {
    restoreProduction();
    if (prior != null) {
      prior.projectFailed(event);
    }
  }

  @Override
  public void projectSucceeded(final ExecutionEvent event) {
    restoreProduction();
    if (prior != null) {
      prior.projectSucceeded(event);
    }
  }

  @Override
  public void sessionEnded(final ExecutionEvent event) {
    restoreProduction();
    clear();
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

  private void captureOriginal(final MavenProject current) {
    if (!EliderTestViewPlan.requested(session, current)) {
      return;
    }
    if (compilerView) {
      throw new IllegalStateException("Elide started while the test compiler view is active");
    }
    clear();
    project = current;
    originals = new LinkedHashSet<>(current.getArtifacts());
    rememberFiles(originals, originalFiles);
  }

  private void captureProduction(final MavenProject current) {
    if (current != project) {
      return;
    }
    plan = EliderTestViewPlan.read(session, current);
    if (plan == null) {
      throw new IllegalStateException("Elide did not publish the requested test view plan");
    }
    production = new LinkedHashSet<>(current.getArtifacts());
    rememberFiles(originals, productionFiles);
    rememberFiles(production, productionFiles);
  }

  private void beginCompilerView(final MavenProject current) {
    if (!EliderTestViewPlan.requested(session, current)) {
      return;
    }
    if (current != project || plan == null || production == null) {
      throw new IllegalStateException(
          "Test compilation view requires a successful Elide goal in this Maven invocation");
    }
    if (compilerView) {
      throw new IllegalStateException("Test compilation view is already active");
    }
    final Map<EliderTestViewPlan.Identity, Artifact> available = new LinkedHashMap<>();
    for (final Artifact artifact : originals) {
      final EliderTestViewPlan.Identity identity = EliderTestViewPlan.Identity.of(artifact);
      if (available.putIfAbsent(identity, artifact) != null) {
        throw new IllegalStateException("Ambiguous original test artifact: " + identity);
      }
    }
    final Set<Artifact> allowed = new LinkedHashSet<>();
    for (final EliderTestViewPlan.Descriptor descriptor : plan.artifacts()) {
      final Artifact artifact = available.get(descriptor.identity());
      if (artifact == null
          || !descriptor.path().equals(normalizedPath(originalFiles.get(artifact)))) {
        throw new IllegalStateException(
            "Allowed original artifact no longer matches Maven's captured view: "
                + descriptor.identity());
      }
      allowed.add(artifact);
    }
    try {
      compilerView = true;
      restoreFiles(originalFiles, allowed);
      current.setResolvedArtifacts(new LinkedHashSet<>(allowed));
      current.setArtifacts(new LinkedHashSet<>(allowed));
    } catch (final RuntimeException failure) {
      restoreProduction();
      throw failure;
    }
  }

  private void restoreProduction() {
    if (!compilerView) {
      return;
    }
    restoreFiles(productionFiles, productionFiles.keySet());
    project.setResolvedArtifacts(new LinkedHashSet<>(production));
    project.setArtifacts(new LinkedHashSet<>(production));
    compilerView = false;
  }

  private void addTestRuntimeJar(final MavenProject current, final MojoExecution execution) {
    if (current != project || plan == null || plan.addition().isBlank()) {
      return;
    }
    if (compilerView) {
      throw new IllegalStateException("Surefire cannot start during the test compiler view");
    }
    final Path addition = Path.of(plan.addition());
    if (!Files.isRegularFile(addition)) {
      throw new IllegalStateException("Test additions JAR is missing: " + addition);
    }
    final Xpp3Dom previous = execution.getConfiguration();
    final Xpp3Dom configuration =
        previous == null ? new Xpp3Dom("configuration") : new Xpp3Dom(previous);
    Xpp3Dom elements = configuration.getChild("additionalClasspathElements");
    if (elements == null) {
      elements = new Xpp3Dom("additionalClasspathElements");
      configuration.addChild(elements);
    }
    final String userClasspath =
        session.getUserProperties().getProperty(SUREFIRE_CLASSPATH_PROPERTY);
    final String configuredClasspath =
        userClasspath == null
            ? current.getProperties().getProperty(SUREFIRE_CLASSPATH_PROPERTY)
            : userClasspath;
    if (configuredClasspath != null) {
      // Maven's array converter prefers this value over child entries.
      elements.setValue(
          configuredClasspath.isEmpty()
              ? addition.toString()
              : configuredClasspath + "," + addition);
    } else {
      final Xpp3Dom element = new Xpp3Dom("additionalClasspathElement");
      element.setValue(addition.toString());
      elements.addChild(element);
    }
    execution.setConfiguration(configuration);
  }

  private void clear() {
    project = null;
    originals = null;
    production = null;
    plan = null;
    compilerView = false;
    originalFiles.clear();
    productionFiles.clear();
    EliderTestViewPlan.clear(session);
  }

  private static void rememberFiles(
      final Set<Artifact> artifacts, final Map<Artifact, File> files) {
    artifacts.forEach(artifact -> files.put(artifact, artifact.getFile()));
  }

  private static void restoreFiles(
      final Map<Artifact, File> files, final Iterable<Artifact> artifacts) {
    for (final Artifact artifact : artifacts) {
      artifact.setFile(files.get(artifact));
    }
  }

  private static String normalizedPath(final File file) {
    return file == null ? null : file.toPath().toAbsolutePath().normalize().toString();
  }

  private static boolean isGoal(
      final MojoExecution execution, final String artifactId, final String goal) {
    return execution != null
        && artifactId.equals(execution.getArtifactId())
        && goal.equals(execution.getGoal());
  }
}
