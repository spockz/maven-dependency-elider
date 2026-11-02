// WHY: Proves unsupported original scopes and Maven types survive real offline TEST-context
// resolution before audit rejection.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;
import org.apache.maven.execution.DefaultMavenExecutionRequest;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.model.Dependency;
import org.apache.maven.model.Model;
import org.apache.maven.model.io.xpp3.MavenXpp3Writer;
import org.apache.maven.project.DefaultProjectDependenciesResolver;
import org.apache.maven.project.DependencyResolutionResult;
import org.apache.maven.project.MavenProject;
import org.apache.maven.project.ProjectDependenciesResolver;
import org.apache.maven.repository.internal.MavenRepositorySystemUtils;
import org.codehaus.plexus.logging.Logger;
import org.codehaus.plexus.logging.console.ConsoleLogger;
import org.eclipse.aether.DefaultRepositorySystemSession;
import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.repository.LocalRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Resolves original effective scopes through Maven Core. */
@SuppressWarnings({
  "PMD.AtLeastOneConstructor",
  "PMD.CommentDefaultAccessModifier",
  "PMD.CommentRequired",
  "PMD.ExcessiveImports",
  "PMD.LawOfDemeter"
})
final class MavenOriginalInputScopeResolutionTest {
  private static final String GROUP = "audit.fixture";
  private static final String VERSION = "1";
  private static final String BANNED = "provider";
  private static final String JAR = "jar";
  private static final String COMPILE = "compile";
  @TempDir Path directory;

  @Test
  void validatesEveryMatchFromTheRealOriginalTestResolution() throws Exception {
    final Path repository = Files.createDirectory(directory.resolve("repository"));
    install(repository, BANNED, List.of(), List.of("test", "provided", "supported", "tests"));
    installRoot(repository, "test-root", "test", JAR);
    installRoot(repository, "provided-root", "provided", JAR);
    installRoot(repository, "supported-root", "supported", JAR);
    installRoot(repository, "testjar-root", "tests", "test-jar");
    final RepositorySystem system =
        MavenRepositorySystemUtils.newServiceLocator().getService(RepositorySystem.class);
    if (system == null) {
      throw new IllegalStateException("Maven Resolver components are unavailable");
    }
    final DefaultRepositorySystemSession repositorySession =
        MavenRepositorySystemUtils.newSession();
    repositorySession.setOffline(true);
    repositorySession.setLocalRepositoryManager(
        system.newLocalRepositoryManager(
            repositorySession, new LocalRepository(repository.toFile())));
    final DefaultProjectDependenciesResolver realResolver =
        new DefaultProjectDependenciesResolver();
    inject(realResolver, "repoSystem", system);
    inject(realResolver, "logger", new ConsoleLogger(Logger.LEVEL_WARN, "original-audit"));
    inject(realResolver, "decorators", List.of());
    final List<Scenario> scenarios =
        List.of(
            new Scenario("test-root", "test", JAR),
            new Scenario("provided-root", "provided", JAR),
            new Scenario("testjar-root", COMPILE, "test-jar"));

    assertAll(
        "real Maven resolution preserves unsupported matches before policy validation",
        scenarios.stream()
            .map(
                scenario ->
                    () ->
                        assertAll(
                            scenario.toString(),
                            List.of(false, true).stream()
                                .map(
                                    mixed ->
                                        () ->
                                            verifyScenario(
                                                realResolver,
                                                repositorySession,
                                                scenario,
                                                mixed)))));
  }

  private void verifyScenario(
      final ProjectDependenciesResolver realResolver,
      final DefaultRepositorySystemSession repositorySession,
      final Scenario scenario,
      final boolean mixed) {
    final Model model = model("consumer");
    final List<Dependency> roots = new ArrayList<>();
    roots.add(dependency(scenario.root(), "", JAR, scenario.scope()));
    if (mixed) {
      roots.add(dependency("supported-root", "", JAR, COMPILE));
    }
    model.setDependencies(roots);
    final MavenProject project = new MavenProject(model);
    project.setArtifact(
        new DefaultArtifact(
            GROUP, "consumer", VERSION, COMPILE, JAR, null, new DefaultArtifactHandler(JAR)));
    project.setFile(directory.resolve("consumer-pom.xml").toFile());
    final List<String> bans = List.of(GROUP + ":" + BANNED);
    final BanishedDependencyOriginalModel captured =
        BanishedDependencyOriginalModel.capture(project, List.of(), bans);
    final DefaultRepositorySystemSession sessionState =
        new DefaultRepositorySystemSession(repositorySession);
    sessionState.setData(new org.eclipse.aether.DefaultSessionData());
    sessionState
        .getData()
        .set(
            BanishedDependencyLifecycleActivation.CAPTURE_STORE_KEY,
            BanishedDependencyCaptureStore.empty().withModel(captured).toPayload());
    project.setDependencies(BanishedDependencyLifecycleActivation.injectExclusions(project, bans));
    final MavenSession session =
        new MavenSession(null, sessionState, new DefaultMavenExecutionRequest(), null);
    session.setCurrentProject(project);
    MavenOriginalInputAudit.markHookPresent(session);
    final AtomicReference<DependencyResolutionResult> actualResult = new AtomicReference<>();
    final ProjectDependenciesResolver recording =
        request -> {
          final DependencyResolutionResult result = realResolver.resolve(request);
          actualResult.set(result);
          return result;
        };
    final Throwable failure =
        org.assertj.core.api.Assertions.catchThrowable(
            () -> MavenOriginalInputAudit.audit(project, session, recording));

    assertAll(
        "original " + scenario + ", mixed=" + mixed,
        () -> {
          assertThat(actualResult.get())
              .as("policy must inspect a completed real Maven resolution")
              .isNotNull();
          final List<org.eclipse.aether.graph.Dependency> matches =
              actualResult.get().getResolvedDependencies().stream()
                  .filter(value -> BANNED.equals(value.getArtifact().getArtifactId()))
                  .toList();
          assertAll(
              () -> assertThat(matches).hasSize(mixed ? 2 : 1),
              () ->
                  assertThat(matches)
                      .anySatisfy(
                          value ->
                              assertAll(
                                  () -> assertThat(value.getScope()).isEqualTo(scenario.scope()),
                                  () ->
                                      assertThat(
                                              value
                                                  .getArtifact()
                                                  .getProperty(
                                                      "type", value.getArtifact().getExtension()))
                                          .isEqualTo(scenario.mavenType()))),
              () -> {
                if (mixed) {
                  assertThat(matches)
                      .anySatisfy(
                          value ->
                              assertAll(
                                  () -> assertThat(value.getScope()).isEqualTo(COMPILE),
                                  () ->
                                      assertThat(value.getArtifact().getClassifier())
                                          .isEqualTo("supported")));
                }
              });
        },
        () ->
            assertThat(failure)
                .isInstanceOf(IOException.class)
                .hasMessageContaining("unsupported resolved artifact")
                .hasMessageContaining("Maven type: " + scenario.mavenType())
                .hasMessageContaining("(" + scenario.scope() + ")"));
  }

  @SuppressWarnings("PMD.AvoidAccessibilityAlteration")
  // Maven's component has no constructor for dependency injection.
  private static void inject(final Object target, final String name, final Object value)
      throws ReflectiveOperationException {
    final Field field = target.getClass().getDeclaredField(name);
    field.setAccessible(true);
    field.set(target, value);
  }

  private static Model model(final String artifactId) {
    final Model model = new Model();
    model.setModelVersion("4.0.0");
    model.setGroupId(GROUP);
    model.setArtifactId(artifactId);
    model.setVersion(VERSION);
    return model;
  }

  private static Dependency dependency(
      final String artifactId, final String classifier, final String type, final String scope) {
    final Dependency dependency = new Dependency();
    dependency.setGroupId(GROUP);
    dependency.setArtifactId(artifactId);
    dependency.setVersion(VERSION);
    dependency.setClassifier(classifier);
    dependency.setType(type);
    dependency.setScope(scope);
    return dependency;
  }

  private static void installRoot(
      final Path repository, final String root, final String classifier, final String type)
      throws IOException {
    install(repository, root, List.of(dependency(BANNED, classifier, type, COMPILE)), List.of(""));
  }

  @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
  private static void install(
      final Path repository,
      final String artifactId,
      final List<Dependency> dependencies,
      final List<String> classifiers)
      throws IOException {
    final Path target =
        Files.createDirectories(
            repository.resolve("audit/fixture").resolve(artifactId).resolve(VERSION));
    final Model model = model(artifactId);
    model.setDependencies(dependencies);
    try (java.io.Writer writer = Files.newBufferedWriter(target.resolve(artifactId + "-1.pom"))) {
      new MavenXpp3Writer().write(writer, model);
    }
    for (final String classifier : classifiers) {
      final String suffix = classifier.isEmpty() ? "" : "-" + classifier;
      try (JarOutputStream archive =
          new JarOutputStream(
              Files.newOutputStream(target.resolve(artifactId + "-1" + suffix + ".jar")))) {
        archive.putNextEntry(new JarEntry("fixture.txt"));
        archive.write(1);
        archive.closeEntry();
      }
    }
  }

  private record Scenario(String root, String scope, String mavenType) {}
}
