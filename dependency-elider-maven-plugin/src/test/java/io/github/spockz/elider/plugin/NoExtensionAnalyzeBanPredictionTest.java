// WHY: Proves strict bans use the detached Analyze graph and never publish artifact changes.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.plugin.ElisionAnalysisModel.AnalysisOptions;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.CompletenessOptions;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.DynamicRootOptions;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.TrimOptions;
import java.io.IOException;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.apache.maven.execution.DefaultMavenExecutionRequest;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.model.Build;
import org.apache.maven.model.Dependency;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.project.DependencyResolutionResult;
import org.apache.maven.project.MavenProject;
import org.apache.maven.project.ProjectDependenciesResolver;
import org.apache.maven.toolchain.DefaultToolchainManager;
import org.codehaus.plexus.PlexusContainer;
import org.eclipse.aether.DefaultRepositorySystemSession;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.collection.DependencyGraphTransformationContext;
import org.eclipse.aether.graph.DefaultDependencyNode;
import org.eclipse.aether.graph.DependencyNode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;

/** Tests detached bans. JUnit constructs the test. */
@SuppressWarnings({
  "PMD.AtLeastOneConstructor",
  "PMD.CommentRequired",
  "PMD.CouplingBetweenObjects",
  "PMD.ExcessiveImports",
  "PMD.LawOfDemeter",
  "PMD.TooManyMethods"
})
final class NoExtensionAnalyzeBanPredictionTest {
  private static final String BAN = "fixture:banned";
  private static final String USED_TRACE = "used.Api\n";
  private static final String GROUP_ID = "fixture";
  private static final String JAR_TYPE = "jar";
  private static final String VERSION = "1.0";

  /** Isolates each graph and evidence fixture from the other scenarios. */
  @TempDir private Path temporaryDirectory;

  @Test
  void plansSafeTransitiveBanWithoutChangingLiveViews() throws Exception {
    final Fixture fixture = fixture(USED_TRACE);
    final Set<org.apache.maven.artifact.Artifact> liveResolved = fixture.project().getArtifacts();
    final Set<org.apache.maven.artifact.Artifact> liveDirect =
        fixture.project().getDependencyArtifacts();

    final AnalyzePrediction prediction =
        new MavenElisionService()
            .predict(fixture.project(), fixture.options(List.of(BAN)), fixture.resolver());

    assertAll(
        "detached ban is only an uncommitted prediction tied to its Resolver inventory",
        () ->
            assertThat(prediction.provenance())
                .isEqualTo(AnalyzePrediction.Provenance.DETACHED_CURRENT_MODEL),
        () ->
            assertThat(prediction.banPlan().entries())
                .singleElement()
                .satisfies(
                    entry ->
                        assertAll(
                            () -> assertThat(entry.dependency().toString()).isEqualTo(BAN),
                            () -> assertThat(entry.matched()).isTrue(),
                            () -> assertThat(entry.artifacts()).hasSize(1))),
        () ->
            assertThat(prediction.wouldElideArtifacts())
                .containsAll(prediction.banPlan().forcedAbsentAfterResolution()),
        () -> assertThat(fixture.project().getArtifacts()).isSameAs(liveResolved),
        () -> assertThat(fixture.project().getDependencyArtifacts()).isSameAs(liveDirect),
        () ->
            assertThat(
                    fixture
                        .session()
                        .getRepositorySession()
                        .getData()
                        .get(EliderMediatedGraphCaptureDecorator.SESSION_DATA_KEY))
                .isNull());
  }

  @Test
  void reportsMatchedAndUnmatchedBansAsUnappliedSchemaOnePlans() throws Exception {
    final Fixture fixture = fixture(USED_TRACE);
    final AnalyzePrediction prediction =
        new MavenElisionService()
            .predict(
                fixture.project(),
                fixture.options(List.of("fixture:missing", BAN)),
                fixture.resolver());
    final AnalyzePrediction withoutBan =
        new MavenElisionService()
            .predict(fixture.project(), fixture.options(List.of()), fixture.resolver());
    final Path report = temporaryDirectory.resolve("ban-plan-report.json");
    MavenClassUsageReportWriter.write(
        report,
        prediction.evidence().classUsageReport(),
        prediction.evidence().bytecodeScan(),
        prediction);
    final com.fasterxml.jackson.databind.JsonNode json =
        new com.fasterxml.jackson.databind.ObjectMapper().readTree(report.toFile());
    final com.fasterxml.jackson.databind.JsonNode rows =
        json.path("dependencyPrediction").path("banPlan");

    assertAll(
        "schema-one prediction records action, unmatched policy, and no applied Maven mutation",
        () -> assertThat(json.path("schemaVersion").asInt()).isEqualTo(1),
        () ->
            assertThat(json.path("dependencyPrediction").path("banContextFingerprint").asText())
                .hasSize(64),
        () -> assertThat(rows.size()).isEqualTo(2),
        () -> assertThat(rows.get(0).path("dependency").asText()).isEqualTo(BAN),
        () ->
            assertThat(rows.get(0).path("status").asText())
                .isEqualTo("FORCED_ABSENT_AFTER_RESOLUTION"),
        () -> assertThat(rows.get(0).path("matchedArtifacts").size()).isEqualTo(1),
        () -> assertThat(rows.get(0).path("applied").asBoolean()).isFalse(),
        () -> assertThat(rows.get(1).path("dependency").asText()).isEqualTo("fixture:missing"),
        () ->
            assertThat(rows.get(1).path("status").asText()).isEqualTo("NO_CURRENT_INVENTORY_MATCH"),
        () -> assertThat(rows.get(1).path("matchedArtifacts").size()).isZero(),
        () -> assertThat(rows.get(1).path("applied").asBoolean()).isFalse(),
        () ->
            assertThat(prediction.operationFingerprint())
                .isNotEqualTo(withoutBan.operationFingerprint()));
  }

  @Test
  void rejectsRuntimeObservationOfBannedProviderBeforePrediction() throws Exception {
    final Fixture fixture = fixture("used.Api\nbanned.Idle\n");

    assertThatThrownBy(
            () ->
                new MavenElisionService()
                    .predict(fixture.project(), fixture.options(List.of(BAN)), fixture.resolver()))
        .hasMessageContaining("runtime trace requires class banned.Idle");
  }

  @Test
  void keepsActiveHookMissingCaptureDistinctFromPluginOnlyPlanning() throws Exception {
    final Fixture fixture = fixture(USED_TRACE);
    MavenOriginalInputAudit.markHookPresent(fixture.session());

    assertThatThrownBy(
            () ->
                new MavenElisionService()
                    .predict(fixture.project(), fixture.options(List.of(BAN)), fixture.resolver()))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Active Resolver capture is missing for Analyze");
  }

  @Test
  void rejectsPreMediationVersionProtectionAndAncestorPromotion() throws Exception {
    final Fixture competing = fixture(USED_TRACE);
    final DefaultDependencyNode direct =
        (DefaultDependencyNode) competing.root().getChildren().getFirst();
    final DependencyNode winner = direct.getChildren().getFirst();
    final org.eclipse.aether.graph.Dependency otherVersion =
        new org.eclipse.aether.graph.Dependency(
            new org.eclipse.aether.artifact.DefaultArtifact(
                GROUP_ID, "banned", "", JAR_TYPE, "2.0"),
            "runtime");
    direct.setChildren(List.of(winner, new DefaultDependencyNode(otherVersion)));
    competing
        .repositorySession()
        .setDependencyGraphTransformer(
            (root, context) -> {
              direct.setChildren(List.of(winner));
              return root;
            });
    final Fixture ancestor = fixture(USED_TRACE);
    final DefaultDependencyNode bannedNode =
        (DefaultDependencyNode) ancestor.root().getChildren().getFirst().getChildren().getFirst();
    bannedNode.setChildren(List.of(new DefaultDependencyNode(ancestor.usedDependency())));

    assertAll(
        "a forced ban cannot override graph protection or retained-descendant promotion",
        () ->
            assertThatThrownBy(() -> predict(competing))
                .hasMessageContaining("graph protects or promotes"),
        () ->
            assertThatThrownBy(() -> predict(ancestor))
                .hasMessageContaining("graph protects or promotes"));
  }

  @Test
  void rejectsRetainedBytecodeClosureWithAndWithoutTrim() throws Exception {
    final Fixture fixture = fixture(USED_TRACE, true);

    assertAll(
        "retained bytecode cannot promote the banned provider in either trim mode",
        () ->
            assertThatThrownBy(() -> predict(fixture))
                .hasMessageContaining("retained bytecode, resources, or providers"),
        () ->
            assertThatThrownBy(
                    () ->
                        new MavenElisionService()
                            .predict(
                                fixture.project(),
                                fixture.options(List.of(BAN), true),
                                fixture.resolver()))
                .hasMessageContaining("retained bytecode, resources, or providers"));
  }

  @Test
  void ignoresOnlySelfOriginServiceMetadataWithAndWithoutTrim() throws Exception {
    final Fixture selfOrigin = fixture(USED_TRACE, false, false, true);
    final AnalyzePrediction withoutTrim =
        new MavenElisionService()
            .predict(
                selfOrigin.project(),
                selfOrigin.options(List.of(BAN), false, true),
                selfOrigin.resolver());
    final AnalyzePrediction withTrim =
        new MavenElisionService()
            .predict(
                selfOrigin.project(),
                selfOrigin.options(List.of(BAN), true, true),
                selfOrigin.resolver());
    final String bannedProvider = "banned.Idle";
    assertAll(
        "self-origin metadata remains in evidence but cannot retain its own banned artifact",
        () ->
            assertThat(withoutTrim.wouldElideArtifacts())
                .containsAll(withoutTrim.banPlan().forcedAbsentAfterResolution()),
        () ->
            assertThat(withTrim.wouldElideArtifacts())
                .containsAll(withTrim.banPlan().forcedAbsentAfterResolution()),
        () ->
            assertThat(withoutTrim.evidence().unprovenServiceRoots().values())
                .anySatisfy(roots -> assertThat(roots).contains(bannedProvider)),
        () ->
            assertThat(withTrim.evidence().unprovenServiceRoots().values())
                .anySatisfy(roots -> assertThat(roots).contains(bannedProvider)));
  }

  @Test
  void rejectsRetainedServiceProviderMetadata() throws Exception {
    final Fixture fixture = fixture(USED_TRACE, false, true, true);

    assertThatThrownBy(
            () ->
                new MavenElisionService()
                    .predict(
                        fixture.project(),
                        fixture.options(List.of(BAN), false, true),
                        fixture.resolver()))
        .hasMessageContaining("dynamic metadata or provider requires class banned.Idle");
  }

  private static AnalyzePrediction predict(final Fixture fixture)
      throws IOException, MojoFailureException {
    return new MavenElisionService()
        .predict(fixture.project(), fixture.options(List.of(BAN)), fixture.resolver());
  }

  private Fixture fixture(final String traceContents) throws IOException {
    return fixture(traceContents, false);
  }

  private Fixture fixture(final String traceContents, final boolean usedReferencesBanned)
      throws IOException {
    return fixture(traceContents, usedReferencesBanned, false);
  }

  private Fixture fixture(
      final String traceContents, final boolean usedReferencesBanned, final boolean serviceProvider)
      throws IOException {
    return fixture(traceContents, usedReferencesBanned, serviceProvider, false);
  }

  private Fixture fixture(
      final String traceContents,
      final boolean usedReferencesBanned,
      final boolean retainedServiceProvider,
      final boolean bannedServiceProvider)
      throws IOException {
    final Path directory = Files.createTempDirectory(temporaryDirectory, "ban-");
    final Path usedJar =
        jar(
            directory.resolve("used.jar"),
            "used/Api",
            usedReferencesBanned,
            retainedServiceProvider ? "used.Api" : null);
    final Path bannedJar =
        jar(
            directory.resolve("banned.jar"),
            "banned/Idle",
            false,
            bannedServiceProvider ? "banned.Service" : null);
    final MavenProject project = new MavenProject();
    project.setGroupId(GROUP_ID);
    project.setArtifactId("consumer");
    project.setVersion(VERSION);
    project.setPackaging(JAR_TYPE);
    project.setFile(Files.createFile(directory.resolve("pom.xml")).toFile());
    project.getProperties().setProperty("maven.compiler.release", "17");
    final Build build = new Build();
    build.setDirectory(directory.resolve("target").toString());
    project.setBuild(build);
    final Dependency declared = new Dependency();
    declared.setGroupId(GROUP_ID);
    declared.setArtifactId("used");
    declared.setVersion(VERSION);
    project.getDependencies().add(declared);
    final Path sourceRoot = Files.createDirectories(directory.resolve("src"));
    Files.writeString(
        sourceRoot.resolve("App.java"), "public class App { private used.Api value; }\n");
    project.addCompileSourceRoot(sourceRoot.toString());
    final org.eclipse.aether.artifact.Artifact used = resolverArtifact("used", usedJar);
    final org.eclipse.aether.artifact.Artifact banned = resolverArtifact("banned", bannedJar);
    final org.eclipse.aether.graph.Dependency usedDependency =
        new org.eclipse.aether.graph.Dependency(used, "compile");
    final org.eclipse.aether.graph.Dependency bannedDependency =
        new org.eclipse.aether.graph.Dependency(banned, "runtime");
    final org.apache.maven.artifact.Artifact liveUsed =
        org.apache.maven.RepositoryUtils.toArtifact(used);
    liveUsed.setScope("compile");
    final org.apache.maven.artifact.Artifact liveBanned =
        org.apache.maven.RepositoryUtils.toArtifact(banned);
    liveBanned.setScope("runtime");
    project.setArtifacts(new LinkedHashSet<>(List.of(liveUsed, liveBanned)));
    project.setDependencyArtifacts(new LinkedHashSet<>(List.of(liveUsed)));
    final DefaultRepositorySystemSession repositorySession = new DefaultRepositorySystemSession();
    final DefaultMavenExecutionRequest request = new DefaultMavenExecutionRequest();
    request.setBaseDirectory(directory.toFile());
    final PlexusContainer container =
        (PlexusContainer)
            Proxy.newProxyInstance(
                Thread.currentThread().getContextClassLoader(),
                new Class<?>[] {PlexusContainer.class},
                (proxy, method, arguments) ->
                    "lookup".equals(method.getName()) ? new DefaultToolchainManager() : null);
    final MavenSession session = new MavenSession(container, repositorySession, request, null);
    session.setCurrentProject(project);
    final DefaultDependencyNode root =
        new DefaultDependencyNode(
            new org.eclipse.aether.artifact.DefaultArtifact(
                GROUP_ID, "consumer", "", "pom", VERSION));
    final DefaultDependencyNode direct = new DefaultDependencyNode(usedDependency);
    direct.setChildren(List.of(new DefaultDependencyNode(bannedDependency)));
    root.setChildren(List.of(direct));
    final ProjectDependenciesResolver resolver =
        resolutionRequest -> {
          final RepositorySystemSession detachedSession = resolutionRequest.getRepositorySession();
          final DependencyNode transformed;
          try {
            transformed =
                detachedSession
                    .getDependencyGraphTransformer()
                    .transformGraph(root, context(detachedSession));
          } catch (final org.eclipse.aether.RepositoryException exception) {
            throw new IllegalStateException("Cannot transform detached fixture", exception);
          }
          return result(List.of(usedDependency, bannedDependency), transformed);
        };
    final Path trace = directory.resolve("trace.lst");
    Files.writeString(trace, traceContents);
    return new Fixture(project, session, repositorySession, resolver, trace, root, usedDependency);
  }

  private static Path jar(
      final Path path,
      final String className,
      final boolean referencesBanned,
      final String serviceInterface)
      throws IOException {
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, className, null, "java/lang/Object", null);
    if (referencesBanned) {
      writer.visitField(Opcodes.ACC_PRIVATE, "dependency", "Lbanned/Idle;", null, null).visitEnd();
    }
    writer.visitEnd();
    try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(path))) {
      zip.putNextEntry(new ZipEntry(className + ".class"));
      zip.write(writer.toByteArray());
      zip.closeEntry();
      if (serviceInterface != null) {
        zip.putNextEntry(new ZipEntry("META-INF/services/" + serviceInterface));
        zip.write("banned.Idle\n".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        zip.closeEntry();
      }
    }
    return path;
  }

  private static org.eclipse.aether.artifact.Artifact resolverArtifact(
      final String artifactId, final Path file) {
    return new org.eclipse.aether.artifact.DefaultArtifact(
        GROUP_ID,
        artifactId,
        "",
        JAR_TYPE,
        VERSION,
        Map.of("type", JAR_TYPE, "constitutesBuildPath", "true"),
        file.toFile());
  }

  private static DependencyGraphTransformationContext context(
      final RepositorySystemSession session) {
    return (DependencyGraphTransformationContext)
        Proxy.newProxyInstance(
            Thread.currentThread().getContextClassLoader(),
            new Class<?>[] {DependencyGraphTransformationContext.class},
            (proxy, method, arguments) -> "getSession".equals(method.getName()) ? session : null);
  }

  private static DependencyResolutionResult result(
      final List<org.eclipse.aether.graph.Dependency> dependencies, final DependencyNode graph) {
    return (DependencyResolutionResult)
        Proxy.newProxyInstance(
            Thread.currentThread().getContextClassLoader(),
            new Class<?>[] {DependencyResolutionResult.class},
            (proxy, method, arguments) ->
                switch (method.getName()) {
                  case "getCollectionErrors", "getUnresolvedDependencies", "getResolutionErrors" ->
                      List.of();
                  case "getResolvedDependencies" -> dependencies;
                  case "getDependencyGraph" -> graph;
                  default -> null;
                });
  }

  private record Fixture(
      MavenProject project,
      MavenSession session,
      DefaultRepositorySystemSession repositorySession,
      ProjectDependenciesResolver resolver,
      Path trace,
      DefaultDependencyNode root,
      org.eclipse.aether.graph.Dependency usedDependency) {
    private AnalysisOptions options(final List<String> bans) {
      return options(bans, false);
    }

    private AnalysisOptions options(final List<String> bans, final boolean trim) {
      return options(bans, trim, false);
    }

    private AnalysisOptions options(
        final List<String> bans, final boolean trim, final boolean conservativeServiceRoots) {
      return new AnalysisOptions(
          List.of(trace.toFile()),
          List.of(),
          bans,
          null,
          session,
          new CompletenessOptions(true, false, false, true),
          new TrimOptions(
              trim,
              List.of(),
              false,
              List.of(),
              false,
              MavenDependencyTrimmer.DEFAULT_TRIM_WORKERS,
              MavenDependencyTrimmer.MRJAR_VERTICAL_SHADING),
          new DynamicRootOptions(conservativeServiceRoots));
    }
  }
}
