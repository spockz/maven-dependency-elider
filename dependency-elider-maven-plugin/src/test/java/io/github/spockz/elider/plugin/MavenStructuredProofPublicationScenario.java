// WHY: Runs the real Mojo publication path with a synthetic, schema-pinned source advisory.

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.CacheProducerIdentity;
import io.github.spockz.elider.scanner.VulnerabilityCacheEnvelope;
import io.github.spockz.elider.scanner.VulnerabilityCacheEnvelopeReader;
import io.github.spockz.elider.scanner.VulnerabilityCacheEnvelopeWriter;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.execution.DefaultMavenExecutionRequest;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.model.Build;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.project.MavenProject;
import org.apache.maven.toolchain.ToolchainManager;
import org.codehaus.plexus.PlexusContainer;
import org.eclipse.aether.DefaultRepositorySystemSession;
import org.eclipse.aether.RepositorySystem;

/** Builds one published result through the configured exact source resolver. */
@SuppressWarnings("PMD.CouplingBetweenObjects")
final class MavenStructuredProofPublicationScenario {
  /** JSON mapper used for fixture and output inspection. */
  private static final ObjectMapper JSON = new ObjectMapper();

  /** Test plugin identity written into the source fixture cache envelope. */
  private static final CacheProducerIdentity PRODUCER =
      new CacheProducerIdentity(
          "io.github.spockz", "dependency-elider-maven-plugin", "1.0.0", null);

  /** Name requested through Plexus when Maven constructs the Mojo. */
  private static final String TOOLCHAIN_LOOKUP = "lookup";

  private MavenStructuredProofPublicationScenario() {
    throw new AssertionError("No instances");
  }

  /* default */ static PublishedResult publish(final Path temporaryDirectory)
      throws IOException,
          ReflectiveOperationException,
          MojoExecutionException,
          MojoFailureException {
    final Path run = temporaryDirectory.resolve("published-structured-proof");
    final MavenCorroboratedSourceScenario.Prepared prepared =
        MavenCorroboratedSourceScenario.prepareReproducibleClaim(
            run, List.of(MavenSourceCorrespondenceTestArtifacts.SOURCE_ENTRY), List.of("parse"));
    final JsonNode syntheticCve = JSON.readTree(prepared.cveRecord().toFile());
    final Set<?> cveSchemaErrors = CveRecordFormatSchema.validate(syntheticCve);
    final MavenSourceCorrespondenceTestArtifacts.Archives archives =
        MavenSourceCorrespondenceTestArtifacts.write(run, false, false, false, true);
    final Path trace = run.resolve("runtime.lst");
    Files.writeString(trace, "org.example.HeuristicOnly\n");
    rebindCacheProducer(prepared.cacheConfig().cacheDirectory());
    MavenStructuredProofScenario.copyCurrentCveRecord(prepared);

    final PublicationPaths paths =
        publicationPaths(run, prepared.coordinate(), archives.originalJar(), trace);
    final AtomicInteger sourceResolutions = new AtomicInteger();
    final org.eclipse.aether.repository.RemoteRepository sourceRepository =
        new org.eclipse.aether.repository.RemoteRepository.Builder(
                "publication-source-fixture", "default", "https://repo.example.invalid/maven2")
            .build();
    final RepositorySystem resolver =
        MavenSourceCorrespondenceTestArtifacts.resolver(
            archives.sourcesJar(),
            sourceRepository,
            ignored -> sourceResolutions.incrementAndGet());
    final ElideMojo mojo = new ElideMojo();
    final RecordingMavenLog log = new RecordingMavenLog(true);
    configureMojo(mojo, paths, prepared, resolver, log);
    mojo.execute();

    return new PublishedResult(
        paths,
        sourceResolutions.get(),
        syntheticCve,
        cveSchemaErrors,
        MavenElisionReportWriter.read(paths.summary()),
        JSON.readTree(paths.sbom().toFile()),
        JSON.readTree(paths.vex().toFile()),
        JSON.readTree(paths.manifest().toFile()),
        log.debugMessages());
  }

  private static void rebindCacheProducer(final Path cacheDirectory) throws IOException {
    final Path index = cacheDirectory.resolve("index.json");
    final byte[] currentEnvelope = Files.readAllBytes(index);
    final VulnerabilityCacheEnvelope envelope =
        new VulnerabilityCacheEnvelopeReader()
            .read(
                new ByteArrayInputStream(currentEnvelope), MavenAssessmentFixtures.CACHE_PRODUCER);
    Files.write(index, new VulnerabilityCacheEnvelopeWriter().encode(PRODUCER, envelope.records()));
  }

  private static PublicationPaths publicationPaths(
      final Path run, final ArtifactCoordinate coordinate, final Path originalJar, final Path trace)
      throws IOException {
    final Path projectRoot = Files.createDirectories(run.resolve("consumer"));
    final Path buildDirectory = Files.createDirectories(projectRoot.resolve("target"));
    final MavenProject project = new MavenProject();
    project.setFile(projectRoot.resolve("pom.xml").toFile());
    project.setGroupId("org.example");
    project.setArtifactId("consumer");
    project.setVersion("1.0");
    project.setName("Consumer");
    project.setPackaging("jar");
    project.getProperties().setProperty("maven.compiler.release", "21");
    project.getProperties().setProperty("maven.compiler.proc", "none");
    final Artifact artifact =
        new DefaultArtifact(
            coordinate.groupId(),
            coordinate.artifactId(),
            coordinate.version(),
            "runtime",
            coordinate.type(),
            coordinate.classifier().isEmpty() ? null : coordinate.classifier(),
            new org.apache.maven.artifact.handler.DefaultArtifactHandler(coordinate.type()));
    artifact.setFile(originalJar.toFile());
    final Set<Artifact> artifacts = new LinkedHashSet<>(List.of(artifact));
    project.setArtifacts(artifacts);
    project.setDependencyArtifacts(new LinkedHashSet<>(artifacts));
    final Build build = new Build();
    build.setDirectory(buildDirectory.toString());
    build.setOutputDirectory(buildDirectory.resolve("classes").toString());
    build.setTestOutputDirectory(buildDirectory.resolve("test-classes").toString());
    project.setBuild(build);
    final MavenSession session = newSession(project);
    return new PublicationPaths(
        project,
        session,
        trace,
        buildDirectory.resolve("dependency-elider-report.json"),
        buildDirectory.resolve("dependency-elider-class-usage.json"),
        buildDirectory.resolve("dependency-elider-sbom.cdx.json"),
        buildDirectory.resolve("baseline-sbom.cdx.json"),
        buildDirectory.resolve("dependency-elider.openvex.json"),
        MavenGeneratedOutputs.manifestPath(project));
  }

  private static void configureMojo(
      final ElideMojo mojo,
      final PublicationPaths paths,
      final MavenCorroboratedSourceScenario.Prepared prepared,
      final RepositorySystem resolver,
      final RecordingMavenLog log)
      throws ReflectiveOperationException {
    mojo.setLog(log);
    set(mojo, "project", paths.project());
    set(mojo, "session", paths.session());
    set(mojo, "traceFiles", List.of(paths.trace().toFile()));
    set(mojo, "trimJars", true);
    set(mojo, "leafOnly", false);
    set(mojo, "assumeConventionalJavaSourceLayout", true);
    set(mojo, "reportFile", paths.classUsage().toFile());
    set(mojo, "summaryFile", paths.summary().toFile());
    set(mojo, "sbomFile", paths.sbom().toFile());
    set(mojo, "baselineSbomFile", paths.baselineSbom().toFile());
    set(mojo, "vexFile", paths.vex().toFile());
    set(mojo, "cveCacheDirectory", prepared.cacheConfig().cacheDirectory().toFile());
    set(mojo, "osvSnapshotUri", null);
    set(mojo, "cveListGitUri", null);
    set(
        PluginCacheMojoSupport.class,
        mojo,
        "pluginDescriptor",
        MavenPluginDescriptorFixtures.releasedPluginDescriptor());
    set(PluginCacheMojoSupport.class, mojo, "repositorySystem", resolver);
    set(
        mojo,
        "planPublication",
        (ElideMojo.PlanPublication)
            (ignoredSession, ignoredProject, ignoredRecords, ignoredProjection) -> {});
  }

  private static MavenSession newSession(final MavenProject project) {
    final DefaultMavenExecutionRequest request = new DefaultMavenExecutionRequest();
    request.setOffline(true);
    final MavenSession session =
        new MavenSession(testContainer(), new DefaultRepositorySystemSession(), request, null);
    session.setCurrentProject(project);
    return session;
  }

  @SuppressWarnings("PMD.UseProperClassLoader")
  private static PlexusContainer testContainer() {
    return (PlexusContainer)
        Proxy.newProxyInstance(
            PlexusContainer.class.getClassLoader(),
            new Class<?>[] {PlexusContainer.class},
            (proxy, method, arguments) -> {
              if (TOOLCHAIN_LOOKUP.equals(method.getName())) {
                return Proxy.newProxyInstance(
                    ToolchainManager.class.getClassLoader(),
                    new Class<?>[] {ToolchainManager.class},
                    (manager, managerMethod, managerArguments) -> null);
              }
              return null;
            });
  }

  private static void set(final Object target, final String name, final Object value)
      throws ReflectiveOperationException {
    set(target.getClass(), target, name, value);
  }

  @SuppressWarnings("PMD.AvoidAccessibilityAlteration")
  private static void set(
      final Class<?> declaringType, final Object target, final String name, final Object value)
      throws ReflectiveOperationException {
    final Field field = declaringType.getDeclaredField(name);
    field.setAccessible(true);
    field.set(target, value);
  }

  /* default */ record PublicationPaths(
      MavenProject project,
      MavenSession session,
      Path trace,
      Path summary,
      Path classUsage,
      Path sbom,
      Path baselineSbom,
      Path vex,
      Path manifest) {}

  /* default */ record PublishedResult(
      PublicationPaths paths,
      int sourceResolutions,
      JsonNode syntheticCve,
      Set<?> cveSchemaErrors,
      MavenElisionReportSnapshot report,
      JsonNode cycloneDx,
      JsonNode openVex,
      JsonNode manifestDocument,
      List<String> diagnostics) {}
}
