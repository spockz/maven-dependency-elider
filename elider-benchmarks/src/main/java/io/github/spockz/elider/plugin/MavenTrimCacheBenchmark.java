/* WHY: Measures the production Maven JAR-trim cache path so the sub-10ms lifecycle budget is
 * evaluated with exact artifact, platform, and trimmed-output validation. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.CacheProducerIdentity;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.AnalysisOptions;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.CompletenessOptions;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.DynamicRootOptions;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.TrimOptions;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.jar.JarFile;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import javax.tools.ToolProvider;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;
import org.apache.maven.execution.DefaultMavenExecutionRequest;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.model.Build;
import org.apache.maven.project.MavenProject;
import org.apache.maven.toolchain.Toolchain;
import org.apache.maven.toolchain.ToolchainManager;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.TearDown;

/** Benchmarks production Maven trim-cache hits with JMH-managed fixture state. */
@State(Scope.Thread)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@SuppressWarnings("PMD.ExcessiveImports")
public class MavenTrimCacheBenchmark {
  /** Synthetic package for benchmark fixture classes. */
  private static final String PACKAGE = "benchmark.fixture";

  /** Root class kept in the trimmed fixture JAR. */
  private static final String ROOT_CLASS = PACKAGE + ".CacheRoot";

  /** Number of trimmed archives produced by the fixture. */
  private static final int EXPECTED_TRIMMED_ARCHIVE_COUNT = 1;

  /** Temporary fixture directory cleaned up at teardown. */
  private Path fixtureDirectory;

  /** Synthetic Maven project for the benchmark fixture. */
  private MavenProject project;

  /** Trace file listing the single root class. */
  private Path trace;

  /** Warmed analysis reused across invocations. */
  private ElisionAnalysisModel.EffectiveAnalysis warmedAnalysis;

  /** Per-invocation fresh-session analysis. */
  private ElisionAnalysisModel.EffectiveAnalysis freshSessionAnalysis;

  /** Creates benchmark state before JMH setup runs. */
  public MavenTrimCacheBenchmark() {
    // JMH populates fixture state in @Setup.
  }

  /** Creates inputs and verifies cache population and warm validation. */
  @Setup
  public void setUp() throws IOException, org.apache.maven.plugin.MojoFailureException {
    final Path fixtureRoot = Files.createTempDirectory("elider-trim-cache-benchmark-");
    fixtureDirectory = fixtureRoot;
    final Path originalJar = BenchmarkFixture.createFixtureJar(fixtureRoot);
    final ArtifactCoordinate coordinate =
        new ArtifactCoordinate(PACKAGE, "trim-cache-input", "1.0", "jar", "", "runtime");
    final Artifact artifact = BenchmarkFixture.benchmarkArtifact(originalJar, coordinate);
    project = new MavenProject();
    project.setArtifacts(Set.of(artifact));
    project.setDependencyArtifacts(Set.of(artifact));
    project.setGroupId(PACKAGE);
    project.setArtifactId("trim-cache-consumer");
    project.setVersion("1.0");
    project.getProperties().setProperty("maven.compiler.release", "21");
    project.getProperties().setProperty("maven.compiler.proc", "none");
    final Build build = new Build();
    build.setDirectory(fixtureDirectory.resolve("build").toString());
    project.setBuild(build);
    trace = fixtureRoot.resolve("roots.txt");
    Files.writeString(trace, ROOT_CLASS + "\n");
    warmedAnalysis = analysis(newSession(), trace);
    final TrimResult cold = trim(warmedAnalysis);
    BenchmarkFixture.validateColdResult(cold, originalJar, EXPECTED_TRIMMED_ARCHIVE_COUNT);
    final TrimResult warm = trim(warmedAnalysis);
    if (warm.analysisRuns() != 0 || warm.cacheHits() != 1) {
      throw new IllegalStateException("Trim cache fixture did not pass the production warm path");
    }
  }

  /** Creates a fresh session analysis before each measured invocation. */
  @Setup(Level.Invocation)
  public void prepareFreshInvocation()
      throws IOException, org.apache.maven.plugin.MojoFailureException {
    freshSessionAnalysis = analysis(newSession(), trace);
  }

  /** Runs exact input/output digest validation and returns the cached trim records. */
  @Benchmark
  public TrimResult validatedMavenTrimCacheHit()
      throws IOException, org.apache.maven.plugin.MojoFailureException {
    return trim(warmedAnalysis);
  }

  /** Runs cache-hit trimming on a pre-analyzed fresh Maven session. */
  @Benchmark
  public TrimResult preparedAnalysisFreshSessionCacheHit()
      throws IOException, org.apache.maven.plugin.MojoFailureException {
    return trim(freshSessionAnalysis);
  }

  /** Measures full fresh-request analysis preparation plus validated trim cache hit. */
  @Benchmark
  public TrimResult freshRequestLifecycleCacheHit()
      throws IOException, org.apache.maven.plugin.MojoFailureException {
    final ElisionAnalysisModel.EffectiveAnalysis analysis = analysis(newSession(), trace);
    final TrimResult result = trim(analysis);
    if (result.analysisRuns() != 0 || result.cacheHits() != 1) {
      throw new IllegalStateException("Fresh lifecycle request did not hit the trim cache");
    }
    return result;
  }

  /** Removes the trial JAR and cache outputs after measurement. */
  @TearDown
  public void tearDown() throws IOException {
    if (fixtureDirectory != null) {
      try (Stream<Path> paths = Files.walk(fixtureDirectory)) {
        for (final Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
          Files.delete(path);
        }
      }
    }
  }

  private ElisionAnalysisModel.EffectiveAnalysis analysis(
      final MavenSession session, final Path trace)
      throws IOException, org.apache.maven.plugin.MojoFailureException {
    final AnalysisOptions options =
        new AnalysisOptions(
            List.of(trace.toFile()),
            List.of(),
            List.of(),
            null,
            session,
            new CompletenessOptions(false, false, false, true),
            new TrimOptions(
                true,
                List.of(),
                false,
                List.of(),
                false,
                MavenDependencyTrimmer.DEFAULT_TRIM_WORKERS,
                MavenDependencyTrimmer.MRJAR_VERTICAL_SHADING,
                new PluginCacheProducerIdentityResolver.Resolution(
                    Optional.of(new CacheProducerIdentity(PACKAGE, "trim-cache", "1.0", null)),
                    Optional.empty())),
            new DynamicRootOptions(false));
    final MavenElisionService service = new MavenElisionService();
    return service.finishAnalysis(service.prepare(project, options));
  }

  private static TrimResult trim(final ElisionAnalysisModel.EffectiveAnalysis effective)
      throws IOException, org.apache.maven.plugin.MojoFailureException {
    return MavenDependencyTrimmer.trimEffectiveOutputs(effective);
  }

  private MavenSession newSession() {
    return new BenchmarkSession(new DefaultMavenExecutionRequest(), project);
  }

  /** Minimal MavenSession stub supplying a no-op ToolchainManager. */
  private static final class BenchmarkSession extends MavenSession {
    /** No-op toolchain manager for isolated trim-cache benchmark sessions. */
    private static final ToolchainManager TOOLCHAIN_MANAGER =
        new ToolchainManager() {
          @Override
          public Toolchain getToolchainFromBuildContext(
              final String type, final MavenSession session) {
            return null;
          }

          @Override
          public List<Toolchain> getToolchains(
              final MavenSession session,
              final String type,
              final java.util.Map<String, String> requirements) {
            return List.of();
          }
        };

    private BenchmarkSession(
        final DefaultMavenExecutionRequest request, final MavenProject project) {
      super(null, request, null, project);
    }

    @Override
    public Object lookup(final String role) {
      return TOOLCHAIN_MANAGER;
    }
  }

  /** Fixture compilation, packaging, and cold-path validation helpers. */
  private static final class BenchmarkFixture {
    private static void validateColdResult(
        final TrimResult cold, final Path originalJar, final int expectedArchiveCount)
        throws IOException {
      if (cold.records().size() != expectedArchiveCount) {
        throw new IllegalStateException("Trim cache fixture did not produce one trimmed archive");
      }
      final boolean archivePruned;
      try (JarFile trimmed = new JarFile(cold.records().getFirst().trimmedPath().toFile())) {
        archivePruned =
            trimmed.getEntry("benchmark/fixture/CacheRoot.class") != null
                && trimmed.getEntry("benchmark/fixture/CacheUnused.class") == null;
      }
      if (cold.analysisRuns() == 0
          || cold.cacheHits() != 0
          || !archivePruned
          || Files.size(cold.records().getFirst().trimmedPath()) >= Files.size(originalJar)) {
        throw new IllegalStateException("Trim cache fixture failed cold-path validation");
      }
    }

    private static Artifact benchmarkArtifact(
        final Path originalJar, final ArtifactCoordinate coordinate) {
      final Artifact artifact =
          new DefaultArtifact(
              coordinate.groupId(),
              coordinate.artifactId(),
              coordinate.version(),
              coordinate.scope(),
              coordinate.type(),
              null,
              new DefaultArtifactHandler("jar"));
      artifact.setFile(originalJar.toFile());
      return artifact;
    }

    private static Path createFixtureJar(final Path fixtureRoot) throws IOException {
      final Path sourceDirectory = fixtureRoot.resolve("src");
      final Path classesDirectory = fixtureRoot.resolve("classes");
      final Path packageDirectory = sourceDirectory.resolve("benchmark/fixture");
      Files.createDirectories(packageDirectory);
      Files.createDirectories(classesDirectory);
      final Path rootSource = packageDirectory.resolve("CacheRoot.java");
      final Path unusedSource = packageDirectory.resolve("CacheUnused.java");
      Files.writeString(rootSource, "package benchmark.fixture; final class CacheRoot {}\n");
      Files.writeString(unusedSource, "package benchmark.fixture; final class CacheUnused {}\n");
      final int compileResult =
          ToolProvider.getSystemJavaCompiler()
              .run(
                  null,
                  null,
                  null,
                  "--release",
                  "21",
                  "-proc:none",
                  "-d",
                  classesDirectory.toString(),
                  rootSource.toString(),
                  unusedSource.toString());
      if (compileResult != 0) {
        throw new IOException("Could not compile the trim cache benchmark fixture");
      }
      final Path jarPath = fixtureRoot.resolve("trim-cache-input.jar");
      try (ZipOutputStream archive = new ZipOutputStream(Files.newOutputStream(jarPath));
          Stream<Path> files = Files.walk(classesDirectory)) {
        for (final Path classFile : files.filter(Files::isRegularFile).toList()) {
          writeJarEntry(archive, classesDirectory, classFile);
        }
      }
      return jarPath;
    }

    private static void writeJarEntry(
        final ZipOutputStream archive, final Path classesDirectory, final Path classFile)
        throws IOException {
      final String entryName = classesDirectory.relativize(classFile).toString().replace('\\', '/');
      archive.putNextEntry(new ZipEntry(entryName));
      Files.copy(classFile, archive);
      archive.closeEntry();
    }
  }
}
