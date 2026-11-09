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
// JMH invokes the implicit constructor for this public benchmark state.
@SuppressWarnings({
  "PMD.CommentRequired",
  "PMD.ExcessiveImports",
  "PMD.AvoidInstantiatingObjectsInLoops",
  "PMD.AtLeastOneConstructor"
})
public class MavenTrimCacheBenchmark {
  private static final String PACKAGE = "benchmark.fixture";
  private static final String ROOT_CLASS = PACKAGE + ".CacheRoot";
  private static final int EXPECTED_TRIMMED_ARCHIVE_COUNT = 1;

  private Path fixtureDirectory;
  private MavenProject project;
  private Path trace;
  private ElisionAnalysisModel.EffectiveAnalysis warmedAnalysis;
  private ElisionAnalysisModel.EffectiveAnalysis freshSessionAnalysis;

  /** Creates inputs and verifies cache population and warm validation. */
  // WHY: Setup verifies the cold and warm invariants before JMH records timings.
  @SuppressWarnings("PMD.CyclomaticComplexity")
  @Setup
  public void setUp() throws IOException, org.apache.maven.plugin.MojoFailureException {
    final Path fixtureRoot = Files.createTempDirectory("elider-trim-cache-benchmark-");
    fixtureDirectory = fixtureRoot;
    final Path originalJar = createFixtureJar(fixtureRoot);
    final ArtifactCoordinate coordinate =
        new ArtifactCoordinate(PACKAGE, "trim-cache-input", "1.0", "jar", "", "runtime");
    final Artifact artifact = benchmarkArtifact(originalJar, coordinate);
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
    if (cold.records().size() != EXPECTED_TRIMMED_ARCHIVE_COUNT) {
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
    final TrimResult warm = trim(warmedAnalysis);
    if (warm.analysisRuns() != 0 || warm.cacheHits() != 1) {
      throw new IllegalStateException("Trim cache fixture did not pass the production warm path");
    }
  }

  /** Warms a fresh session before each measured invocation. */
  @Setup(Level.Invocation)
  public void prepareFreshInvocation()
      throws IOException, org.apache.maven.plugin.MojoFailureException {
    freshSessionAnalysis = analysis(newSession(), trace);
    final TrimResult freshWarm = trim(freshSessionAnalysis);
    if (freshWarm.analysisRuns() != 0 || freshWarm.cacheHits() != 1) {
      throw new IllegalStateException(
          "Fresh Maven session did not reuse the production trim cache");
    }
  }

  /** Runs exact input/output digest validation and returns the cached trim records. */
  @Benchmark
  public TrimResult validatedMavenTrimCacheHit()
      throws IOException, org.apache.maven.plugin.MojoFailureException {
    return trim(warmedAnalysis);
  }

  /** Runs the same cache hit with a fresh single-project Maven execution request. */
  @Benchmark
  public TrimResult validatedFreshMavenTrimCacheHit()
      throws IOException, org.apache.maven.plugin.MojoFailureException {
    return trim(freshSessionAnalysis);
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

  private Artifact benchmarkArtifact(final Path originalJar, final ArtifactCoordinate coordinate) {
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

  private MavenSession newSession() {
    return new BenchmarkSession(new DefaultMavenExecutionRequest(), project);
  }

  private static final class BenchmarkSession extends MavenSession {
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

    @SuppressWarnings("PMD.CommentDefaultAccessModifier")
    BenchmarkSession(final DefaultMavenExecutionRequest request, final MavenProject project) {
      super(null, request, null, project);
    }

    @Override
    public Object lookup(final String role) {
      return TOOLCHAIN_MANAGER;
    }
  }

  private Path createFixtureJar(final Path fixtureRoot) throws IOException {
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
        final String entryName =
            classesDirectory.relativize(classFile).toString().replace('\\', '/');
        archive.putNextEntry(new ZipEntry(entryName));
        Files.copy(classFile, archive);
        archive.closeEntry();
      }
    }
    return jarPath;
  }
}
