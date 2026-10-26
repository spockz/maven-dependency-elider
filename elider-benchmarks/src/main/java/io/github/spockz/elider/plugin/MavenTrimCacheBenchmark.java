/* WHY: Measures the production Maven JAR-trim cache path so the sub-10ms lifecycle budget is
 * evaluated with exact artifact, platform, and trimmed-output validation. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ArtifactFileRef;
import io.github.spockz.elider.model.TraceData;
import io.github.spockz.elider.scanner.ArtifactClassIndex;
import io.github.spockz.elider.scanner.JarIndexScanner;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import javax.tools.ToolProvider;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;
import org.apache.maven.model.Build;
import org.apache.maven.project.MavenProject;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.TearDown;

/** Benchmarks the actual Maven dependency-JAR trim cache-hit operation. */
@State(Scope.Benchmark)
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

  private Path fixtureDirectory;
  private MavenProject project;
  private List<MavenElisionService.ArtifactSnapshot> candidates;
  private ArtifactClassIndex classIndex;
  private ArtifactCoordinate coordinate;
  private TraceData trace;

  /** Creates inputs and verifies cache population and warm validation. */
  @Setup
  public void setUp() throws IOException, org.apache.maven.plugin.MojoFailureException {
    final Path fixtureRoot = Files.createTempDirectory("elider-trim-cache-benchmark-");
    fixtureDirectory = fixtureRoot;
    final Path originalJar = createFixtureJar(fixtureRoot);
    coordinate = ArtifactCoordinate.of("benchmark.fixture", "trim-cache-input", "1.0");
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
    project = new MavenProject();
    project.setArtifacts(new LinkedHashSet<>(List.of(artifact)));
    project.setDependencyArtifacts(new LinkedHashSet<>(List.of(artifact)));
    project.setGroupId("benchmark.fixture");
    project.setArtifactId("trim-cache-consumer");
    project.setVersion("1.0");
    project.getProperties().setProperty("maven.compiler.release", "21");
    project.getProperties().setProperty("maven.compiler.proc", "none");
    final Build build = new Build();
    build.setDirectory(fixtureDirectory.resolve("build").toString());
    project.setBuild(build);
    candidates =
        List.of(new MavenElisionService.ArtifactSnapshot(artifact, coordinate, originalJar));
    final ArtifactFileRef fileRef = ArtifactFileRef.fromPath(coordinate, originalJar);
    classIndex = new JarIndexScanner().scan(List.of(fileRef));
    trace = TraceData.of(Set.of(ROOT_CLASS));
    final MavenDependencyTrimmer.TrimResult cold = trim();
    if (cold.analysisRuns() == 0 || cold.cacheHits() != 0) {
      throw new IllegalStateException("Trim cache fixture did not populate via ProGuard analysis");
    }
    final MavenDependencyTrimmer.TrimResult warm = trim();
    if (warm.analysisRuns() != 0 || warm.cacheHits() != 1) {
      throw new IllegalStateException("Trim cache fixture did not pass the production warm path");
    }
  }

  /** Runs exact input/output digest validation and returns the cached trim records. */
  @Benchmark
  public MavenDependencyTrimmer.TrimResult validatedMavenTrimCacheHit()
      throws IOException, org.apache.maven.plugin.MojoFailureException {
    return trim();
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

  private MavenDependencyTrimmer.TrimResult trim()
      throws IOException, org.apache.maven.plugin.MojoFailureException {
    return MavenDependencyTrimmer.trim(
        new MavenDependencyTrimmer.TrimRequest(
            project,
            null,
            candidates,
            classIndex,
            Set.of(coordinate),
            trace,
            Set.of(ROOT_CLASS),
            Set.of(),
            List.of(),
            false,
            List.of(),
            false));
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
