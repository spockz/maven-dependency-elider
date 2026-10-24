// WHY: Compares equivalent parallel and sequential central-directory class indexing over local
// fixtures without depending on repository artifacts or the network.

package io.github.spockz.elider.benchmark;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ArtifactFileRef;
import io.github.spockz.elider.scanner.JarIndexScanner;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.TearDown;

/** Benchmarks parallel and sequential JAR indexing. */
@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@SuppressWarnings({"PMD.CommentRequired", "PMD.AvoidInstantiatingObjectsInLoops"})
public class ZipCenScannerBenchmark {
  private static final int JAR_COUNT = 100;
  private static final int CLASS_COUNT_PER_JAR = 32;

  /** Temporary root containing the trial's JAR files. */
  private Path fixtureDirectory;

  /** Artifact refs consumed by the production scanner. */
  private List<ArtifactFileRef> artifacts;

  /** Production scanner instance reused between benchmark invocations. */
  private final JarIndexScanner scanner = new JarIndexScanner();

  /** Creates benchmark state before its trial fixtures are populated. */
  public ZipCenScannerBenchmark() {
    artifacts = List.of();
  }

  /** Creates deterministic, local JAR fixtures once per benchmark trial. */
  @Setup
  public void setUp() throws IOException {
    fixtureDirectory = Files.createTempDirectory("elider-cen-benchmark-");
    artifacts = new ArrayList<>(JAR_COUNT);
    for (int jarIndex = 0; jarIndex < JAR_COUNT; jarIndex++) {
      final Path jarPath = fixtureDirectory.resolve("fixture-%03d.jar".formatted(jarIndex));
      createFixtureJar(jarPath, jarIndex);
      artifacts.add(
          ArtifactFileRef.fromPath(
              ArtifactCoordinate.of("benchmark.fixture", "fixture-" + jarIndex, "1.0"), jarPath));
    }
  }

  /** Removes the trial's temporary JARs after JMH has finished using the fixture. */
  @TearDown
  public void tearDown() throws IOException {
    if (fixtureDirectory != null) {
      try (java.util.stream.Stream<Path> paths = Files.walk(fixtureDirectory)) {
        for (final Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
          Files.delete(path);
        }
      }
    }
  }

  /** Includes parallel task creation, JAR opening, class name normalization, and index assembly. */
  @SuppressWarnings("PMD.CommentSize")
  @Benchmark
  public int scannerClassIndex() throws IOException {
    return scanner.scan(artifacts).classesByArtifact().values().stream()
        .mapToInt(java.util.Set::size)
        .sum();
  }

  /** Uses production extraction and assembly without parallel scheduling. */
  @Benchmark
  public int sequentialClassIndex() throws IOException {
    return scanner.scanSequential(artifacts).classesByArtifact().values().stream()
        .mapToInt(java.util.Set::size)
        .sum();
  }

  private static void createFixtureJar(final Path jarPath, final int jarIndex) throws IOException {
    try (OutputStream output = Files.newOutputStream(jarPath);
        ZipOutputStream zip = new ZipOutputStream(output)) {
      for (int classIndex = 0; classIndex < CLASS_COUNT_PER_JAR; classIndex++) {
        final String entryName = "fixture/%03d/Type%03d.class".formatted(jarIndex, classIndex);
        final ZipEntry classEntry = new ZipEntry(entryName);
        classEntry.setTime(0);
        zip.putNextEntry(classEntry);
        zip.write(new byte[] {(byte) jarIndex, (byte) classIndex});
        zip.closeEntry();
      }
      final ZipEntry dataEntry = new ZipEntry("fixture/%03d/data.txt".formatted(jarIndex));
      dataEntry.setTime(0);
      zip.putNextEntry(dataEntry);
      zip.write("deterministic fixture".getBytes(java.nio.charset.StandardCharsets.UTF_8));
      zip.closeEntry();
    }
  }
}
