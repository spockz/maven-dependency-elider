/* WHY: Compares the production and former JarFile scanners on identical archive inputs. */

package io.github.spockz.elider.plugin.nativeimage;

import io.github.spockz.elider.plugin.nativeimage.DependencyDynamicRoots.RootScan;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.concurrent.TimeUnit;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.stream.Stream;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OperationsPerInvocation;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.TearDown;
import org.openjdk.jmh.annotations.Warmup;

/** Measures raw GC work over equal archive scan workloads. */
@BenchmarkMode(Mode.SingleShotTime)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@Warmup(iterations = 5, batchSize = DependencyDynamicRootsBenchmark.SCANS_PER_BATCH)
@Measurement(iterations = 5, batchSize = DependencyDynamicRootsBenchmark.SCANS_PER_BATCH)
@OperationsPerInvocation(DependencyDynamicRootsBenchmark.SCANS_PER_BATCH)
@Fork(
    value = 2,
    jvmArgsAppend = {"-Xms512m", "-Xmx512m"})
@State(Scope.Benchmark)
public class DependencyDynamicRootsBenchmark {
  /** Keeps measurement, warm-up, and per-scan normalization in sync. */
  /* package */ static final int SCANS_PER_BATCH = 30_000;

  /** Holds benchmark-local fixtures outside the build outputs. */
  private Path fixtureDirectory;

  /** Archive containing no dynamic metadata. */
  private Path ordinaryJar;

  /** Archive containing service and reflection declarations. */
  private Path metadataJar;

  /** Excludes scan-context setup from ordinary archive measurements. */
  private NativeImageScanContext ordinaryContext;

  /** Excludes scan-context setup from metadata archive measurements. */
  private NativeImageScanContext metadataContext;

  /** Creates benchmark state before JMH setup runs. */
  public DependencyDynamicRootsBenchmark() {
    // JMH initializes fixtures outside the measured workload.
  }

  /** Builds equivalent archive inventories with and without dynamic-root metadata. */
  @Setup
  public void setUp() throws IOException {
    fixtureDirectory = Files.createTempDirectory("elider-dynamic-roots-bench-");
    ordinaryJar = fixtureDirectory.resolve("ordinary.jar");
    metadataJar = fixtureDirectory.resolve("metadata.jar");
    writeFixture(ordinaryJar, false);
    writeFixture(metadataJar, true);
    ordinaryContext = NativeImageScanContext.singleArchive(ordinaryJar);
    metadataContext = NativeImageScanContext.singleArchive(metadataJar);
  }

  private static void writeFixture(final Path jar, final boolean includeMetadata)
      throws IOException {
    try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(jar))) {
      for (int file = 0; file < 256; file++) {
        writeEntry(output, "assets/fixture-" + file + ".txt", "ordinary resource");
      }
      if (includeMetadata) {
        writeEntry(output, "META-INF/services/sample.Service", "sample.Provider\n");
        writeEntry(
            output,
            "META-INF/native-image/example/library/reflect-config.json",
            "[{\"name\":\"sample.Reflective\"}]");
      }
    }
  }

  private static void writeEntry(final JarOutputStream output, final String name, final String body)
      throws IOException {
    output.putNextEntry(new JarEntry(name));
    output.write(body.getBytes(StandardCharsets.UTF_8));
    output.closeEntry();
  }

  /** Scans an ordinary archive with the production scanner. */
  @Benchmark
  public RootScan currentOrdinaryJarScan() throws IOException {
    return DependencyDynamicRoots.scan(ordinaryJar, ordinaryContext);
  }

  /** Scans the same ordinary archive with the former production scanner. */
  @Benchmark
  public RootScan referenceOrdinaryJarScan() throws IOException {
    return ReferenceDependencyDynamicRoots.scan(ordinaryJar, ordinaryContext);
  }

  /** Scans an archive with unique metadata using the production scanner. */
  @Benchmark
  public RootScan currentMetadataJarScan() throws IOException {
    return DependencyDynamicRoots.scan(metadataJar, metadataContext);
  }

  /** Scans the same metadata with the former production scanner. */
  @Benchmark
  public RootScan referenceMetadataJarScan() throws IOException {
    return ReferenceDependencyDynamicRoots.scan(metadataJar, metadataContext);
  }

  /** Removes temporary benchmark archives. */
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
}
