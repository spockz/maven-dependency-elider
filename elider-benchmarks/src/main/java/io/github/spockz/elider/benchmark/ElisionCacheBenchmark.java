/* WHY: Measures cache fingerprinting and decision decoding over realistic local fixture sizes. */

package io.github.spockz.elider.benchmark;

import io.github.spockz.elider.cache.ElisionCache;
import io.github.spockz.elider.cache.FingerprintEngine;
import io.github.spockz.elider.engine.PruneConfig;
import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ArtifactFileRef;
import io.github.spockz.elider.model.ElisionDecision;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.TearDown;

/** Benchmarks the core cache API without invoking the Maven plugin. */
@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@SuppressWarnings("PMD.CommentRequired")
public class ElisionCacheBenchmark {
  private static final int ARTIFACT_COUNT = 100;
  private static final int RETAINED_ARTIFACT_COUNT = 70;
  private static final int CLASS_COUNT_PER_ARTIFACT = 32;
  private static final String SEMANTICS_VERSION = "benchmark-cache-v1";

  private Path fixtureDirectory;
  private Path cacheFile;
  private List<ArtifactFileRef> artifacts;
  private Set<ArtifactCoordinate> inventory;
  private List<Path> tracePaths;
  private PruneConfig config;
  private ElisionCache cache;
  private long fingerprint;

  /** Creates fixture state once per benchmark trial. */
  public ElisionCacheBenchmark() {
    artifacts = List.of();
    inventory = Set.of();
    tracePaths = List.of();
    config = new PruneConfig();
    cache = new ElisionCache();
  }

  /** Creates cache fixtures outside measured operations. */
  @Setup
  @SuppressWarnings("PMD.UseConcurrentHashMap")
  public void setUp() throws IOException {
    fixtureDirectory = Files.createTempDirectory("elider-cache-benchmark-");
    cacheFile = fixtureDirectory.resolve("decision.cache");
    artifacts = new ArrayList<>(ARTIFACT_COUNT);
    inventory = new HashSet<>(ARTIFACT_COUNT);
    final Set<ArtifactCoordinate> retained = new HashSet<>();
    final Set<ArtifactCoordinate> elided = new HashSet<>();
    final Map<ArtifactCoordinate, Set<String>> usedClasses = new HashMap<>(ARTIFACT_COUNT);
    final Map<ArtifactCoordinate, Set<String>> unusedClasses = new HashMap<>(ARTIFACT_COUNT);
    for (int artifactIndex = 0; artifactIndex < ARTIFACT_COUNT; artifactIndex++) {
      final ArtifactCoordinate coordinate =
          ArtifactCoordinate.of("benchmark.fixture", "fixture-" + artifactIndex, "1.0.0");
      final Path artifactPath =
          fixtureDirectory.resolve("fixture-%03d.jar".formatted(artifactIndex));
      Files.writeString(artifactPath, "fixture artifact " + artifactIndex, StandardCharsets.UTF_8);
      artifacts.add(ArtifactFileRef.fromPath(coordinate, artifactPath));
      inventory.add(coordinate);
      if (artifactIndex < RETAINED_ARTIFACT_COUNT) {
        retained.add(coordinate);
      } else {
        elided.add(coordinate);
      }
      usedClasses.put(coordinate, classNames(artifactIndex, "Used", CLASS_COUNT_PER_ARTIFACT / 2));
      unusedClasses.put(
          coordinate, classNames(artifactIndex, "Unused", CLASS_COUNT_PER_ARTIFACT / 2));
    }
    tracePaths = List.of();
    config = new PruneConfig();
    cache = new ElisionCache();
    fingerprint = FingerprintEngine.fingerprint(artifacts, tracePaths, config, SEMANTICS_VERSION);
    final ElisionDecision expectedDecision =
        new ElisionDecision(retained, elided, usedClasses, unusedClasses, 2_500_000L);
    cache.store(cacheFile, fingerprint, inventory, expectedDecision);
    final ElisionCache.Lookup fixtureLookup = cache.load(cacheFile, fingerprint, inventory);
    if (!fixtureLookup.hit() || !expectedDecision.equals(fixtureLookup.decision())) {
      throw new IllegalStateException("Cache benchmark fixture did not load its stored decision");
    }
  }

  /** Removes trial files after all benchmark methods complete. */
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

  /** Fingerprints current metadata for all fixture artifacts. */
  @Benchmark
  public long freshMetadataFingerprinting() throws IOException {
    return FingerprintEngine.fingerprint(artifacts, tracePaths, config, SEMANTICS_VERSION);
  }

  /** Reads, checks, decodes, and validates the complete cached decision. */
  @Benchmark
  public ElisionCache.Lookup completeDecisionCacheLoad() throws IOException {
    return cache.load(cacheFile, fingerprint, inventory);
  }

  /** Measures fresh metadata fingerprinting followed by a complete cache lookup. */
  @Benchmark
  public ElisionCache.Lookup fingerprintAndCacheLookup() throws IOException {
    final long currentFingerprint =
        FingerprintEngine.fingerprint(artifacts, tracePaths, config, SEMANTICS_VERSION);
    return cache.load(cacheFile, currentFingerprint, inventory);
  }

  private static Set<String> classNames(
      final int artifactIndex, final String category, final int classCount) {
    final Set<String> classNames = new HashSet<>(classCount);
    for (int classIndex = 0; classIndex < classCount; classIndex++) {
      classNames.add(
          "benchmark.fixture.artifact%03d.%s%03d".formatted(artifactIndex, category, classIndex));
    }
    return classNames;
  }
}
