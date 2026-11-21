/* WHY: Checks comparative JMH measurements against a production reference. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.plugin.nativeimage.DependencyDynamicRootsBenchmark;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import org.openjdk.jmh.profile.GCProfiler;
import org.openjdk.jmh.results.Result;
import org.openjdk.jmh.results.RunResult;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.ChainedOptionsBuilder;
import org.openjdk.jmh.runner.options.OptionsBuilder;

/**
 * Runs comparative JMH benchmarks and enforces two invariants for every pair.
 *
 * <ul>
 *   <li>No dimension may regress (time, CPU, allocation, GC).
 *   <li>At least one dimension must improve by the required factor.
 * </ul>
 */
public final class BenchmarkComparisonVerifier {
  /** JMH GCProfiler key for normalized heap bytes allocated per op. */
  private static final String GC_ALLOC_RATE_NORM = "gc.alloc.rate.norm";

  /** JMH GCProfiler key for GC pause count during the measurement window. */
  private static final String GC_COUNT = "gc.count";

  /** JMH GCProfiler key for total GC pause time in ms (omitted if 0). */
  private static final String GC_TIME = "gc.time";

  /** One millisecond is the resolution of the JVM collection timing counters. */
  private static final double GC_TIMING_TICK_MS = 1.0;

  /** Strict non-regression ratio (reference / optimized &gt;= 1.0). */
  private static final double NO_REGRESSION = 1.0;

  /** Fully qualified JMH benchmark name prefix. */
  private static final String ROOT_SCAN = DependencyDynamicRootsBenchmark.class.getName() + ".";

  /** Comparative benchmark pairs; regressions require explicit user approval. */
  private static final List<ComparisonExpectation> DEFAULT_EXPECTATIONS =
      List.of(
          new ComparisonExpectation(
              ROOT_SCAN + "currentOrdinaryJarScan",
              ROOT_SCAN + "referenceOrdinaryJarScan",
              NO_REGRESSION),
          new ComparisonExpectation(
              ROOT_SCAN + "currentMetadataJarScan",
              ROOT_SCAN + "referenceMetadataJarScan",
              NO_REGRESSION));

  /** Expected comparative invariant between an optimized benchmark and its reference. */
  public record ComparisonExpectation(
      String optimizedBenchmark, String referenceBenchmark, double minImprovementRatio) {
    /** Validates expectation fields. */
    public ComparisonExpectation {
      Objects.requireNonNull(optimizedBenchmark, "optimizedBenchmark");
      Objects.requireNonNull(referenceBenchmark, "referenceBenchmark");
    }
  }

  /** Measured primary time, process CPU, allocation, and GC metrics. */
  public record MeasuredMetric(
      double timeScore,
      String timeUnit,
      double processCpuNsPerOp,
      double allocBytesPerOp,
      double gcTimeMs,
      double gcCount) {}

  private BenchmarkComparisonVerifier() {}

  /** Executes default comparative benchmarks and fails if any invariant is violated. */
  public static void main(final String[] args) throws RunnerException {
    final Map<String, MeasuredMetric> metrics = run(DEFAULT_EXPECTATIONS);
    verify(DEFAULT_EXPECTATIONS, metrics);
  }

  /** Runs JMH with {@link GCProfiler} and {@link ProcessCpuProfiler} attached. */
  @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
  public static Map<String, MeasuredMetric> run(final List<ComparisonExpectation> expectations)
      throws RunnerException {
    final ChainedOptionsBuilder builder =
        new OptionsBuilder()
            .addProfiler(GCProfiler.class)
            .addProfiler(ProcessCpuProfiler.class)
            .shouldFailOnError(true);
    for (final ComparisonExpectation expectation : expectations) {
      builder.include(exactPattern(expectation.optimizedBenchmark()));
      builder.include(exactPattern(expectation.referenceBenchmark()));
    }
    final Collection<RunResult> results = new Runner(builder.build()).run();
    final Map<String, MeasuredMetric> metrics = new ConcurrentHashMap<>();
    for (final RunResult result : results) {
      final String benchmarkName = result.getParams().getBenchmark();
      // JMH places @BenchmarkMode in getPrimaryResult(), while profiler
      // metrics (GCProfiler, ProcessCpuProfiler) are in secondary results.
      final Result<?> primary = result.getPrimaryResult();
      final Map<String, Result> profilerMetrics = result.getSecondaryResults();
      final double cpuNsPerOp =
          requireProfilerMetric(
              profilerMetrics, ProcessCpuProfiler.PROCESS_CPU_TIME_NORM, benchmarkName);
      final double allocBytesPerOp =
          requireProfilerMetric(profilerMetrics, GC_ALLOC_RATE_NORM, benchmarkName);
      final double gcCount = requireProfilerMetric(profilerMetrics, GC_COUNT, benchmarkName);
      // GCProfiler omits gc.time when gc.count is zero.
      final Result<?> gcTimeResult = profilerMetrics.get(GC_TIME);
      final double gcTimeMs = gcTimeResult == null ? 0.0 : gcTimeResult.getScore();
      metrics.put(
          benchmarkName,
          new MeasuredMetric(
              primary.getScore(),
              primary.getScoreUnit(),
              cpuNsPerOp,
              allocBytesPerOp,
              gcTimeMs,
              gcCount));
    }
    return metrics;
  }

  /** Verifies non-regression across every dimension and the configured minimum gain. */
  public static void verify(
      final List<ComparisonExpectation> expectations, final Map<String, MeasuredMetric> metrics) {
    for (final ComparisonExpectation expectation : expectations) {
      final MeasuredMetric optimized = requireMetric(metrics, expectation.optimizedBenchmark());
      final MeasuredMetric reference = requireMetric(metrics, expectation.referenceBenchmark());
      verifyPair(expectation, optimized, reference);
    }
  }

  @SuppressWarnings("PMD.SystemPrintln")
  private static void verifyPair(
      final ComparisonExpectation expectation,
      final MeasuredMetric optimized,
      final MeasuredMetric reference) {
    final double speedup = reference.timeScore() / optimized.timeScore();
    final double cpuReduction = reference.processCpuNsPerOp() / optimized.processCpuNsPerOp();
    final double allocReduction = reference.allocBytesPerOp() / optimized.allocBytesPerOp();
    final double gcTimeReduction =
        optimized.gcTimeMs() > 0.0
                && reference.gcTimeMs() - optimized.gcTimeMs() > GC_TIMING_TICK_MS
            ? reference.gcTimeMs() / optimized.gcTimeMs()
            : NO_REGRESSION;
    System.out.printf(
        Locale.ROOT,
        "JMH compare: %s vs %s -> speedup=%.2fx, cpuReduction=%.2fx, allocReduction=%.2fx,"
            + " gcCount=%.0f vs %.0f, gcTime=%.0f vs %.0f ms (min best >= %.2fx)%n",
        expectation.optimizedBenchmark(),
        expectation.referenceBenchmark(),
        speedup,
        cpuReduction,
        allocReduction,
        optimized.gcCount(),
        reference.gcCount(),
        optimized.gcTimeMs(),
        reference.gcTimeMs(),
        expectation.minImprovementRatio());

    requireNonRegression(
        "wall-clock time",
        expectation.optimizedBenchmark(),
        expectation.referenceBenchmark(),
        speedup);
    requireNonRegression(
        "process CPU time",
        expectation.optimizedBenchmark(),
        expectation.referenceBenchmark(),
        cpuReduction);
    requireNonRegression(
        "heap allocation",
        expectation.optimizedBenchmark(),
        expectation.referenceBenchmark(),
        allocReduction);
    verifyGcWork(expectation, optimized, reference);

    final double bestImprovement =
        Math.max(Math.max(speedup, cpuReduction), Math.max(allocReduction, gcTimeReduction));
    if (Double.isNaN(bestImprovement) || bestImprovement < expectation.minImprovementRatio()) {
      throw new IllegalStateException(
          String.format(
              Locale.ROOT,
              "Benchmark %s best improvement %.2fx vs %s (speedup=%.2fx, cpu=%.2fx, alloc=%.2fx)"
                  + " is below minimum %.2fx",
              expectation.optimizedBenchmark(),
              bestImprovement,
              expectation.referenceBenchmark(),
              speedup,
              cpuReduction,
              allocReduction,
              expectation.minImprovementRatio()));
    }
  }

  private static void verifyGcWork(
      final ComparisonExpectation expectation,
      final MeasuredMetric optimized,
      final MeasuredMetric reference) {
    if (optimized.gcCount() > reference.gcCount()) {
      throw new IllegalStateException(
          String.format(
              Locale.ROOT,
              "Benchmark %s GC count %.0f regressed vs %s (%.0f)",
              expectation.optimizedBenchmark(),
              optimized.gcCount(),
              expectation.referenceBenchmark(),
              reference.gcCount()));
    }
    final double tolerance = optimized.gcCount() == reference.gcCount() ? GC_TIMING_TICK_MS : 0.0;
    if (optimized.gcTimeMs() - reference.gcTimeMs() > tolerance) {
      throw new IllegalStateException(
          String.format(
              Locale.ROOT,
              "Benchmark %s GC pause time %.0f ms regressed vs %s (%.0f ms)",
              expectation.optimizedBenchmark(),
              optimized.gcTimeMs(),
              expectation.referenceBenchmark(),
              reference.gcTimeMs()));
    }
  }

  private static void requireNonRegression(
      final String dimension,
      final String optimized,
      final String reference,
      final double actualRatio) {
    if (Double.isNaN(actualRatio) || actualRatio < NO_REGRESSION) {
      throw new IllegalStateException(
          String.format(
              Locale.ROOT,
              "Benchmark %s %s regressed (%.2fx vs %s; must be >= %.2fx)",
              optimized,
              dimension,
              actualRatio,
              reference,
              NO_REGRESSION));
    }
  }

  /** Reads a required profiler metric from secondary results without defaults. */
  private static double requireProfilerMetric(
      @SuppressWarnings("rawtypes") final Map<String, Result> profilerMetrics,
      final String metricKey,
      final String benchmarkName) {
    final Result<?> result = profilerMetrics.get(metricKey);
    if (result == null) {
      throw new IllegalStateException(
          "Missing profiler metric '" + metricKey + "' for benchmark " + benchmarkName);
    }
    return result.getScore();
  }

  private static MeasuredMetric requireMetric(
      final Map<String, MeasuredMetric> metrics, final String benchmarkName) {
    final MeasuredMetric metric = metrics.get(benchmarkName);
    if (metric == null) {
      throw new IllegalStateException("Missing benchmark result for " + benchmarkName);
    }
    return metric;
  }

  private static String exactPattern(final String benchmarkName) {
    return "^" + java.util.regex.Pattern.quote(benchmarkName) + "$";
  }
}
