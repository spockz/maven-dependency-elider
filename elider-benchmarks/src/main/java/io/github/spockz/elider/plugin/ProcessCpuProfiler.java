/* WHY: Measures total JVM process CPU nanoseconds per operation across all threads in JMH. */

package io.github.spockz.elider.plugin;

import com.sun.management.OperatingSystemMXBean;
import java.lang.management.ManagementFactory;
import java.util.Collection;
import java.util.List;
import org.openjdk.jmh.infra.BenchmarkParams;
import org.openjdk.jmh.infra.IterationParams;
import org.openjdk.jmh.profile.InternalProfiler;
import org.openjdk.jmh.results.AggregationPolicy;
import org.openjdk.jmh.results.IterationResult;
import org.openjdk.jmh.results.Result;
import org.openjdk.jmh.results.ScalarResult;
import org.openjdk.jmh.runner.IterationType;

/**
 * JMH {@link InternalProfiler} recording {@code process.cpu.time.norm} in ns/op.
 *
 * <p>Sums CPU across all JVM threads to catch changes that trade
 *
 * <p>wall-clock speed for extra CPU work.
 */
public final class ProcessCpuProfiler implements InternalProfiler {
  /** Metric key emitted into JMH's secondary (profiler) results map. */
  public static final String PROCESS_CPU_TIME_NORM = "process.cpu.time.norm";

  /** Operating-system MXBean providing process-wide CPU nanoseconds. */
  private final OperatingSystemMXBean osBean;

  /** Process CPU timestamp captured at the start of each measurement iteration. */
  private long cpuBeforeNs;

  /** Creates the profiler and fails fast if process CPU timing is unsupported. */
  public ProcessCpuProfiler() {
    if (!(ManagementFactory.getOperatingSystemMXBean() instanceof OperatingSystemMXBean bean)) {
      throw new IllegalStateException(
          "com.sun.management.OperatingSystemMXBean is required to measure process CPU time");
    }
    this.osBean = bean;
  }

  @Override
  public String getDescription() {
    return "Total JVM process CPU time per operation across all threads";
  }

  @Override
  public void beforeIteration(
      final BenchmarkParams benchmarkParams, final IterationParams iterationParams) {
    // Only record measurement iterations; warmup iterations are excluded.
    if (iterationParams.getType() == IterationType.MEASUREMENT) {
      cpuBeforeNs = osBean.getProcessCpuTime();
    }
  }

  @Override
  public Collection<? extends Result<?>> afterIteration(
      final BenchmarkParams benchmarkParams,
      final IterationParams iterationParams,
      final IterationResult result) {
    if (iterationParams.getType() != IterationType.MEASUREMENT) {
      return List.of();
    }
    final long cpuAfterNs = osBean.getProcessCpuTime();
    if (cpuBeforeNs < 0 || cpuAfterNs < 0) {
      throw new IllegalStateException("Process CPU time measurement returned a negative value");
    }
    // Normalize total CPU nanoseconds by actual measured operations in this iteration.
    final long ops = result.getMetadata().getMeasuredOps();
    if (ops <= 0) {
      throw new IllegalStateException("Measured operation count must be positive, got: " + ops);
    }
    final double cpuNsPerOp = (cpuAfterNs - cpuBeforeNs) / (double) ops;
    return List.of(
        new ScalarResult(PROCESS_CPU_TIME_NORM, cpuNsPerOp, "ns/op", AggregationPolicy.AVG));
  }
}
