/* WHY: Verifies multi-dimensional JMH non-regression and 10x+ gain on at least one metric. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.plugin.BenchmarkComparisonVerifier.ComparisonExpectation;
import io.github.spockz.elider.plugin.BenchmarkComparisonVerifier.MeasuredMetric;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Unit tests for {@link BenchmarkComparisonVerifier}. */
@SuppressWarnings("PMD.AtLeastOneConstructor")
/* package */ final class BenchmarkComparisonVerifierTest {
  /** Order-of-magnitude threshold required on at least one dimension. */
  private static final double TEN_X = 10.0;

  /** Optimized benchmark identifier. */
  private static final String OPTIMIZED = "example.Bench.optimized";

  /** Reference benchmark identifier. */
  private static final String REFERENCE = "example.Bench.reference";

  /** Unit string used in synthetic metrics. */
  private static final String MS_PER_OP = "ms/op";

  /* package */
  @Test
  void requiresNonRegressionEverywhereAndOrderOfMagnitudeOnAtLeastOneDimension() {
    final List<ComparisonExpectation> expectations =
        List.of(new ComparisonExpectation(OPTIMIZED, REFERENCE, TEN_X));
    final Map<String, MeasuredMetric> speedupOnlyTenfold =
        Map.of(
            OPTIMIZED, new MeasuredMetric(0.5, MS_PER_OP, 5_000_000.0, 2560.0, 0.0, 0.0),
            REFERENCE, new MeasuredMetric(5.0, MS_PER_OP, 9_500_000.0, 3530.0, 0.0, 0.0));
    final Map<String, MeasuredMetric> allocOnlyTenfold =
        Map.of(
            OPTIMIZED, new MeasuredMetric(5.0, MS_PER_OP, 5_000_000.0, 350.0, 0.0, 0.0),
            REFERENCE, new MeasuredMetric(9.5, MS_PER_OP, 9_500_000.0, 3530.0, 0.0, 0.0));
    final Map<String, MeasuredMetric> belowTenfoldEverywhere =
        Map.of(
            OPTIMIZED, new MeasuredMetric(4.0, MS_PER_OP, 4_000_000.0, 1000.0, 0.0, 0.0),
            REFERENCE, new MeasuredMetric(9.5, MS_PER_OP, 9_500_000.0, 3530.0, 0.0, 0.0));
    final Map<String, MeasuredMetric> wallClockRegressed =
        Map.of(
            OPTIMIZED, new MeasuredMetric(10.0, MS_PER_OP, 25_000.0, 256.0, 0.0, 0.0),
            REFERENCE, new MeasuredMetric(9.5, MS_PER_OP, 9_500_000.0, 3530.0, 0.0, 0.0));
    final Map<String, MeasuredMetric> cpuRegressed =
        Map.of(
            OPTIMIZED, new MeasuredMetric(0.025, MS_PER_OP, 20_000_000.0, 2560.0, 0.0, 0.0),
            REFERENCE, new MeasuredMetric(9.5, MS_PER_OP, 9_500_000.0, 3530.0, 0.0, 0.0));
    final Map<String, MeasuredMetric> allocRegressed =
        Map.of(
            OPTIMIZED, new MeasuredMetric(0.025, MS_PER_OP, 25_000.0, 10_000.0, 0.0, 0.0),
            REFERENCE, new MeasuredMetric(9.5, MS_PER_OP, 9_500_000.0, 3530.0, 0.0, 0.0));
    final Map<String, MeasuredMetric> gcRegressed =
        Map.of(
            OPTIMIZED, new MeasuredMetric(0.025, MS_PER_OP, 25_000.0, 2560.0, 10.0, 2.0),
            REFERENCE, new MeasuredMetric(9.5, MS_PER_OP, 9_500_000.0, 3530.0, 1.0, 1.0));
    final Map<String, MeasuredMetric> missingRef =
        Map.of(OPTIMIZED, new MeasuredMetric(0.025, MS_PER_OP, 25_000.0, 2560.0, 0.0, 0.0));

    assertAll(
        "Multi-dimensional JMH comparison assertions",
        () ->
            assertThatNoException()
                .isThrownBy(
                    () -> BenchmarkComparisonVerifier.verify(expectations, speedupOnlyTenfold)),
        () ->
            assertThatNoException()
                .isThrownBy(
                    () -> BenchmarkComparisonVerifier.verify(expectations, allocOnlyTenfold)),
        () ->
            assertThatThrownBy(
                    () -> BenchmarkComparisonVerifier.verify(expectations, belowTenfoldEverywhere))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("best improvement"),
        () ->
            assertThatThrownBy(
                    () -> BenchmarkComparisonVerifier.verify(expectations, wallClockRegressed))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("wall-clock time regressed"),
        () ->
            assertThatThrownBy(() -> BenchmarkComparisonVerifier.verify(expectations, cpuRegressed))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("process CPU time regressed"),
        () ->
            assertThatThrownBy(
                    () -> BenchmarkComparisonVerifier.verify(expectations, allocRegressed))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("heap allocation regressed"),
        () ->
            assertThatThrownBy(() -> BenchmarkComparisonVerifier.verify(expectations, gcRegressed))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("GC count"),
        () ->
            assertThatThrownBy(() -> BenchmarkComparisonVerifier.verify(expectations, missingRef))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Missing benchmark result"));
  }

  @Test
  void toleratesOneTickOfGcTimingAtEqualCountButRejectsLargerChanges() {
    final List<ComparisonExpectation> expectations =
        List.of(new ComparisonExpectation(OPTIMIZED, REFERENCE, 1.0));
    final MeasuredMetric reference = new MeasuredMetric(5, MS_PER_OP, 500, 2560, 0, 1);
    final MeasuredMetric oneTick = new MeasuredMetric(4, MS_PER_OP, 400, 2000, 1, 1);
    final MeasuredMetric twoTicks = new MeasuredMetric(4, MS_PER_OP, 400, 2000, 2, 1);
    final MeasuredMetric extraCollection = new MeasuredMetric(4, MS_PER_OP, 400, 2000, 1, 2);
    assertAll(
        () ->
            assertThatNoException()
                .isThrownBy(
                    () ->
                        BenchmarkComparisonVerifier.verify(
                            expectations, Map.of(REFERENCE, reference, OPTIMIZED, oneTick))),
        () ->
            assertThatThrownBy(
                    () ->
                        BenchmarkComparisonVerifier.verify(
                            expectations, Map.of(REFERENCE, reference, OPTIMIZED, twoTicks)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("GC pause time"),
        () ->
            assertThatThrownBy(
                    () ->
                        BenchmarkComparisonVerifier.verify(
                            expectations, Map.of(REFERENCE, reference, OPTIMIZED, extraCollection)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("GC count"));
  }
}
