/* WHY: Loads frozen platform views for exactly the releases included in one
 * MRJAR analysis. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.trimmer.JdkApiClassPoolReader;
import io.github.spockz.elider.trimmer.JdkPlatformContext;
import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import proguard.classfile.ClassPool;

/** Loads platform class pools for the analyzed runtime releases. */
final class TierPlatformReader {
  /** Bounds and policy belong to this analysis operation. */
  private final MultiReleaseTrimContext operation;

  /* package */ TierPlatformReader(final MultiReleaseTrimContext operation) {
    this.operation = operation;
  }

  /* package */ PlatformPlan readPlatforms(final List<Integer> tiers) throws IOException {
    final List<JdkPlatformContext.PlatformSnapshot> snapshots = new ArrayList<>();
    try (JdkPlatformContext context = new JdkPlatformContext(operation.javaHome())) {
      for (final int tier : tiers) {
        snapshots.add(context.snapshot(tier));
      }
    }
    final JdkApiClassPoolReader reader = new JdkApiClassPoolReader();
    final Map<Integer, ClassPool> pools =
        LinkedHashMap.newLinkedHashMap(MultiReleaseTrimContext.DEFAULT_EXPECTED_MAP_SIZE);
    for (final JdkPlatformContext.PlatformSnapshot snapshot : snapshots) {
      pools.put(snapshot.effectiveRelease(), reader.read(snapshot));
    }
    return new PlatformPlan(snapshots, Map.copyOf(pools));
  }

  /* package */ record PlatformPlan(
      List<JdkPlatformContext.PlatformSnapshot> snapshots, Map<Integer, ClassPool> byRelease) {}
}
