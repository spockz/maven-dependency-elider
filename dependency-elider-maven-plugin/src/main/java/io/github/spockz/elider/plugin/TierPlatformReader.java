/* WHY: Builds isolated JDK class tables for the releases included in one
 * MRJAR analysis. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.trimmer.JdkApiClassTableReader;
import io.github.spockz.elider.trimmer.JdkPlatformContext;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import proguard.classfile.ClassPool;

/** Builds JDK class tables for the analyzed runtime releases. */
final class TierPlatformReader {
  /** Bounds and policy belong to this analysis operation. */
  private final MultiReleaseTrimContext operation;

  /* package */ TierPlatformReader(final MultiReleaseTrimContext operation) {
    this.operation = operation;
  }

  /* package */ JdkClassTablePlan readJdkClassTables(final List<Integer> tiers) throws IOException {
    final JdkPlatformContext.PlatformSnapshot snapshot =
        MavenPlatformContextHolder.forOperation(operation.request().session()).snapshot();
    final JdkApiClassTableReader reader = new JdkApiClassTableReader();
    final Map<Integer, ClassPool> tablesByRelease =
        LinkedHashMap.newLinkedHashMap(MultiReleaseTrimContext.DEFAULT_EXPECTED_MAP_SIZE);
    for (final int tier : tiers) {
      tablesByRelease.put(tier, reader.readFrozen(snapshot));
    }
    return new JdkClassTablePlan(List.of(snapshot), Map.copyOf(tablesByRelease));
  }

  /* package */ record JdkClassTablePlan(
      List<JdkPlatformContext.PlatformSnapshot> snapshots, Map<Integer, ClassPool> byRelease) {}
}
