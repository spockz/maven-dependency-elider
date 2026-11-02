/* WHY: Completes source, platform, and projected inventories together before
 * root planning can begin. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.plugin.TierArchiveProjector.TierContext;
import io.github.spockz.elider.plugin.TierInventoryReader.Inventory;
import io.github.spockz.elider.plugin.TierPlatformReader.JdkClassTablePlan;
import java.io.IOException;
import java.util.List;

/** Binds source inventories, platforms, and projections for root planning. */
final class TierInventoryPreparer {
  private TierInventoryPreparer() {}

  /* package */ static PreparedInventory prepare(final MultiReleaseTrimContext operation)
      throws IOException {
    final TierInventoryReader reader = new TierInventoryReader(operation);
    Inventory inventory = reader.readInventory();
    final JdkClassTablePlan classTables =
        new TierPlatformReader(operation).readJdkClassTables(inventory.tiers());
    inventory = inventory.withPlatformSnapshots(classTables.snapshots());
    final List<TierContext> projections =
        new TierArchiveProjector(operation).projectInventory(inventory, classTables);
    return new PreparedInventory(inventory, classTables, projections);
  }

  /* package */ record PreparedInventory(
      Inventory inventory, JdkClassTablePlan classTables, List<TierContext> projections) {}
}
