/* WHY: Completes source, platform, and projected inventories together before
 * root planning can begin. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.plugin.TierArchiveProjector.TierContext;
import io.github.spockz.elider.plugin.TierInventoryReader.Inventory;
import io.github.spockz.elider.plugin.TierPlatformReader.PlatformPlan;
import java.io.IOException;
import java.util.List;

/** Binds source inventories, platforms, and projections for root planning. */
final class TierInventoryPreparer {
  private TierInventoryPreparer() {}

  /* package */ static PreparedInventory prepare(final MultiReleaseTrimContext operation)
      throws IOException {
    final TierInventoryReader reader = new TierInventoryReader(operation);
    Inventory inventory = reader.readInventory();
    final PlatformPlan platforms =
        new TierPlatformReader(operation).readPlatforms(inventory.tiers());
    inventory = inventory.withPlatformSnapshots(platforms.snapshots());
    final List<TierContext> projections =
        new TierArchiveProjector(operation).projectInventory(inventory, platforms);
    return new PreparedInventory(inventory, platforms, projections);
  }

  /* package */ record PreparedInventory(
      Inventory inventory, PlatformPlan platforms, List<TierContext> projections) {}
}
