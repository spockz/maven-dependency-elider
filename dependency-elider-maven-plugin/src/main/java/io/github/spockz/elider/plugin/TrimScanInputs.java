/* WHY: Keeps class and dynamic-root inventories bound to the same plugin
 * analysis operation. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.scanner.ArtifactClassIndex;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

/** Binds class ownership and dynamic-root scans for one operation. */
record TrimScanInputs(
    ArtifactClassIndex classIndex,
    Map<Path, DependencyDynamicRoots.RootScan> dynamicRootScans,
    List<NativeImageConsumedInput> consumedInputs) {
  /* package */ TrimScanInputs {
    consumedInputs = NativeImageConsumedInput.ordered(consumedInputs);
  }

  /* package */ TrimScanInputs(
      final ArtifactClassIndex classIndex,
      final Map<Path, DependencyDynamicRoots.RootScan> dynamicRootScans) {
    this(classIndex, dynamicRootScans, List.of());
  }
}
