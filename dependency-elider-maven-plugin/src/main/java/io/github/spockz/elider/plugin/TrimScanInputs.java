/* WHY: Keeps class and dynamic-root inventories bound to the same plugin
 * analysis operation. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.scanner.ArtifactClassIndex;
import java.nio.file.Path;
import java.util.Map;

/** Binds class ownership and dynamic-root scans for one operation. */
record TrimScanInputs(
    ArtifactClassIndex classIndex, Map<Path, DependencyDynamicRoots.RootScan> dynamicRootScans) {}
