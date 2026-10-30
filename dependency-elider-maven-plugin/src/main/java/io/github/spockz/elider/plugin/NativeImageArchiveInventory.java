/* WHY: Shares one archive's logical classes and physical resources across invocation indexes. */

package io.github.spockz.elider.plugin;

import java.nio.file.Path;
import java.util.Map;
import java.util.Set;

/** Holds the resource and class inventory for one candidate archive. */
/* package */ record NativeImageArchiveInventory(
    Path path, Set<String> logicalClasses, Map<String, Integer> resources) {}
