/* WHY: Keeps archive policy and worker limits together so every analysis and
 * publication path applies the same defaults. */

package io.github.spockz.elider.plugin;

import java.util.List;

/** Policy shared by pass-through selection, closure analysis, and publication. */
record TrimPolicy(
    List<String> explicitRoots,
    boolean failOnUnsupportedMultiRelease,
    List<String> explicitPassThroughCoordinates,
    boolean failOnUnsupportedModuleInfo,
    String mrjarStrategy,
    boolean trimEnabled,
    boolean conservativeServiceLoaderRoots,
    int trimWorkers) {
  TrimPolicy {
    if (trimWorkers < MavenDependencyTrimmer.MIN_TRIM_WORKERS) {
      throw new IllegalArgumentException("trimWorkers must be at least 1");
    }
  }

  /* package */ TrimPolicy(
      final List<String> explicitRoots,
      final boolean failOnUnsupportedMultiRelease,
      final List<String> explicitPassThroughCoordinates,
      final boolean failOnUnsupportedModuleInfo,
      final boolean conservativeServiceLoaderRoots) {
    this(
        explicitRoots,
        failOnUnsupportedMultiRelease,
        explicitPassThroughCoordinates,
        failOnUnsupportedModuleInfo,
        MavenDependencyTrimmer.MRJAR_VERTICAL_SHADING,
        true,
        conservativeServiceLoaderRoots,
        MavenDependencyTrimmer.DEFAULT_TRIM_WORKERS);
  }

  /* package */ TrimPolicy(
      final List<String> explicitRoots,
      final boolean failOnUnsupportedMultiRelease,
      final List<String> explicitPassThroughCoordinates,
      final boolean failOnUnsupportedModuleInfo) {
    this(
        explicitRoots,
        failOnUnsupportedMultiRelease,
        explicitPassThroughCoordinates,
        failOnUnsupportedModuleInfo,
        true);
  }
}
