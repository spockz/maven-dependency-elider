/* WHY: Checks cached class evidence against current roots and archive
 * ownership. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.plugin.JarTrimCache.CacheEntry;
import io.github.spockz.elider.trimmer.DependencyJarTrimmer;
import java.util.Set;

/** Checks cached class evidence against current roots and archive ownership. */
final class TrimCacheEvidence {
  private TrimCacheEvidence() {}

  /* package */ static boolean validRetainedClassEvidence(
      final CacheEntry entry, final TrimCandidate candidate) {
    return validMultiReleaseRetainedCount(entry, candidate)
        && matchesCurrentAnalysis(entry, candidate)
        && retainedClassNamesBelongToCandidate(entry, candidate);
  }

  /* package */ static boolean validMultiReleaseRetainedCount(
      final CacheEntry entry, final TrimCandidate candidate) {
    if (!candidate.archive().multiRelease()) {
      return true;
    }
    final Set<String> logicalRetained = normalizedNames(entry.retainedClassNames());
    logicalRetained.addAll(candidate.archive().upperTierClasses());
    return logicalRetained.size() == entry.retainedClasses();
  }

  /* package */ static boolean matchesCurrentAnalysis(
      final CacheEntry entry, final TrimCandidate candidate) {
    final DependencyJarTrimmer.TrimAnalysis analysis = candidate.analysis();
    return analysis == null
        || (candidate.targetRoots().equals(entry.roots())
            && candidate.targetRoots().equals(normalizedNames(analysis.roots()))
            && entry.retainedClassNames().equals(analysis.retainedClasses())
            && entry.reachableLibraryClasses().equals(analysis.reachableLibraryClasses()));
  }

  /* package */ static boolean retainedClassNamesBelongToCandidate(
      final CacheEntry entry, final TrimCandidate candidate) {
    for (final String retainedClass : entry.retainedClassNames()) {
      if (!candidate.archive().classes().contains(retainedClass.replace('/', '.'))) {
        return false;
      }
    }
    return true;
  }

  /* package */ static Set<String> normalizedNames(final Set<String> names) {
    return names.stream()
        .map(name -> name.replace('/', '.'))
        .collect(java.util.stream.Collectors.toSet());
  }
}
