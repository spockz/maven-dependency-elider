/* WHY: Preserves candidate ordering when validating or writing a direct trim
 * cache manifest after archive preparation succeeds. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.plugin.DirectTrimPreparation.PreparedDirectTrim;
import io.github.spockz.elider.plugin.JarTrimCache.CacheEntry;
import io.github.spockz.elider.plugin.JarTrimCache.CacheLoadContext;
import io.github.spockz.elider.plugin.JarTrimCache.CacheManifest;
import java.io.IOException;
import java.util.List;
import java.util.Map;

/** Applies direct-plan cache lookup and publication. */
final class DirectTrimCache {
  private DirectTrimCache() {}

  /* package */ static TrimResult load(final PreparedDirectTrim plan) throws IOException {
    NativeImageConsumedInput.verifyAll(plan.request().scanInputs().consumedInputs());
    if (plan.request().cacheProducerIdentity().isEmpty()) {
      return null;
    }
    final TrimResult result =
        JarTrimCache.loadCache(
            plan.manifest(),
            plan.fingerprint().value(),
            plan.fingerprint().inputDigests(),
            plan.candidatePlan().work(),
            plan.passThrough().multiReleaseCoordinates(),
            plan.passThrough().moduleInfoCoordinates(),
            plan.passThrough().configuredCoordinates(),
            plan.request().cacheProducerIdentity().orElseThrow(),
            new CacheLoadContext(
                new TrimExecutionEnvironment(plan.compilerRelease(), plan.runtimeRelease()),
                plan.cacheStarted()));
    NativeImageConsumedInput.verifyAll(plan.request().scanInputs().consumedInputs());
    return result;
  }

  /* package */ static void store(
      final PreparedDirectTrim plan, final Map<TrimCandidate, CacheEntry> entries)
      throws IOException {
    NativeImageConsumedInput.verifyAll(plan.request().scanInputs().consumedInputs());
    if (plan.request().cacheProducerIdentity().isEmpty()) {
      return;
    }
    final List<CacheEntry> ordered =
        JarTrimCache.orderedEntries(
            plan.candidatePlan().work(), entries, "Missing trim-cache entry for ");
    JarTrimCache.storeCache(
        plan.manifest(),
        new CacheManifest(
            MavenDependencyTrimmer.CACHE_SCHEMA_VERSION,
            MavenDependencyTrimmer.CACHE_FORMAT_ID,
            plan.request().cacheProducerIdentity().orElseThrow(),
            plan.fingerprint().value(),
            ordered));
  }
}
