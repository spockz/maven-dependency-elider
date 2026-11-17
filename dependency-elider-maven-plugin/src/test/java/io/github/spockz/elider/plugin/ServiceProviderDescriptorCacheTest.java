/* WHY: Ensures unchanged cache entries cannot bypass required descriptor filtering. */

package io.github.spockz.elider.plugin;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.spockz.elider.model.ArtifactDigests;
import io.github.spockz.elider.model.ArtifactFileRef;
import io.github.spockz.elider.trimmer.DependencyJarTrimmer.TrimAnalysis;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** Validates cache handling when a descriptor output is part of the trim plan. */
final class ServiceProviderDescriptorCacheTest
    extends MavenDependencyTrimmerInMemoryClosureSupport {
  /** Provider that remains live in the effective dependency set. */
  private static final String RETAINED_PROVIDER = "closure.a.Extra";

  @SuppressWarnings("PMD.UnnecessaryConstructor")
  /* default */ ServiceProviderDescriptorCacheTest() {
    super();
  }

  @Test
  void descriptorOutputPlanRejectsUnchangedCacheEntry() throws Exception {
    final Fixture fixture = fixtureWithDuplicateAndUnusedSecond();
    final Path trace = temporaryDirectory.resolve("descriptor-cache.lst");
    Files.writeString(trace, "closure/a/Entry\n");
    final ElisionAnalysisModel.PreparedAnalysis prepared =
        new MavenElisionService()
            .prepare(
                fixture.projectValue(),
                MavenElisionServiceEffectiveAnalysisFixtures.options(
                    List.of(trace.toFile()), null, true));
    final Map<ArtifactFileRef, Set<String>> classesByArtifact =
        prepared.index().classesByArtifact();
    final ElisionAnalysisModel.ArtifactSnapshot snapshot =
        prepared.resolvedSnapshots().stream()
            .filter(value -> "a".equals(value.coordinate().artifactId()))
            .findFirst()
            .orElseThrow();
    final Set<String> classes =
        classesByArtifact.entrySet().stream()
            .filter(entry -> entry.getKey().coordinate().equals(snapshot.coordinate()))
            .map(Map.Entry::getValue)
            .findFirst()
            .orElseThrow();
    final TrimCandidate candidate =
        new TrimCandidate(
            snapshot,
            classes,
            classes,
            Path.of("descriptor-owner-trimmed.jar"),
            false,
            classes.size());
    candidate.analysis(new TrimAnalysis(classes.size(), classes, classes));
    candidate.serviceDescriptorPlan(
        Set.of(RETAINED_PROVIDER),
        List.of(
            new ServiceDescriptorChange(
                "META-INF/services/closure.Service", ServiceDescriptorChange.Outcome.REPLACED)));
    final Path input = snapshot.filePath().toAbsolutePath().normalize();
    final Map<Path, ArtifactDigests> sourceDigest = Map.of(input, ArtifactDigests.read(input));
    final JarTrimCache.CacheEntry cachePayload =
        JarTrimCache.cacheEntry(candidate, null, sourceDigest);
    final ObjectMapper mapper = new ObjectMapper();
    final JarTrimCache.CacheEntry unchanged =
        mapper.convertValue(cachePayload, JarTrimCache.CacheEntry.class);
    final boolean outputRequired = candidate.requiresOutput();
    final boolean cacheEntryValid = TrimCacheValidator.validCacheEntry(unchanged, candidate);

    assertAll(
        "descriptor changes require an output archive rather than an unchanged cache hit",
        () -> assertTrue(outputRequired, "A changed descriptor requires a rewritten output"),
        () -> assertFalse(cacheEntryValid, "An unchanged cache entry cannot satisfy that rewrite"));
  }
}
