/* WHY: Keeps cache test fixtures separate from the cache assertions themselves. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

/** Shared external descriptor setup and cache assertions. */
/* package */ final class NativeImageExternalConfigurationCacheTestSupport {
  private NativeImageExternalConfigurationCacheTestSupport() {
    throw new AssertionError("static fixture holder");
  }

  /* package */ static Path declaringWithPointer(
      final Path directory,
      final MavenDependencyTrimmerInMemoryClosureSupport.Fixture fixture,
      final String filename)
      throws IOException {
    return NativeImageExternalConfigurationInputTestSupport.appendEntries(
        directory,
        fixture.snapshot("a").filePath(),
        filename,
        Map.of(
            "META-INF/native-image/test/native-image.properties",
            "Args = -H:ReflectionConfigurationFiles=cache-descriptor.payload\n"));
  }

  /* package */ static Path writeTrace(final Path directory) throws IOException {
    final Path trace = directory.resolve("cache-identity-trace.lst");
    Files.writeString(trace, "closure.a.Entry\n");
    return trace;
  }

  /* package */ static String reflection() {
    return "[{\"name\":\"closure.b.Middle\"},{\"name\":\"closure.c.Leaf\"}]";
  }

  /* package */ static void changeWhitespaceOnly(final Path descriptor) throws IOException {
    Files.writeString(descriptor, reflection() + "\n");
  }

  /* package */ static void assertLegacyBehavior(
      final MavenElisionService.Analysis first,
      final MavenElisionService.Analysis warm,
      final MavenElisionService.Analysis changed,
      final MavenElisionService.PreparedAnalysis firstPrepared,
      final MavenElisionService.PreparedAnalysis changedPrepared) {
    assertThat(changedPrepared.dynamicRootInputs().classNames())
        .isEqualTo(firstPrepared.dynamicRootInputs().classNames());
    assertCacheBehavior(first.trimCacheHits(), warm.trimCacheHits(), changed.trimCacheHits());
  }

  /* package */ static void assertEffectiveBehavior(
      final MavenDependencyTrimmer.TrimResult first,
      final MavenDependencyTrimmer.TrimResult warm,
      final MavenDependencyTrimmer.TrimResult changed,
      final MavenElisionServiceEffectiveOutputSupport.ServiceOperation firstOperation,
      final MavenElisionServiceEffectiveOutputSupport.ServiceOperation changedOperation) {
    assertThat(changedOperation.prepared().dynamicRootInputs().classNames())
        .isEqualTo(firstOperation.prepared().dynamicRootInputs().classNames());
    assertCacheBehavior(first.cacheHits(), warm.cacheHits(), changed.cacheHits());
  }

  private static void assertCacheBehavior(
      final int coldHits, final int warmHits, final int changedInputHits) {
    assertThat(coldHits).isZero();
    assertThat(warmHits).isPositive();
    assertThat(changedInputHits).isZero();
  }

  /* package */ record CacheRun(
      MavenDependencyTrimmerInMemoryClosureSupport.Fixture fixture,
      Path descriptor,
      Path trace,
      MavenElisionService service,
      MavenElisionService.PreparedAnalysis first) {}
}
