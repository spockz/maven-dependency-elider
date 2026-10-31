// WHY: Verifies malformed JSON cannot pass effective trim-cache manifest parsing.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.apache.maven.plugin.MojoFailureException;
import org.junit.jupiter.api.Test;

/** Verifies strict trim-manifest parsing rejects malformed JSON values. */
final class MavenElisionServiceEffectiveOutputManifestParsingTest
    extends MavenElisionServiceEffectiveOutputSupport {
  /** Trace root retained by the effective-output fixture. */
  private static final String ENTRY_TRACE = "closure/a/Entry";

  /** Creates shared fixture support for malformed-manifest tests. */
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  MavenElisionServiceEffectiveOutputManifestParsingTest() {
    super();
  }

  @Test
  void effectiveCacheRejectsDuplicateManifestKeysFractionalSchemaAndTrailingDocuments()
      throws Exception {
    final Fixture fixture = fixture(false);
    final ServiceOperation operation =
        operation(fixture, trace(temporaryDirectory, ENTRY_TRACE), null);
    final ElisionAnalysisModel.EffectiveAnalysis effective =
        operation.service().finishAnalysis(operation.prepared());
    MavenDependencyTrimmer.trimEffectiveOutputs(effective);
    final Path manifest = EffectiveOutputCacheTestFiles.cacheManifest(fixture.mavenProject());
    final String validJson = Files.readString(manifest);

    assertAll(
        "strict manifest parsing rejects duplicate keys, fractional schema, and trailing JSON",
        () ->
            assertMalformedManifestMiss(
                effective,
                manifest,
                validJson.replaceFirst(
                    "\"schemaVersion\":\\d+,", "\"schemaVersion\":1,\"schemaVersion\":1,")),
        () ->
            assertMalformedManifestMiss(
                effective,
                manifest,
                validJson.replaceFirst("\"schemaVersion\":\\d+", "\"schemaVersion\":1.5")),
        () ->
            assertMalformedManifestMiss(
                effective,
                manifest,
                validJson.replaceFirst("\"producer\":\\{", "\"producer\":{},\"producer\":")),
        () -> assertMalformedManifestMiss(effective, manifest, validJson + "\n{}"));
  }

  private void assertMalformedManifestMiss(
      final ElisionAnalysisModel.EffectiveAnalysis effective,
      final Path manifest,
      final String malformedJson)
      throws IOException, MojoFailureException {
    Files.writeString(manifest, malformedJson);
    assertThat(MavenDependencyTrimmer.trimEffectiveOutputs(effective).cacheHits()).isZero();
  }
}
