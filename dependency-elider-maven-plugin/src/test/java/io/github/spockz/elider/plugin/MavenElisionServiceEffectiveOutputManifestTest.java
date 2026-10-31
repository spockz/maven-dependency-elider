// WHY: Verifies schema and producer gates independently for effective trim manifests.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.nio.file.Path;
import org.apache.maven.plugin.MojoFailureException;
import org.junit.jupiter.api.Test;

/** Verifies independent schema and producer compatibility gates. */
final class MavenElisionServiceEffectiveOutputManifestTest
    extends MavenElisionServiceEffectiveOutputSupport {
  /** Root retained by the effective trim fixture. */
  private static final String ENTRY_TRACE = "closure/a/Entry";

  /** Manifest field carrying the schema version. */
  private static final String SCHEMA_VERSION = "schemaVersion";

  /** Creates shared fixture support for manifest gate tests. */
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  MavenElisionServiceEffectiveOutputManifestTest() {
    super();
  }

  @Test
  void trimCacheChecksSchemaAndProducerAsIndependentGates() throws Exception {
    final Fixture fixture = fixture(false);
    final ServiceOperation operation =
        operation(fixture, trace(temporaryDirectory, ENTRY_TRACE), null);
    final ElisionAnalysisModel.EffectiveAnalysis effective =
        operation.service().finishAnalysis(operation.prepared());
    MavenDependencyTrimmer.trimEffectiveOutputs(effective);
    final Path manifest = EffectiveOutputCacheTestFiles.cacheManifest(fixture.mavenProject());
    final ObjectMapper mapper = new ObjectMapper();

    assertAll(
        "schema and producer compatibility each reject an otherwise fresh manifest",
        () -> {
          final ObjectNode unsupportedSchema = readManifest(mapper, manifest);
          unsupportedSchema.put(SCHEMA_VERSION, MavenDependencyTrimmer.CACHE_SCHEMA_VERSION + 1);
          EffectiveOutputCacheTestFiles.writeManifest(manifest, unsupportedSchema);
          assertCacheMiss(effective);
        },
        () -> {
          final ObjectNode wrongProducer = readManifest(mapper, manifest);
          wrongProducer.put(SCHEMA_VERSION, MavenDependencyTrimmer.CACHE_SCHEMA_VERSION);
          wrongProducer.with("producer").put("artifactId", "different-plugin");
          EffectiveOutputCacheTestFiles.writeManifest(manifest, wrongProducer);
          assertCacheMiss(effective);
        },
        () -> {
          final ObjectNode missingProducer = readManifest(mapper, manifest);
          missingProducer.put(SCHEMA_VERSION, MavenDependencyTrimmer.CACHE_SCHEMA_VERSION);
          missingProducer.remove("producer");
          EffectiveOutputCacheTestFiles.writeManifest(manifest, missingProducer);
          assertCacheMiss(effective);
        });
  }

  private static ObjectNode readManifest(final ObjectMapper mapper, final Path manifest)
      throws IOException {
    return mapper.readTree(manifest.toFile()).deepCopy();
  }

  private static void assertCacheMiss(final ElisionAnalysisModel.EffectiveAnalysis effective)
      throws IOException, MojoFailureException {
    final int cacheHits = MavenDependencyTrimmer.trimEffectiveOutputs(effective).cacheHits();
    assertThat(cacheHits).isZero();
  }
}
