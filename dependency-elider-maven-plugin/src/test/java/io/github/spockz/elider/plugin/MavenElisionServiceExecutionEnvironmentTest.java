// WHY: Verifies report provenance across direct, effective, cached and trim-disabled executions.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.Analysis;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.apache.maven.plugin.MojoFailureException;
import org.junit.jupiter.api.Test;

/** Covers required target/runtime report metadata and replay. */
final class MavenElisionServiceExecutionEnvironmentTest
    extends MavenElisionServiceEffectiveOutputSupport {
  /** Maven compiler release property used by the report fixtures. */
  private static final String MAVEN_COMPILER_RELEASE = "maven.compiler.release";

  /** Direct trace roots that retain all artifacts in the output fixture. */
  private static final List<String> ALL_ARTIFACT_ROOTS =
      List.of(
          "closure/a/Entry",
          "closure/b/Middle",
          "closure/c/Leaf",
          "closure/d/Ancestor",
          "closure/e/Leaf");

  /** Creates shared execution-environment fixture support. */
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  MavenElisionServiceExecutionEnvironmentTest() {
    super();
  }

  @Test
  void reportRoundTripRetainsTargetAndRuntimeForTrimmedAnalysis()
      throws IOException, MojoFailureException {
    final ReportEnvironments environments = reportEnvironments(true, false);

    assertAll(
        "miss and cache-hit reports retain the captured direct trim environment",
        () -> assertExecutionEnvironment(environments.firstInvocation()),
        () -> assertExecutionEnvironment(environments.repeatedInvocation()));
  }

  @Test
  void reportRetainsTargetAndRuntimeWhenTrimmingIsDisabled()
      throws IOException, MojoFailureException {
    final ReportEnvironments environments = reportEnvironments(false, false);

    assertAll(
        "trim-disabled report retains the captured analysis environment",
        () -> assertExecutionEnvironment(environments.firstInvocation()));
  }

  @Test
  void trimDisabledReportDoesNotRejectForkedCompilerConfiguration()
      throws IOException, MojoFailureException {
    final ReportEnvironments environments = reportEnvironments(false, true);

    assertAll(
        "disabled direct and effective paths preserve target metadata with fork configured",
        () -> assertExecutionEnvironment(environments.firstInvocation()),
        () -> assertExecutionEnvironment(environments.effectivePath()));
  }

  private ReportEnvironments reportEnvironments(
      final boolean trimJars, final boolean forkedCompiler)
      throws IOException, MojoFailureException {
    final Fixture fixture = fixture(false);
    fixture.mavenProject().getProperties().setProperty(MAVEN_COMPILER_RELEASE, "11");
    final Path traceFile = temporaryDirectory.resolve("all-artifact-roots.lst");
    Files.writeString(traceFile, String.join("\n", ALL_ARTIFACT_ROOTS) + "\n");
    final ServiceOperation operation = operation(fixture, traceFile, null, trimJars);
    if (forkedCompiler) {
      fixture.mavenProject().getProperties().setProperty("maven.compiler.fork", "true");
    }
    final Analysis first = operation.service().finish(operation.prepared());
    final Analysis repeated = trimJars ? operation.service().finish(operation.prepared()) : first;
    final Analysis effectivePath =
        forkedCompiler
            ? operation
                .service()
                .finishEffectiveOutputs(operation.service().finishAnalysis(operation.prepared()))
            : null;
    if (trimJars) {
      final TrimResult repeatedResult = repeated.trimResult();
      final int cacheHits = repeatedResult.cacheHits();
      assertThat(cacheHits)
          .as("the repeated direct invocation should use its validated cache")
          .isPositive();
    }
    fixture.mavenProject().getProperties().setProperty(MAVEN_COMPILER_RELEASE, "17");
    final JsonNode firstEnvironment = reportEnvironment(first, fixture, "first-" + trimJars);
    final JsonNode repeatedEnvironment =
        trimJars ? reportEnvironment(repeated, fixture, "repeated-" + trimJars) : firstEnvironment;
    final JsonNode effectiveEnvironment =
        effectivePath == null
            ? null
            : reportEnvironment(effectivePath, fixture, "effective-" + trimJars);
    return new ReportEnvironments(firstEnvironment, repeatedEnvironment, effectiveEnvironment);
  }

  private JsonNode reportEnvironment(
      final Analysis analysis, final Fixture fixture, final String suffix) throws IOException {
    final MavenElisionReportSnapshot snapshot =
        MavenElisionReportSnapshot.from(fixture.mavenProject(), analysis);
    final Path report = temporaryDirectory.resolve("report-" + suffix + ".json");
    MavenElisionReportWriter.write(report, snapshot);
    return new ObjectMapper()
        .valueToTree(MavenElisionReportWriter.read(report))
        .path("executionEnvironment");
  }

  private void assertExecutionEnvironment(final JsonNode environment) {
    assertAll(
        () -> assertThat(environment.path("targetRelease").asInt()).isEqualTo(11),
        () ->
            assertThat(environment.path("runtimeRelease").asInt())
                .isEqualTo(Runtime.version().feature()));
  }

  /** Holds persisted observations from related trim operations. */
  private record ReportEnvironments(
      /* Saved metadata from the first direct invocation. */
      JsonNode firstInvocation,
      /* Saved metadata from a repeat/cache-hit invocation. */
      JsonNode repeatedInvocation,
      /* Saved metadata from the effective-output path when exercised. */
      JsonNode effectivePath) {}
}
