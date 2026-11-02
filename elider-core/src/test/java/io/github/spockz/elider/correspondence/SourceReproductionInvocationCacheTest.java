// WHY: Verifies reproduction reuse stays local to one invocation and current artifact identity.

package io.github.spockz.elider.correspondence;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.model.ArtifactCoordinate;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Checks claim reuse and cache invalidation. */
@SuppressWarnings({"PMD.AtLeastOneConstructor", "PMD.UnitTestContainsTooManyAsserts"})
// Shared setup avoids repeated compilation within each scenario.
final class SourceReproductionInvocationCacheTest {
  /** Exact source entry used by the ordinary-layout fixture. */
  private static final String SOURCE_ENTRY = "src/main/java/org/example/Outer.java";

  /** Source containing a uniquely owned routine. */
  private static final String SOURCE =
      "package org.example; public class Outer { public void parse() {} }";

  /** Exact artifact identity shared by the source and binary fixture archives. */
  private static final ArtifactCoordinate CANDIDATE =
      ArtifactCoordinate.of("org.example", "demo", "1.0");

  /** Descriptive resolver origin included in the compilation cache identity. */
  private static final String SOURCE_REPOSITORY = "remote:fixture-repository";

  /** Isolates generated JARs and replacement files for each test. */
  @TempDir private Path temporaryDirectory;

  @org.junit.jupiter.api.BeforeEach
  void verifySupportedJdk() {
    org.junit.jupiter.api.Assumptions.assumeTrue(
        SourceJdkIdentity.isSupported(), "Skipping source reproduction tests on non-pinned JDK");
  }

  @Test
  void differentClaimsShareOneSuccessfulClaimIndependentReproduction() throws IOException {
    final SourceReproductionTestArchives.Archives archives = fixture("shared-claims");
    final SourceReproductionEngine engine = SourceReproductionEngine.forCurrentJdk();
    final SourceReproductionResult fileResult =
        engine.reproduce(request(archives, List.of(SOURCE_ENTRY), List.of(), false));
    final SourceReproductionResult routineResult =
        engine.reproduce(request(archives, List.of(), List.of("parse"), false));
    final SourceReproductionEngine.InvocationDiagnostics diagnostics = engine.diagnostics();

    assertAll(
        "two advisory claim sets reuse immutable archive/build results but map claims separately",
        () ->
            assertThat(fileResult)
                .isInstanceOfSatisfying(
                    SourceReproductionResult.Completed.class,
                    completed ->
                        assertThat(completed.mappedClaims())
                            .containsEntry(SOURCE_ENTRY, SOURCE_ENTRY)),
        () ->
            assertThat(routineResult)
                .isInstanceOfSatisfying(
                    SourceReproductionResult.Completed.class,
                    completed -> assertThat(completed.mappedClaims()).isEmpty()),
        () -> assertThat(diagnostics.originalArchiveParses()).isEqualTo(1),
        () -> assertThat(diagnostics.sourceArchiveParses()).isEqualTo(1),
        () -> assertThat(diagnostics.compilerInvocations()).isEqualTo(1),
        () -> assertThat(diagnostics.reproductionCacheHits()).isEqualTo(1));

    final String originalDigest = SourceFileDigest.sha256(archives.originalJar());
    final Set<String> firstInventory =
        engine.readPhysicalClassInventory(CANDIDATE, archives.originalJar(), originalDigest);
    final Set<String> cachedInventory =
        engine.readPhysicalClassInventory(CANDIDATE, archives.originalJar(), originalDigest);
    final SourceReproductionEngine.InvocationDiagnostics inventoryDiagnostics =
        engine.diagnostics();
    assertAll(
        "proof inventory reads are tied to exact current bytes and reuse the reproduced original",
        () -> assertThat(firstInventory).contains("org/example/Outer"),
        () -> assertThat(cachedInventory).isEqualTo(firstInventory),
        () ->
            assertThat(inventoryDiagnostics.physicalInventoryReusesFromReproduction()).isEqualTo(2),
        () -> assertThat(inventoryDiagnostics.physicalInventoryCacheHits()).isEqualTo(2),
        () -> assertThat(inventoryDiagnostics.physicalInventoryParses()).isEqualTo(0));
  }

  @Test
  void byteLayoutProvenanceAndEngineChangesMissInvocationCache() throws IOException {
    final SourceReproductionTestArchives.Archives archives = fixture("invalidation");
    final SourceReproductionEngine engine = SourceReproductionEngine.forCurrentJdk();
    final SourceReproductionRequest exactPathRequest =
        request(archives, List.of(SOURCE_ENTRY), List.of(), false);
    assertThat(engine.reproduce(exactPathRequest))
        .isInstanceOf(SourceReproductionResult.Completed.class);

    SourceReproductionTestArchives.addResourceInPlace(archives.sourcesJar(), "cache-marker.txt");
    final SourceReproductionResult changedSource = engine.reproduce(exactPathRequest);
    SourceReproductionTestArchives.addResourceInPlace(archives.originalJar(), "binary-marker.txt");
    final SourceReproductionResult changedOriginal = engine.reproduce(exactPathRequest);
    final SourceReproductionRequest changedLayout =
        request(archives, List.of(SOURCE_ENTRY), List.of(), true);
    final SourceReproductionResult changedAssumption = engine.reproduce(changedLayout);
    final SourceReproductionRequest changedOrigin =
        new SourceReproductionRequest(
            CANDIDATE,
            exactPathRequest.sourcesCoordinate(),
            exactPathRequest.originalJar(),
            exactPathRequest.sourcesJar(),
            "remote:other-repository",
            exactPathRequest.sourceClaims(),
            exactPathRequest.routineClaims(),
            exactPathRequest.conventionalLayoutAssumed());
    final SourceReproductionResult changedRepository = engine.reproduce(changedOrigin);
    final SourceReproductionEngine.InvocationDiagnostics sharedDiagnostics = engine.diagnostics();

    final SourceReproductionEngine isolatedEngine = SourceReproductionEngine.forCurrentJdk();
    final SourceReproductionResult isolated = isolatedEngine.reproduce(changedOrigin);
    final SourceReproductionEngine.InvocationDiagnostics isolatedDiagnostics =
        isolatedEngine.diagnostics();

    assertAll(
        "new source bytes, assumption, origin, or engine cannot reuse a different cache identity",
        () -> assertThat(changedSource).isInstanceOf(SourceReproductionResult.Completed.class),
        () -> assertThat(changedOriginal).isInstanceOf(SourceReproductionResult.Completed.class),
        () -> assertThat(changedAssumption).isInstanceOf(SourceReproductionResult.Completed.class),
        () -> assertThat(changedRepository).isInstanceOf(SourceReproductionResult.Completed.class),
        () -> assertThat(isolated).isInstanceOf(SourceReproductionResult.Completed.class),
        () -> assertThat(sharedDiagnostics.originalArchiveParses()).isEqualTo(5),
        () -> assertThat(sharedDiagnostics.sourceArchiveParses()).isEqualTo(5),
        () -> assertThat(sharedDiagnostics.compilerInvocations()).isEqualTo(5),
        () -> assertThat(sharedDiagnostics.reproductionCacheHits()).isEqualTo(0),
        () -> assertThat(isolatedDiagnostics.originalArchiveParses()).isEqualTo(1),
        () -> assertThat(isolatedDiagnostics.sourceArchiveParses()).isEqualTo(1),
        () -> assertThat(isolatedDiagnostics.compilerInvocations()).isEqualTo(1),
        () -> assertThat(isolatedDiagnostics.reproductionCacheHits()).isEqualTo(0));
  }

  @Test
  void physicalInventoryCacheInvalidatesOnValidArchiveByteChange() throws IOException {
    final SourceReproductionTestArchives.Archives archives = fixture("physical-inventory");
    final SourceReproductionEngine engine = SourceReproductionEngine.forCurrentJdk();
    final String firstDigest = SourceFileDigest.sha256(archives.originalJar());
    final Set<String> first =
        engine.readPhysicalClassInventory(CANDIDATE, archives.originalJar(), firstDigest);
    SourceReproductionTestArchives.addResourceInPlace(archives.originalJar(), "extra-resource.txt");
    final String changedDigest = SourceFileDigest.sha256(archives.originalJar());
    final Set<String> changed =
        engine.readPhysicalClassInventory(CANDIDATE, archives.originalJar(), changedDigest);
    final SourceReproductionEngine.InvocationDiagnostics diagnostics = engine.diagnostics();

    assertAll(
        "physical inventory reuse requires exact GAVCE, real path, and current whole-file digest",
        () -> assertThat(firstDigest).isNotEqualTo(changedDigest),
        () -> assertThat(changed).isEqualTo(first),
        () -> assertThat(diagnostics.physicalInventoryParses()).isEqualTo(2),
        () -> assertThat(diagnostics.physicalInventoryCacheHits()).isEqualTo(0));
  }

  private SourceReproductionTestArchives.Archives fixture(final String name) throws IOException {
    return SourceReproductionTestArchives.write(
        temporaryDirectory.resolve(name), SOURCE_ENTRY, SOURCE, false, Optional.empty(), false);
  }

  private static SourceReproductionRequest request(
      final SourceReproductionTestArchives.Archives archives,
      final List<String> files,
      final List<String> routines,
      final boolean assumeLayout) {
    final ArtifactCoordinate sources =
        new ArtifactCoordinate("org.example", "demo", "1.0", "jar", "sources", "compile");
    return new SourceReproductionRequest(
        CANDIDATE,
        sources,
        archives.originalJar(),
        archives.sourcesJar(),
        SOURCE_REPOSITORY,
        files,
        routines,
        assumeLayout);
  }
}
