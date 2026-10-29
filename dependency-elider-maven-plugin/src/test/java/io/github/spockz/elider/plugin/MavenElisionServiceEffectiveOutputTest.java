// WHY: Proves actual trimmed outputs and cache identity consume the finalized graph/bytecode roots.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.trimmer.ArtifactDigests;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.jar.JarFile;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.model.Build;
import org.apache.maven.project.MavenProject;
import org.junit.jupiter.api.Test;

/** Verifies effective output bytes and cache behavior. */
@SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
final class MavenElisionServiceEffectiveOutputTest
    extends MavenElisionServiceEffectiveOutputSupport {
  /** Trace root shared by the retained-dependency fixture cases. */
  private static final String ENTRY_TRACE = "closure/a/Entry";

  /** Non-class ZIP entry preserved by archive sanitization. */
  private static final String FIXTURE_RESOURCE = "data/fixture.txt";

  /** Exact bytes stored at the fixture resource path. */
  private static final String FIXTURE_RESOURCE_CONTENT = "preserve this resource\n";

  /** Creates the test group for output-producing effective analysis. */
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  MavenElisionServiceEffectiveOutputTest() {
    super();
  }

  @Test
  void finishUsesEffectiveRootsAndReusesTheValidatedGeneration() throws Exception {
    final Fixture fixture = fixture(false);
    final Path trace = trace(temporaryDirectory, ENTRY_TRACE);
    final ServiceOperation operation = operation(fixture, trace, null);
    final MavenElisionService.EffectiveAnalysis effective =
        operation.service().finishAnalysis(operation.prepared());
    assertThat(effective.prepared().rawDecision()).isEqualTo(operation.prepared().rawDecision());
    assertThat(effective.forcedUnchangedCoordinates())
        .contains(fixture.coordinate("b"), fixture.coordinate("c"));
    final List<Artifact> beforeResolved = List.copyOf(fixture.mavenProject().getArtifacts());
    final String originalDigest = ArtifactDigests.read(fixture.snapshot("a").filePath()).sha256();
    final String unchangedDigest = ArtifactDigests.read(fixture.snapshot("b").filePath()).sha256();
    assertThat(fixture.mavenProject().getDependencyArtifacts()).isNull();

    final MavenDependencyTrimmer.TrimResult cold =
        MavenDependencyTrimmer.trimEffectiveOutputs(effective);
    assertThat(effective.rawDecision().retainedClassesPerArtifact().get(fixture.coordinate("a")))
        .contains("closure.a.Entry");
    final ArtifactTrimRecord coldRecord = record(cold.records(), fixture.coordinate("a"));
    assertThat(coldRecord.trimmedPath().toString()).contains(".generations");
    assertThat(coldRecord.trimmedPath()).isRegularFile();
    assertThat(coldRecord.originalSha256()).isEqualTo(originalDigest);
    assertThat(ArtifactDigests.read(coldRecord.trimmedPath()).sha256())
        .isEqualTo(coldRecord.trimmedSha256());
    try (JarFile output = new JarFile(coldRecord.trimmedPath().toFile())) {
      assertThat(output.getEntry("closure/a/Entry.class")).isNotNull();
      assertThat(output.getEntry("closure/a/Extra.class")).isNull();
      assertThat(output.getEntry(FIXTURE_RESOURCE)).isNotNull();
      assertThat(
              new String(
                  output.getInputStream(output.getEntry(FIXTURE_RESOURCE)).readAllBytes(),
                  StandardCharsets.UTF_8))
          .isEqualTo(FIXTURE_RESOURCE_CONTENT);
    }
    assertThat(fixture.mavenProject().getArtifacts())
        .containsExactlyInAnyOrderElementsOf(beforeResolved);
    assertThat(fixture.mavenProject().getDependencyArtifacts()).isNull();
    assertThat(ArtifactDigests.read(fixture.snapshot("a").filePath()).sha256())
        .isEqualTo(originalDigest);
    assertThat(ArtifactDigests.read(fixture.snapshot("b").filePath()).sha256())
        .isEqualTo(unchangedDigest);
    try (JarFile unchanged = new JarFile(fixture.snapshot("b").filePath().toFile())) {
      assertThat(unchanged.getEntry(FIXTURE_RESOURCE)).isNotNull();
      assertThat(
              new String(
                  unchanged.getInputStream(unchanged.getEntry(FIXTURE_RESOURCE)).readAllBytes(),
                  StandardCharsets.UTF_8))
          .isEqualTo(FIXTURE_RESOURCE_CONTENT);
    }

    final MavenDependencyTrimmer.TrimResult warm =
        MavenDependencyTrimmer.trimEffectiveOutputs(
            operation.service().finishAnalysis(operation.prepared()));
    final ArtifactTrimRecord warmRecord = record(warm.records(), fixture.coordinate("a"));
    assertThat(warm.cacheHits()).isPositive();
    assertThat(warm.analysisRuns()).isZero();
    assertThat(warmRecord.trimmedPath()).isEqualTo(coldRecord.trimmedPath());
    assertThat(warmRecord.trimmedSha256()).isEqualTo(coldRecord.trimmedSha256());
  }

  @Test
  void effectiveRootChangeSelectsAnotherGenerationAndMissesCache() throws Exception {
    final Fixture fixture = fixture(false);
    final ServiceOperation firstOperation =
        operation(fixture, trace(temporaryDirectory.resolve("entry"), ENTRY_TRACE), null);
    final MavenDependencyTrimmer.TrimResult first = trimEffective(firstOperation);
    final ArtifactTrimRecord firstRecord = record(first.records(), fixture.coordinate("a"));

    final ServiceOperation secondOperation =
        operation(fixture, trace(temporaryDirectory.resolve("extra"), "closure/a/Extra"), null);
    final MavenDependencyTrimmer.TrimResult second = trimEffective(secondOperation);
    final ArtifactTrimRecord secondRecord = record(second.records(), fixture.coordinate("a"));

    assertThat(second.cacheHits()).isZero();
    assertThat(secondRecord.trimmedPath()).isNotEqualTo(firstRecord.trimmedPath());
    try (JarFile output = new JarFile(secondRecord.trimmedPath().toFile())) {
      assertThat(output.getEntry("closure/a/Extra.class")).isNotNull();
      assertThat(output.getEntry("closure/a/Entry.class")).isNull();
    }
  }

  @Test
  void productionContentChangeAloneInvalidatesOutputCache() throws Exception {
    final Fixture fixture = fixture(false);
    final Path trace = trace(temporaryDirectory, ENTRY_TRACE);
    final Path production = Files.createDirectories(temporaryDirectory.resolve("production"));
    compileProductionClass(production, 1);
    final ServiceOperation firstOperation = operation(fixture, trace, production.toFile());
    final MavenDependencyTrimmer.TrimResult first = trimEffective(firstOperation);
    final ArtifactTrimRecord firstRecord = record(first.records(), fixture.coordinate("a"));
    final java.util.Set<String> firstReferences =
        java.util.Set.copyOf(
            firstOperation.prepared().bytecodeScan().orElseThrow().referencedClasses());
    final String firstProductionDigest = firstOperation.prepared().productionOutputFingerprint();

    compileProductionClass(production, 2);
    final ServiceOperation secondOperation = operation(fixture, trace, production.toFile());
    final MavenDependencyTrimmer.TrimResult second = trimEffective(secondOperation);
    final ArtifactTrimRecord secondRecord = record(second.records(), fixture.coordinate("a"));

    assertThat(secondOperation.prepared().bytecodeScan().orElseThrow().referencedClasses())
        .containsExactlyInAnyOrderElementsOf(firstReferences);
    assertThat(secondOperation.prepared().productionOutputFingerprint())
        .isNotEqualTo(firstProductionDigest);
    assertThat(second.cacheHits()).isZero();
    assertThat(secondRecord.trimmedPath()).isNotEqualTo(firstRecord.trimmedPath());
  }

  @Test
  void trimmingDisabledProducesNoOutputGeneration() throws Exception {
    final Fixture fixture = fixture(false);
    final ServiceOperation operation =
        operation(fixture, trace(temporaryDirectory, ENTRY_TRACE), null, false);
    final List<String> before = sourceDigests(fixture);

    final MavenDependencyTrimmer.TrimResult result = trimEffective(operation);

    assertThat(result.records()).isEmpty();
    assertThat(sourceDigests(fixture)).isEqualTo(before);
    assertThat(
            Path.of(
                fixture.mavenProject().getBuild().getDirectory(),
                "elided-artifacts",
                ".trim-analysis-cache.json"))
        .doesNotExist();
  }

  @Test
  void retainedResourceOnlyJarPassesThroughByteIdentically() throws Exception {
    final Fixture fixture = fixture(false, false, true);
    final ServiceOperation operation =
        operationWithExcludedArtifacts(
            fixture,
            trace(temporaryDirectory, ENTRY_TRACE),
            null,
            List.of("fixture:b:1.0:jar"),
            true);
    final MavenElisionService.EffectiveAnalysis effective =
        operation.service().finishAnalysis(operation.prepared());
    assertThat(effective.rawDecision().retainedArtifacts()).contains(fixture.coordinate("b"));
    assertThat(effective.effectiveDecision().retainedArtifacts()).contains(fixture.coordinate("b"));
    final Path source = fixture.snapshot("b").filePath();
    final String sourceDigest = ArtifactDigests.read(source).sha256();

    final MavenDependencyTrimmer.TrimResult result = trimEffective(operation);

    assertThat(result.records())
        .extracting(ArtifactTrimRecord::coordinate)
        .doesNotContain(fixture.coordinate("b"));
    assertThat(ArtifactDigests.read(source).sha256()).isEqualTo(sourceDigest);
    try (JarFile resourceOnly = new JarFile(source.toFile())) {
      assertThat(resourceOnly.getEntry(FIXTURE_RESOURCE)).isNotNull();
      assertThat(resourceOnly.stream().map(java.util.jar.JarEntry::getName))
          .containsExactly("data/fixture.txt");
      assertThat(
              new String(
                  resourceOnly
                      .getInputStream(resourceOnly.getEntry(FIXTURE_RESOURCE))
                      .readAllBytes(),
                  StandardCharsets.UTF_8))
          .isEqualTo(FIXTURE_RESOURCE_CONTENT);
    }
  }

  @Test
  void relativeBuildDirectoryProducesAnAbsoluteGenerationPath() {
    final MavenProject project = new MavenProject();
    final Build build = new Build();
    build.setDirectory("relative-build-output");
    project.setBuild(build);

    assertThat(MavenDependencyTrimmer.generationPath(project, "fingerprint")).isAbsolute();
  }

  private static ArtifactTrimRecord record(
      final List<ArtifactTrimRecord> records, final ArtifactCoordinate coordinate) {
    return records.stream()
        .filter(value -> value.coordinate().equals(coordinate))
        .findFirst()
        .orElseThrow();
  }

  private static List<String> sourceDigests(final Fixture fixture) throws IOException {
    final List<String> digests = new java.util.ArrayList<>();
    for (final MavenElisionService.ArtifactSnapshot snapshot : fixture.allSnapshots()) {
      digests.add(ArtifactDigests.read(snapshot.filePath()).sha256());
    }
    return List.copyOf(digests);
  }

  private void compileProductionClass(final Path output, final int constant) throws IOException {
    final Path sourceRoot =
        Files.createDirectories(temporaryDirectory.resolve("source-" + constant));
    final Path source = sourceRoot.resolve("generated/Output.java");
    Files.createDirectories(source.getParent());
    Files.writeString(
        source,
        "package generated; public class Output { public int value() { return "
            + constant
            + "; } }\n");
    io.github.spockz.elider.test.CompilationFixtureSupport.compile(output, List.of(source));
  }
}
