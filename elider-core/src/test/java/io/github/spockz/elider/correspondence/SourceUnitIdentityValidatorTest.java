// WHY: Prevents basename-only class metadata from being mistaken for source path identity.

package io.github.spockz.elider.correspondence;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.spockz.elider.model.ArtifactCoordinate;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.jar.JarFile;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Checks source path/package binding through the public reproduction engine. */
@SuppressWarnings("PMD.AtLeastOneConstructor") // JUnit supplies the test instance lifecycle.
final class SourceUnitIdentityValidatorTest {
  /** Exact source claim whose basename also appears in an alternate path. */
  private static final String CLAIMED_ENTRY = "src/main/java/org/example/Outer.java";

  /** Candidate and source coordinates bind the independently built archive pair. */
  private static final ArtifactCoordinate CANDIDATE =
      ArtifactCoordinate.of("org.example", "demo", "1.0");

  /** Resolver provenance is descriptive input only. */
  private static final String SOURCE_REPOSITORY = "remote:fixture-repository";

  /** Isolates archive fixtures for each test. */
  @TempDir private Path temporaryDirectory;

  @org.junit.jupiter.api.BeforeEach
  void verifySupportedJdk() {
    org.junit.jupiter.api.Assumptions.assumeTrue(
        SourceJdkIdentity.isSupported(),
        "Skipping source reproduction tests on non-pinned JDK");
  }

  @Test
  void crossPackageSameBasenameSwapAbstainsDespiteExactCompiledClassArchive() throws IOException {
    final SourceReproductionTestArchives.Archives archives =
        archives(
            temporaryDirectory.resolve("package-swap"),
            "package org.other; class Other {}",
            "alternate/org/other/Outer.java",
            "package org.example; class Outer {}");
    final boolean archiveContainsSwappedClass =
        originalContains(archives.originalJar(), "org/other/Other.class");
    final SourceReproductionResult result =
        SourceReproductionEngine.forCurrentJdk()
            .reproduce(request(archives, List.of(CLAIMED_ENTRY)));

    assertAll(
        "the sources and binary JARs come from the same compiled units, but claim path is wrong",
        () -> assertTrue(archiveContainsSwappedClass, "the swapped compilation output is present"),
        () -> assertRefused(result, "path disagrees with the declared Java package"));
  }

  @Test
  void duplicatePackageAndBasenameAcrossRootsAbstainsDespiteExactCompiledClassArchive()
      throws IOException {
    final SourceReproductionTestArchives.Archives archives =
        archives(
            temporaryDirectory.resolve("duplicate-basename"),
            "package org.example; class Outer {}",
            "alternate/org/example/Outer.java",
            "package org.example; class Helper {}");
    final boolean archiveContainsAlternateClass =
        originalContains(archives.originalJar(), "org/example/Helper.class");
    final SourceReproductionResult result =
        SourceReproductionEngine.forCurrentJdk()
            .reproduce(request(archives, List.of(CLAIMED_ENTRY)));

    assertAll(
        "SourceFile metadata cannot distinguish same-package same-basename units across roots",
        () ->
            assertTrue(
                archiveContainsAlternateClass, "the alternate compilation output is present"),
        () -> assertRefused(result, "ambiguous package and basename identities"));
  }

  private static SourceReproductionTestArchives.Archives archives(
      final Path directory,
      final String claimedSource,
      final String alternateEntry,
      final String alternateSource)
      throws IOException {
    return SourceReproductionTestArchives.write(
        directory,
        CLAIMED_ENTRY,
        claimedSource,
        false,
        Optional.of(
            new SourceReproductionTestArchives.AdditionalSource(alternateEntry, alternateSource)),
        false);
  }

  private static SourceReproductionRequest request(
      final SourceReproductionTestArchives.Archives archives, final List<String> sourceClaims) {
    final ArtifactCoordinate sources =
        new ArtifactCoordinate("org.example", "demo", "1.0", "jar", "sources", "compile");
    return new SourceReproductionRequest(
        CANDIDATE,
        sources,
        archives.originalJar(),
        archives.sourcesJar(),
        SOURCE_REPOSITORY,
        sourceClaims,
        List.of(),
        false);
  }

  private static boolean originalContains(final Path jar, final String entry) throws IOException {
    try (JarFile archive = new JarFile(jar.toFile())) {
      return archive.getEntry(entry) != null;
    }
  }

  private static void assertRefused(final SourceReproductionResult result, final String reason) {
    assertThat(result)
        .isInstanceOf(SourceReproductionResult.Abstained.class)
        .extracting(value -> ((SourceReproductionResult.Abstained) value).rationale())
        .asString()
        .contains(reason);
  }
}
