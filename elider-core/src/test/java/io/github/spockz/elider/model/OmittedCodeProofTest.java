/* WHY: Exercises physical archive and digest conditions that gate VEX attestations.
 * These cases protect against trusting trim counts in place of archive contents.
 */

package io.github.spockz.elider.model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.spockz.elider.trimmer.ArtifactDigests;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Exercises physical archive and digest checks that gate VEX attestations. */
@SuppressWarnings({
  "PMD.CommentDefaultAccessModifier",
  "PMD.AtLeastOneConstructor",
  "PMD.UnitTestContainsTooManyAsserts",
  "PMD.AvoidDuplicateLiterals",
  "PMD.AvoidInstantiatingObjectsInLoops",
  "PMD.TooManyMethods"
})
class OmittedCodeProofTest {
  /** Temporary workspace for controlled test JARs. */
  @TempDir Path directory;

  @Test
  void attestationConstructionIsRestrictedToProofPackage() {
    assertThat(java.lang.reflect.Modifier.isFinal(VexAttestation.class.getModifiers())).isTrue();
    assertThat(
            java.lang.reflect.Modifier.isPublic(
                VexAttestation.class.getDeclaredConstructors()[0].getModifiers()))
        .isFalse();
  }

  @Test
  void provesMappedClassAndAllOriginalNestedClassesAreAbsent() throws Exception {
    final ArtifactTrimRecord record =
        record(
            jar(
                "original.jar",
                "org/example/Vulnerable.class",
                "org/example/Vulnerable$Inner.class",
                "org/example/Safe.class"),
            jar("trimmed.jar", "org/example/Safe.class"));
    final VexAttestation result = OmittedCodeProof.prove(mapping("org.example.Vulnerable"), record);
    assertThat(result.cveId()).isEqualTo("CVE-2025-12345");
    assertThat(result.coordinate()).isEqualTo(record.coordinate());
    assertThat(result.evidenceSymbols())
        .containsExactly("org.example.Vulnerable", "org.example.Vulnerable$Inner");
    assertThat(result.justification()).isEqualTo("vulnerable_code_not_present");
  }

  @Test
  void rejectsSurvivingMappedClassEvenWhenClassCountStillLooksReduced() throws Exception {
    final ArtifactTrimRecord record =
        record(
            jar(
                "original.jar",
                "org/example/Vulnerable.class",
                "org/example/Unused.class",
                "org/example/Safe.class"),
            jar("trimmed.jar", "org/example/Vulnerable.class", "org/example/Safe.class"));
    assertThatThrownBy(() -> OmittedCodeProof.prove(mapping("org.example.Vulnerable"), record))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("survives");
  }

  @Test
  void rejectsSurvivingNestedClass() throws Exception {
    final ArtifactTrimRecord record =
        record(
            jar(
                "original.jar",
                "org/example/Vulnerable.class",
                "org/example/Vulnerable$Inner.class"),
            jar("trimmed.jar", "org/example/Vulnerable$Inner.class"));
    assertThatThrownBy(() -> OmittedCodeProof.prove(mapping("org.example.Vulnerable"), record))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("survives");
  }

  @Test
  void rejectsDigestMutationAfterTrimRecordWasCreated() throws Exception {
    final Path original = jar("original.jar", "org/example/Vulnerable.class");
    final Path trimmed = jar("trimmed.jar");
    final ArtifactTrimRecord record = record(original, trimmed);
    Files.writeString(original, "mutated");
    assertThatThrownBy(() -> OmittedCodeProof.prove(mapping("org.example.Vulnerable"), record))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("digest");
  }

  @Test
  void rejectsMappingAbsentFromOriginalArchive() throws Exception {
    final ArtifactTrimRecord record =
        record(jar("original.jar", "org/example/Other.class"), jar("trimmed.jar"));
    assertThatThrownBy(() -> OmittedCodeProof.prove(mapping("org.example.Vulnerable"), record))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("absent from original");
  }

  @Test
  void rejectsMappingsBelowHighConfidence() throws Exception {
    final ArtifactTrimRecord record =
        record(jar("original.jar", "org/example/Vulnerable.class"), jar("trimmed.jar"));
    final VulnerabilitySymbolMapping lowConfidence =
        new VulnerabilitySymbolMapping(
            "CVE-2025-12345",
            ArtifactCoordinate.of("org.example", "demo", "1.0"),
            "[1.0,2.0)",
            Set.of("org.example.Vulnerable"),
            null,
            VulnerabilitySymbolMapping.ConfidenceLevel.LOW);
    assertThatThrownBy(() -> OmittedCodeProof.prove(lowConfidence, record))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("HIGH confidence");
  }

  @Test
  void rejectsCoordinateVersionMismatch() throws Exception {
    final ArtifactTrimRecord record =
        record(jar("original.jar", "org/example/Vulnerable.class"), jar("trimmed.jar"));
    final VulnerabilitySymbolMapping mismatched =
        new VulnerabilitySymbolMapping(
            "CVE-2025-12345",
            ArtifactCoordinate.of("org.example", "demo", "2.0"),
            "[2.0,3.0)",
            Set.of("org.example.Vulnerable"),
            null,
            VulnerabilitySymbolMapping.ConfidenceLevel.HIGH);
    assertThatThrownBy(() -> OmittedCodeProof.prove(mismatched, record))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("does not match");
  }

  private ArtifactTrimRecord record(final Path original, final Path trimmed) throws IOException {
    final ArtifactDigests originalHash = ArtifactDigests.read(original);
    final ArtifactDigests trimmedHash = ArtifactDigests.read(trimmed);
    return new ArtifactTrimRecord(
        ArtifactCoordinate.of("org.example", "demo", "1.0"),
        original,
        originalHash.sha256(),
        originalHash.sha1(),
        trimmed,
        trimmedHash.sha256(),
        trimmedHash.sha1(),
        3,
        2,
        1);
  }

  private Path jar(final String name, final String... entries) throws IOException {
    final Path path = directory.resolve(name);
    try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(path))) {
      for (final String entry : entries) {
        output.putNextEntry(new JarEntry(entry));
        output.write(new byte[] {0});
        output.closeEntry();
      }
    }
    return path;
  }

  private static VulnerabilitySymbolMapping mapping(final String className) {
    return new VulnerabilitySymbolMapping(
        "CVE-2025-12345",
        ArtifactCoordinate.of("org.example", "demo", "1.0"),
        "[1.0,2.0)",
        Set.of(className),
        null,
        VulnerabilitySymbolMapping.ConfidenceLevel.HIGH);
  }
}
