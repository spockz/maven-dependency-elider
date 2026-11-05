/* WHY: Exercises physical archive and digest conditions that gate VEX attestations.
 * These cases protect against trusting trim counts in place of archive contents.
 */

package io.github.spockz.elider.model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.trimmer.ArtifactDigests;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import org.junit.jupiter.api.DisplayName;
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
  void explicitClassEvidenceRetainsPomOrigin() {
    assertAll(
        "explicit owner evidence provenance",
        () -> {
          final ExplicitClassMappingEvidence evidence =
              ExplicitEvidenceTestSupport.classEvidence(mapping("org.example.Vulnerable"));
          assertAll(
              () -> assertThat(evidence.origin()).isEqualTo(EvidenceOrigin.POM),
              () -> assertThat(evidence.configurationOrigin()).isEqualTo("test-project-pom"));
        });
  }

  @Test
  void genericProofRequiresMatchingComponentAndAffectedVersion() throws Exception {
    final ArtifactTrimRecord record =
        record(jar("bound-original.jar", "org/example/Vulnerable.class"), jar("bound-trimmed.jar"));
    final GenericVulnerabilityFinding matching =
        GenericProofTestSupport.finding(mapping("org.example.Vulnerable"));
    final GenericVulnerabilityFinding wrongVersion =
        GenericProofTestSupport.finding(
            new VulnerabilitySymbolMapping(
                "CVE-2025-12345",
                ArtifactCoordinate.of("org.example", "demo", "1.0"),
                "[2.0,3.0)",
                Set.of("org.example.Vulnerable"),
                null,
                ConfidenceLevel.HIGH));
    final GenericVulnerabilityFinding wrongComponent =
        GenericProofTestSupport.finding(
            new VulnerabilitySymbolMapping(
                "CVE-2025-12345",
                ArtifactCoordinate.of("org.example", "other", "1.0"),
                "[1.0,2.0)",
                Set.of("org.example.Vulnerable"),
                null,
                ConfidenceLevel.HIGH));
    assertAll(
        () ->
            assertThat(OmittedCodeProof.prove(matching, record, false).evidenceSymbols())
                .contains("org.example.Vulnerable"),
        () ->
            assertThatThrownBy(() -> OmittedCodeProof.prove(wrongVersion, record, false))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("affected exact version"),
        () ->
            assertThatThrownBy(() -> OmittedCodeProof.prove(wrongComponent, record, false))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("component"));
  }

  @Test
  @DisplayName("ADR-0003: attestation reports verified per-JAR source and trimmed artifact digests")
  void adr0003AttestsVerifiedPerJarProvenanceAndOmittedClasses() throws Exception {
    final ArtifactTrimRecord record =
        record(
            jar(
                "original.jar",
                "org/example/Vulnerable.class",
                "org/example/Vulnerable$Inner.class",
                "org/example/Safe.class"),
            jar("trimmed.jar", "org/example/Safe.class"));
    final VexAttestation result =
        GenericProofTestSupport.classProof(mapping("org.example.Vulnerable"), record);
    assertThat(result.cveId()).isEqualTo("CVE-2025-12345");
    assertThat(result.coordinate()).isEqualTo(record.coordinate());
    assertThat(result.originalSha256()).isEqualTo(record.originalSha256());
    assertThat(result.trimmedSha256()).isEqualTo(record.trimmedSha256());
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
    assertThatThrownBy(
            () -> GenericProofTestSupport.classProof(mapping("org.example.Vulnerable"), record))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("survives");
  }

  @Test
  void rejectsVulnerableClassSurvivingOnlyInHighestMultiReleaseTier() throws Exception {
    final ArtifactTrimRecord record =
        record(
            multiReleaseJar(
                "multi-tier-original.jar",
                "org/example/Vulnerable.class",
                "META-INF/versions/9/org/example/Vulnerable.class",
                "META-INF/versions/17/org/example/Vulnerable.class",
                "org/example/Safe.class"),
            multiReleaseJar(
                "multi-tier-trimmed.jar",
                "org/example/Safe.class",
                "META-INF/versions/17/org/example/Vulnerable.class"),
            2,
            2,
            2);

    assertThatThrownBy(
            () -> GenericProofTestSupport.classProof(mapping("org.example.Vulnerable"), record))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Vulnerable class survives trimmed archive");
  }

  @Test
  void provesVulnerableClassOmittedFromEveryMultiReleaseTier() throws Exception {
    final ArtifactTrimRecord record =
        record(
            multiReleaseJar(
                "multi-tier-original.jar",
                "org/example/Vulnerable.class",
                "META-INF/versions/9/org/example/Vulnerable.class",
                "META-INF/versions/17/org/example/Vulnerable.class",
                "META-INF/versions/99/org/example/Vulnerable.class",
                "org/example/Vulnerable$Inner.class",
                "META-INF/versions/9/org/example/Vulnerable$Inner.class",
                "META-INF/versions/17/org/example/Vulnerable$Inner.class",
                "META-INF/versions/99/org/example/Vulnerable$Inner.class",
                "org/example/Safe.class"),
            multiReleaseJar("multi-tier-trimmed.jar", "org/example/Safe.class"),
            3,
            1,
            8);

    assertThat(
            GenericProofTestSupport.classProof(mapping("org.example.Vulnerable"), record)
                .evidenceSymbols())
        .containsExactly("org.example.Vulnerable", "org.example.Vulnerable$Inner");
  }

  @Test
  void rejectsMalformedMultiReleaseClassPaths() throws Exception {
    assertAll(
        () ->
            assertMalformedVersionedClassPath(
                "META-INF/versions/8/org/example/Vulnerable.class", "at least 9"),
        () ->
            assertMalformedVersionedClassPath(
                "META-INF/versions/09/org/example/Vulnerable.class", "Non-canonical"),
        () ->
            assertMalformedVersionedClassPath(
                "META-INF/versions/bogus/org/example/Vulnerable.class", "Non-canonical"),
        () ->
            assertMalformedVersionedClassPath(
                "META-INF/versions/17/.class", "Malformed class entry identity"));
  }

  @Test
  void rejectsNestedClassSurvivingOnlyAboveRuntimeRelease() throws Exception {
    final ArtifactTrimRecord record =
        record(
            multiReleaseJar(
                "nested-tier-original.jar",
                "org/example/Vulnerable.class",
                "org/example/Vulnerable$Inner.class",
                "META-INF/versions/9/org/example/Vulnerable.class",
                "META-INF/versions/9/org/example/Vulnerable$Inner.class",
                "META-INF/versions/99/org/example/Vulnerable.class",
                "META-INF/versions/99/org/example/Vulnerable$Inner.class",
                "org/example/Safe.class"),
            multiReleaseJar(
                "nested-tier-trimmed.jar",
                "org/example/Safe.class",
                "META-INF/versions/99/org/example/Vulnerable$Inner.class"),
            3,
            2,
            5);

    assertThatThrownBy(
            () -> GenericProofTestSupport.classProof(mapping("org.example.Vulnerable"), record))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Vulnerable class survives trimmed archive");
  }

  @Test
  void rejectsDuplicatePhysicalClassEntryPath() throws Exception {
    final Path original =
        duplicatePhysicalEntryJar(
            "duplicate-physical-entry.jar",
            "org/example/Vulnerable.class",
            "org/example/Vulnerablf.class");
    final ArtifactTrimRecord record = record(original, jar("duplicate-physical-trimmed.jar"));

    assertThatThrownBy(
            () -> GenericProofTestSupport.classProof(mapping("org.example.Vulnerable"), record))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("duplicate physical ZIP entry");
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
    assertThatThrownBy(
            () -> GenericProofTestSupport.classProof(mapping("org.example.Vulnerable"), record))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("survives");
  }

  @Test
  void rejectsMatchingNestedClassPresentOnlyInTrimmedArchive() throws Exception {
    final ArtifactTrimRecord record =
        record(
            jar("original.jar", "org/example/Vulnerable.class"),
            jar("trimmed.jar", "org/example/Vulnerable$Unexpected.class"));
    assertThatThrownBy(
            () -> GenericProofTestSupport.classProof(mapping("org.example.Vulnerable"), record))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("nested class survives");
  }

  @Test
  @DisplayName("ADR-0003: changed original archive bytes violate recorded provenance")
  void adr0003RejectsChangedOriginalBytesAgainstRecordedDigest() throws Exception {
    final Path original = jar("original.jar", "org/example/Vulnerable.class");
    final Path trimmed = jar("trimmed.jar");
    final ArtifactTrimRecord record = record(original, trimmed);
    jar("original.jar", "org/example/Vulnerable.class", "org/example/Changed.class");
    assertThatThrownBy(
            () -> GenericProofTestSupport.classProof(mapping("org.example.Vulnerable"), record))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("digest");
  }

  @Test
  void provesOmissionWhenEveryMappedSymbolIsPresentAndPruned() throws Exception {
    final ArtifactTrimRecord record =
        record(
            jar(
                "original.jar",
                "org/example/PresentVulnerable.class",
                "org/example/AbsentInOlderVersion.class",
                "org/example/Safe.class"),
            jar("trimmed.jar", "org/example/Safe.class"));
    final VulnerabilitySymbolMapping multiSymbol =
        new VulnerabilitySymbolMapping(
            "CVE-2026-68494",
            ArtifactCoordinate.of("org.example", "demo", "1.0"),
            "[1.0,2.0)",
            Set.of("org.example.PresentVulnerable", "org.example.AbsentInOlderVersion"),
            null,
            ConfidenceLevel.HIGH);

    final VexAttestation attestation = GenericProofTestSupport.classProof(multiSymbol, record);
    assertAll(
        () -> assertThat(attestation.cveId()).isEqualTo("CVE-2026-68494"),
        () -> assertThat(attestation.justification()).isEqualTo("vulnerable_code_not_present"),
        () ->
            assertThat(attestation.evidenceSymbols())
                .containsExactly(
                    "org.example.AbsentInOlderVersion", "org.example.PresentVulnerable"));
  }

  @Test
  void rejectsMappingWhenNoneOfMappedSymbolsWereInOriginalArchive() throws Exception {
    final ArtifactTrimRecord record =
        record(jar("original.jar", "org/example/Other.class"), jar("trimmed.jar"));
    assertThatThrownBy(
            () -> GenericProofTestSupport.classProof(mapping("org.example.Vulnerable"), record))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("attribution");
  }

  @Test
  void doesNotAdmitLowConfidenceMappingAsProofEvidence() throws Exception {
    final ArtifactTrimRecord record =
        record(jar("original.jar", "org/example/Vulnerable.class"), jar("trimmed.jar"));
    final VulnerabilitySymbolMapping lowConfidence =
        new VulnerabilitySymbolMapping(
            "CVE-2025-12345",
            ArtifactCoordinate.of("org.example", "demo", "1.0"),
            "[1.0,2.0)",
            Set.of("org.example.Vulnerable"),
            null,
            ConfidenceLevel.LOW);
    assertAll(
        () -> assertRejectedLowConfidenceMapping(lowConfidence, record),
        () ->
            assertRejectedLowConfidenceMapping(
                new VulnerabilitySymbolMapping(
                    "CVE-2025-12345",
                    ArtifactCoordinate.of("org.example", "demo", "1.0"),
                    "[1.0,2.0)",
                    Set.of("org.example.Vulnerable"),
                    null,
                    ConfidenceLevel.MEDIUM),
                record));
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
            ConfidenceLevel.HIGH);
    assertThatThrownBy(() -> GenericProofTestSupport.classProof(mismatched, record))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("supported affected exact version");
  }

  @Test
  void unresolvedAbsentDeclarationBlocksAggregateProof() throws Exception {
    final ArtifactTrimRecord record =
        record(
            jar("original.jar", "org/example/PresentVulnerable.class", "org/example/Safe.class"),
            jar("trimmed.jar", "org/example/Safe.class"));
    final VulnerabilitySymbolMapping mapping =
        new VulnerabilitySymbolMapping(
            "CVE-2026-68494",
            ArtifactCoordinate.of("org.example", "demo", "1.0"),
            "[1.0,2.0)",
            Set.of("org.example.PresentVulnerable", "org.example.AbsentClass"),
            null,
            ConfidenceLevel.HIGH);
    final GenericVulnerabilityFinding finding = GenericProofTestSupport.finding(mapping);
    final CodeAttributionResolver.Result attribution =
        CodeAttributionResolver.resolve(
            finding.effectiveCodeClaimsFor("1.0"),
            io.github.spockz.elider.scanner.JarSourceFileIndex.read(record.originalPath()),
            false);
    assertAll(
        () ->
            assertThat(attribution.declarations())
                .anyMatch(
                    value ->
                        "org.example.AbsentClass".equals(value.claim().reference().value())
                            && value.status() == CodeAttributionResolver.Status.UNRESOLVED),
        () ->
            assertThat(attribution.declarations())
                .anyMatch(
                    value ->
                        "org.example.PresentVulnerable".equals(value.claim().reference().value())
                            && value.status() == CodeAttributionResolver.Status.RESOLVED),
        () ->
            assertThatThrownBy(() -> GenericProofTestSupport.classProof(mapping, record))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("attribution"));
  }

  @Test
  void survivingDeclarationBlocksAggregateProof() throws Exception {
    final ArtifactTrimRecord record =
        record(
            jar("original.jar", "org/example/PresentVulnerable.class", "org/example/Second.class"),
            jar("trimmed.jar", "org/example/PresentVulnerable.class"));
    final VulnerabilitySymbolMapping mapping =
        new VulnerabilitySymbolMapping(
            "CVE-2026-68494",
            ArtifactCoordinate.of("org.example", "demo", "1.0"),
            "[1.0,2.0)",
            Set.of("org.example.PresentVulnerable", "org.example.Second"),
            null,
            ConfidenceLevel.HIGH);
    assertThatThrownBy(() -> GenericProofTestSupport.classProof(mapping, record))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("survives");
  }

  private ArtifactTrimRecord record(final Path original, final Path trimmed) throws IOException {
    return record(original, trimmed, 3, 2, 1);
  }

  private ArtifactTrimRecord record(
      final Path original,
      final Path trimmed,
      final int totalClasses,
      final int retainedClasses,
      final long prunedClassBytes)
      throws IOException {
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
        totalClasses,
        retainedClasses,
        prunedClassBytes);
  }

  private Path jar(final String name, final String... entries) throws IOException {
    final Path path = directory.resolve(name);
    try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(path))) {
      for (final String entry : entries) {
        output.putNextEntry(new JarEntry(entry));
        output.write(classBytes(entry));
        output.closeEntry();
      }
    }
    return path;
  }

  private Path multiReleaseJar(final String name, final String... entries) throws IOException {
    final Path path = directory.resolve(name);
    final Manifest manifest = new Manifest();
    manifest.getMainAttributes().putValue("Manifest-Version", "1.0");
    manifest.getMainAttributes().putValue("Multi-Release", "true");
    try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(path), manifest)) {
      for (final String entry : entries) {
        output.putNextEntry(new JarEntry(entry));
        output.write(classBytes(entry));
        output.closeEntry();
      }
    }
    return path;
  }

  private static byte[] classBytes(final String entry) {
    if (!entry.endsWith(".class")) {
      return new byte[] {0};
    }
    String internalName = entry.substring(0, entry.length() - ".class".length());
    if (internalName.startsWith("META-INF/versions/")) {
      final int versionEnd = internalName.indexOf('/', "META-INF/versions/".length());
      if (versionEnd >= 0) {
        internalName = internalName.substring(versionEnd + 1);
      }
    }
    final org.objectweb.asm.ClassWriter writer = new org.objectweb.asm.ClassWriter(0);
    writer.visit(
        org.objectweb.asm.Opcodes.V21,
        org.objectweb.asm.Opcodes.ACC_PUBLIC,
        internalName,
        null,
        "java/lang/Object",
        null);
    writer.visitEnd();
    return writer.toByteArray();
  }

  private Path duplicatePhysicalEntryJar(
      final String name, final String firstEntry, final String secondEntry) throws IOException {
    final Path source = jar(name, firstEntry, secondEntry);
    final byte[] originalBytes = Files.readAllBytes(source);
    final String archive = new String(originalBytes, StandardCharsets.ISO_8859_1);
    final byte[] duplicateBytes =
        archive.replace(secondEntry, firstEntry).getBytes(StandardCharsets.ISO_8859_1);
    Files.write(source, duplicateBytes);
    return source;
  }

  private void assertMalformedVersionedClassPath(
      final String malformedPath, final String diagnostic) throws IOException {
    final ArtifactTrimRecord record =
        record(
            multiReleaseJar(
                "malformed-versioned-class.jar", "org/example/Vulnerable.class", malformedPath),
            jar("malformed-versioned-trimmed.jar"));
    assertThatThrownBy(
            () -> GenericProofTestSupport.classProof(mapping("org.example.Vulnerable"), record))
        .isInstanceOf(IOException.class)
        .hasMessageContaining(diagnostic);
  }

  private static VulnerabilitySymbolMapping mapping(final String className) {
    return new VulnerabilitySymbolMapping(
        "CVE-2025-12345",
        ArtifactCoordinate.of("org.example", "demo", "1.0"),
        "[1.0,2.0)",
        Set.of(className),
        null,
        ConfidenceLevel.HIGH);
  }

  private static void assertRejectedLowConfidenceMapping(
      final VulnerabilitySymbolMapping mapping, final ArtifactTrimRecord record) {
    assertThatThrownBy(() -> GenericProofTestSupport.classProof(mapping, record))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("review");
  }
}
