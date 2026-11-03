/* WHY: Exercises physical archive and digest conditions that gate VEX attestations.
 * These cases protect against trusting trim counts in place of archive contents.
 */

package io.github.spockz.elider.model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.metadata.CycloneDxSbomGenerator;
import io.github.spockz.elider.metadata.OpenVexGenerator;
import io.github.spockz.elider.trimmer.ArtifactDigests;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
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
  void openVexRejectsStructuredAttestationsWithConflictingSourceProvenance() throws Exception {
    final Path componentPath = directory.resolve("component.jar");
    Files.writeString(componentPath, "component bytes");
    final ArtifactCoordinate coordinate = ArtifactCoordinate.of("org.example", "demo", "1.0");
    final ArtifactFileRef component = ArtifactFileRef.fromPath(coordinate, componentPath);
    final String componentDigest = ArtifactDigests.read(componentPath).sha256();
    final String sharedDigest = "a".repeat(64);
    final VexAttestation first = structuredAttestation(coordinate, componentDigest, sharedDigest);
    final VexAttestation second =
        structuredAttestation(coordinate, componentDigest, "b".repeat(64));
    final OpenVexGenerator generator = new OpenVexGenerator();
    final CycloneDxSbomGenerator.RootIdentity root =
        new CycloneDxSbomGenerator.RootIdentity("org.example", "app", "1.0", "app");
    final OpenVexGenerator.DocumentMetadata metadata =
        new OpenVexGenerator.DocumentMetadata(
            "urn:uuid:123e4567-e89b-12d3-a456-426614174000",
            "Elider Project",
            "Build System",
            Instant.parse("2026-10-29T00:00:00Z"),
            1);

    assertThatThrownBy(
            () -> generator.generate(root, List.of(component), List.of(first, second), metadata))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Conflicting duplicate omitted-code VEX attestation");
  }

  private static VexAttestation structuredAttestation(
      final ArtifactCoordinate coordinate,
      final String componentDigest,
      final String cveSourceDigest) {
    final StructuredProofProvenance.RawScopeEvidence rawScope =
        new StructuredProofProvenance.RawScopeEvidence(
            "2026-10-28T00:00:00Z",
            "Maven",
            "org.example:demo",
            List.of("1.0"),
            List.of(),
            "PUBLISHED",
            null,
            List.of(),
            "AFFECTED",
            "AFFECTED",
            "exact OSV version claim",
            "exact CNA version claim");
    final StructuredProofProvenance provenance =
        new StructuredProofProvenance(
            "GHSA-test",
            cveSourceDigest,
            "containers.cna.affected[0]",
            "purl:pkg:maven/org.example/demo@1.0",
            StructuredProofProvenance.OsvSourceAuthority.CONFIGURED_PRODUCER_COMPATIBLE_INDEX,
            new ArtifactCoordinate("org.example", "demo", "1.0", "jar", "sources", "compile"),
            "c".repeat(64),
            "remote:test-repository",
            "pinned-jdk-21",
            List.of("--release", "21", "-encoding", "UTF-8"),
            true,
            rawScope,
            List.of(
                new StructuredProofProvenance.ClaimAttribution(
                    StructuredProofProvenance.ClaimType.FILE,
                    "src/main/java/org/example/Vulnerable.java",
                    "src/main/java/org/example/Vulnerable.java",
                    null,
                    List.of(
                        new StructuredProofProvenance.ClassEntry(
                            "org/example/Vulnerable.class", "e".repeat(64))))));
    return VexAttestation.structuredOmittedCode(
        "CVE-2025-12345",
        coordinate,
        "Structured source claims were verified and omitted.",
        Set.of("org.example.Vulnerable"),
        "d".repeat(64),
        componentDigest,
        provenance);
  }

  @Test
  void explicitClassEvidenceRetainsPomOrigin() {
    assertAll(
        "explicit owner evidence provenance",
        () -> {
          final ExplicitClassMappingEvidence evidence = mapping("org.example.Vulnerable");
          assertAll(
              () -> assertThat(evidence.origin()).isEqualTo(EvidenceOrigin.POM),
              () -> assertThat(evidence.configurationOrigin()).isEqualTo("test-project-pom"));
        });
  }

  @Test
  void proofRequiresOwnerEvidenceBoundToMatchingVersionScope() throws Exception {
    final ArtifactCoordinate coordinate = ArtifactCoordinate.of("org.example", "demo", "1.0");
    final ExplicitClassMappingEvidence declared =
        ExplicitClassMappingEvidence.declare(
            "CVE-2025-12345",
            coordinate,
            "[1.0,2.0)",
            Set.of("org.example.Vulnerable"),
            null,
            ConfidenceLevel.HIGH,
            "effective-project-pom:vulnerabilityMappings[0]");
    final ArtifactTrimRecord record =
        record(jar("bound-original.jar", "org/example/Vulnerable.class"), jar("bound-trimmed.jar"));

    assertAll(
        "proof admission requires bound owner evidence",
        () -> {
          assertThatThrownBy(() -> OmittedCodeProof.prove(declared, record))
              .isInstanceOf(IllegalArgumentException.class)
              .hasMessageContaining("must be bound");
        },
        () -> {
          assertThatThrownBy(() -> declared.bindTo(coordinate, (range, version) -> false))
              .isInstanceOf(IllegalArgumentException.class)
              .hasMessageContaining("version scope");
        },
        () -> {
          final VexAttestation proof =
              OmittedCodeProof.prove(declared.bindTo(coordinate, (range, version) -> true), record);
          assertAll(
              "matching owner assertion passes physical proof",
              () -> assertThat(proof).isNotNull(),
              () -> assertThat(proof.evidenceSymbols()).contains("org.example.Vulnerable"));
        });
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
    final VexAttestation result = OmittedCodeProof.prove(mapping("org.example.Vulnerable"), record);
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
    assertThatThrownBy(() -> OmittedCodeProof.prove(mapping("org.example.Vulnerable"), record))
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

    assertThatThrownBy(() -> OmittedCodeProof.prove(mapping("org.example.Vulnerable"), record))
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

    assertThat(OmittedCodeProof.prove(mapping("org.example.Vulnerable"), record).evidenceSymbols())
        .containsExactly("org.example.Vulnerable", "org.example.Vulnerable$Inner");
  }

  @Test
  void rejectsMalformedMultiReleaseClassPaths() throws Exception {
    assertMalformedVersionedClassPath("META-INF/versions/8/org/example/Vulnerable.class");
    assertMalformedVersionedClassPath("META-INF/versions/09/org/example/Vulnerable.class");
    assertMalformedVersionedClassPath("META-INF/versions/bogus/org/example/Vulnerable.class");
    assertMalformedVersionedClassPath("META-INF/versions/17/.class");
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

    assertThatThrownBy(() -> OmittedCodeProof.prove(mapping("org.example.Vulnerable"), record))
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

    assertThatThrownBy(() -> OmittedCodeProof.prove(mapping("org.example.Vulnerable"), record))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Duplicate physical archive entry");
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
  void rejectsMatchingNestedClassPresentOnlyInTrimmedArchive() throws Exception {
    final ArtifactTrimRecord record =
        record(
            jar("original.jar", "org/example/Vulnerable.class"),
            jar("trimmed.jar", "org/example/Vulnerable$Unexpected.class"));
    assertThatThrownBy(() -> OmittedCodeProof.prove(mapping("org.example.Vulnerable"), record))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("nested class survives");
  }

  @Test
  @DisplayName("ADR-0003: changed original archive bytes violate recorded provenance")
  void adr0003RejectsChangedOriginalBytesAgainstRecordedDigest() throws Exception {
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
    assertThatThrownBy(
            () ->
                OmittedCodeProof.prove(
                    ExplicitEvidenceTestSupport.classEvidence(mismatched), record))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("does not match");
  }

  @Test
  void evaluatesConservativeOmissionForMultiSymbolMappingWithAbsentSymbol() throws Exception {
    final ArtifactTrimRecord record =
        record(
            jar("original.jar", "org/example/PresentVulnerable.class", "org/example/Safe.class"),
            jar("trimmed.jar", "org/example/Safe.class"));
    final VulnerabilitySymbolMapping multiSymbol =
        new VulnerabilitySymbolMapping(
            "CVE-2026-68494",
            ArtifactCoordinate.of("org.example", "demo", "1.0"),
            "[1.0,2.0)",
            Set.of("org.example.PresentVulnerable", "org.example.AbsentClass"),
            null,
            ConfidenceLevel.HIGH);

    final java.util.Optional<OmittedCodeProof.ConservativeOmission> omission =
        OmittedCodeProof.evaluateConservativeOmission(multiSymbol, record);
    assertThat(omission).isPresent();
    assertThat(omission.get().cveId()).isEqualTo("CVE-2026-68494");
    assertThat(omission.get().absentFromOriginal()).containsExactly("org.example.AbsentClass");
    assertThat(omission.get().presentAndPruned()).containsExactly("org.example.PresentVulnerable");
  }

  @Test
  void doesNotEvaluateConservativeOmissionIfMappedSymbolSurvives() throws Exception {
    final ArtifactTrimRecord record =
        record(
            jar("original.jar", "org/example/PresentVulnerable.class", "org/example/Safe.class"),
            jar("trimmed.jar", "org/example/PresentVulnerable.class", "org/example/Safe.class"));
    final VulnerabilitySymbolMapping multiSymbol =
        new VulnerabilitySymbolMapping(
            "CVE-2026-68494",
            ArtifactCoordinate.of("org.example", "demo", "1.0"),
            "[1.0,2.0)",
            Set.of("org.example.PresentVulnerable", "org.example.AbsentClass"),
            null,
            ConfidenceLevel.HIGH);

    final java.util.Optional<OmittedCodeProof.ConservativeOmission> omission =
        OmittedCodeProof.evaluateConservativeOmission(multiSymbol, record);
    assertThat(omission).isEmpty();
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
        output.write(new byte[] {0});
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
        output.write(new byte[] {0});
        output.closeEntry();
      }
    }
    return path;
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

  private void assertMalformedVersionedClassPath(final String malformedPath) throws IOException {
    final ArtifactTrimRecord record =
        record(
            multiReleaseJar(
                "malformed-versioned-class.jar", "org/example/Vulnerable.class", malformedPath),
            jar("malformed-versioned-trimmed.jar"));
    assertThatThrownBy(() -> OmittedCodeProof.prove(mapping("org.example.Vulnerable"), record))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Malformed");
  }

  private static ExplicitClassMappingEvidence mapping(final String className) {
    return ExplicitEvidenceTestSupport.classEvidence(
        new VulnerabilitySymbolMapping(
            "CVE-2025-12345",
            ArtifactCoordinate.of("org.example", "demo", "1.0"),
            "[1.0,2.0)",
            Set.of(className),
            null,
            ConfidenceLevel.HIGH));
  }

  private static void assertRejectedLowConfidenceMapping(
      final VulnerabilitySymbolMapping mapping, final ArtifactTrimRecord record) {
    assertThatThrownBy(
            () ->
                OmittedCodeProof.prove(ExplicitEvidenceTestSupport.classEvidence(mapping), record))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("requires HIGH confidence");
  }
}
