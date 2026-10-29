/* WHY: Verifies ADR-0008 fails closed outside a complete exact-class inventory. */

package io.github.spockz.elider.model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.spockz.elider.model.PreconditionClassInventory.Provider;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;

/** ADR-0008 evidence tests for exact-class absence within a complete inventory. */
@SuppressWarnings({
  "PMD.AvoidDuplicateLiterals",
  "PMD.AvoidInstantiatingObjectsInLoops",
  "PMD.AtLeastOneConstructor",
  "PMD.TooManyMethods",
  "PMD.UnitTestContainsTooManyAsserts",
  "checkstyle:AbbreviationAsWordInName"
})
@DisplayName("ADR-0008: exact-class precondition proof")
final class ADR0008PreconditionProofTest {
  /** Group and artifact pair required by the proof fixture. */
  private static final String REQUIRED_DEPENDENCY = "org.example:prerequisite";

  /** Exact class name required by the proof fixture. */
  private static final String REQUIRED_CLASS = "org.example.Prerequisite";

  /** Exact coordinate whose provider is bound into the emitted evidence. */
  private static final ArtifactCoordinate AFFECTED_COORDINATE =
      ArtifactCoordinate.of("org.example", "affected", "1.0");

  /** Temporary archive and provider files used by proof cases. */
  @TempDir private Path directory;

  @Test
  @DisplayName("ADR-0008/complete inventory produces a bound proof")
  void provesAbsentClassInExplicitlyCompleteInventoryAndBindsAffectedArtifact() throws Exception {
    final Path affectedPath =
        archive(
            "affected.jar",
            Map.of("org/example/Affected.class", classBytes("org/example/Affected")));
    final Path retainedPath = archive("retained.jar", Map.of());
    final Path resourcePath = directory.resolve("application/config/settings.properties");
    Files.createDirectories(resourcePath.getParent());
    Files.writeString(resourcePath, "feature=true\n");
    final Provider affected = Provider.dependencyArchive(AFFECTED_COORDINATE, affectedPath);
    final Provider retained =
        Provider.dependencyArchive(
            ArtifactCoordinate.of("org.example", "retained", "2.0"), retainedPath);
    final Provider resource = Provider.applicationResourceFile(resourcePath);
    final PreconditionClassInventory inventory =
        PreconditionClassInventory.complete(List.of(retained, resource, affected));

    final VexAttestation attestation =
        PreconditionProof.prove(mapping(REQUIRED_CLASS, REQUIRED_DEPENDENCY, "HIGH"), inventory);

    assertThat(attestation.justification()).isEqualTo("requires_dependency");
    assertThat(attestation.coordinate()).isEqualTo(AFFECTED_COORDINATE);
    assertThat(attestation.requiredDependency()).isEqualTo(REQUIRED_DEPENDENCY);
    assertThat(attestation.requiredClass()).isEqualTo(REQUIRED_CLASS);
    assertThat(attestation.affectedArtifactPath()).isEqualTo(affected.path());
    assertThat(attestation.postElisionSha256()).isEqualTo(affected.sha256());
    assertThat(attestation.inventorySha256()).isEqualTo(inventory.fingerprint());
    assertThat(attestation.evidenceSymbols()).isEmpty();
    assertThat(attestation.originalSha256()).isNull();
    assertThat(attestation.trimmedSha256()).isNull();
    assertThat(attestation.impactDetail()).contains("complete declared Maven inventory");
  }

  @Test
  @DisplayName("ADR-0008/empty inventory cannot bind the affected artifact")
  void emptyCompleteInventoryIsDistinctButCannotBindAffectedArtifact() throws Exception {
    final PreconditionClassInventory inventory = PreconditionClassInventory.complete(List.of());

    assertThat(inventory.status()).isEqualTo(PreconditionClassInventory.Status.COMPLETE);
    assertThatThrownBy(
            () ->
                PreconditionProof.prove(
                    mapping(REQUIRED_CLASS, REQUIRED_DEPENDENCY, "HIGH"), inventory))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("exactly one retained affected artifact");
  }

  @Test
  @DisplayName("ADR-0008/coordinate-only mapping does not qualify")
  void rejectsCoordinateOnlyMapping() throws Exception {
    final PreconditionClassInventory inventory = inventoryWithAffected();

    assertThatThrownBy(
            () -> PreconditionProof.prove(mapping(null, REQUIRED_DEPENDENCY, "HIGH"), inventory))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("exact fully qualified prerequisite class");
  }

  @Test
  @DisplayName("ADR-0008/malformed prerequisite metadata does not qualify")
  void rejectsMalformedDependencyMetadata() throws Exception {
    final PreconditionClassInventory inventory = inventoryWithAffected();

    assertThatThrownBy(
            () ->
                PreconditionProof.prove(
                    mapping(REQUIRED_CLASS, "org.example:prerequisite:1.0", "HIGH"), inventory))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("group:artifact");
  }

  @Test
  @DisplayName("ADR-0008/low-confidence mappings do not qualify")
  void rejectsLowConfidenceMapping() throws Exception {
    final PreconditionClassInventory inventory = inventoryWithAffected();

    assertThatThrownBy(
            () ->
                PreconditionProof.prove(
                    mapping(REQUIRED_CLASS, REQUIRED_DEPENDENCY, "LOW"), inventory))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("HIGH confidence");
  }

  @Test
  @DisplayName("ADR-0008/incomplete and failed inventories do not qualify")
  void rejectsIncompleteAndInspectionFailedInventories() throws Exception {
    final Provider affected = affectedProvider();
    final PreconditionClassInventory incomplete =
        PreconditionClassInventory.incomplete(
            List.of(affected), "application resource root unknown");
    final PreconditionClassInventory failed =
        PreconditionClassInventory.inspectionFailed(List.of(affected), "resource file unreadable");

    assertThatThrownBy(
            () ->
                PreconditionProof.prove(
                    mapping(REQUIRED_CLASS, REQUIRED_DEPENDENCY, "HIGH"), incomplete))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("inventory is incomplete");
    assertThatThrownBy(
            () ->
                PreconditionProof.prove(
                    mapping(REQUIRED_CLASS, REQUIRED_DEPENDENCY, "HIGH"), failed))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("inspection failed");
  }

  @Test
  @DisplayName("ADR-0008/retained prerequisite coordinates block proof")
  void rejectsRetainedRequiredDependencyEvenWhenItsClassIsAbsent() throws Exception {
    final Provider affected = affectedProvider();
    final Path prerequisitePath = archive("prerequisite.jar", Map.of());
    final Provider prerequisite =
        Provider.dependencyArchive(
            ArtifactCoordinate.of("org.example", "prerequisite", "3.0"), prerequisitePath);
    final PreconditionClassInventory inventory =
        PreconditionClassInventory.complete(List.of(affected, prerequisite));

    assertThatThrownBy(
            () ->
                PreconditionProof.prove(
                    mapping(REQUIRED_CLASS, REQUIRED_DEPENDENCY, "HIGH"), inventory))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Required dependency is present");
  }

  @Test
  @DisplayName("ADR-0008/alternate dependency class providers block proof")
  void rejectsAlternateDependencyProviderOfTheRequiredClass() throws Exception {
    final Provider affected = affectedProvider();
    final Path alternatePath =
        archive(
            "alternate.jar",
            Map.of("org/example/Prerequisite.class", classBytes("org/example/Prerequisite")));
    final Provider alternate =
        Provider.dependencyArchive(
            ArtifactCoordinate.of("org.other", "alternate", "1.0"), alternatePath);
    final PreconditionClassInventory inventory =
        PreconditionClassInventory.complete(List.of(affected, alternate));

    assertThatThrownBy(
            () ->
                PreconditionProof.prove(
                    mapping(REQUIRED_CLASS, REQUIRED_DEPENDENCY, "HIGH"), inventory))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Required class is present");
  }

  @Test
  @DisplayName("ADR-0008/class bytes under resource paths block proof")
  void rejectsClassBytesInApplicationResourcePath() throws Exception {
    final Provider affected = affectedProvider();
    final Path resourcePath = directory.resolve("application/resources/provider.bin");
    Files.createDirectories(resourcePath.getParent());
    Files.write(resourcePath, classBytes("org/example/Prerequisite"));
    final Provider resource = Provider.applicationResourceFile(resourcePath);
    final PreconditionClassInventory inventory =
        PreconditionClassInventory.complete(List.of(affected, resource));

    assertThatThrownBy(
            () ->
                PreconditionProof.prove(
                    mapping(REQUIRED_CLASS, REQUIRED_DEPENDENCY, "HIGH"), inventory))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Required class is present");
  }

  @Test
  @DisplayName("ADR-0008/raw class bytes in archive resources block proof")
  void rejectsRawClassBytesInArchiveResourceEntry() throws Exception {
    final Provider affected = affectedProvider();
    final Path resourceArchive =
        archive(
            "application-resource.jar",
            Map.of("application/resources/provider.bin", classBytes("org/example/Prerequisite")));
    final Provider resource = Provider.applicationResourceFile(resourceArchive);
    final PreconditionClassInventory inventory =
        PreconditionClassInventory.complete(List.of(affected, resource));

    assertThatThrownBy(
            () ->
                PreconditionProof.prove(
                    mapping(REQUIRED_CLASS, REQUIRED_DEPENDENCY, "HIGH"), inventory))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Required class is present");
  }

  @Test
  @DisplayName("ADR-0008/nested resource JARs fail closed")
  void rejectsNestedResourceJarContainingRequiredClass() throws Exception {
    final Provider affected = affectedProvider();
    final Path nestedJar =
        archive(
            "nested-prerequisite.jar",
            Map.of("org/example/Prerequisite.class", classBytes("org/example/Prerequisite")));
    final Path resourceArchive =
        archive(
            "application-resources.jar",
            Map.of("BOOT-INF/lib/prerequisite.jar", Files.readAllBytes(nestedJar)));
    final Provider resource = Provider.applicationResourceFile(resourceArchive);
    final PreconditionClassInventory inventory =
        PreconditionClassInventory.complete(List.of(affected, resource));

    assertThatThrownBy(
            () ->
                PreconditionProof.prove(
                    mapping(REQUIRED_CLASS, REQUIRED_DEPENDENCY, "HIGH"), inventory))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Nested archive provider is not supported");
  }

  @Test
  @DisplayName("ADR-0008/application class providers block proof")
  void rejectsClassBytesInApplicationClassPath() throws Exception {
    final Provider affected = affectedProvider();
    final Path classPath = directory.resolve("application/classes/org/example/Prerequisite.class");
    Files.createDirectories(classPath.getParent());
    Files.write(classPath, classBytes("org/example/Prerequisite"));
    final Provider applicationClass = Provider.applicationClassFile(classPath);
    final PreconditionClassInventory inventory =
        PreconditionClassInventory.complete(List.of(affected, applicationClass));

    assertThatThrownBy(
            () ->
                PreconditionProof.prove(
                    mapping(REQUIRED_CLASS, REQUIRED_DEPENDENCY, "HIGH"), inventory))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Required class is present");
  }

  @Test
  @DisplayName("ADR-0008/base and versioned class variants count as present")
  void countsMultiReleaseClassVariantsAsPresent() throws Exception {
    final Provider affected = affectedProvider();
    final byte[] requiredClass = classBytes("org/example/Prerequisite");
    final Path shadedPath =
        archive(
            "shaded.jar",
            Map.of(
                "org/example/Prerequisite.class", requiredClass,
                "META-INF/versions/17/org/example/Prerequisite.class", requiredClass));
    final Provider shaded =
        Provider.dependencyArchive(ArtifactCoordinate.of("org.other", "shaded", "1.0"), shadedPath);
    final PreconditionClassInventory inventory =
        PreconditionClassInventory.complete(List.of(affected, shaded));

    assertThatThrownBy(
            () ->
                PreconditionProof.prove(
                    mapping(REQUIRED_CLASS, REQUIRED_DEPENDENCY, "HIGH"), inventory))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Required class is present");
  }

  @Test
  @DisplayName("ADR-0008/versioned-only classes count as present")
  void countsMultiReleaseOnlyPrerequisiteAsPresent() throws Exception {
    final Provider affected = affectedProvider();
    final Path versionedOnlyPath =
        archive(
            "versioned-only.jar",
            Map.of(
                "META-INF/versions/17/org/example/Prerequisite.class",
                classBytes("org/example/Prerequisite")));
    final Provider versionedOnly =
        Provider.dependencyArchive(
            ArtifactCoordinate.of("org.other", "versioned-only", "1.0"), versionedOnlyPath);
    final PreconditionClassInventory inventory =
        PreconditionClassInventory.complete(List.of(affected, versionedOnly));

    assertThatThrownBy(
            () ->
                PreconditionProof.prove(
                    mapping(REQUIRED_CLASS, REQUIRED_DEPENDENCY, "HIGH"), inventory))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Required class is present");
  }

  @Test
  @DisplayName("ADR-0008/unrelated versioned classes do not block proof")
  void allowsUnrelatedMultiReleaseClass() throws Exception {
    final Provider affected = affectedProvider();
    final Path unrelatedPath =
        archive(
            "unrelated-versioned.jar",
            Map.of(
                "META-INF/versions/17/org/example/Unrelated.class",
                classBytes("org/example/Unrelated")));
    final Provider unrelated =
        Provider.dependencyArchive(
            ArtifactCoordinate.of("org.other", "unrelated", "1.0"), unrelatedPath);
    final PreconditionClassInventory inventory =
        PreconditionClassInventory.complete(List.of(affected, unrelated));

    final VexAttestation attestation =
        PreconditionProof.prove(mapping(REQUIRED_CLASS, REQUIRED_DEPENDENCY, "HIGH"), inventory);

    assertThat(attestation.requiredClass()).isEqualTo(REQUIRED_CLASS);
  }

  @Test
  @DisplayName("ADR-0008/malformed multi-release paths and releases fail closed")
  void rejectsMalformedMultiReleaseEntryNames() throws Exception {
    final Provider affected = affectedProvider();
    final List<String> malformedEntries =
        List.of(
            "META-INF/versions/not-a-release/org/example/Other.class",
            "META-INF/versions/8/org/example/Other.class",
            "META-INF/versions/17//org/example/Other.class");
    int index = 0;
    for (final String malformedEntry : malformedEntries) {
      final String archiveIndex = Integer.toString(index);
      index++;
      final Path malformedPath =
          archive(
              "malformed-multi-release-" + archiveIndex + ".jar",
              Map.of(malformedEntry, classBytes("org/example/Other")));
      final Provider malformed =
          Provider.dependencyArchive(
              ArtifactCoordinate.of("org.other", "malformed" + archiveIndex, "1.0"), malformedPath);
      final PreconditionClassInventory inventory =
          PreconditionClassInventory.complete(List.of(affected, malformed));

      assertThatThrownBy(
              () ->
                  PreconditionProof.prove(
                      mapping(REQUIRED_CLASS, REQUIRED_DEPENDENCY, "HIGH"), inventory))
          .isInstanceOf(IOException.class);
    }
  }

  @Test
  @DisplayName("ADR-0008/duplicate same-release class providers fail closed")
  void rejectsDuplicateClassProvidersWithinOneRelease() throws Exception {
    final Provider affected = affectedProvider();
    final byte[] duplicateClass = classBytes("org/example/Other");
    final Path duplicatePath =
        archive(
            "duplicate-class-provider.jar",
            Map.of(
                "org/example/Other.class", duplicateClass,
                "resources/other.bin", duplicateClass));
    final Provider duplicate =
        Provider.dependencyArchive(
            ArtifactCoordinate.of("org.other", "duplicate-classes", "1.0"), duplicatePath);
    final PreconditionClassInventory inventory =
        PreconditionClassInventory.complete(List.of(affected, duplicate));

    assertThatThrownBy(
            () ->
                PreconditionProof.prove(
                    mapping(REQUIRED_CLASS, REQUIRED_DEPENDENCY, "HIGH"), inventory))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Duplicate class provider entry");
  }

  @Test
  @DisplayName("ADR-0008/scanner-discovered source classes block proof")
  void rejectsScannerDiscoveredPrerequisiteInApplicationSource() throws Exception {
    final Provider affected = affectedProvider();
    final Path sourcePath = directory.resolve("application/src/Prerequisite.java");
    Files.createDirectories(sourcePath.getParent());
    Files.writeString(sourcePath, "package org.example; class Prerequisite {}\n");
    final Provider source = Provider.applicationSourceFile(sourcePath, Set.of(REQUIRED_CLASS));
    final PreconditionClassInventory inventory =
        PreconditionClassInventory.complete(List.of(affected, source));

    assertThatThrownBy(
            () ->
                PreconditionProof.prove(
                    mapping(REQUIRED_CLASS, REQUIRED_DEPENDENCY, "HIGH"), inventory))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Required class is present");
  }

  @Test
  @DisplayName("ADR-0008/source mutations invalidate proof")
  void bindsScannerDiscoveredSourceNamesToTheSourceDigest() throws Exception {
    final Provider affected = affectedProvider();
    final Path sourcePath = directory.resolve("application/src/Other.java");
    Files.createDirectories(sourcePath.getParent());
    Files.writeString(sourcePath, "package org.example; class Other {}\n");
    final Provider source = Provider.applicationSourceFile(sourcePath, Set.of("org.example.Other"));
    final PreconditionClassInventory inventory =
        PreconditionClassInventory.complete(List.of(affected, source));
    Files.writeString(sourcePath, "package org.example; class Prerequisite {}\n");

    assertThatThrownBy(
            () ->
                PreconditionProof.prove(
                    mapping(REQUIRED_CLASS, REQUIRED_DEPENDENCY, "HIGH"), inventory))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("digest changed");
  }

  @Test
  @DisplayName("ADR-0008/source class names participate in the fingerprint")
  void fingerprintsScannerDiscoveredSourceNames() throws Exception {
    final Path sourcePath = directory.resolve("application/src/Fingerprint.java");
    Files.createDirectories(sourcePath.getParent());
    Files.writeString(sourcePath, "package org.example; class Fingerprint {}\n");
    final Provider first = Provider.applicationSourceFile(sourcePath, Set.of("org.example.First"));
    final Provider second =
        Provider.applicationSourceFile(sourcePath, Set.of("org.example.Second"));

    assertThat(PreconditionClassInventory.complete(List.of(first)).fingerprint())
        .isNotEqualTo(PreconditionClassInventory.complete(List.of(second)).fingerprint());
  }

  @Test
  @DisplayName("ADR-0008/duplicate dependency identities fail closed")
  void rejectsDuplicateDependencyIdentityInInventory() throws Exception {
    final Path firstPath = archive("first.jar", Map.of());
    final Path secondPath = archive("second.jar", Map.of());
    final ArtifactCoordinate coordinate = ArtifactCoordinate.of("org.example", "duplicate", "1.0");

    assertThatThrownBy(
            () ->
                PreconditionClassInventory.complete(
                    List.of(
                        Provider.dependencyArchive(coordinate, firstPath),
                        Provider.dependencyArchive(coordinate, secondPath))))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Duplicate retained dependency provider");
  }

  @Test
  @DisplayName("ADR-0008/provider mutations invalidate proof")
  void rejectsProviderMutationAfterInventoryCapture() throws Exception {
    final Path affectedPath = archive("affected-mutated.jar", Map.of());
    final Provider affected = Provider.dependencyArchive(AFFECTED_COORDINATE, affectedPath);
    final PreconditionClassInventory inventory =
        PreconditionClassInventory.complete(List.of(affected));
    Files.writeString(affectedPath, "changed after capture");

    assertThatThrownBy(
            () ->
                PreconditionProof.prove(
                    mapping(REQUIRED_CLASS, REQUIRED_DEPENDENCY, "HIGH"), inventory))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("digest changed");
  }

  @Test
  @DisplayName("ADR-0008/unreadable dependency archives fail closed")
  void rejectsUnreadableDependencyArchive() throws Exception {
    final Provider affected = affectedProvider();
    final Path unreadablePath = directory.resolve("unreadable.jar");
    Files.writeString(unreadablePath, "not a zip archive");
    final Provider unreadable =
        Provider.dependencyArchive(
            ArtifactCoordinate.of("org.other", "unreadable", "1.0"), unreadablePath);
    final PreconditionClassInventory inventory =
        PreconditionClassInventory.complete(List.of(affected, unreadable));

    assertThatThrownBy(
            () ->
                PreconditionProof.prove(
                    mapping(REQUIRED_CLASS, REQUIRED_DEPENDENCY, "HIGH"), inventory))
        .isInstanceOf(IOException.class);
  }

  @Test
  @DisplayName("ADR-0008/proof binds the exact affected artifact")
  void requiresExactAffectedArtifactIdentityAndPath() throws Exception {
    final Provider affected = affectedProvider();
    final PreconditionClassInventory inventory =
        PreconditionClassInventory.complete(List.of(affected));
    final VulnerabilitySymbolMapping mismatched =
        new VulnerabilitySymbolMapping(
            "CVE-2025-12345",
            ArtifactCoordinate.of("org.example", "different", "1.0"),
            "[1.0]",
            Set.of(),
            null,
            VulnerabilitySymbolMapping.ConfidenceLevel.HIGH,
            REQUIRED_DEPENDENCY,
            REQUIRED_CLASS);

    assertThatThrownBy(() -> PreconditionProof.prove(mismatched, inventory))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("exactly one retained affected artifact");
  }

  private PreconditionClassInventory inventoryWithAffected() throws IOException {
    return PreconditionClassInventory.complete(List.of(affectedProvider()));
  }

  private Provider affectedProvider() throws IOException {
    return Provider.dependencyArchive(
        AFFECTED_COORDINATE, archive("affected-" + System.nanoTime() + ".jar", Map.of()));
  }

  private static VulnerabilitySymbolMapping mapping(
      final String requiredClass, final String requiredDependency, final String confidence) {
    return new VulnerabilitySymbolMapping(
        "CVE-2025-12345",
        AFFECTED_COORDINATE,
        "[1.0]",
        Set.of(),
        null,
        VulnerabilitySymbolMapping.ConfidenceLevel.valueOf(confidence),
        requiredDependency,
        requiredClass);
  }

  private Path archive(final String fileName, final Map<String, byte[]> entries)
      throws IOException {
    final Path path = directory.resolve(fileName);
    try (ZipOutputStream output = new ZipOutputStream(Files.newOutputStream(path))) {
      for (final Map.Entry<String, byte[]> entry : entries.entrySet()) {
        output.putNextEntry(new ZipEntry(entry.getKey()));
        output.write(entry.getValue());
        output.closeEntry();
      }
    }
    return path;
  }

  private static byte[] classBytes(final String internalName) {
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, internalName, null, "java/lang/Object", null);
    writer.visitEnd();
    return writer.toByteArray();
  }
}
