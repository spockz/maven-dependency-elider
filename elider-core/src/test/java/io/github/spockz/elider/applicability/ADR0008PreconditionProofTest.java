/* WHY: Verifies ADR-0008 fails closed outside a complete exact-class inventory. */

package io.github.spockz.elider.applicability;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.applicability.PreconditionClassInventory.Provider;
import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.AssessmentIntent;
import io.github.spockz.elider.model.ClaimGroupStatus;
import io.github.spockz.elider.model.ConfidenceLevel;
import io.github.spockz.elider.model.FieldValue;
import io.github.spockz.elider.model.GenericProofTestSupport;
import io.github.spockz.elider.model.GenericVulnerabilityFinding;
import io.github.spockz.elider.model.MergePriority;
import io.github.spockz.elider.model.PrerequisiteClaim;
import io.github.spockz.elider.model.PrerequisiteGroup;
import io.github.spockz.elider.model.PrerequisiteOperator;
import io.github.spockz.elider.model.UnresolvedContributionField;
import io.github.spockz.elider.model.VersionCoverageClaim;
import io.github.spockz.elider.model.VexAttestation;
import io.github.spockz.elider.model.VulnerabilityFindingContribution;
import io.github.spockz.elider.model.VulnerabilitySymbolMapping;
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
  "PMD.ExcessiveImports",
  "PMD.AvoidDuplicateLiterals",
  "PMD.AvoidInstantiatingObjectsInLoops",
  "PMD.AtLeastOneConstructor",
  "PMD.TooManyMethods",
  "checkstyle:AbbreviationAsWordInName"
})
@DisplayName("ADR-0008: exact-class precondition proof")
final class ADR0008PreconditionProofTest {
  /** Group and artifact pair required by the proof fixture. */
  private static final String REQUIRED_DEPENDENCY = "org.example:prerequisite";

  /** Exact class name required by the proof fixture. */
  private static final String REQUIRED_CLASS = "org.example.Prerequisite";

  /** Second member used to compare alternative and conjunctive group behavior. */
  private static final PrerequisiteClaim SECOND_REQUIRED =
      new PrerequisiteClaim("org.example:second", "org.example.SecondPrerequisite");

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
        GenericProofTestSupport.prerequisiteProof(
            mapping(REQUIRED_CLASS, REQUIRED_DEPENDENCY, "HIGH"), inventory);

    assertThat(attestation.justification()).isEqualTo("requires_dependency");
    assertThat(attestation.coordinate()).isEqualTo(AFFECTED_COORDINATE);
    assertThat(attestation.requiredPrerequisites())
        .containsExactly(new PrerequisiteClaim(REQUIRED_DEPENDENCY, REQUIRED_CLASS));
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
                GenericProofTestSupport.prerequisiteProof(
                    mapping(REQUIRED_CLASS, REQUIRED_DEPENDENCY, "HIGH"), inventory))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("exactly one retained affected artifact");
  }

  @Test
  @DisplayName("ADR-0008/coordinate-only mapping does not qualify")
  void rejectsCoordinateOnlyMapping() throws Exception {
    final PreconditionClassInventory inventory = inventoryWithAffected();

    assertThatThrownBy(
            () ->
                GenericProofTestSupport.prerequisiteProof(
                    mapping(null, REQUIRED_DEPENDENCY, "HIGH"), inventory))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("requiresClass");
  }

  @Test
  @DisplayName("ADR-0008/malformed prerequisite metadata does not qualify")
  void rejectsMalformedDependencyMetadata() throws Exception {
    final PreconditionClassInventory inventory = inventoryWithAffected();

    assertThatThrownBy(
            () ->
                GenericProofTestSupport.prerequisiteProof(
                    mapping(REQUIRED_CLASS, "org.example:prerequisite:1.0", "HIGH"), inventory))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("group:artifact");
  }

  @Test
  @DisplayName("ADR-0008/low-confidence mappings do not qualify")
  void rejectsLowConfidenceMapping() throws Exception {
    final PreconditionClassInventory inventory = inventoryWithAffected();

    assertAll(
        () -> assertRejectedLowConfidencePrerequisite("LOW", inventory),
        () -> assertRejectedLowConfidencePrerequisite("MEDIUM", inventory));
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
                GenericProofTestSupport.prerequisiteProof(
                    mapping(REQUIRED_CLASS, REQUIRED_DEPENDENCY, "HIGH"), incomplete))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("inventory is incomplete");
    assertThatThrownBy(
            () ->
                GenericProofTestSupport.prerequisiteProof(
                    mapping(REQUIRED_CLASS, REQUIRED_DEPENDENCY, "HIGH"), failed))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("inspection failed");
  }

  @Test
  @DisplayName("ADR-0008/retained coordinate without required class does not block proof")
  void retainedDependencyWithoutRequiredClassDoesNotRefuteAbsence() throws Exception {
    final Provider affected = affectedProvider();
    final Path prerequisitePath = archive("prerequisite.jar", Map.of());
    final Provider prerequisite =
        Provider.dependencyArchive(
            ArtifactCoordinate.of("org.example", "prerequisite", "3.0"), prerequisitePath);
    final PreconditionClassInventory inventory =
        PreconditionClassInventory.complete(List.of(affected, prerequisite));

    final VexAttestation attestation =
        GenericProofTestSupport.prerequisiteProof(
            mapping(REQUIRED_CLASS, REQUIRED_DEPENDENCY, "HIGH"), inventory);

    assertThat(attestation.requiredPrerequisites())
        .containsExactly(new PrerequisiteClaim(REQUIRED_DEPENDENCY, REQUIRED_CLASS));
  }

  @Test
  @DisplayName("ADR-0008/present ClassBodyEvaluator blocks proof when ScriptEvaluator is absent")
  void janinoClassBodyEvaluatorBlocksProofEvenWhenScriptEvaluatorIsAbsent() throws Exception {
    final Provider affected = affectedProvider();
    final String requiredClass = "org.codehaus.janino.ClassBodyEvaluator";
    final Path janinoPath =
        archive(
            "janino.jar",
            Map.of(
                "org/codehaus/janino/ClassBodyEvaluator.class",
                classBytes("org/codehaus/janino/ClassBodyEvaluator")));
    final Provider janino =
        Provider.dependencyArchive(
            ArtifactCoordinate.of("org.codehaus.janino", "janino", "3.1.12"), janinoPath);
    final PreconditionClassInventory inventory =
        PreconditionClassInventory.complete(List.of(affected, janino));

    assertThatThrownBy(
            () ->
                GenericProofTestSupport.prerequisiteProof(
                    mapping(requiredClass, "org.codehaus.janino:janino", "HIGH"), inventory))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Required class is present");
  }

  @Test
  @DisplayName(
      "ADR-0008/trimmed ClassBodyEvaluator permits proof even when ScriptEvaluator remains")
  void janinoTrimmedClassBodyEvaluatorAllowsProofWhenScriptEvaluatorRemains() throws Exception {
    final Provider affected = affectedProvider();
    final String requiredClass = "org.codehaus.janino.ClassBodyEvaluator";
    final Path janinoPath =
        archive(
            "janino-trimmed.jar",
            Map.of(
                "org/codehaus/janino/ScriptEvaluator.class",
                classBytes("org/codehaus/janino/ScriptEvaluator")));
    final Provider janino =
        Provider.dependencyArchive(
            ArtifactCoordinate.of("org.codehaus.janino", "janino", "3.1.12"), janinoPath);
    final PreconditionClassInventory inventory =
        PreconditionClassInventory.complete(List.of(affected, janino));

    final VexAttestation attestation =
        GenericProofTestSupport.prerequisiteProof(
            mapping(requiredClass, "org.codehaus.janino:janino", "HIGH"), inventory);

    assertThat(attestation.requiredPrerequisites())
        .containsExactly(new PrerequisiteClaim("org.codehaus.janino:janino", requiredClass));
  }

  @Test
  @DisplayName("ADR-0008/group operators are evaluated against every physical provider")
  void evaluatesAtomicGroupsAgainstTheSamePhysicalProviderState() throws Exception {
    final Provider affected = affectedProvider();
    final Provider firstClassProvider =
        Provider.dependencyArchive(
            ArtifactCoordinate.of("org.other", "shaded-provider", "1.0"),
            archive(
                "first-class-provider.jar",
                Map.of(
                    "org/example/Prerequisite.class",
                    classBytes("org/example/Prerequisite"),
                    "org/example/PresentOne.class",
                    classBytes("org/example/PresentOne"),
                    "org/example/PresentTwo.class",
                    classBytes("org/example/PresentTwo"))));
    final PreconditionClassInventory inventory =
        PreconditionClassInventory.complete(List.of(affected, firstClassProvider));
    final PreconditionClassInventory allAbsentInventory =
        PreconditionClassInventory.complete(List.of(affected));
    final PrerequisiteClaim first = new PrerequisiteClaim(REQUIRED_DEPENDENCY, REQUIRED_CLASS);
    final PrerequisiteClaim second = SECOND_REQUIRED;
    final PrerequisiteGroup anyOf =
        new PrerequisiteGroup(PrerequisiteOperator.ANY_OF, Set.of(first, second));
    final PrerequisiteGroup allOf =
        new PrerequisiteGroup(PrerequisiteOperator.ALL_OF, Set.of(first, second));
    final PrerequisiteGroup disjointAllOf =
        new PrerequisiteGroup(
            PrerequisiteOperator.ALL_OF,
            Set.of(
                new PrerequisiteClaim("org.example:absent", "org.example.Absent"),
                new PrerequisiteClaim("org.example:present-one", "org.example.PresentOne")));
    final GenericVulnerabilityFinding anyOfFinding = findingWithGroups(List.of(anyOf));
    final GenericVulnerabilityFinding allOfFinding = findingWithGroups(List.of(allOf));
    final GenericVulnerabilityFinding disjointOperatorGroups =
        GenericVulnerabilityFinding.merge(
            List.of(
                anyOfFinding.contributions().getFirst(),
                findingWithGroups(List.of(disjointAllOf)).contributions().getFirst()));
    final GenericVulnerabilityFinding partiallyDisarmedGroups =
        findingWithGroups(
            List.of(
                allOf,
                new PrerequisiteGroup(
                    PrerequisiteOperator.ALL_OF,
                    Set.of(
                        new PrerequisiteClaim("org.example:present-one", "org.example.PresentOne"),
                        new PrerequisiteClaim(
                            "org.example:present-two", "org.example.PresentTwo")))));
    final GenericVulnerabilityFinding emptyGroups = findingWithGroups(List.of());
    final GenericVulnerabilityFinding unresolvedGroups =
        findingWithGroups(
            List.of(anyOf),
            AssessmentIntent.AUTO_VERIFY,
            Set.of(UnresolvedContributionField.PREREQUISITES));
    final GenericVulnerabilityFinding conflictingGroups =
        GenericVulnerabilityFinding.merge(
            List.of(
                anyOfFinding.contributions().getFirst(), allOfFinding.contributions().getFirst()));
    final GenericVulnerabilityFinding reviewOnlyGroups =
        findingWithGroups(List.of(anyOf), AssessmentIntent.REVIEW_ONLY, Set.of());

    assertAll(
        "operator proof uses exact class presence from any physical provider",
        () -> assertProofRejected(anyOfFinding, inventory, "prerequisite group remains present"),
        () ->
            assertThat(allOfFinding.prerequisiteGroupStatusFor("1.0"))
                .isEqualTo(ClaimGroupStatus.DECLARED),
        () ->
            assertThat(PreconditionProof.prove(allOfFinding, AFFECTED_COORDINATE, inventory))
                .satisfies(
                    attestation ->
                        assertAll(
                            () ->
                                assertThat(attestation.requiredPrerequisites())
                                    .containsExactlyInAnyOrder(first, second),
                            () ->
                                assertThat(attestation.requiredPrerequisiteGroups())
                                    .containsExactly(allOf))),
        () ->
            assertThat(
                    PreconditionProof.prove(anyOfFinding, AFFECTED_COORDINATE, allAbsentInventory)
                        .requiredPrerequisites())
                .containsExactlyInAnyOrder(first, second),
        () ->
            assertThat(disjointOperatorGroups.prerequisiteGroupStatusFor("1.0"))
                .isEqualTo(ClaimGroupStatus.DECLARED),
        () ->
            assertThat(disjointOperatorGroups.effectivePrerequisiteGroupsFor("1.0"))
                .containsExactlyInAnyOrder(anyOf, disjointAllOf),
        () ->
            assertProofRejected(
                disjointOperatorGroups, inventory, "prerequisite group remains present"),
        () ->
            assertThat(
                    PreconditionProof.prove(
                            disjointOperatorGroups, AFFECTED_COORDINATE, allAbsentInventory)
                        .requiredPrerequisiteGroups())
                .containsExactlyInAnyOrder(anyOf, disjointAllOf),
        () -> assertProofRejected(partiallyDisarmedGroups, inventory, "prerequisite"),
        () -> assertProofRejected(emptyGroups, inventory, "declared prerequisite pairs"),
        () -> assertProofRejected(unresolvedGroups, inventory, "declared prerequisite pairs"),
        () -> assertProofRejected(conflictingGroups, inventory, "declared prerequisite pairs"),
        () -> assertProofRejected(reviewOnlyGroups, inventory, "requires review"));
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
                GenericProofTestSupport.prerequisiteProof(
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
                GenericProofTestSupport.prerequisiteProof(
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
                GenericProofTestSupport.prerequisiteProof(
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
                GenericProofTestSupport.prerequisiteProof(
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
                GenericProofTestSupport.prerequisiteProof(
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
                GenericProofTestSupport.prerequisiteProof(
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
                GenericProofTestSupport.prerequisiteProof(
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
        GenericProofTestSupport.prerequisiteProof(
            mapping(REQUIRED_CLASS, REQUIRED_DEPENDENCY, "HIGH"), inventory);

    assertThat(attestation.requiredPrerequisites())
        .containsExactly(new PrerequisiteClaim(REQUIRED_DEPENDENCY, REQUIRED_CLASS));
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
                  GenericProofTestSupport.prerequisiteProof(
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
                GenericProofTestSupport.prerequisiteProof(
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
                GenericProofTestSupport.prerequisiteProof(
                    mapping(REQUIRED_CLASS, REQUIRED_DEPENDENCY, "HIGH"), inventory))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Required class is present");
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
                GenericProofTestSupport.prerequisiteProof(
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
            ConfidenceLevel.HIGH,
            REQUIRED_DEPENDENCY,
            REQUIRED_CLASS);

    assertThatThrownBy(() -> GenericProofTestSupport.prerequisiteProof(mismatched, inventory))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("exactly one retained affected artifact");
  }

  private PreconditionClassInventory inventoryWithAffected() throws IOException {
    return PreconditionClassInventory.complete(List.of(affectedProvider()));
  }

  private static void assertRejectedLowConfidencePrerequisite(
      final String confidence, final PreconditionClassInventory inventory) {
    assertThatThrownBy(
            () ->
                GenericProofTestSupport.prerequisiteProof(
                    mapping(REQUIRED_CLASS, REQUIRED_DEPENDENCY, confidence), inventory))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("review");
  }

  private static void assertProofRejected(
      final GenericVulnerabilityFinding finding,
      final PreconditionClassInventory inventory,
      final String diagnostic) {
    assertThatThrownBy(() -> PreconditionProof.prove(finding, AFFECTED_COORDINATE, inventory))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining(diagnostic);
  }

  private static GenericVulnerabilityFinding findingWithGroups(
      final List<PrerequisiteGroup> groups) {
    return findingWithGroups(groups, AssessmentIntent.AUTO_VERIFY, Set.of());
  }

  private static GenericVulnerabilityFinding findingWithGroups(
      final List<PrerequisiteGroup> groups,
      final AssessmentIntent intent,
      final Set<UnresolvedContributionField> unresolvedFields) {
    final VulnerabilityFindingContribution contribution =
        new VulnerabilityFindingContribution(
            "CVE-2025-12345",
            Set.of(),
            AFFECTED_COORDINATE.groupId(),
            AFFECTED_COORDINATE.artifactId(),
            AFFECTED_COORDINATE.type(),
            AFFECTED_COORDINATE.classifier(),
            List.of(VersionCoverageClaim.affected("[1.0]")),
            FieldValue.omitted(),
            FieldValue.supplied(Set.copyOf(groups)),
            MergePriority.MANUAL,
            intent,
            "typed proof fixture",
            Set.of(),
            ConfidenceLevel.HIGH,
            unresolvedFields);
    return GenericVulnerabilityFinding.merge(List.of(contribution));
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
        ConfidenceLevel.valueOf(confidence),
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
