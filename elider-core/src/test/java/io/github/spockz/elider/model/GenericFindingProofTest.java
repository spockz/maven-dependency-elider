/* WHY: Proves generic effective findings obey the same physical and inventory limits. */

package io.github.spockz.elider.model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.model.PreconditionClassInventory.Provider;
import io.github.spockz.elider.trimmer.ArtifactDigests;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;

/** Exercises source-neutral proof admission using real class files. */
@SuppressWarnings({
  "PMD.AvoidDuplicateLiterals",
  "PMD.CouplingBetweenObjects",
  "PMD.CommentRequired",
  "PMD.AvoidInstantiatingObjectsInLoops"
})
class GenericFindingProofTest {
  private static final ArtifactCoordinate COMPONENT =
      ArtifactCoordinate.of("org.example", "library", "1.5");
  @TempDir private Path directory;

  /** Creates a test instance. */
  /* package */
  GenericFindingProofTest() {
    super();
  }

  @Test
  void verifiesAllEffectiveDeclarationsIndependentlyOfProvenanceAndReusesInspection()
      throws IOException {
    final ArtifactTrimRecord record =
        record(jar("original.jar", "p/Vulnerable", "p/Vulnerable$Inner"), jar("trimmed.jar"));
    final OmittedCodeProof.ArchiveInspection inspected = OmittedCodeProof.inspect(record);
    final Set<CodeClaim> claims =
        Set.of(CodeClaim.declared(CodeReference.className("p.Vulnerable")));
    final GenericVulnerabilityFinding first =
        finding(claims, Set.of(), AssessmentIntent.AUTO_VERIFY, "provider-a");
    final GenericVulnerabilityFinding second =
        finding(claims, Set.of(), AssessmentIntent.AUTO_VERIFY, "provider-b");
    final VexAttestation firstProof = OmittedCodeProof.prove(first, inspected, false);
    final VexAttestation secondProof = OmittedCodeProof.prove(second, inspected, false);

    assertAll(
        () ->
            assertThat(firstProof.evidenceSymbols())
                .containsExactly("p.Vulnerable", "p.Vulnerable$Inner"),
        () -> assertThat(secondProof.evidenceSymbols()).isEqualTo(firstProof.evidenceSymbols()),
        () -> assertThat(firstProof.sourceLabels()).containsExactly("provider-a"),
        () -> assertThat(secondProof.sourceLabels()).containsExactly("provider-b"),
        () -> assertThat(secondProof.originalSha256()).isEqualTo(firstProof.originalSha256()),
        () -> assertThat(firstProof.trimmedSha256()).isEqualTo(record.trimmedSha256()),
        () -> {
          final GenericVulnerabilityFinding incomplete =
              finding(
                  Set.of(
                      CodeClaim.declared(CodeReference.className("p.Vulnerable")),
                      CodeClaim.declared(CodeReference.className("p.Missing"))),
                  Set.of(),
                  AssessmentIntent.AUTO_VERIFY,
                  "arbitrary-label");
          assertThatThrownBy(() -> OmittedCodeProof.prove(incomplete, inspected, false))
              .isInstanceOf(IllegalArgumentException.class)
              .hasMessageContaining("attribution");
        },
        () -> {
          final ArtifactTrimRecord survivingInner =
              record(record.originalPath(), jar("surviving.jar", "p/Vulnerable$Inner"));
          assertThatThrownBy(
                  () ->
                      OmittedCodeProof.prove(
                          first, OmittedCodeProof.inspect(survivingInner), false))
              .isInstanceOf(IllegalArgumentException.class)
              .hasMessageContaining("survives");
        });
  }

  @Test
  void rejectsReviewOnlyUnattributedOrIncorrectlyBoundInputs() throws IOException {
    final ArtifactTrimRecord record =
        record(jar("original.jar", "p/Vulnerable"), jar("trimmed.jar"));
    final Set<CodeClaim> classes =
        Set.of(CodeClaim.declared(CodeReference.className("p.Vulnerable")));
    final OmittedCodeProof.ArchiveInspection inspected = OmittedCodeProof.inspect(record);
    final GenericVulnerabilityFinding review =
        finding(classes, Set.of(), AssessmentIntent.REVIEW_ONLY, "manual");
    final GenericVulnerabilityFinding heuristic =
        finding(
            Set.of(CodeClaim.heuristic(CodeReference.className("p.Vulnerable"))),
            Set.of(),
            AssessmentIntent.AUTO_VERIFY,
            "automatic");
    final GenericVulnerabilityFinding fileWithMissingMetadata =
        finding(
            Set.of(CodeClaim.declared(CodeReference.sourceFile("p/Vulnerable.java"))),
            Set.of(),
            AssessmentIntent.AUTO_VERIFY,
            "declaration");
    final ArtifactTrimRecord wrongOriginalDigest =
        new ArtifactTrimRecord(
            COMPONENT,
            record.originalPath(),
            "a".repeat(64),
            record.originalSha1(),
            record.trimmedPath(),
            record.trimmedSha256(),
            record.trimmedSha1(),
            1,
            0,
            1);
    final ArtifactTrimRecord wrongTrimmedDigest =
        new ArtifactTrimRecord(
            COMPONENT,
            record.originalPath(),
            record.originalSha256(),
            record.originalSha1(),
            record.trimmedPath(),
            "b".repeat(64),
            record.trimmedSha1(),
            1,
            0,
            1);

    assertAll(
        () ->
            assertThatThrownBy(() -> OmittedCodeProof.prove(review, inspected, false))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("review"),
        () ->
            assertThatThrownBy(() -> OmittedCodeProof.prove(heuristic, inspected, false))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("declared"),
        () ->
            assertThatThrownBy(
                    () -> OmittedCodeProof.prove(fileWithMissingMetadata, inspected, true))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("attribution"),
        () ->
            assertThatThrownBy(() -> OmittedCodeProof.inspect(wrongOriginalDigest))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("digest"),
        () ->
            assertThatThrownBy(() -> OmittedCodeProof.inspect(wrongTrimmedDigest))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("digest"),
        () ->
            assertThatThrownBy(
                    () ->
                        PreconditionProof.prove(
                            review,
                            ArtifactCoordinate.of("org.other", "library", "1.5"),
                            PreconditionClassInventory.complete(List.of())))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("component"));
  }

  @Test
  void checksEveryPrerequisitePairAgainstOneCompleteInventory() throws IOException {
    final Path affectedJar = jar("affected.jar", "p/Affected");
    final Provider affected = Provider.dependencyArchive(COMPONENT, affectedJar);
    final PreconditionClassInventory complete =
        PreconditionClassInventory.complete(List.of(affected));
    final PrerequisiteClaim first = new PrerequisiteClaim("org.example:first", "p.First");
    final PrerequisiteClaim second = new PrerequisiteClaim("org.example:second", "p.Second");
    final GenericVulnerabilityFinding finding =
        finding(Set.of(), Set.of(first, second), AssessmentIntent.AUTO_VERIFY, "source-a");
    final VexAttestation proof = PreconditionProof.prove(finding, COMPONENT, complete);

    assertAll(
        () -> assertThat(proof.requiredPrerequisites()).containsExactly(first, second),
        () -> assertThat(proof.inventorySha256()).isEqualTo(complete.fingerprint()),
        () ->
            assertThat(proof.impactDetail())
                .contains("org.example:first", "p.First", "org.example:second", "p.Second"),
        () -> {
          final Provider classProvider =
              Provider.dependencyArchive(
                  ArtifactCoordinate.of("org.other", "provider", "1"),
                  jar("class-provider.jar", "p/Second"));
          assertThatThrownBy(
                  () ->
                      PreconditionProof.prove(
                          finding,
                          COMPONENT,
                          PreconditionClassInventory.complete(List.of(affected, classProvider))))
              .isInstanceOf(IllegalArgumentException.class)
              .hasMessageContaining("Required class");
        },
        () -> {
          final Provider coordinateProvider =
              Provider.dependencyArchive(
                  ArtifactCoordinate.of("org.example", "second", "1"),
                  jar("dependency-provider.jar"));
          assertThatThrownBy(
                  () ->
                      PreconditionProof.prove(
                          finding,
                          COMPONENT,
                          PreconditionClassInventory.complete(
                              List.of(affected, coordinateProvider))))
              .isInstanceOf(IllegalArgumentException.class)
              .hasMessageContaining("Required dependency");
        },
        () ->
            assertThatThrownBy(
                    () ->
                        PreconditionProof.prove(
                            finding,
                            COMPONENT,
                            PreconditionClassInventory.incomplete(
                                List.of(affected), "runtime providers unknown")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("incomplete"));
  }

  @Test
  void reusesVerifiedInventoryAcrossFindings() throws IOException {
    final Path archive = jar("inventory-reuse.jar");
    final PreconditionClassInventory inventory =
        PreconditionClassInventory.complete(
            List.of(Provider.dependencyArchive(COMPONENT, archive)));
    final PreconditionProof.InventoryInspection inspection = PreconditionProof.inspect(inventory);
    final PrerequisiteClaim pair = new PrerequisiteClaim("org.example:missing", "p.Missing");
    final VexAttestation first =
        PreconditionProof.prove(
            finding(Set.of(), Set.of(pair), AssessmentIntent.AUTO_VERIFY, "first"),
            COMPONENT,
            inspection);
    final VexAttestation second =
        PreconditionProof.prove(
            finding(Set.of(), Set.of(pair), AssessmentIntent.AUTO_VERIFY, "second"),
            COMPONENT,
            inspection);
    assertAll(
        () -> assertThat(first.requiredPrerequisites()).containsExactly(pair),
        () -> assertThat(second.requiredPrerequisites()).isEqualTo(first.requiredPrerequisites()),
        () -> assertThat(first.inventorySha256()).isEqualTo(inventory.fingerprint()),
        () -> assertThat(second.postElisionSha256()).isEqualTo(first.postElisionSha256()));
  }

  @Test
  void unknownPotentialDeclarationsBlockOnlyTheirEffectiveGroup() throws IOException {
    final ArtifactTrimRecord record =
        record(
            jar("unknown-original.jar", "p/Vulnerable", "p/Uncertain"),
            jar("unknown-trimmed.jar", "p/Uncertain"));
    final OmittedCodeProof.ArchiveInspection inspected = OmittedCodeProof.inspect(record);
    final Set<CodeClaim> knownCode =
        Set.of(CodeClaim.declared(CodeReference.className("p.Vulnerable")));
    final VulnerabilityFindingContribution known =
        finding(knownCode, Set.of(), AssessmentIntent.AUTO_VERIFY, "known")
            .contributions()
            .getFirst();
    final VersionCoverageClaim unknown =
        VersionCoverageClaim.unresolvedRange("[1,2)", "source status unknown");
    final VulnerabilityFindingContribution unknownCode =
        contribution(
            unknown,
            FieldValue.supplied(Set.of(CodeClaim.declared(CodeReference.className("p.Uncertain")))),
            FieldValue.omitted(),
            MergePriority.AUTOMATIC);
    final VulnerabilityFindingContribution replacement =
        contribution(
            VersionCoverageClaim.affected("[1,2)"),
            FieldValue.supplied(knownCode),
            FieldValue.omitted(),
            MergePriority.MANUAL);
    final GenericVulnerabilityFinding unresolved =
        GenericVulnerabilityFinding.merge(List.of(known, unknownCode));
    final GenericVulnerabilityFinding overridden =
        GenericVulnerabilityFinding.merge(List.of(known, unknownCode, replacement));
    final GenericVulnerabilityFinding packageOnly =
        GenericVulnerabilityFinding.merge(
            List.of(
                known,
                contribution(
                    unknown, FieldValue.omitted(), FieldValue.omitted(), MergePriority.AUTOMATIC)));
    final PrerequisiteClaim prerequisite =
        new PrerequisiteClaim("org.example:missing", "p.Missing");
    final GenericVulnerabilityFinding unknownPrerequisite =
        GenericVulnerabilityFinding.merge(
            List.of(
                finding(Set.of(), Set.of(prerequisite), AssessmentIntent.AUTO_VERIFY, "known-pair")
                    .contributions()
                    .getFirst(),
                contribution(
                    unknown,
                    FieldValue.omitted(),
                    FieldValue.supplied(
                        Set.of(new PrerequisiteClaim("org.example:uncertain", "p.Uncertain"))),
                    MergePriority.AUTOMATIC)));

    assertAll(
        () -> assertThat(unresolved.applicability("1.5")).isEqualTo(VersionApplicability.AFFECTED),
        () ->
            assertThat(unresolved.codeGroupStatusFor("1.5")).isEqualTo(ClaimGroupStatus.UNRESOLVED),
        () ->
            assertThatThrownBy(() -> OmittedCodeProof.prove(unresolved, inspected, false))
                .isInstanceOf(IllegalArgumentException.class),
        () ->
            assertThat(OmittedCodeProof.prove(overridden, inspected, false).evidenceSymbols())
                .containsExactly("p.Vulnerable"),
        () ->
            assertThat(OmittedCodeProof.prove(packageOnly, inspected, false).evidenceSymbols())
                .containsExactly("p.Vulnerable"),
        () ->
            assertThat(unknownPrerequisite.prerequisiteGroupStatusFor("1.5"))
                .isEqualTo(ClaimGroupStatus.UNRESOLVED),
        () ->
            assertThatThrownBy(
                    () ->
                        PreconditionProof.prove(
                            unknownPrerequisite,
                            COMPONENT,
                            PreconditionClassInventory.complete(
                                List.of(
                                    Provider.dependencyArchive(COMPONENT, record.originalPath())))))
                .isInstanceOf(IllegalArgumentException.class));
  }

  @Test
  void unknownGroupsAreScopedAndIndependentlyOverridden() throws IOException {
    final ArtifactTrimRecord record =
        record(jar("group-original.jar", "p/Vulnerable"), jar("group-trimmed.jar"));
    final OmittedCodeProof.ArchiveInspection archive = OmittedCodeProof.inspect(record);
    final PreconditionProof.InventoryInspection inventory =
        PreconditionProof.inspect(
            PreconditionClassInventory.complete(
                List.of(Provider.dependencyArchive(COMPONENT, record.originalPath()))));
    final Set<CodeClaim> code = Set.of(CodeClaim.declared(CodeReference.className("p.Vulnerable")));
    final Set<PrerequisiteClaim> pairs =
        Set.of(new PrerequisiteClaim("org.example:missing", "p.Missing"));
    final VulnerabilityFindingContribution known =
        finding(code, pairs, AssessmentIntent.AUTO_VERIFY, "known").contributions().getFirst();
    final VersionCoverageClaim unknown = VersionCoverageClaim.unresolvedRange("[1,2)", "unknown");
    final VulnerabilityFindingContribution unknownCode =
        contribution(
            unknown, FieldValue.supplied(code), FieldValue.omitted(), MergePriority.AUTOMATIC);
    final VulnerabilityFindingContribution unknownPair =
        contribution(
            unknown, FieldValue.omitted(), FieldValue.supplied(pairs), MergePriority.AUTOMATIC);
    final GenericVulnerabilityFinding knownPlusUnknown =
        GenericVulnerabilityFinding.merge(List.of(known.withVersionClaim(unknown)));
    final GenericVulnerabilityFinding codeUncertain =
        GenericVulnerabilityFinding.merge(List.of(known, unknownCode));
    final GenericVulnerabilityFinding pairUncertain =
        GenericVulnerabilityFinding.merge(List.of(known, unknownPair));
    final GenericVulnerabilityFinding outOfRange =
        GenericVulnerabilityFinding.merge(
            List.of(
                known,
                contribution(
                    VersionCoverageClaim.unresolvedRange("[2,3)", "unknown"),
                    FieldValue.supplied(code),
                    FieldValue.supplied(pairs),
                    MergePriority.AUTOMATIC)));
    final GenericVulnerabilityFinding heuristic =
        GenericVulnerabilityFinding.merge(
            List.of(
                known,
                contribution(
                    unknown,
                    FieldValue.supplied(
                        Set.of(CodeClaim.heuristic(CodeReference.className("p.Other")))),
                    FieldValue.omitted(),
                    MergePriority.AUTOMATIC)));
    final GenericVulnerabilityFinding omittedManual =
        GenericVulnerabilityFinding.merge(
            List.of(
                known,
                unknownCode,
                contribution(
                    VersionCoverageClaim.affected("[1,2)"),
                    FieldValue.omitted(),
                    FieldValue.omitted(),
                    MergePriority.MANUAL)));
    final GenericVulnerabilityFinding pairManual =
        GenericVulnerabilityFinding.merge(
            List.of(
                known,
                unknownPair,
                contribution(
                    VersionCoverageClaim.affected("[1,2)"),
                    FieldValue.omitted(),
                    FieldValue.supplied(pairs),
                    MergePriority.MANUAL)));
    assertAll(
        () ->
            assertThat(OmittedCodeProof.prove(knownPlusUnknown, archive, false).evidenceSymbols())
                .containsExactly("p.Vulnerable"),
        () ->
            assertThat(
                    PreconditionProof.prove(knownPlusUnknown, COMPONENT, inventory)
                        .requiredPrerequisites())
                .isEqualTo(pairs),
        () ->
            assertThat(codeUncertain.codeFor("1.5"))
                .containsExactly(CodeReference.className("p.Vulnerable")),
        () ->
            assertThatThrownBy(() -> OmittedCodeProof.prove(codeUncertain, archive, false))
                .isInstanceOf(IllegalArgumentException.class),
        () ->
            assertThat(
                    PreconditionProof.prove(codeUncertain, COMPONENT, inventory)
                        .requiredPrerequisites())
                .isEqualTo(pairs),
        () ->
            assertThat(OmittedCodeProof.prove(pairUncertain, archive, false).evidenceSymbols())
                .containsExactly("p.Vulnerable"),
        () ->
            assertThatThrownBy(() -> PreconditionProof.prove(pairUncertain, COMPONENT, inventory))
                .isInstanceOf(IllegalArgumentException.class),
        () ->
            assertThat(OmittedCodeProof.prove(outOfRange, archive, false).evidenceSymbols())
                .containsExactly("p.Vulnerable"),
        () ->
            assertThat(
                    PreconditionProof.prove(outOfRange, COMPONENT, inventory)
                        .requiredPrerequisites())
                .isEqualTo(pairs),
        () ->
            assertThat(OmittedCodeProof.prove(heuristic, archive, false).evidenceSymbols())
                .containsExactly("p.Vulnerable"),
        () ->
            assertThatThrownBy(() -> OmittedCodeProof.prove(omittedManual, archive, false))
                .isInstanceOf(IllegalArgumentException.class),
        () ->
            assertThat(
                    PreconditionProof.prove(pairManual, COMPONENT, inventory)
                        .requiredPrerequisites())
                .isEqualTo(pairs));
  }

  private static VulnerabilityFindingContribution contribution(
      final VersionCoverageClaim coverage,
      final FieldValue<Set<CodeClaim>> code,
      final FieldValue<Set<PrerequisiteClaim>> prerequisites,
      final MergePriority priority) {
    return new VulnerabilityFindingContribution(
        "CVE-2026-10000",
        Set.of(),
        "org.example",
        "library",
        "jar",
        "",
        List.of(coverage),
        code,
        prerequisites,
        priority,
        AssessmentIntent.AUTO_VERIFY,
        "source-" + priority,
        Set.of());
  }

  private static GenericVulnerabilityFinding finding(
      final Set<CodeClaim> claims,
      final Set<PrerequisiteClaim> prerequisites,
      final AssessmentIntent intent,
      final String provenance) {
    return GenericVulnerabilityFinding.merge(
        List.of(
            new VulnerabilityFindingContribution(
                "CVE-2026-10000",
                Set.of(),
                "org.example",
                "library",
                "jar",
                "",
                List.of(VersionCoverageClaim.affected("[1,2)")),
                claims.isEmpty() ? FieldValue.omitted() : FieldValue.supplied(claims),
                prerequisites.isEmpty() ? FieldValue.omitted() : FieldValue.supplied(prerequisites),
                MergePriority.AUTOMATIC,
                intent,
                provenance,
                Set.of())));
  }

  private static ArtifactTrimRecord record(final Path original, final Path trimmed)
      throws IOException {
    final ArtifactDigests originalDigest = ArtifactDigests.read(original);
    final ArtifactDigests trimmedDigest = ArtifactDigests.read(trimmed);
    return new ArtifactTrimRecord(
        COMPONENT,
        original,
        originalDigest.sha256(),
        originalDigest.sha1(),
        trimmed,
        trimmedDigest.sha256(),
        trimmedDigest.sha1(),
        2,
        0,
        1);
  }

  private Path jar(final String name, final String... classes) throws IOException {
    final Path path = directory.resolve(name);
    try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(path))) {
      for (final String className : classes) {
        final ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, className, null, "java/lang/Object", null);
        writer.visitEnd();
        output.putNextEntry(new JarEntry(className + ".class"));
        output.write(writer.toByteArray());
        output.closeEntry();
      }
    }
    return path;
  }
}
