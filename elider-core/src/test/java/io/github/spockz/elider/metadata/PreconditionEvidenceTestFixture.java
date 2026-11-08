/* WHY: Shares real archive and proof construction across final-evidence test classes. */

package io.github.spockz.elider.metadata;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.spockz.elider.model.AdvisoryProvenance;
import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.AssessmentIntent;
import io.github.spockz.elider.model.ConfidenceLevel;
import io.github.spockz.elider.model.EvidenceOrigin;
import io.github.spockz.elider.model.FieldValue;
import io.github.spockz.elider.model.GenericVulnerabilityFinding;
import io.github.spockz.elider.model.MergePriority;
import io.github.spockz.elider.model.PreconditionClassInventory;
import io.github.spockz.elider.model.PreconditionProof;
import io.github.spockz.elider.model.PrerequisiteClaim;
import io.github.spockz.elider.model.PrerequisiteGroup;
import io.github.spockz.elider.model.PrerequisiteOperator;
import io.github.spockz.elider.model.PrerequisiteProofResult;
import io.github.spockz.elider.model.VersionCoverageClaim;
import io.github.spockz.elider.model.VexAttestation;
import io.github.spockz.elider.model.VulnerabilityFindingContribution;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.TreeMap;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;

/** Creates real archive-backed fixtures for adjacent evidence tests. */
final class PreconditionEvidenceTestFixture {
  /** Exact candidate whose VEX evidence is compared. */
  /* package */ static final ArtifactCoordinate CANDIDATE =
      ArtifactCoordinate.of("org.example", "affected", "1.2");

  /** First prerequisite owner in the test inventory. */
  /* package */ static final ArtifactCoordinate PROVIDER_ONE =
      ArtifactCoordinate.of("org.example", "provider-one", "1.0");

  /** Second prerequisite owner in the test inventory. */
  /* package */ static final ArtifactCoordinate PROVIDER_TWO =
      ArtifactCoordinate.of("org.example", "provider-two", "1.0");

  /** First exact class checked by proof. */
  /* package */ static final String CLASS_ONE = "org.example.First";

  /** Second exact class checked by proof. */
  /* package */ static final String CLASS_TWO = "org.example.Second";

  /** Prevents stateful fixture instances. */
  private PreconditionEvidenceTestFixture() {}

  /* package */ static PrerequisiteProofResult prove(
      final Path directory,
      final String source,
      final PrerequisiteGroup group,
      final PreconditionClassInventory baseline,
      final PreconditionClassInventory actualFinal)
      throws IOException {
    final VulnerabilityFindingContribution contribution =
        new VulnerabilityFindingContribution(
            "CVE-2026-13579",
            Set.of(),
            CANDIDATE.groupId(),
            CANDIDATE.artifactId(),
            CANDIDATE.type(),
            CANDIDATE.classifier(),
            List.of(VersionCoverageClaim.affected("[1.2]")),
            FieldValue.omitted(),
            FieldValue.supplied(Set.of(group)),
            MergePriority.MANUAL,
            AssessmentIntent.AUTO_VERIFY,
            source,
            Set.of(
                new AdvisoryProvenance(
                    EvidenceOrigin.POM, source, URI.create("https://example.org/" + source), null)),
            ConfidenceLevel.HIGH);
    final GenericVulnerabilityFinding finding =
        GenericVulnerabilityFinding.merge(List.of(contribution));
    return PreconditionProof.proveWithAttribution(finding, CANDIDATE, baseline, actualFinal);
  }

  /* package */ static PrerequisiteGroup group(
      final PrerequisiteOperator operator, final PrerequisiteClaim... claims) {
    return new PrerequisiteGroup(operator, Set.of(claims));
  }

  /* package */ static PrerequisiteClaim claimOne() {
    return new PrerequisiteClaim("org.example:provider-one", CLASS_ONE);
  }

  /* package */ static PrerequisiteClaim claimTwo() {
    return new PrerequisiteClaim("org.example:provider-two", CLASS_TWO);
  }

  /* package */ static PreconditionClassInventory.Provider provider(
      final Path directory, final ArtifactCoordinate coordinate, final String name)
      throws IOException {
    final Path archive = directory.resolve(name);
    try (ZipOutputStream output = new ZipOutputStream(Files.newOutputStream(archive))) {
      output.finish();
    }
    return PreconditionClassInventory.Provider.dependencyArchive(coordinate, archive);
  }

  /* package */ static PreconditionClassInventory.Provider providerWithClass(
      final Path directory,
      final ArtifactCoordinate coordinate,
      final String name,
      final String className)
      throws IOException {
    final Path archive = directory.resolve(name);
    try (ZipOutputStream output = new ZipOutputStream(Files.newOutputStream(archive))) {
      final String entryName = className.replace('.', '/') + ".class";
      output.putNextEntry(new ZipEntry(entryName));
      final ClassWriter writer = new ClassWriter(0);
      writer.visit(
          Opcodes.V21,
          Opcodes.ACC_PUBLIC,
          className.replace('.', '/'),
          null,
          "java/lang/Object",
          null);
      writer.visitEnd();
      output.write(writer.toByteArray());
      output.closeEntry();
    }
    return PreconditionClassInventory.Provider.dependencyArchive(coordinate, archive);
  }

  @SuppressWarnings("PMD.UseConcurrentHashMap")
  /* package */ static void assertConflictingEvidence(
      final VexAttestation first, final VexAttestation second) {
    // The map is local to this comparison and has one writer.
    final java.util.Map<String, VexAttestation> preconditions = new TreeMap<>();
    VexSerializerSupport.addAttestation(java.util.Map.of(), preconditions, first.cveId(), first);
    assertThatThrownBy(
            () ->
                VexSerializerSupport.addAttestation(
                    java.util.Map.of(), preconditions, second.cveId(), second))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Conflicting duplicate precondition VEX attestation");
  }
}
