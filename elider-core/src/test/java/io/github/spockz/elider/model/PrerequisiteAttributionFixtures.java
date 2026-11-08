/* WHY: Shares the real archive and finding setup used by prerequisite attribution tests. */

package io.github.spockz.elider.model;

import io.github.spockz.elider.model.PreconditionClassInventory.Provider;
import io.github.spockz.elider.model.PrerequisiteProofResult.GroupOutcome;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;

/** Physical archive inputs shared by prerequisite attribution cases. */
final class PrerequisiteAttributionFixtures {
  /** Exact affected artifact used by all proof fixtures. */
  /* package */ static final ArtifactCoordinate CANDIDATE =
      ArtifactCoordinate.of("org.example", "affected", "1.0");

  /** First exact dependency provider used in baseline/final comparisons. */
  /* package */ static final ArtifactCoordinate PROVIDER_ONE =
      ArtifactCoordinate.of("org.example", "provider-one", "1.0");

  /** Second exact dependency provider used in duplicate-provider comparisons. */
  /* package */ static final ArtifactCoordinate PROVIDER_TWO =
      ArtifactCoordinate.of("org.example", "provider-two", "1.0");

  /** Fully qualified class whose physical provider state is attributed. */
  /* package */ static final String REQUIRED_CLASS = "org.example.Required";

  /** Maven dependency pair bound to the prerequisite class. */
  /* package */ static final String REQUIRED_DEPENDENCY = "org.example:provider-one";

  private PrerequisiteAttributionFixtures() {}

  /* package */ static Provider archive(
      final Path directory,
      final ArtifactCoordinate coordinate,
      final String name,
      final Map<String, byte[]> entries)
      throws IOException {
    final Path path = directory.resolve(name);
    try (ZipOutputStream output = new ZipOutputStream(Files.newOutputStream(path))) {
      for (final Map.Entry<String, byte[]> entry : entries.entrySet()) {
        writeEntry(output, entry.getKey(), entry.getValue());
      }
    }
    return Provider.dependencyArchive(coordinate, path);
  }

  /* package */ static Map<String, byte[]> requiredClass() {
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(
        Opcodes.V17, Opcodes.ACC_PUBLIC, "org/example/Required", null, "java/lang/Object", null);
    writer.visitEnd();
    return Map.of("org/example/Required.class", writer.toByteArray());
  }

  /* package */ static GenericVulnerabilityFinding finding(final String cveId) {
    return GenericProofTestSupport.finding(
        new VulnerabilitySymbolMapping(
            cveId,
            CANDIDATE,
            "[1.0]",
            Set.of(),
            null,
            ConfidenceLevel.HIGH,
            REQUIRED_DEPENDENCY,
            REQUIRED_CLASS));
  }

  /* package */ static PrerequisiteProofResult prove(
      final PreconditionClassInventory baseline, final PreconditionClassInventory actualFinal)
      throws IOException {
    return PreconditionProof.proveWithAttribution(
        finding("CVE-2025-12345"), CANDIDATE, baseline, actualFinal);
  }

  /* package */ static GroupOutcome onlyGroup(final PrerequisiteProofResult result) {
    return result.groups().getFirst();
  }

  private static void writeEntry(
      final ZipOutputStream output, final String name, final byte[] bytes) throws IOException {
    output.putNextEntry(new ZipEntry(name));
    output.write(bytes);
    output.closeEntry();
  }
}
