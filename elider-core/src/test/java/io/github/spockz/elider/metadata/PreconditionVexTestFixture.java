// WHY: Supplies proof-produced prerequisite attestations to both serializer test suites.

package io.github.spockz.elider.metadata;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ArtifactFileRef;
import io.github.spockz.elider.model.PreconditionClassInventory;
import io.github.spockz.elider.model.PreconditionProof;
import io.github.spockz.elider.model.VexAttestation;
import io.github.spockz.elider.model.VulnerabilitySymbolMapping;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.zip.ZipOutputStream;

@SuppressWarnings({"PMD.CommentDefaultAccessModifier"})
record PreconditionVexTestFixture(
    ArtifactCoordinate coordinate, ArtifactFileRef inventory, VexAttestation attestation) {

  static PreconditionVexTestFixture proven(final Path directory) throws IOException {
    final Path affectedPath = directory.resolve("precondition-affected.jar");
    try (ZipOutputStream output = new ZipOutputStream(Files.newOutputStream(affectedPath))) {
      output.finish();
    }
    final ArtifactCoordinate affected = ArtifactCoordinate.of("org.example", "affected", "1.2");
    final PreconditionClassInventory inventory =
        PreconditionClassInventory.complete(
            List.of(PreconditionClassInventory.Provider.dependencyArchive(affected, affectedPath)));
    final VulnerabilitySymbolMapping mapping =
        new VulnerabilitySymbolMapping(
            "CVE-2025-67890",
            affected,
            "[1.0,2.0)",
            Set.of(),
            URI.create("https://example.org/advisory/CVE-2025-67890"),
            VulnerabilitySymbolMapping.ConfidenceLevel.HIGH,
            "org.example:optional",
            "org.example.RequiredApi");
    final VexAttestation attestation = PreconditionProof.prove(mapping, inventory);
    return new PreconditionVexTestFixture(
        affected, ArtifactFileRef.fromPath(affected, affectedPath), attestation);
  }
}
