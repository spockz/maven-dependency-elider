// WHY: Builds minimal valid trim provenance so generator tests can consume only proof-produced
// attestations.

package io.github.spockz.elider.metadata;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ArtifactFileRef;
import io.github.spockz.elider.model.OmittedCodeProof;
import io.github.spockz.elider.model.VexAttestation;
import io.github.spockz.elider.model.VulnerabilitySymbolMapping;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

@SuppressWarnings({
  "PMD.AvoidInstantiatingObjectsInLoops",
  "PMD.CommentDefaultAccessModifier",
  "PMD.LocalVariableCouldBeFinal",
  "PMD.MethodArgumentCouldBeFinal"
})
record VexTestFixture(
    ArtifactCoordinate coordinate,
    ArtifactTrimRecord trimRecord,
    ArtifactFileRef inventory,
    VexAttestation attestation) {

  static VexTestFixture proven(Path directory) throws IOException, NoSuchAlgorithmException {
    Path original = directory.resolve("original-vex.jar");
    Path trimmed = directory.resolve("trimmed-vex.jar");
    writeJar(
        original,
        "org/example/Vulnerable.class",
        "org/example/Vulnerable$Nested.class",
        "org/example/Safe.class");
    writeJar(trimmed, "org/example/Safe.class");
    ArtifactCoordinate coordinate = ArtifactCoordinate.of("org.example", "library", "1.2");
    ArtifactTrimRecord trimRecord =
        new ArtifactTrimRecord(
            coordinate,
            original,
            digest(original, "SHA-256"),
            digest(original, "SHA-1"),
            trimmed,
            digest(trimmed, "SHA-256"),
            digest(trimmed, "SHA-1"),
            3,
            1,
            0);
    ArtifactFileRef inventory = ArtifactFileRef.fromPath(coordinate, trimmed);
    VulnerabilitySymbolMapping mapping =
        new VulnerabilitySymbolMapping(
            "CVE-2025-12345",
            coordinate,
            "[1.0,2.0)",
            Set.of("org.example.Vulnerable"),
            java.net.URI.create("https://example.org/advisory/CVE-2025-12345"),
            VulnerabilitySymbolMapping.ConfidenceLevel.HIGH);
    VexAttestation attestation = OmittedCodeProof.prove(mapping, trimRecord);
    return new VexTestFixture(coordinate, trimRecord, inventory, attestation);
  }

  private static void writeJar(Path path, String... entries) throws IOException {
    try (ZipOutputStream output = new ZipOutputStream(Files.newOutputStream(path))) {
      for (String name : entries) {
        output.putNextEntry(new ZipEntry(name));
        output.write(1);
        output.closeEntry();
      }
    }
  }

  private static String digest(Path file, String algorithm)
      throws IOException, NoSuchAlgorithmException {
    return HexFormat.of()
        .formatHex(MessageDigest.getInstance(algorithm).digest(Files.readAllBytes(file)));
  }
}
