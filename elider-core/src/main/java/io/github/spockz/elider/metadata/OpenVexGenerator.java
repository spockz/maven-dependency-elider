// WHY: Emits standalone OpenVEX assertions only for proof-backed vulnerability evidence.

package io.github.spockz.elider.metadata;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ArtifactFileRef;
import io.github.spockz.elider.model.VexAttestation;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.util.Collection;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.UUID;

/** Generates deterministic OpenVEX documents for verified vulnerability evidence. */
@SuppressWarnings({
  "PMD.CommentRequired",
  "PMD.LocalVariableCouldBeFinal",
  "PMD.MethodArgumentCouldBeFinal",
  "PMD.UseConcurrentHashMap"
})
public final class OpenVexGenerator {
  private static final int MINIMUM_VERSION = 1;
  private static final String VULNERABLE_CODE_NOT_PRESENT = "vulnerable_code_not_present";

  /** Reuses a mapper with fixed configuration for every generated document. */
  private static final ObjectMapper JSON = new ObjectMapper();

  /** OpenVEX context URL for version 0.2.0. */
  private static final String CONTEXT = "https://openvex.dev/ns/v0.2.0";

  /** Creates a generator with the default JSON configuration. */
  public OpenVexGenerator() {
    // An explicit constructor keeps the generator's lifecycle visible to callers.
  }

  /** Metadata required for the standalone VEX document. */
  public record DocumentMetadata(
      String documentId, String author, String role, Instant timestamp, int version) {
    /** Validates that required OpenVEX document metadata is present. */
    public DocumentMetadata {
      requireText(documentId, "document id");
      requireText(author, "author");
      requireText(role, "role");
      Objects.requireNonNull(timestamp, "timestamp must not be null");
      if (version < MINIMUM_VERSION) {
        throw new IllegalArgumentException("version must be positive");
      }
      URI parsedId;
      try {
        parsedId = URI.create(documentId);
      } catch (IllegalArgumentException exception) {
        throw new IllegalArgumentException("document id must be an absolute IRI", exception);
      }
      if (!parsedId.isAbsolute()) {
        throw new IllegalArgumentException("document id must be an absolute IRI");
      }
    }
  }

  /** Builds and atomically writes a standalone OpenVEX document. */
  public void write(
      Path output,
      CycloneDxSbomGenerator.RootIdentity root,
      Collection<ArtifactFileRef> postElisionInventory,
      Collection<VexAttestation> attestations,
      DocumentMetadata metadata)
      throws IOException {
    Objects.requireNonNull(output, "output must not be null");
    byte[] bytes = generate(root, postElisionInventory, attestations, metadata);
    Path absolute = output.toAbsolutePath();
    Path parent = absolute.getParent();
    if (parent == null) {
      throw new IOException("Output path must have a parent directory: " + absolute);
    }
    Files.createDirectories(parent);
    Path temporary =
        parent.resolve("." + absolute.getFileName() + "." + UUID.randomUUID() + ".tmp");
    try {
      Files.write(temporary, bytes);
      Files.move(
          temporary, absolute, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    } finally {
      Files.deleteIfExists(temporary);
    }
  }

  /** Generates OpenVEX JSON referencing components in the post-elision SBOM. */
  public byte[] generate(
      CycloneDxSbomGenerator.RootIdentity root,
      Collection<ArtifactFileRef> postElisionInventory,
      Collection<VexAttestation> attestations,
      DocumentMetadata metadata)
      throws IOException {
    Objects.requireNonNull(root, "root must not be null");
    Objects.requireNonNull(postElisionInventory, "postElisionInventory must not be null");
    Objects.requireNonNull(attestations, "attestations must not be null");
    Objects.requireNonNull(metadata, "metadata must not be null");
    if (attestations.isEmpty()) {
      throw new IllegalArgumentException(
          "OpenVEX document requires at least one verified statement");
    }
    Map<String, ArtifactFileRef> componentsByPurl = indexComponents(postElisionInventory);
    Map<String, String> componentDigests = new TreeMap<>();
    Map<String, VexAttestation> unique =
        uniqueAttestations(attestations, componentsByPurl, componentDigests);
    ObjectNode document = document(metadata);
    ArrayNode statements = document.putArray("statements");
    unique
        .values()
        .forEach(
            attestation -> {
              String purl = CycloneDxSbomGenerator.componentPurl(attestation.coordinate());
              String key = attestation.cveId() + "\u0000" + purl;
              addStatement(statements, root, attestation, componentDigests.get(key));
            });
    return JSON.writeValueAsBytes(document);
  }

  private static Map<String, ArtifactFileRef> indexComponents(
      Collection<ArtifactFileRef> postElisionInventory) {
    Map<String, ArtifactFileRef> componentsByPurl = new TreeMap<>();
    for (ArtifactFileRef ref : postElisionInventory) {
      Objects.requireNonNull(ref, "post-elision inventory item must not be null");
      requireResolved(ref.coordinate());
      String purl = CycloneDxSbomGenerator.componentPurl(ref.coordinate());
      ArtifactFileRef prior = componentsByPurl.putIfAbsent(purl, ref);
      if (prior != null && !prior.filePath().equals(ref.filePath())) {
        throw new IllegalArgumentException("Conflicting post-elision component files for " + purl);
      }
    }
    return componentsByPurl;
  }

  private static Map<String, VexAttestation> uniqueAttestations(
      Collection<VexAttestation> attestations,
      Map<String, ArtifactFileRef> componentsByPurl,
      Map<String, String> componentDigests)
      throws IOException {
    Map<String, VexAttestation> omittedCode = new TreeMap<>();
    Map<String, VexAttestation> preconditions = new TreeMap<>();
    for (VexAttestation attestation : attestations) {
      Objects.requireNonNull(attestation, "VEX attestation must not be null");
      String componentSha256 = validateAttestation(attestation, componentsByPurl);
      final String purl = CycloneDxSbomGenerator.componentPurl(attestation.coordinate());
      String key = attestation.cveId() + "\u0000" + purl;
      VexSerializerSupport.addAttestation(omittedCode, preconditions, key, attestation);
      componentDigests.put(key, componentSha256);
    }

    return VexSerializerSupport.preferredAttestations(omittedCode, preconditions);
  }

  private static ObjectNode document(DocumentMetadata metadata) {
    ObjectNode document = JSON.createObjectNode();
    document.put("@context", CONTEXT);
    document.put("@id", metadata.documentId());
    document.put("author", metadata.author());
    document.put("role", metadata.role());
    document.put("timestamp", metadata.timestamp().toString());
    document.put("version", metadata.version());
    return document;
  }

  private static void addStatement(
      ArrayNode statements,
      CycloneDxSbomGenerator.RootIdentity root,
      VexAttestation attestation,
      String componentSha256) {
    final String purl = CycloneDxSbomGenerator.componentPurl(attestation.coordinate());
    ObjectNode statement = statements.addObject();
    statement.putObject("vulnerability").put("name", attestation.cveId());
    ObjectNode product = statement.putArray("products").addObject();
    String rootBomRef = CycloneDxSbomGenerator.rootBomRef(root);
    product.put("@id", rootBomRef);
    product.putObject("identifiers").put("purl", rootBomRef);
    ObjectNode subcomponent = product.putArray("subcomponents").addObject();
    subcomponent.put("@id", purl);
    subcomponent.putObject("identifiers").put("purl", purl);
    subcomponent.putObject("hashes").put("sha-256", componentSha256);
    statement.put("status", "not_affected");
    if (!VexSerializerSupport.isPrecondition(attestation)) {
      statement.put("justification", VULNERABLE_CODE_NOT_PRESENT);
    }
    statement.put("impact_statement", attestation.impactDetail());
  }

  private static String validateAttestation(
      VexAttestation attestation, Map<String, ArtifactFileRef> componentsByPurl)
      throws IOException {
    String purl = CycloneDxSbomGenerator.componentPurl(attestation.coordinate());
    ArtifactFileRef component = componentsByPurl.get(purl);
    if (component == null) {
      throw new IllegalArgumentException(
          "VEX attestation has no matching post-elision component: " + purl);
    }
    return VexSerializerSupport.verifyAttestation(attestation, component);
  }

  private static void requireResolved(ArtifactCoordinate coordinate) {
    Objects.requireNonNull(coordinate, "coordinate must not be null");
    requireText(coordinate.version(), "component version");
  }

  private static void requireText(String value, String name) {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException(name + " must not be blank");
    }
  }
}
