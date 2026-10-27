// WHY: Emits standalone OpenVEX assertions only for vulnerability evidence proven by core trimming.

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

/** Generates deterministic OpenVEX documents for verified omitted-code evidence. */
@SuppressWarnings({
  "PMD.CommentDefaultAccessModifier",
  "PMD.CommentRequired",
  "PMD.LocalVariableCouldBeFinal",
  "PMD.MethodArgumentCouldBeFinal",
  "PMD.TooManyMethods",
  "PMD.UseConcurrentHashMap"
})
public final class OpenVexGenerator {
  private static final int MINIMUM_VERSION = 1;
  private static final String VULNERABLE_CODE_NOT_PRESENT = "vulnerable_code_not_present";

  /** Reuses a mapper with fixed configuration for every generated document. */
  private static final ObjectMapper JSON = new ObjectMapper();

  /** OpenVEX context URL for version 0.2.0. */
  private static final String CONTEXT = "https://openvex.dev/ns/v0.2.0";

  /** Lowercase SHA-256 digest format used by the immutable evidence model. */
  private static final String SHA256_PATTERN = "[0-9a-f]{64}";

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
    Map<String, VexAttestation> unique = uniqueAttestations(attestations, componentsByPurl);
    ObjectNode document = document(metadata);
    ArrayNode statements = document.putArray("statements");
    unique.values().forEach(attestation -> addStatement(statements, root, attestation));
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
      Collection<VexAttestation> attestations, Map<String, ArtifactFileRef> componentsByPurl)
      throws IOException {
    Map<String, VexAttestation> unique = new TreeMap<>();
    for (VexAttestation attestation : attestations) {
      Objects.requireNonNull(attestation, "VEX attestation must not be null");
      validateAttestation(attestation, componentsByPurl);
      final String purl = CycloneDxSbomGenerator.componentPurl(attestation.coordinate());
      String key = attestation.cveId() + "\u0000" + purl;
      VexAttestation prior = unique.putIfAbsent(key, attestation);
      if (prior != null && !sameEvidence(prior, attestation)) {
        throw new IllegalArgumentException("Conflicting duplicate VEX attestation for " + key);
      }
    }

    return unique;
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
      ArrayNode statements, CycloneDxSbomGenerator.RootIdentity root, VexAttestation attestation) {
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
    subcomponent.putObject("hashes").put("sha-256", attestation.trimmedSha256());
    statement.put("status", "not_affected");
    statement.put("justification", VULNERABLE_CODE_NOT_PRESENT);
    statement.put("impact_statement", attestation.impactDetail());
  }

  private static void validateAttestation(
      VexAttestation attestation, Map<String, ArtifactFileRef> componentsByPurl)
      throws IOException {
    validateEvidenceContent(attestation);
    validateEvidenceDigests(attestation);
    validatePostElisionDigest(attestation, componentsByPurl);
  }

  private static void validateEvidenceContent(VexAttestation attestation) {
    requireText(attestation.cveId(), "VEX vulnerability id");
    requireText(attestation.impactDetail(), "VEX impact detail");
    if (!VULNERABLE_CODE_NOT_PRESENT.equals(attestation.justification())) {
      throw new IllegalArgumentException(
          "VEX attestation justification must be vulnerable_code_not_present");
    }
    if (attestation.evidenceSymbols() == null || attestation.evidenceSymbols().isEmpty()) {
      throw new IllegalArgumentException("VEX attestation has no purged symbol evidence");
    }
  }

  private static void validateEvidenceDigests(VexAttestation attestation) {
    if (!isSha256(attestation.originalSha256()) || !isSha256(attestation.trimmedSha256())) {
      throw new IllegalArgumentException("VEX attestation must contain exact SHA-256 digests");
    }
  }

  private static void validatePostElisionDigest(
      VexAttestation attestation, Map<String, ArtifactFileRef> componentsByPurl)
      throws IOException {
    String purl = CycloneDxSbomGenerator.componentPurl(attestation.coordinate());
    ArtifactFileRef component = componentsByPurl.get(purl);
    if (component == null) {
      throw new IllegalArgumentException(
          "VEX attestation has no matching post-elision component: " + purl);
    }
    if (!CycloneDxSbomGenerator.sha256(component.filePath()).equals(attestation.trimmedSha256())) {
      throw new IllegalArgumentException(
          "VEX attestation trimmed digest does not match post-elision component: " + purl);
    }
  }

  /** Checks whether duplicate evidence would produce the same VEX statement. */
  static boolean sameEvidence(VexAttestation left, VexAttestation right) {
    return left.coordinate().equals(right.coordinate())
        && left.justification().equals(right.justification())
        && left.impactDetail().equals(right.impactDetail())
        && left.evidenceSymbols().equals(right.evidenceSymbols())
        && left.originalSha256().equals(right.originalSha256())
        && left.trimmedSha256().equals(right.trimmedSha256());
  }

  private static void requireResolved(ArtifactCoordinate coordinate) {
    Objects.requireNonNull(coordinate, "coordinate must not be null");
    requireText(coordinate.version(), "component version");
  }

  private static boolean isSha256(String value) {
    return value != null && value.matches(SHA256_PATTERN);
  }

  private static void requireText(String value, String name) {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException(name + " must not be blank");
    }
  }
}
